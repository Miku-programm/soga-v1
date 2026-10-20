package proxy

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	tfo "github.com/database64128/tfo-go/v2"
	apicommon "github.com/enfein/mieru/v3/apis/common"
	mconstant "github.com/enfein/mieru/v3/apis/constant"
	"github.com/enfein/mieru/v3/apis/model"
	"github.com/enfein/mieru/v3/apis/server"
	"github.com/enfein/mieru/v3/apis/trafficpattern"
	"github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
	"github.com/enfein/mieru/v3/pkg/sockopts"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	"google.golang.org/protobuf/proto"
)

type mieruOptions struct{ Config }

type mieruInbound struct {
	inbound.Adapter
	ctx     context.Context
	router  adapter.Router
	server  server.Server
	users   map[string]int64
	mu      sync.Mutex
	active  map[net.Conn]bool
	stopped bool
}

func newMieruInbound(ctx context.Context, router adapter.Router, _ log.ContextLogger, tag string, options mieruOptions) (adapter.Inbound, error) {
	c := options.Config
	p := appctlpb.TransportProtocol_TCP
	switch strings.ToUpper(c.MieruTransport) {
	case "", "TCP":
	case "UDP":
		p = appctlpb.TransportProtocol_UDP
	default:
		return nil, errors.New("proxy: invalid Mieru transport")
	}
	cfg := &appctlpb.ServerConfig{ListenIPAddress: proto.String(c.Listen),
		AdvancedSettings: &appctlpb.ServerAdvancedSettings{UserHintIsMandatory: proto.Bool(c.MieruForceUserHint)},
		PortBindings:     []*appctlpb.PortBinding{{Port: proto.Int32(int32(c.Port)), Protocol: &p}}}
	m := &mieruInbound{Adapter: inbound.NewAdapter("mieru", tag), ctx: ctx, router: router,
		server: server.NewServer(), users: make(map[string]int64), active: make(map[net.Conn]bool)}
	for _, user := range c.Users {
		if user.Username == "" || m.users[user.Username] != 0 {
			return nil, errors.New("proxy: Mieru usernames must be nonempty and unique")
		}
		m.users[user.Username] = user.ID
		cfg.Users = append(cfg.Users, &appctlpb.User{Name: proto.String(user.Username), Password: proto.String(user.Password)})
	}
	if c.TrafficPattern != "" {
		pattern, err := trafficpattern.Decode(c.TrafficPattern)
		if err != nil {
			return nil, err
		}
		cfg.TrafficPattern = pattern
	}
	streamListener := &tfo.ListenConfig{
		ListenConfig: net.ListenConfig{Control: sockopts.DefaultListenerControl()},
		DisableTFO:   !c.TCPFastOpen,
	}
	streamListener.SetMultipathTCP(c.TCPMultiPath)
	var factory apicommon.StreamListenerFactory = streamListener
	if c.Tunnel != nil {
		factory = &mieruTunnelFactory{socket: streamListener, config: *c.Tunnel,
			directProxy: c.ProxyProtocol, required: c.ForceProxyProtocol, trusted: c.ProxyProtocolTrusted}
	}
	if err := m.server.Store(&server.ServerConfig{Config: cfg, StreamListenerFactory: factory}); err != nil {
		return nil, err
	}
	return m, nil
}

func (m *mieruInbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	if err := m.server.Start(); err != nil {
		return err
	}
	scope.Add(m.close)
	go m.accept()
	return nil
}

func (m *mieruInbound) close() error {
	m.mu.Lock()
	m.stopped = true
	conns := make([]net.Conn, 0, len(m.active))
	for c := range m.active {
		conns = append(conns, c)
	}
	m.mu.Unlock()
	err := m.server.Stop()
	// Mieru's API Stop explicitly preserves established sessions. Reconstruct
	// user revocation semantics by closing all sessions owned by this adapter.
	for _, c := range conns {
		_ = c.Close()
	}
	return err
}

func (m *mieruInbound) accept() {
	for {
		c, req, err := m.server.Accept()
		if err != nil {
			if !m.server.IsRunning() {
				return
			}
			continue
		}
		m.mu.Lock()
		if m.stopped {
			m.mu.Unlock()
			_ = c.Close()
			return
		}
		m.active[c] = true
		m.mu.Unlock()
		go m.handle(c, req)
	}
}

func (m *mieruInbound) handle(c net.Conn, req *model.Request) {
	done := func(error) {
		_ = c.Close()
		m.mu.Lock()
		delete(m.active, c)
		m.mu.Unlock()
	}
	user, ok := c.(apicommon.UserContext)
	if !ok || m.users[user.UserName()] == 0 {
		done(errors.New("missing Mieru user"))
		return
	}
	metadata := adapter.InboundContext{Inbound: m.Tag(), InboundType: "mieru",
		Source: M.SocksaddrFromNet(c.RemoteAddr()), Destination: M.ParseSocksaddr(req.DstAddr.String()),
		User: strconv.FormatInt(m.users[user.UserName()], 10)}
	if req.Command != mconstant.Socks5ConnectCmd && req.Command != mconstant.Socks5UDPAssociateCmd {
		done(errors.New("unsupported Mieru command"))
		return
	}
	response := &model.Response{Reply: mconstant.Socks5ReplySuccess, BindAddr: model.AddrSpec{IP: net.IPv4zero, Port: 0}}
	if err := response.WriteToSocks5(c); err != nil {
		done(err)
		return
	}
	if req.Command == mconstant.Socks5ConnectCmd {
		m.router.RouteConnectionEx(m.ctx, c, metadata, done)
		return
	}
	packet := bufio.NewPacketConn(apicommon.NewUDPAssociateWrapper(apicommon.NewPacketOverStreamTunnel(c)))
	// UDP ASSOCIATE addresses may be 0.0.0.0:0. Authorize the first actual
	// destination before establishing the routed association.
	c.SetReadDeadline(time.Now().Add(30 * time.Second))
	first := buf.NewPacket()
	destination, err := packet.ReadPacket(first)
	c.SetReadDeadline(time.Time{})
	if err != nil {
		first.Release()
		done(err)
		return
	}
	metadata.Destination = destination
	m.router.RoutePacketConnectionEx(m.ctx, bufio.NewCachedPacketConn(packet, first, destination), metadata, done)
}
