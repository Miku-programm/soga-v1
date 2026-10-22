package proxy

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/uot"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-shadowsocks"
	"github.com/sagernet/sing-shadowsocks/shadowaead_2022"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/ntp"
	shadowaead "reconstructed.local/soga/proxy/internal/shadowaeadcompat"
	"reconstructed.local/soga/proxy/simpleobfs"
	"reconstructed.local/soga/proxy/ssrcore"
	"reconstructed.local/soga/proxy/wireproxy"
)

type shadowsocksOptions struct{ Config }
type ssWireService interface {
	N.TCPConnectionHandler
	N.UDPHandler
}

func isSSAEAD(method string) bool {
	return slices.Contains(shadowaead.List, method) || slices.Contains(shadowaead_2022.List, method)
}

type shadowsocksInbound struct {
	inbound.Adapter
	ctx       context.Context
	config    Config
	router    adapter.ConnectionRouterEx
	listener  *listener.Listener
	service   ssWireService
	invalid   *invalidAccessGuard
	mu        sync.Mutex
	closed    bool
	active    map[io.Closer]bool
	userOf    map[io.Closer]string          // authenticated user per tracked connection
	multi     shadowsocks.MultiService[string] // nil in single-user (obfs carrier) mode
	muHosts   map[string]string
	carrierID string
}

func isSSObfsMulti(c Config) bool {
	return c.Protocol == "ssr" && c.SSRSinglePortType == "obfs" && (c.SSRObfs == "simple_obfs_http" || c.SSRObfs == "simple_obfs_tls")
}
func ssMultiUsers(c Config) (User, map[string]string, error) {
	if c.MURegex == "" {
		c.MURegex = "%5m%id.%suffix"
	}
	if c.MUSuffix == "" {
		c.MUSuffix = "microsoft.com"
	}
	var carrier User
	hosts := map[string]string{}
	for _, u := range c.Users {
		if u.ID == c.SSRCarrierID {
			carrier = u
			continue
		}
		host, err := ssrcore.HostForUser(ssrcore.User{ID: u.ID, Password: u.Password, Method: u.Method, Protocol: u.Protocol, Obfs: u.Obfs}, c.MURegex, c.MUSuffix)
		if err != nil {
			return carrier, nil, err
		}
		host = strings.ToLower(host)
		if _, ok := hosts[host]; ok {
			return carrier, nil, errors.New("proxy: duplicate Shadowsocks mu hostname")
		}
		hosts[host] = strconv.FormatInt(u.ID, 10)
	}
	if c.Password != "" {
		carrier.Password = c.Password
	}
	if carrier.ID == 0 {
		carrier.ID = c.SSRCarrierID
	}
	if carrier.Password == "" || carrier.ID < 0 {
		return carrier, nil, errors.New("proxy: Shadowsocks mu carrier password absent or negative carrier ID")
	}
	return carrier, hosts, nil
}

func ssObfsOptions(c Config) (simpleobfs.Options, error) {
	o := simpleobfs.Options{Mode: c.SSObfsMode, Host: c.SSHost, Path: c.SSPath}
	if isSSObfsMulti(c) {
		c.SSObfs = c.SSRObfs
		o.Mode = "relaxed"
	}
	switch c.SSObfs {
	case "", "plain", "none":
		return o, nil
	case "http", "simple_obfs_http":
		o.Protocol = "http"
	case "tls", "simple_obfs_tls":
		o.Protocol = "tls"
	default:
		return o, errors.New("proxy: unknown Shadowsocks obfuscation")
	}
	return o, simpleobfs.Validate(o)
}

func ssLegacyOptions(c Config) ssrcore.Options {
	o := ssrcore.Options{Listen: c.Listen, Port: c.Port, Method: c.Method, Protocol: "origin", Obfs: "plain",
		TCPFastOpen: c.TCPFastOpen, TCPMultiPath: c.TCPMultiPath, ProxyProtocol: c.ProxyProtocol,
		UDPProxyProtocol: c.UDPProxyProtocol, ForceProxyProtocol: c.ForceProxyProtocol, ProxyProtocolTrusted: c.ProxyProtocolTrusted}
	for _, u := range c.Users {
		o.Users = append(o.Users, ssrcore.User{ID: u.ID, ProtocolID: 1, Password: u.Password})
	}
	obfs, _ := ssObfsOptions(c)
	if obfs.Protocol != "" {
		o.WrapConnection = func(conn net.Conn) (net.Conn, error) {
			wrapped, _, err := simpleobfs.Server(conn, obfs)
			return wrapped, err
		}
	}
	return o
}

func validateShadowsocks(c Config) error {
	if _, err := ssObfsOptions(c); err != nil {
		return err
	}
	if isSSObfsMulti(c) {
		if !slices.Contains(shadowaead.List, c.Method) {
			return errors.New("proxy: SS obfs multiuser currently requires a 2017 AEAD cipher")
		}
		carrier, _, err := ssMultiUsers(c)
		if err != nil {
			return err
		}
		_, err = shadowaead.New(c.Method, nil, carrier.Password)
		return err
	}
	if slices.Contains(shadowaead.List, c.Method) {
		for _, u := range c.Users {
			if _, err := shadowaead.New(c.Method, nil, u.Password); err != nil {
				return err
			}
		}
		return nil
	}
	if slices.Contains(shadowaead_2022.List, c.Method) {
		s, err := shadowaead_2022.NewMultiServiceWithPassword[string](c.Method, c.Password, 300, nil, time.Now)
		if err != nil {
			return err
		}
		var ids, passwords []string
		for _, u := range c.Users {
			ids = append(ids, strconv.FormatInt(u.ID, 10))
			passwords = append(passwords, u.Password)
		}
		return s.UpdateUsersWithPasswords(ids, passwords)
	}
	if len(c.Users) == 0 {
		return nil
	}
	return ssrcore.Validate(ssLegacyOptions(c))
}

func newShadowsocksInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, opts shadowsocksOptions) (adapter.Inbound, error) {
	c := opts.Config
	h := &shadowsocksInbound{Adapter: inbound.NewAdapter("shadowsocks", tag), ctx: ctx, config: c, router: uot.NewRouter(router, logger), invalid: newInvalidAccessGuard(c.InvalidAccess), active: make(map[io.Closer]bool), userOf: make(map[io.Closer]string)}
	handler := adapter.NewLegacyUpstreamHandler(adapter.InboundContext{}, h.newConnection, h.newPacketConnection, h)
	timeout := int64(300)
	if c.UDPTimeoutMinutes > 0 {
		timeout = int64(c.UDPTimeoutMinutes) * 60
	}
	var err error
	var multi shadowsocks.MultiService[string]
	if isSSObfsMulti(c) {
		var carrier User
		carrier, h.muHosts, err = ssMultiUsers(c)
		if err != nil {
			return nil, err
		}
		h.carrierID = strconv.FormatInt(carrier.ID, 10)
		h.service, err = shadowaead.NewService(c.Method, nil, carrier.Password, timeout, handler)
	} else if slices.Contains(shadowaead_2022.List, c.Method) {
		multi, err = shadowaead_2022.NewMultiServiceWithPassword[string](c.Method, c.Password, timeout, handler, ntp.TimeFuncFromContext(ctx))
	} else {
		var s *shadowaead.MultiService[string]
		s, err = shadowaead.NewMultiService[string](c.Method, timeout, handler)
		if err == nil && c.AuthCache != nil {
			s.SetAuthenticationCache(func(ip string) (string, bool) { id := c.AuthCache.Candidate(ip); return id, id != "" }, c.AuthCache.Remember)
		}
		multi = s
	}
	if err != nil {
		return nil, err
	}
	var ids, passwords []string
	for _, u := range c.Users {
		ids = append(ids, strconv.FormatInt(u.ID, 10))
		passwords = append(passwords, u.Password)
	}
	if multi != nil {
		if err = multi.UpdateUsersWithPasswords(ids, passwords); err != nil {
			return nil, err
		}
		h.service, h.multi = multi, multi
	}
	addr := badoption.Addr(netip.MustParseAddr(c.Listen))
	networks := []string{"tcp", "udp"}
	if h.muHosts != nil && !c.SSRObfsUDP {
		networks = []string{"tcp"}
	}
	h.listener = listener.New(listener.Options{Context: ctx, Logger: logger, Network: networks,
		Listen:            option.ListenOptions{Listen: &addr, ListenPort: c.Port, TCPFastOpen: c.TCPFastOpen, TCPMultiPath: c.TCPMultiPath},
		ConnectionHandler: h, PacketHandler: h, ThreadUnsafePacketWriter: true})
	return h, nil
}

func (h *shadowsocksInbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	if err := h.listener.Start(); err != nil {
		return err
	}
	scope.Add(func() error {
		h.listener.Close()
		h.mu.Lock()
		h.closed = true
		active := make([]io.Closer, 0, len(h.active))
		for c := range h.active {
			active = append(active, c)
		}
		h.mu.Unlock()
		for _, c := range active {
			c.Close()
		}
		return nil
	})
	return nil
}
func (h *shadowsocksInbound) track(c io.Closer) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return false
	}
	h.active[c] = true
	return true
}
func (h *shadowsocksInbound) untrack(c io.Closer) {
	h.mu.Lock()
	delete(h.active, c)
	delete(h.userOf, c)
	h.mu.Unlock()
}

// authenticated records the user behind a tracked connection for live updates.
func (h *shadowsocksInbound) authenticated(c io.Closer, id string) {
	h.mu.Lock()
	if h.active[c] {
		h.userOf[c] = id
	}
	h.mu.Unlock()
}

// updateUsers replaces the multi-user password set in place and closes the
// sessions of removed or re-keyed users. The single-user obfs carrier mode
// derives its host table from the users, so it still needs a rebuild.
func (h *shadowsocksInbound) updateUsers(users []User) error {
	if h.multi == nil || h.muHosts != nil {
		return errors.New("proxy: this Shadowsocks mode cannot update users in place")
	}
	ids := make([]string, 0, len(users))
	passwords := make([]string, 0, len(users))
	for _, u := range users {
		ids = append(ids, strconv.FormatInt(u.ID, 10))
		passwords = append(passwords, u.Password)
	}
	if err := h.multi.UpdateUsersWithPasswords(ids, passwords); err != nil {
		return err
	}
	h.mu.Lock()
	previous := make(map[string]string, len(h.config.Users))
	for _, u := range h.config.Users {
		previous[strconv.FormatInt(u.ID, 10)] = u.Password
	}
	keep := make(map[string]bool, len(users))
	for i, id := range ids {
		if before, known := previous[id]; !known || before == passwords[i] {
			keep[id] = true
		}
	}
	var drop []io.Closer
	for c, id := range h.userOf {
		if !keep[id] {
			drop = append(drop, c)
		}
	}
	h.config.Users = slices.Clone(users)
	h.mu.Unlock()
	for _, c := range drop {
		_ = c.Close()
	}
	return nil
}

type ssAuthenticatedKey struct{}

func (h *shadowsocksInbound) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	raw := conn
	if !h.track(raw) {
		raw.Close()
		return
	}
	defer h.untrack(raw)
	defer raw.Close()
	var err error
	defer func() {
		if onClose != nil {
			onClose(err)
		}
	}()
	if h.config.ProxyProtocol {
		conn, err = wireproxy.Connection(conn, h.config.ForceProxyProtocol, h.config.ProxyProtocolTrusted)
		if err != nil {
			return
		}
		metadata.Source = M.SocksaddrFromNet(conn.RemoteAddr())
	}
	ip := metadata.Source.Addr.String()
	if h.invalid.blocked(ip) {
		return
	}
	obfs, _ := ssObfsOptions(h.config)
	if obfs.Protocol != "" {
		conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		var meta simpleobfs.Metadata
		conn, meta, err = simpleobfs.Server(conn, obfs)
		if err != nil {
			h.invalid.failure(ip)
			return
		}
		conn.SetReadDeadline(time.Time{})
		if h.muHosts != nil {
			host := meta.Host
			if name, _, e := net.SplitHostPort(host); e == nil {
				host = name
			}
			id := h.muHosts[strings.ToLower(host)]
			if id == "" {
				err = errors.New("proxy: unregistered Shadowsocks mu host")
				return
			}
			ctx = auth.ContextWithUser(ctx, id)
		}
	}
	authenticated := new(atomic.Bool)
	ctx = context.WithValue(ctx, ssAuthenticatedKey{}, authenticated)
	ctx = armHandshake(ctx, conn, raw)
	err = h.service.NewConnection(ctx, conn, adapter.UpstreamMetadata(metadata))
	if err != nil && !authenticated.Load() {
		h.invalid.failure(ip)
	}
}
func (h *shadowsocksInbound) NewPacket(buffer *buf.Buffer, source M.Socksaddr) {
	if h.muHosts != nil && !h.config.SSRObfsUDP {
		buffer.Release()
		return
	}
	peer := source
	if h.config.UDPProxyProtocol {
		wire, real, err := wireproxy.Datagram(buffer.Bytes(), source.UDPAddr(), h.config.ForceProxyProtocol, h.config.ProxyProtocolTrusted)
		if err != nil {
			buffer.Release()
			return
		}
		buffer.Advance(buffer.Len() - len(wire))
		source = M.SocksaddrFromNet(real)
	}
	ip := source.Addr.String()
	if h.invalid.blocked(ip) {
		buffer.Release()
		return
	}
	ctx := h.ctx
	if h.muHosts != nil {
		ctx = auth.ContextWithUser(ctx, h.carrierID)
		ctx = context.WithValue(ctx, unattributedContextKey{}, true)
	}
	err := h.service.NewPacket(ctx, &ssPacketWriter{PacketWriter: h.listener.PacketWriter(), peer: peer}, buffer, M.Metadata{Source: source})
	if err != nil {
		h.invalid.failure(ip)
		buffer.Release()
	}
}
func (h *shadowsocksInbound) newConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext) error {
	id, ok := auth.UserFromContext[string](ctx)
	if !ok {
		return os.ErrInvalid
	}
	if flag, _ := ctx.Value(ssAuthenticatedKey{}).(*atomic.Bool); flag != nil {
		flag.Store(true)
	}
	if raw := handshakeDone(ctx); raw != nil {
		h.authenticated(raw, id)
	}
	if h.muHosts == nil {
		h.config.AuthCache.Remember(metadata.Source.Addr.String(), id)
	}
	metadata.User = id
	metadata.Inbound = h.Tag()
	metadata.InboundType = "shadowsocks"
	return h.router.RouteConnection(ctx, conn, metadata)
}
func (h *shadowsocksInbound) newPacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext) error {
	id, ok := auth.UserFromContext[string](ctx)
	if !ok {
		return os.ErrInvalid
	}
	if h.muHosts == nil {
		h.config.AuthCache.Remember(metadata.Source.Addr.String(), id)
	}
	metadata.User = id
	metadata.Inbound = h.Tag()
	metadata.InboundType = "shadowsocks"
	if !h.track(conn) {
		return net.ErrClosed
	}
	defer h.untrack(conn)
	h.authenticated(conn, id)
	return h.router.RoutePacketConnection(ctx, conn, metadata)
}
func (h *shadowsocksInbound) NewError(context.Context, error) {}

type ssPacketWriter struct {
	N.PacketWriter
	peer M.Socksaddr
}

func (c *ssPacketWriter) WritePacket(b *buf.Buffer, _ M.Socksaddr) error {
	return c.PacketWriter.WritePacket(b, c.peer)
}
func (c *ssPacketWriter) ReadPacket(*buf.Buffer) (M.Socksaddr, error) {
	return M.Socksaddr{}, os.ErrInvalid
}
func (c *ssPacketWriter) Close() error                     { return nil }
func (c *ssPacketWriter) LocalAddr() net.Addr              { return nil }
func (c *ssPacketWriter) SetDeadline(time.Time) error      { return os.ErrInvalid }
func (c *ssPacketWriter) SetReadDeadline(time.Time) error  { return os.ErrInvalid }
func (c *ssPacketWriter) SetWriteDeadline(time.Time) error { return nil }
