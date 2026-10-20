package proxy

import (
	stdBufio "bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	anytls "github.com/anytls/sing-anytls"
	"github.com/anytls/sing-anytls/padding"
	"github.com/pires/go-proxyproto"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/listener"
	boxTLS "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/common/uot"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	trojanCodec "github.com/sagernet/sing-box/transport/trojan"
	"github.com/sagernet/sing-box/transport/v2ray"
	"github.com/sagernet/sing-vmess/packetaddr"
	vlessCodec "github.com/sagernet/sing-vmess/vless"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	vmess "reconstructed.local/soga/proxy/internal/vmesscompat"
)

// TLS application adapter uses the real upstream authentication/session codecs.
// AnyTLS exposes a native fallback callback. VMess failures are replayed only
// before an authenticated stream has reached its handler.
type tlsServiceOptions struct{ Config }
type tlsServiceInbound struct {
	inbound.Adapter
	config    Config
	router    adapter.ConnectionRouterEx
	listener  *listener.Listener
	tls       boxTLS.ServerConfig
	any       *anytls.Service
	vmess     *vmess.Service[string]
	vless     *vlessCodec.Service[string]
	trojan    *trojanCodec.Service[string]
	transport adapter.V2RayServerTransport
	invalid   *invalidAccessGuard
	mu        sync.Mutex
	active    map[net.Conn]bool
	closed    bool
}

func newTLSServiceInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, opts tlsServiceOptions) (adapter.Inbound, error) {
	c := opts.Config
	h := &tlsServiceInbound{Adapter: inbound.NewAdapter(c.Protocol, tag), config: c, router: uot.NewRouter(router, logger), active: make(map[net.Conn]bool)}
	h.invalid = newInvalidAccessGuard(c.InvalidAccess)
	var err error
	if c.TLS != nil && c.TLS.Enabled {
		h.tls, err = boxTLS.NewServer(ctx, logger, *c.TLS)
		if err != nil {
			return nil, err
		}
	}
	if c.Protocol == "anytls" {
		scheme := padding.DefaultPaddingScheme
		if len(c.PaddingScheme) > 0 {
			scheme = []byte(strings.Join(c.PaddingScheme, "\n"))
		}
		service := anytls.ServiceConfig{Handler: h, Logger: logger, PaddingScheme: scheme}
		if c.FallbackAddress != "" {
			service.FallbackHandler = (*tlsFallbackHandler)(h)
		}
		for _, u := range c.Users {
			service.Users = append(service.Users, anytls.User{Name: strconv.FormatInt(u.ID, 10), Password: u.Password})
		}
		h.any, err = anytls.NewService(service)
		if err != nil {
			return nil, err
		}
	} else if c.Protocol == "vless" {
		h.vless = vlessCodec.NewService[string](logger, h)
		var names, ids, flows []string
		for _, u := range c.Users {
			names = append(names, strconv.FormatInt(u.ID, 10))
			ids = append(ids, u.UUID)
			flows = append(flows, c.Flow)
		}
		h.vless.UpdateUsers(names, ids, flows)
	} else if c.Protocol == "trojan" {
		h.trojan = trojanCodec.NewService[string](h, nil, logger)
		var names, passwords []string
		for _, u := range c.Users {
			names = append(names, strconv.FormatInt(u.ID, 10))
			passwords = append(passwords, u.Password)
		}
		if err = h.trojan.UpdateUsers(names, passwords); err != nil {
			return nil, err
		}
	} else {
		serviceOptions := []vmess.ServiceOption{vmess.ServiceWithAuthMode(c.VMessAuthMode), vmess.ServiceWithAuthenticationCache(c.AuthCache), vmess.ServiceWithReducedMemory(c.VMessReduceMemory)}
		if c.Transport != nil {
			serviceOptions = append(serviceOptions, vmess.ServiceWithDisableHeaderProtection())
		}
		h.vmess = vmess.NewService[string](h, serviceOptions...)
		var names, ids []string
		var alters []int
		for _, u := range c.Users {
			names = append(names, strconv.FormatInt(u.ID, 10))
			ids = append(ids, u.UUID)
			alters = append(alters, u.AlterID)
		}
		if err = h.vmess.UpdateUsers(names, ids, alters); err != nil {
			return nil, err
		}
	}
	if c.Transport != nil {
		h.transport, err = v2ray.NewServerTransport(ctx, logger, *c.Transport, h.tls, (*tlsTransportHandler)(h))
		if err != nil {
			return nil, err
		}
	}
	address := badoption.Addr(netip.MustParseAddr(c.Listen))
	h.listener = listener.New(listener.Options{Context: ctx, Logger: logger, Network: []string{"tcp"},
		Listen: option.ListenOptions{Listen: &address, ListenPort: c.Port, TCPFastOpen: c.TCPFastOpen, TCPMultiPath: c.TCPMultiPath}, ConnectionHandler: h})
	return h, nil
}

func (h *tlsServiceInbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	if h.vmess != nil {
		if err := h.vmess.Start(); err != nil {
			return err
		}
		scope.Add(h.vmess.Close)
	}
	if h.tls != nil {
		if err := h.tls.Start(); err != nil {
			return err
		}
		scope.Add(h.tls.Close)
	}
	if h.transport != nil {
		l, err := h.listener.ListenTCP()
		if err != nil {
			return err
		}
		if h.config.ProxyProtocol {
			policy := proxyproto.USE
			if h.config.ForceProxyProtocol {
				policy = proxyproto.REQUIRE
			}
			l = &proxyproto.Listener{Listener: l, ConnPolicy: func(proxyproto.ConnPolicyOptions) (proxyproto.Policy, error) { return policy, nil }, ReadHeaderTimeout: 5 * time.Second}
		}
		scope.Add(h.transport.Close)
		go h.transport.Serve(l)
	} else {
		if err := h.listener.Start(); err != nil {
			return err
		}
	}
	scope.Add(h.listener.Close)
	scope.Add(func() error {
		h.mu.Lock()
		h.closed = true
		active := make([]net.Conn, 0, len(h.active))
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

type serviceCaptureKey struct{}
type captureConn struct {
	net.Conn
	data      bytes.Buffer
	recording atomic.Bool
}

func (c *captureConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if c.recording.Load() && c.data.Len()+n <= 65536 {
		c.data.Write(p[:n])
	}
	return n, err
}

func (h *tlsServiceInbound) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	raw := conn
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		closeDenied(raw, onClose, net.ErrClosed)
		return
	}
	h.active[raw] = true
	h.mu.Unlock()
	var once sync.Once
	closed := func(err error) {
		once.Do(func() {
			raw.Close()
			h.mu.Lock()
			delete(h.active, raw)
			h.mu.Unlock()
			if onClose != nil {
				onClose(err)
			}
		})
	}
	if h.config.ProxyProtocol && h.transport == nil {
		policy := proxyproto.USE
		if h.config.ForceProxyProtocol {
			policy = proxyproto.REQUIRE
		}
		p := proxyproto.NewConn(conn, proxyproto.WithPolicy(policy), proxyproto.SetReadHeaderTimeout(5*time.Second))
		if _, err := p.Read(nil); err != nil {
			closed(err)
			return
		}
		conn = p
		metadata.Source = M.SocksaddrFromNet(p.RemoteAddr())
	}
	if h.tls != nil && h.transport == nil {
		var err error
		conn, err = boxTLS.ServerHandshake(ctx, conn, h.tls)
		if err != nil {
			closed(err)
			return
		}
	}
	if h.any != nil {
		err := h.any.NewConnection(ctx, conn, metadata.Source, onClose)
		closed(err)
		return
	}
	if h.vless != nil {
		if err := h.vless.NewConnection(ctx, conn, metadata.Source, closed); err != nil {
			closed(err)
		}
		return
	}
	if h.trojan != nil {
		if err := h.trojan.NewConnection(ctx, conn, metadata.Source, closed); err != nil {
			closed(err)
		}
		return
	}
	legacy := false
	sourceIP := metadata.Source.Addr.String()
	if h.config.InvalidAccess != nil {
		reader := stdBufio.NewReader(conn)
		wrapped := &inspectionReaderConn{Conn: conn, reader: reader}
		header, peekErr := reader.Peek(16)
		if peekErr != nil {
			if h.config.FallbackAddress != "" {
				h.fallback(ctx, wrapped, closed)
			} else {
				closed(peekErr)
			}
			return
		}
		legacy = h.vmess.IsLegacyAuthID(header)
		if !legacy && h.invalid.blocked(sourceIP) {
			closed(errors.New("proxy: temporary invalid-access block"))
			return
		}
		conn = wrapped
	}
	capture := &captureConn{Conn: conn}
	capture.recording.Store(true)
	ctx = context.WithValue(ctx, serviceCaptureKey{}, capture)
	err := h.vmess.NewConnection(ctx, capture, metadata.Source, closed)
	if err != nil {
		if capture.recording.Load() && !legacy {
			h.invalid.failure(sourceIP)
		}
		if capture.recording.Load() && h.config.FallbackAddress != "" {
			cached := bufio.NewCachedConn(conn, buf.As(capture.data.Bytes()))
			h.fallback(ctx, cached, closed)
		} else {
			closed(err)
		}
	}
}

type inspectionReaderConn struct {
	net.Conn
	reader io.Reader
}

func (c *inspectionReaderConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

type tlsTransportHandler tlsServiceInbound

func (h *tlsTransportHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	(*tlsServiceInbound)(h).NewConnection(ctx, conn, adapter.InboundContext{Source: source, Destination: destination}, onClose)
}

func (h *tlsServiceInbound) NewConnectionEx(ctx context.Context, conn net.Conn, source, dst M.Socksaddr, onClose N.CloseHandlerFunc) {
	if capture, ok := ctx.Value(serviceCaptureKey{}).(*captureConn); ok {
		capture.recording.Store(false)
	}
	name, ok := auth.UserFromContext[string](ctx)
	if !ok {
		closeDenied(conn, onClose, errors.New("proxy: authenticated identity absent"))
		return
	}
	h.router.RouteConnectionEx(ctx, conn, adapter.InboundContext{Inbound: h.Tag(), InboundType: h.config.Protocol, User: name, Source: source, Destination: dst}, onClose)
}
func (h *tlsServiceInbound) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source, dst M.Socksaddr, onClose N.CloseHandlerFunc) {
	if capture, ok := ctx.Value(serviceCaptureKey{}).(*captureConn); ok {
		capture.recording.Store(false)
	}
	name, ok := auth.UserFromContext[string](ctx)
	if !ok {
		closeDenied(conn, onClose, errors.New("proxy: authenticated identity absent"))
		return
	}
	if dst.Fqdn == packetaddr.SeqPacketMagicAddress {
		dst = M.Socksaddr{}
		conn = packetaddr.NewConn(bufio.NewNetPacketConn(conn), dst)
		// The magic address is a framing marker, not a route destination.
		// Authenticate/authorize the first actual decoded destination before
		// opening an outbound association; preserve its datagram for routing.
		first := buf.NewPacket()
		pending := conn
		timer := time.AfterFunc(30*time.Second, func() { pending.Close() })
		var err error
		dst, err = conn.ReadPacket(first)
		timer.Stop()
		if err != nil {
			first.Release()
			closeDenied(conn, onClose, err)
			return
		}
		conn = bufio.NewCachedPacketConn(conn, first, dst)
	}
	h.router.RoutePacketConnectionEx(ctx, conn, adapter.InboundContext{Inbound: h.Tag(), InboundType: h.config.Protocol, User: name, Source: source, Destination: dst}, onClose)
}

type tlsFallbackHandler tlsServiceInbound

func (h *tlsFallbackHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source, dst M.Socksaddr, onClose N.CloseHandlerFunc) {
	(*tlsServiceInbound)(h).fallback(ctx, conn, onClose)
}
func (h *tlsServiceInbound) fallback(ctx context.Context, conn net.Conn, onClose N.CloseHandlerFunc) {
	target, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", h.config.FallbackAddress)
	if err != nil {
		closeDenied(conn, onClose, err)
		return
	}
	defer target.Close()
	done := make(chan struct{})
	go func() {
		io.Copy(target, conn)
		if tcp, ok := target.(*net.TCPConn); ok {
			tcp.CloseWrite()
		}
		close(done)
	}()
	_, err = io.Copy(conn, target)
	conn.Close()
	<-done
	if onClose != nil {
		onClose(err)
	}
}
