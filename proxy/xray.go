package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/log"
	sbuf "github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	xlog "github.com/xtls/xray-core/app/log"
	"github.com/xtls/xray-core/app/policy"
	"github.com/xtls/xray-core/app/proxyman"
	_ "github.com/xtls/xray-core/app/proxyman/inbound"
	_ "github.com/xtls/xray-core/app/proxyman/outbound"
	xcommon "github.com/xtls/xray-core/common"
	xbuf "github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/net/cnc"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	xinbound "github.com/xtls/xray-core/features/inbound"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/infra/conf"
	xproxy "github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/trojan"
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

type xrayOptions struct{ Config }

type xrayInbound struct {
	inbound.Adapter
	instance *core.Instance
	frontend *proxyFrontend
	h2       *xrayH2Frontend
	dispatch *xrayDispatcher
	ctx      context.Context
	mu       sync.Mutex
	config   Config
}

// The core's session policy governs the paths the core copies itself (Mux
// sub-streams, fallbacks); the direct VLESS path hands its link to our
// dispatcher, where tcp_timeout applies through meterConn. Its 300 s idle
// default is far below tcp_timeout (120 min by default), so idle follows
// tcp_timeout here too, and the handshake and half-closed drain limits use
// the values v2node runs in production (4 s, 2 s uplink-only, 4 s
// downlink-only). Every field is set because a nil Second converts to zero.
const (
	xrayHandshakeSeconds     = 4
	xrayUplinkDrainSeconds   = 2
	xrayDownlinkDrainSeconds = 4
	xrayIdleFallback         = 24 * 60 * 60
)

func xrayPolicy(tcpTimeoutSeconds int) *policy.Config {
	idle := uint32(xrayIdleFallback)
	if tcpTimeoutSeconds > 0 && tcpTimeoutSeconds < xrayIdleFallback {
		idle = uint32(tcpTimeoutSeconds)
	}
	return &policy.Config{Level: map[uint32]*policy.Policy{0: {Timeout: &policy.Policy_Timeout{
		Handshake:      &policy.Second{Value: xrayHandshakeSeconds},
		ConnectionIdle: &policy.Second{Value: idle},
		UplinkOnly:     &policy.Second{Value: xrayUplinkDrainSeconds},
		DownlinkOnly:   &policy.Second{Value: xrayDownlinkDrainSeconds},
	}}}}
}

// xrayAccount builds the parsed core account for one user.
func xrayAccount(protocolName, flow string, u User) (protocol.Account, error) {
	switch protocolName {
	case "vless":
		return (&vless.Account{Id: u.UUID, Flow: flow}).AsAccount()
	case "trojan":
		return (&trojan.Account{Password: u.Password}).AsAccount()
	}
	return nil, errors.New("proxy: this Xray inbound cannot update users in place")
}

func xrayCredential(protocolName, flow string, u User) string {
	if protocolName == "trojan" {
		return u.Password
	}
	return u.UUID + "/" + flow
}

// updateUsers swaps users inside the running core, so Reality, Vision and
// XHTTP sessions of unchanged users survive a panel update. Removed or
// re-credentialed users lose their sessions.
func (h *xrayInbound) updateUsers(users []User) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	protocolName, flow := h.config.Protocol, h.config.Flow
	manager, ok := h.instance.GetFeature(xinbound.ManagerType()).(xinbound.Manager)
	if !ok {
		return errors.New("proxy: Xray inbound manager unavailable")
	}
	handler, err := manager.GetHandler(h.ctx, h.Tag())
	if err != nil {
		return err
	}
	getter, ok := handler.(xproxy.GetInbound)
	if !ok {
		return errors.New("proxy: Xray handler exposes no inbound")
	}
	registry, ok := getter.GetInbound().(xproxy.UserManager)
	if !ok {
		return errors.New("proxy: Xray inbound cannot manage users")
	}
	previous := make(map[string]string, len(h.config.Users))
	for _, u := range h.config.Users {
		previous[strconv.FormatInt(u.ID, 10)] = xrayCredential(protocolName, flow, u)
	}
	type pending struct {
		email   string
		account protocol.Account
	}
	var add []pending
	next := make(map[string]bool, len(users))
	for _, u := range users {
		email := strconv.FormatInt(u.ID, 10)
		next[email] = true
		if before, known := previous[email]; known && before == xrayCredential(protocolName, flow, u) {
			continue
		}
		account, err := xrayAccount(protocolName, flow, u)
		if err != nil {
			return err
		}
		add = append(add, pending{email, account})
	}
	for email := range previous {
		if !next[email] || slices.ContainsFunc(add, func(p pending) bool { return p.email == email }) {
			if err := registry.RemoveUser(h.ctx, email); err != nil {
				return err
			}
			h.dispatch.closeUser(email)
		}
	}
	for _, p := range add {
		if err := registry.AddUser(h.ctx, &protocol.MemoryUser{Email: p.email, Account: p.account}); err != nil {
			return err
		}
	}
	h.config.Users = slices.Clone(users)
	return nil
}

func newXrayInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options xrayOptions) (adapter.Inbound, error) {
	c := options.Config
	var frontend *proxyFrontend
	h2, err := newXrayH2Frontend(ctx, logger, c)
	if err != nil {
		return nil, err
	}
	constructed := false
	defer func() {
		if !constructed && h2 != nil {
			_ = h2.close()
		}
	}()
	// Xray's own acceptProxyProtocol socket option means "require a header from
	// any peer". That is exactly the required-header case without a trusted
	// source list, so Xray then binds the public address itself (TFO/MPTCP still
	// arrive through sockopt). The loopback frontend remains for optional
	// headers and trusted-source lists, which Xray cannot express.
	if h2 != nil || (c.ProxyProtocol && !(c.ForceProxyProtocol && len(c.ProxyProtocolTrusted) == 0)) {
		// Reserve a private core port. The public listener starts only after the
		// core has bound successfully, so a failed allocation exposes no port.
		reservation, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return nil, err
		}
		backend := reservation.Addr().String()
		port := reservation.Addr().(*net.TCPAddr).Port
		reservation.Close()
		if h2 != nil {
			h2.backend = backend
			// HTTP/2 has already been removed by the public frontend. Keep the
			// actual VLESS encryption/authentication in Xray; its private TCP
			// listener receives a fresh PROXY v2 header for every logical stream.
			c.Transport, c.TLS = nil, nil
			c.XrayStream = nil
			c.ProxyProtocol, c.ForceProxyProtocol = true, true
		} else {
			frontend = &proxyFrontend{address: net.JoinHostPort(c.Listen, strconv.Itoa(int(c.Port))), backend: backend, required: c.ForceProxyProtocol, trusted: c.ProxyProtocolTrusted, tfo: c.TCPFastOpen, mptcp: c.TCPMultiPath, idle: relayIdle(c.TCPTimeoutSeconds)}
		}
		c.Listen, c.Port = "127.0.0.1", uint16(port)
	}
	stream, err := xrayStream(c)
	if err != nil {
		return nil, err
	}
	users := make([]map[string]any, 0, len(c.Users))
	for _, u := range c.Users {
		user := map[string]any{"id": u.UUID, "email": strconv.FormatInt(u.ID, 10)}
		if c.Protocol == "vless" {
			user["flow"] = c.Flow
		}
		if c.Protocol == "trojan" {
			delete(user, "id")
			user["password"] = u.Password
		}
		users = append(users, user)
	}
	decryption := c.Decryption
	if decryption == "" {
		decryption = "none"
	}
	settings := map[string]any{"clients": users}
	if c.Protocol == "vless" {
		settings["decryption"] = decryption
	}
	if c.FallbackAddress != "" {
		if c.Protocol == "vmess" {
			return nil, errors.New("proxy: VMess fallback requires dedicated TLS dispatcher")
		}
		if _, _, err := net.SplitHostPort(c.FallbackAddress); err != nil {
			return nil, err
		}
		settings["fallbacks"] = []any{map[string]any{"dest": c.FallbackAddress}}
	}
	raw, err := json.Marshal(map[string]any{
		"protocol": c.Protocol, "listen": c.Listen, "port": c.Port, "tag": tag,
		"settings": settings, "streamSettings": stream,
	})
	if err != nil {
		return nil, err
	}
	var in conf.InboundDetourConfig
	if err = json.Unmarshal(raw, &in); err != nil {
		return nil, err
	}
	handler, err := in.Build()
	if err != nil {
		return nil, err
	}
	instance, err := core.NewWithContext(ctx, &core.Config{App: []*serial.TypedMessage{
		// User-facing audit/lifecycle logging is owned by the reconstruction's
		// engine. Do not emit Xray's default per-connection console logs.
		serial.ToTypedMessage(&xlog.Config{AccessLogType: xlog.LogType_None, ErrorLogType: xlog.LogType_None}),
		serial.ToTypedMessage(xrayPolicy(c.TCPTimeoutSeconds)),
		serial.ToTypedMessage(&proxyman.InboundConfig{}),
		serial.ToTypedMessage(&proxyman.OutboundConfig{}),
	}})
	if err != nil {
		return nil, err
	}
	dispatch := &xrayDispatcher{router: router, tag: tag, protocol: c.Protocol, active: make(map[io.Closer]string)}
	if err = instance.AddFeature(dispatch); err == nil {
		err = core.AddInboundHandler(instance, handler)
	}
	if err != nil {
		_ = instance.Close()
		return nil, err
	}
	constructed = true
	return &xrayInbound{Adapter: inbound.NewAdapter("xray-core", tag), instance: instance, frontend: frontend, h2: h2, dispatch: dispatch, ctx: ctx, config: c}, nil
}

const (
	xrayKeepAliveIdleSeconds     = 60
	xrayKeepAliveIntervalSeconds = 30
)

func xrayStream(c Config) (json.RawMessage, error) {
	stream := map[string]any{"network": "tcp", "security": "none"}
	if len(c.XrayStream) > 0 {
		if err := json.Unmarshal(c.XrayStream, &stream); err != nil {
			return nil, err
		}
	} else {
		if c.Transport != nil {
			stream["network"] = c.Transport.Type
			switch c.Transport.Type {
			case "ws":
				stream["wsSettings"] = map[string]any{"path": c.Transport.WebsocketOptions.Path, "headers": c.Transport.WebsocketOptions.Headers}
			case "grpc":
				stream["grpcSettings"] = map[string]any{"serviceName": c.Transport.GRPCOptions.ServiceName}
			case "httpupgrade":
				stream["httpupgradeSettings"] = map[string]any{"path": c.Transport.HTTPUpgradeOptions.Path, "host": c.Transport.HTTPUpgradeOptions.Host}
			default:
				return nil, errors.New("proxy: use explicit XrayStream for this transport")
			}
		}
		if c.TLS != nil && c.TLS.Enabled {
			if c.TLS.Reality != nil {
				return nil, errors.New("proxy: REALITY requires explicit XrayStream")
			}
			stream["security"] = "tls"
			certificate := map[string]any{"certificateFile": c.TLS.CertificatePath, "keyFile": c.TLS.KeyPath}
			if len(c.TLS.Certificate) > 0 {
				certificate["certificate"] = strings.Split(strings.Join(c.TLS.Certificate, "\n"), "\n")
			}
			if len(c.TLS.Key) > 0 {
				certificate["key"] = strings.Split(strings.Join(c.TLS.Key, "\n"), "\n")
			}
			tlsSettings := map[string]any{"alpn": c.TLS.ALPN, "serverName": c.TLS.ServerName,
				"minVersion": c.TLS.MinVersion, "maxVersion": c.TLS.MaxVersion,
				"certificates": []any{certificate},
			}
			stream["tlsSettings"] = tlsSettings
		}
	}
	sockopt, _ := stream["sockopt"].(map[string]any)
	if sockopt == nil {
		sockopt = make(map[string]any)
	}
	if c.ProxyProtocol || c.TCPFastOpen || c.TCPMultiPath {
		sockopt["acceptProxyProtocol"] = c.ProxyProtocol
		sockopt["tcpFastOpen"] = c.TCPFastOpen
		sockopt["tcpMptcp"] = c.TCPMultiPath
	}
	// The core disables TCP keepalive by default; idle Reality sessions then
	// die silently behind carrier NAT and dead sockets linger until
	// tcp_timeout. Probe idle connections unless the stream sets its own.
	if _, set := sockopt["tcpKeepAliveIdle"]; !set {
		sockopt["tcpKeepAliveIdle"] = xrayKeepAliveIdleSeconds
	}
	if _, set := sockopt["tcpKeepAliveInterval"]; !set {
		sockopt["tcpKeepAliveInterval"] = xrayKeepAliveIntervalSeconds
	}
	stream["sockopt"] = sockopt
	return json.Marshal(stream)
}

func (h *xrayInbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	if err := h.instance.Start(); err != nil {
		_ = h.instance.Close()
		return err
	}
	scope.Add(h.instance.Close)
	if h.h2 != nil {
		scope.Add(h.h2.close)
		if err := h.h2.start(h.ctx); err != nil {
			return err
		}
	}
	if h.frontend != nil {
		if err := h.frontend.start(h.ctx); err != nil {
			return err
		}
		scope.Add(h.frontend.close)
	}
	return nil
}

// Xray terminates its real protocol/transports. This dispatcher passes only
// authenticated decrypted traffic into the same policy/router as other engines.
type xrayDispatcher struct {
	router   adapter.Router
	tag      string
	protocol string
	mu       sync.Mutex
	active   map[io.Closer]string // open sessions and the user they belong to
	closed   bool
}

// closeUser ends every session of one user, for live user removal.
func (d *xrayDispatcher) closeUser(email string) {
	d.mu.Lock()
	var drop []io.Closer
	for c, user := range d.active {
		if user == email {
			drop = append(drop, c)
		}
	}
	d.mu.Unlock()
	for _, c := range drop {
		_ = c.Close()
	}
}

func (d *xrayDispatcher) Type() interface{} { return routing.DispatcherType() }
func (d *xrayDispatcher) Start() error      { return nil }
func (d *xrayDispatcher) Close() error {
	d.mu.Lock()
	d.closed = true
	var active []io.Closer
	for c := range d.active {
		active = append(active, c)
	}
	d.mu.Unlock()
	for _, c := range active {
		_ = c.Close()
	}
	return nil
}

func (d *xrayDispatcher) Dispatch(ctx context.Context, dst xnet.Destination) (*transport.Link, error) {
	inReader, outWriter := pipe.New(pipe.WithSizeLimit(256 * 1024))
	outReader, inWriter := pipe.New(pipe.WithSizeLimit(256 * 1024))
	inside := &transport.Link{Reader: inReader, Writer: inWriter}
	outside := &transport.Link{Reader: outReader, Writer: outWriter}
	go func() {
		if err := d.DispatchLink(ctx, dst, outside); err != nil {
			xcommon.Interrupt(inReader)
			xcommon.Interrupt(outReader)
			_ = inWriter.Close()
			_ = outWriter.Close()
		}
	}()
	return inside, nil
}

func (d *xrayDispatcher) DispatchLink(ctx context.Context, dst xnet.Destination, link *transport.Link) error {
	auth := session.InboundFromContext(ctx)
	if auth == nil || auth.User == nil || auth.User.Email == "" {
		return errors.New("proxy: Xray dispatcher requires authenticated user")
	}
	metadata := adapter.InboundContext{Inbound: d.tag, InboundType: d.protocol,
		User: auth.User.Email, Source: M.ParseSocksaddr(auth.Source.NetAddr()), Destination: M.ParseSocksaddr(dst.NetAddr())}
	stream := newSniffDeadlineConn(&xrayLinkConn{link: link, Conn: cnc.NewConnection(
		cnc.ConnectionInputMulti(link.Writer), cnc.ConnectionOutputMulti(link.Reader),
		cnc.ConnectionRemoteAddr(auth.Source.RawNetAddr()))})
	var closer io.Closer = stream
	var packet *xrayPacketConn
	if dst.Network == xnet.Network_UDP {
		packet = &xrayPacketConn{link: link, destination: metadata.Destination, source: stream.RemoteAddr(), stream: stream}
		closer = packet
	}
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		_ = closer.Close()
		return net.ErrClosed
	}
	d.active[closer] = auth.User.Email
	d.mu.Unlock()
	completed := make(chan struct{})
	var once sync.Once
	done := func(error) {
		once.Do(func() {
			_ = closer.Close()
			d.mu.Lock()
			delete(d.active, closer)
			d.mu.Unlock()
			close(completed)
		})
	}
	switch dst.Network {
	case xnet.Network_TCP:
		go d.router.RouteConnectionEx(ctx, stream, metadata, done)
	case xnet.Network_UDP:
		go d.router.RoutePacketConnectionEx(ctx, packet, metadata, done)
	default:
		done(nil)
		return errors.New("proxy: unsupported Xray destination network")
	}
	// DispatchLink owns an already-decoded live inbound stream. Its caller
	// closes the physical connection on return, so keep ownership until the
	// shared router finishes (unlike Dispatch, which returns pipe endpoints).
	select {
	case <-completed:
		return nil
	case <-ctx.Done():
		done(ctx.Err())
		return ctx.Err()
	}
}

type xrayPacketConn struct {
	link        *transport.Link
	destination M.Socksaddr
	source      net.Addr
	stream      net.Conn
	pending     xbuf.MultiBuffer
	readMu      sync.Mutex
}

func (c *xrayPacketConn) ReadPacket(buffer *sbuf.Buffer) (M.Socksaddr, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	for len(c.pending) == 0 {
		var err error
		c.pending, err = c.link.Reader.ReadMultiBuffer()
		if err != nil {
			return M.Socksaddr{}, err
		}
	}
	b := c.pending[0]
	c.pending = c.pending[1:]
	dst := c.destination
	if b.UDP != nil {
		dst = M.ParseSocksaddr(b.UDP.NetAddr())
	}
	_, err := buffer.Write(b.Bytes())
	b.Release()
	return dst, err
}
func (c *xrayPacketConn) WritePacket(buffer *sbuf.Buffer, dst M.Socksaddr) error {
	b := xbuf.FromBytes(append([]byte(nil), buffer.Bytes()...))
	buffer.Release()
	d := xnet.UDPDestination(xnet.ParseAddress(dst.AddrString()), xnet.Port(dst.Port))
	b.UDP = &d
	return c.link.Writer.WriteMultiBuffer(xbuf.MultiBuffer{b})
}
func (c *xrayPacketConn) Close() error {
	err := c.stream.Close()
	c.readMu.Lock()
	xbuf.ReleaseMulti(c.pending)
	c.pending = nil
	c.readMu.Unlock()
	return err
}
func (c *xrayPacketConn) LocalAddr() net.Addr                { return c.source }
func (c *xrayPacketConn) SetDeadline(t time.Time) error      { return c.stream.SetDeadline(t) }
func (c *xrayPacketConn) SetReadDeadline(t time.Time) error  { return c.stream.SetReadDeadline(t) }
func (c *xrayPacketConn) SetWriteDeadline(t time.Time) error { return c.stream.SetWriteDeadline(t) }
