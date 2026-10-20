package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
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
	"github.com/xtls/xray-core/app/proxyman"
	_ "github.com/xtls/xray-core/app/proxyman/inbound"
	_ "github.com/xtls/xray-core/app/proxyman/outbound"
	xcommon "github.com/xtls/xray-core/common"
	xbuf "github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/net/cnc"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

type xrayOptions struct{ Config }

type xrayInbound struct {
	inbound.Adapter
	instance *core.Instance
	frontend *proxyFrontend
	h2       *xrayH2Frontend
	ctx      context.Context
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
	if c.ProxyProtocol || h2 != nil {
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
			frontend = &proxyFrontend{address: net.JoinHostPort(c.Listen, strconv.Itoa(int(c.Port))), backend: backend, required: c.ForceProxyProtocol, trusted: c.ProxyProtocolTrusted, tfo: c.TCPFastOpen, mptcp: c.TCPMultiPath}
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
		serial.ToTypedMessage(&proxyman.InboundConfig{}),
		serial.ToTypedMessage(&proxyman.OutboundConfig{}),
	}})
	if err != nil {
		return nil, err
	}
	dispatch := &xrayDispatcher{router: router, tag: tag, protocol: c.Protocol, active: make(map[io.Closer]bool)}
	if err = instance.AddFeature(dispatch); err == nil {
		err = core.AddInboundHandler(instance, handler)
	}
	if err != nil {
		_ = instance.Close()
		return nil, err
	}
	constructed = true
	return &xrayInbound{Adapter: inbound.NewAdapter("xray-core", tag), instance: instance, frontend: frontend, h2: h2, ctx: ctx}, nil
}

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
	if c.ProxyProtocol || c.TCPFastOpen || c.TCPMultiPath {
		sockopt, _ := stream["sockopt"].(map[string]any)
		if sockopt == nil {
			sockopt = make(map[string]any)
		}
		sockopt["acceptProxyProtocol"] = c.ProxyProtocol
		sockopt["tcpFastOpen"] = c.TCPFastOpen
		sockopt["tcpMptcp"] = c.TCPMultiPath
		stream["sockopt"] = sockopt
	}
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
	active   map[io.Closer]bool
	closed   bool
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
	stream := cnc.NewConnection(cnc.ConnectionInputMulti(link.Writer), cnc.ConnectionOutputMulti(link.Reader),
		cnc.ConnectionRemoteAddr(auth.Source.RawNetAddr()))
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
	d.active[closer] = true
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
