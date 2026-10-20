package ssrcore

import (
	"context"
	"errors"
	"github.com/database64128/tfo-go/v2"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/log"
	M "github.com/sagernet/sing/common/metadata"

	"reconstructed.local/soga/proxy/simpleobfs"
	"reconstructed.local/soga/proxy/ssrcore/internal/vnet/common/obfs"
	"reconstructed.local/soga/proxy/wireproxy"
)

func RegisterInbound(registry *inbound.Registry) {
	inbound.Register[Options](registry, Type, NewInbound)
}

type server struct {
	inbound.Adapter
	ctx     context.Context
	router  adapter.Router
	options Options
	replay  *obfs.ObfsAuthChainData
	tlsData *obfs.ObfsAuthData
	tcp     net.Listener
	udp     net.PacketConn
	mu      sync.Mutex
	conns   map[net.Conn]bool
	packets map[string]*packetConn
	muHosts map[string]User
	closed  bool
}

func NewInbound(ctx context.Context, router adapter.Router, _ log.ContextLogger, tag string, options Options) (adapter.Inbound, error) {
	o, err := normalize(options)
	if err != nil {
		return nil, err
	}
	s := &server{Adapter: inbound.NewAdapter(Type, tag), ctx: ctx, router: router,
		options: o, replay: obfs.NewObfsAuthChainData(o.Protocol),
		tlsData: obfs.NewObfsAuthData(),
		conns:   make(map[net.Conn]bool), packets: make(map[string]*packetConn)}
	if o.SinglePortType == "obfs" {
		s.muHosts = make(map[string]User, len(o.Users))
		for _, u := range o.Users {
			host, _ := HostForUser(u, o.MURegex, o.MUSuffix) // normalize validated every host.
			s.muHosts[canonicalHost(host)] = u
		}
	}
	return s, nil
}

func (s *server) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	addr := net.JoinHostPort(s.options.Listen, strconv.Itoa(int(s.options.Port)))
	var lc net.ListenConfig
	lc.SetMultipathTCP(s.options.TCPMultiPath)
	var tcp net.Listener
	var err error
	if s.options.TCPFastOpen {
		tfoConfig := tfo.ListenConfig{ListenConfig: lc}
		tcp, err = tfoConfig.Listen(s.ctx, "tcp", addr)
	} else {
		tcp, err = lc.Listen(s.ctx, "tcp", addr)
	}
	if err != nil {
		return err
	}
	var udp net.PacketConn
	if s.options.SinglePortType != "obfs" || s.options.ObfsUDP {
		udp, err = net.ListenPacket("udp", tcp.Addr().String())
		if err != nil {
			tcp.Close()
			return err
		}
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		tcp.Close()
		if udp != nil {
			udp.Close()
		}
		return net.ErrClosed
	}
	s.tcp, s.udp = tcp, udp
	s.mu.Unlock()
	scope.Add(s.close)
	go s.accept()
	if udp != nil {
		go s.acceptPackets()
	}
	return nil
}

func (s *server) close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	tcp, udp := s.tcp, s.udp
	conns := make([]net.Conn, 0, len(s.conns))
	for c := range s.conns {
		conns = append(conns, c)
	}
	packets := make([]*packetConn, 0, len(s.packets))
	for _, c := range s.packets {
		packets = append(packets, c)
	}
	s.mu.Unlock()
	if tcp != nil {
		tcp.Close()
	}
	if udp != nil {
		udp.Close()
	}
	for _, c := range conns {
		c.Close()
	}
	for _, c := range packets {
		c.Close()
	}
	return nil
}

func (s *server) accept() {
	for {
		raw, err := s.tcp.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			raw.Close()
			return
		}
		// Pending handshakes are tracked so updates/shutdown revoke them too.
		s.conns[raw] = true
		s.mu.Unlock()
		go s.handle(raw)
	}
}

func (s *server) handle(raw net.Conn) {
	var c net.Conn = raw
	var once sync.Once
	done := func(error) {
		once.Do(func() {
			c.Close()
			s.mu.Lock()
			delete(s.conns, raw)
			s.mu.Unlock()
		})
	}
	defer func() {
		if recover() != nil {
			done(errors.New("ssr: invalid handshake"))
		}
	}()
	raw.SetDeadline(time.Now().Add(30 * time.Second))
	transport := raw
	var err error
	if s.options.ProxyProtocol {
		transport, err = wireproxy.Connection(transport, s.options.ForceProxyProtocol)
		if err != nil {
			done(err)
			return
		}
	}
	if s.options.WrapConnection != nil {
		transport, err = s.options.WrapConnection(transport)
		if err != nil {
			done(err)
			return
		}
		if transport == nil {
			done(errors.New("ssr: transport wrapper returned nil"))
			return
		}
	}
	options := s.options
	if options.SinglePortType == "obfs" {
		var host string
		switch options.Obfs {
		case "simple_obfs_http", "simple_obfs_tls":
			method := "http"
			if options.Obfs == "simple_obfs_tls" {
				method = "tls"
			}
			var meta simpleobfs.Metadata
			transport, meta, err = simpleobfs.Server(transport, simpleobfs.Options{Protocol: method, Mode: "relaxed"})
			host = canonicalHost(meta.Host)
			// Only simple-obfs has been peeled. The SSR codec now processes the
			// enclosed legacy Shadowsocks stream using the carrier's cipher.
			options.Obfs = "plain"
		default:
			transport, host, err = peekObfsHost(transport, options.Obfs)
		}
		if err != nil {
			done(err)
			return
		}
		user, ok := s.muHosts[host]
		if !ok {
			done(errors.New("ssr: unknown single-port Host"))
			return
		}
		options.Users = []User{user}
		options.ObfsParam = ""
		// Static evidence: constructor 0x1ca3160 uses the carrier password;
		// init 0x1ce4080 selects the billing user afterwards, without rekeying.
	}
	codec, err := newCodec(options, s.replay, transport.RemoteAddr())
	if err != nil {
		done(err)
		return
	}
	if tls, ok := codec.obfs.(*obfs.ObfsTLS); ok {
		tls.ObfsAuthData = s.tlsData
	}
	sc := &streamConn{Conn: transport, codec: codec}
	c = sc
	destination, err := readAddress(sc)
	if err != nil {
		done(err)
		return
	}
	raw.SetDeadline(time.Time{})
	ctx := s.ctx
	if s.options.SinglePortType == "protocol" {
		switch p := codec.protocol.(type) {
		case *obfs.AuthAes128Sha1:
			ctx = context.WithValue(ctx, clientIDKey{}, uint32(p.ClientID))
		case *obfs.AuthChainA:
			ctx = context.WithValue(ctx, clientIDKey{}, uint32(p.ClientID))
		}
	}
	s.router.RouteConnectionEx(ctx, sc, adapter.InboundContext{
		Inbound: s.Tag(), InboundType: Type, Source: M.SocksaddrFromNet(transport.RemoteAddr()),
		Destination: destination, User: strconv.FormatInt(codec.userID, 10),
	}, done)
}

func readAddress(r io.Reader) (M.Socksaddr, error) {
	var typ [1]byte
	if _, err := io.ReadFull(r, typ[:]); err != nil {
		return M.Socksaddr{}, err
	}
	var host string
	switch typ[0] {
	case 1:
		b := make([]byte, 4)
		if _, err := io.ReadFull(r, b); err != nil {
			return M.Socksaddr{}, err
		}
		host = net.IP(b).String()
	case 4:
		b := make([]byte, 16)
		if _, err := io.ReadFull(r, b); err != nil {
			return M.Socksaddr{}, err
		}
		host = net.IP(b).String()
	case 3:
		if _, err := io.ReadFull(r, typ[:]); err != nil || typ[0] == 0 {
			return M.Socksaddr{}, errors.New("ssr: invalid destination")
		}
		b := make([]byte, int(typ[0]))
		if _, err := io.ReadFull(r, b); err != nil {
			return M.Socksaddr{}, err
		}
		host = string(b)
	default:
		return M.Socksaddr{}, errors.New("ssr: invalid address type")
	}
	var port [2]byte
	if _, err := io.ReadFull(r, port[:]); err != nil {
		return M.Socksaddr{}, err
	}
	p := uint16(port[0])<<8 | uint16(port[1])
	dest := M.ParseSocksaddrHostPort(host, p)
	if !dest.IsValid() || p == 0 {
		return M.Socksaddr{}, errors.New("ssr: invalid destination")
	}
	return dest, nil
}

func appendAddress(p []byte, addr M.Socksaddr) ([]byte, error) {
	if addr.IsIPv4() {
		p = append(p, 1)
		ip := addr.Addr.As4()
		p = append(p, ip[:]...)
	} else if addr.IsIPv6() {
		p = append(p, 4)
		ip := addr.Addr.As16()
		p = append(p, ip[:]...)
	} else if len(addr.Fqdn) > 0 && len(addr.Fqdn) <= 255 {
		p = append(p, 3, byte(len(addr.Fqdn)))
		p = append(p, addr.Fqdn...)
	} else {
		return nil, errors.New("ssr: invalid destination")
	}
	return append(p, byte(addr.Port>>8), byte(addr.Port)), nil
}
