package proxy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	tfo "github.com/database64128/tfo-go/v2"
	"github.com/pires/go-proxyproto"
	"reconstructed.local/soga/proxy/wireproxy"
	"reconstructed.local/soga/tunnel"
)

// This frontend removes only pass tunnel framing. Complete protocol ciphertext
// is forwarded to private TCP/UDP listeners of the existing authentication core.
type tunnelFrontend struct {
	config   Config
	backend  string
	listener *tunnel.Listener
	mu       sync.Mutex
	active   map[net.Conn]bool
	closed   bool
	wg       sync.WaitGroup
}

func (s *Server) startTunnel() error {
	backend := s.cfg
	backend.Tunnel = nil
	backend.Listen = "127.0.0.1"
	backend.TCPFastOpen, backend.TCPMultiPath = false, false
	// These headers are emitted only by this frontend and carry the selected
	// original peer. The backend socket is never exposed on a public interface.
	backend.ProxyProtocol, backend.ForceProxyProtocol = true, true
	backend.UDPProxyProtocol = true
	reserved, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	backend.Port = uint16(reserved.Addr().(*net.TCPAddr).Port)
	_ = reserved.Close()
	child := &Server{ctx: s.ctx, cfg: backend, meter: s.meter, done: make(chan struct{})}
	if err = child.start(); err != nil {
		return err
	}
	f := &tunnelFrontend{config: s.cfg, backend: net.JoinHostPort(backend.Listen, strconv.Itoa(int(backend.Port))), active: make(map[net.Conn]bool)}
	if err = f.start(s.ctx); err != nil {
		if child.box != nil {
			_ = child.box.Close()
		}
		return err
	}
	s.box = child.box
	s.tunnel = f
	return nil
}

func (f *tunnelFrontend) start(ctx context.Context) error {
	address := net.JoinHostPort(f.config.Listen, strconv.Itoa(int(f.config.Port)))
	var lc net.ListenConfig
	lc.SetMultipathTCP(f.config.TCPMultiPath)
	var raw net.Listener
	var err error
	if f.config.TCPFastOpen {
		tlc := tfo.ListenConfig{ListenConfig: lc}
		raw, err = tlc.Listen(ctx, "tcp", address)
	} else {
		raw, err = lc.Listen(ctx, "tcp", address)
	}
	if err != nil {
		return err
	}
	// NewListener@0x18b9340 installs the configured direct PROXY listener
	// before tunnel TLS/WebSocket/encryption. The session-level PROXY header
	// below is a separate, always optional layer.
	if f.config.ProxyProtocol {
		pp := &proxyproto.Listener{Listener: raw, ReadHeaderTimeout: 5 * time.Second}
		if f.config.ForceProxyProtocol {
			pp.Policy = func(net.Addr) (proxyproto.Policy, error) { return proxyproto.REQUIRE, nil }
		}
		raw = pp
	}
	f.listener, err = tunnel.WrapListener(raw, *f.config.Tunnel)
	if err != nil {
		_ = raw.Close()
		return err
	}
	f.wg.Add(1)
	go func() {
		defer f.wg.Done()
		for {
			c, err := f.listener.Accept()
			if err != nil {
				return
			}
			if !f.track(c) {
				return
			}
			f.wg.Add(1)
			go func() {
				defer f.wg.Done()
				defer f.release(c)
				conn := c.(*tunnel.Conn)
				if conn.Mode == tunnel.TCP {
					f.tcp(ctx, conn)
				} else {
					f.udp(ctx, conn)
				}
			}()
		}
	}()
	return nil
}

func (f *tunnelFrontend) track(c net.Conn) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		_ = c.Close()
		return false
	}
	f.active[c] = true
	return true
}
func (f *tunnelFrontend) release(c net.Conn) {
	_ = c.Close()
	f.mu.Lock()
	delete(f.active, c)
	f.mu.Unlock()
}
func (f *tunnelFrontend) tcp(ctx context.Context, raw net.Conn) {
	// The original soga tunnel factory unconditionally enables its optional
	// PROXY listener (0x133044a -> 0x11db436). Keep that behavior even when
	// the separate direct-listener proxy_protocol option is false.
	conn, err := wireproxy.Connection(raw, false)
	if err != nil {
		return
	}
	target, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp", f.backend)
	if err != nil {
		return
	}
	if !f.track(target) {
		return
	}
	defer f.release(target)
	if _, err = proxyproto.HeaderProxyFromAddrs(2, conn.RemoteAddr(), conn.LocalAddr()).WriteTo(target); err != nil {
		return
	}
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(target, conn)
		if tcp, ok := target.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
		close(done)
	}()
	_, _ = io.Copy(conn, target)
	_ = conn.Close()
	<-done
}

func (f *tunnelFrontend) udp(ctx context.Context, conn *tunnel.Conn) {
	if f.config.Protocol != "shadowsocks" && f.config.Protocol != "ssr" {
		return
	}
	target, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "udp", f.backend)
	if err != nil {
		return
	}
	if !f.track(target) {
		return
	}
	defer f.release(target)
	idle := 5 * time.Minute
	if f.config.UDPTimeoutMinutes > 0 {
		idle = time.Duration(f.config.UDPTimeoutMinutes) * time.Minute
	}
	_ = conn.SetReadDeadline(time.Now().Add(idle))
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer conn.Close()
		b := make([]byte, 65535)
		for {
			_ = target.SetReadDeadline(time.Now().Add(idle))
			n, err := target.Read(b)
			if err != nil {
				return
			}
			if _, err = conn.Write(b[:n]); err != nil {
				return
			}
		}
	}()
	defer func() { _ = target.Close(); <-done }()
	b := make([]byte, 65535)
	source, err := udpAddress(conn.RemoteAddr())
	if err != nil {
		return
	}
	first := true
	for {
		n, err := conn.Read(b)
		if err != nil {
			return
		}
		payload := b[:n]
		if first || f.config.UDPProxyProtocol {
			payload, source, err = wireproxy.Datagram(payload, source, false)
			if err != nil {
				return
			}
		}
		first = false
		if len(payload) == 0 {
			continue
		}
		dest, err := udpAddress(conn.LocalAddr())
		if err != nil {
			return
		}
		var packet bytes.Buffer
		if _, err = proxyproto.HeaderProxyFromAddrs(2, source, dest).WriteTo(&packet); err != nil {
			return
		}
		_, _ = packet.Write(payload)
		if _, err = target.Write(packet.Bytes()); err != nil {
			return
		}
		_ = conn.SetReadDeadline(time.Now().Add(idle))
	}
}

func udpAddress(a net.Addr) (net.Addr, error) {
	host, port, err := net.SplitHostPort(a.String())
	if err != nil {
		return nil, err
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		return nil, err
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, errors.New("tunnel peer is not an IP address")
	}
	return &net.UDPAddr{IP: ip, Port: p}, nil
}

func (f *tunnelFrontend) close() error {
	f.mu.Lock()
	f.closed = true
	for c := range f.active {
		_ = c.Close()
	}
	f.mu.Unlock()
	err := f.listener.Close()
	f.wg.Wait()
	return err
}
