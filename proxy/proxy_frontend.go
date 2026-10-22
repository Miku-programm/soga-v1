package proxy

import (
	"context"
	"net"
	"sync"
	"time"

	tfo "github.com/database64128/tfo-go/v2"
	"github.com/pires/go-proxyproto"
	"reconstructed.local/soga/proxy/wireproxy"
)

// Xray's native socket setting always requires a PROXY header from any peer.
// This local frontend implements the documented optional/required distinction
// and the trusted-source list, and forwards an unambiguous v2 header to an Xray
// listener bound only to loopback. It is not created when a header is required
// from every peer, which Xray enforces by itself. Encrypted protocol bytes pass
// through untouched; no target traffic is decoded here.
type proxyFrontend struct {
	address, backend string
	required         bool
	trusted          wireproxy.Trusted
	tfo, mptcp       bool
	idle             time.Duration
	listener         net.Listener
	mu               sync.Mutex
	conns            map[net.Conn]bool
	closed           bool
}

func (f *proxyFrontend) start(ctx context.Context) error {
	var lc net.ListenConfig
	lc.SetMultipathTCP(f.mptcp)
	var l net.Listener
	var err error
	if f.tfo {
		tlc := tfo.ListenConfig{ListenConfig: lc}
		l, err = tlc.Listen(ctx, "tcp", f.address)
	} else {
		l, err = lc.Listen(ctx, "tcp", f.address)
	}
	if err != nil {
		return err
	}
	f.listener = l
	f.conns = make(map[net.Conn]bool)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			f.mu.Lock()
			if f.closed {
				f.mu.Unlock()
				c.Close()
				return
			}
			f.conns[c] = true
			f.mu.Unlock()
			go f.serve(ctx, c)
		}
	}()
	return nil
}

func (f *proxyFrontend) serve(ctx context.Context, raw net.Conn) {
	defer func() { raw.Close(); f.mu.Lock(); delete(f.conns, raw); f.mu.Unlock() }()
	policy, err := f.trusted.Policy(raw.RemoteAddr(), f.required)
	if err != nil {
		return
	}
	conn := proxyproto.NewConn(raw, proxyproto.WithPolicy(policy), proxyproto.SetReadHeaderTimeout(5*time.Second))
	if _, err := conn.Read(nil); err != nil {
		return
	}
	target, err := (&net.Dialer{}).DialContext(ctx, "tcp", f.backend)
	if err != nil {
		return
	}
	defer target.Close()
	if _, err = proxyproto.HeaderProxyFromAddrs(2, conn.RemoteAddr(), conn.LocalAddr()).WriteTo(target); err != nil {
		return
	}
	_ = relay(ctx, conn, target, f.idle)
}

func (f *proxyFrontend) close() error {
	f.mu.Lock()
	f.closed = true
	for c := range f.conns {
		c.Close()
	}
	f.mu.Unlock()
	if f.listener != nil {
		return f.listener.Close()
	}
	return nil
}
