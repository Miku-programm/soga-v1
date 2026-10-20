package proxy

import (
	"context"
	"net"
	"sync"
	"time"

	apicommon "github.com/enfein/mieru/v3/apis/common"
	"github.com/pires/go-proxyproto"
	"reconstructed.local/soga/proxy/wireproxy"
	"reconstructed.local/soga/tunnel"
)

// The documented Mieru transport is TCP (including its UDP-associate payloads).
// Feed decrypted tunnel streams directly to the official SDK so the real peer
// address survives authentication, admission checks and accounting.
type mieruTunnelFactory struct {
	socket      apicommon.StreamListenerFactory
	config      tunnel.Config
	directProxy bool
	required    bool
	trusted     wireproxy.Trusted
}

func (f *mieruTunnelFactory) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	raw, err := f.socket.Listen(ctx, network, address)
	if err != nil {
		return nil, err
	}
	if f.directProxy {
		raw = &proxyproto.Listener{Listener: raw, ReadHeaderTimeout: 5 * time.Second,
			ConnPolicy: f.trusted.ConnPolicy(f.required)}
	}
	l, err := tunnel.WrapListener(raw, f.config)
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	out := &mieruTunnelListener{Listener: l, ready: make(chan net.Conn), closed: make(chan struct{}), acceptDone: make(chan struct{})}
	go out.run()
	return out, nil
}

type mieruTunnelListener struct {
	*tunnel.Listener
	ready      chan net.Conn
	closed     chan struct{}
	acceptDone chan struct{}
	once       sync.Once
	workers    sync.WaitGroup
}

func (l *mieruTunnelListener) run() {
	defer close(l.acceptDone)
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return
		}
		if c.(*tunnel.Conn).Mode != tunnel.TCP {
			_ = c.Close()
			continue
		}
		l.workers.Add(1)
		go func() {
			defer l.workers.Done()
			// The SDK reads RemoteAddr immediately on its accept goroutine.
			// Finish optional PROXY parsing here to avoid serial head blocking.
			parsed, err := wireproxy.Connection(c, false, nil)
			if err != nil {
				_ = c.Close()
				return
			}
			select {
			case l.ready <- parsed:
			case <-l.closed:
				_ = c.Close()
			}
		}()
	}
}

func (l *mieruTunnelListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ready:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	case <-l.acceptDone:
		return nil, net.ErrClosed
	}
}

func (l *mieruTunnelListener) Close() error {
	l.once.Do(func() {
		close(l.closed)
		_ = l.Listener.Close()
		<-l.acceptDone
		l.workers.Wait()
	})
	return nil
}
