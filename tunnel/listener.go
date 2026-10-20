package tunnel

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/xtaci/smux"
)

type Config struct {
	Type, Method, Password, WSPath string
	Mux                            bool
	TLSConfig                      *tls.Config
}

func (c Config) normalized() (Config, error) {
	switch c.Type {
	case "", "tcp", "tcp-tunnel":
		c.Type = "tcp"
	case "tls", "tls-tunnel":
		c.Type = "tls"
	case "ws", "ws-tunnel":
		c.Type = "ws"
	case "ws-tls", "ws-tls-tunnel":
		c.Type = "ws-tls"
	default:
		return c, fmt.Errorf("tunnel transport %q has no validated wire implementation", c.Type)
	}
	if c.Type == "tls" || c.Type == "ws-tls" {
		if c.TLSConfig == nil {
			return c, errors.New("TLS tunnel requires a TLS configuration")
		}
	}
	if c.WSPath == "" {
		c.WSPath = "/"
	} else if !strings.HasPrefix(c.WSPath, "/") {
		c.WSPath = "/" + c.WSPath
	}
	if strings.ContainsAny(c.WSPath, "?#") {
		return c, errors.New("tunnel WebSocket path cannot contain query or fragment")
	}
	return c, nil
}

// Validate checks configuration without binding a socket.
func Validate(c Config) error {
	normalized, err := c.normalized()
	if err != nil {
		return err
	}
	if normalized.Type == "tls" || normalized.Type == "ws-tls" {
		if len(c.TLSConfig.Certificates) == 0 && c.TLSConfig.GetCertificate == nil && c.TLSConfig.GetConfigForClient == nil {
			return errors.New("TLS tunnel requires a server certificate")
		}
	}
	_, err = makeKeys(c.Method, c.Password)
	return err
}

// Listener accepts authenticated logical connections. Unlike the artifact,
// handshakes happen outside the accept loop and have a bounded deadline.
type Listener struct {
	raw    net.Listener
	config Config
	keys   *keys
	replay replayCache
	ready  chan *Conn
	closed chan struct{}
	done   chan struct{}
	once   sync.Once
	mu     sync.Mutex
	active map[net.Conn]struct{}
	wg     sync.WaitGroup
	http   *http.Server
}

func WrapListener(raw net.Listener, config Config) (*Listener, error) {
	if err := Validate(config); err != nil {
		return nil, err
	}
	c, err := config.normalized()
	if err != nil {
		return nil, err
	}
	k, err := makeKeys(c.Method, c.Password)
	if err != nil {
		return nil, err
	}
	l := &Listener{raw: raw, config: c, keys: k, ready: make(chan *Conn, 256), closed: make(chan struct{}), done: make(chan struct{}), active: make(map[net.Conn]struct{})}
	base := raw
	if c.Type == "tls" || c.Type == "ws-tls" {
		base = tls.NewListener(raw, c.TLSConfig.Clone())
	}
	l.wg.Add(1)
	if c.Type == "ws" || c.Type == "ws-tls" {
		upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }, HandshakeTimeout: 10 * time.Second}
		l.http = &http.Server{ReadHeaderTimeout: 10 * time.Second, MaxHeaderBytes: 16384, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != c.WSPath {
				http.NotFound(w, r)
				return
			}
			ws, err := upgrader.Upgrade(w, r, nil)
			if err != nil {
				return
			}
			l.start(&websocketConn{Conn: ws})
		})}
		go func() {
			defer l.wg.Done()
			defer close(l.done)
			_ = l.http.Serve(base)
		}()
	} else {
		go func() {
			defer l.wg.Done()
			defer close(l.done)
			for {
				conn, err := base.Accept()
				if err != nil {
					return
				}
				l.start(conn)
			}
		}()
	}
	return l, nil
}

func (l *Listener) start(raw net.Conn) {
	l.mu.Lock()
	select {
	case <-l.closed:
		l.mu.Unlock()
		_ = raw.Close()
		return
	default:
	}
	l.active[raw] = struct{}{}
	l.wg.Add(1)
	l.mu.Unlock()
	go func() {
		defer l.wg.Done()
		_ = raw.SetDeadline(time.Now().Add(10 * time.Second))
		managed := &managedConn{Conn: raw, onClose: func() {
			l.mu.Lock()
			delete(l.active, raw)
			l.mu.Unlock()
		}}
		wire := &wireConn{Conn: managed, keys: l.keys, replay: &l.replay}
		if !l.config.Mux {
			l.handshake(wire)
			return
		}
		defer managed.Close()
		// The artifact's smux fork accepts version 1 or 2 from the first
		// frame (0x1194392..0x11943ed), then uses that version for replies.
		buffered := bufio.NewReaderSize(wire, 8)
		first, err := buffered.Peek(1)
		if err != nil || (first[0] != 1 && first[0] != 2) {
			return
		}
		muxOptions := muxConfig()
		muxOptions.Version = int(first[0])
		session, err := smux.Server(&bufferedConn{Conn: wire, reader: buffered}, muxOptions)
		if err != nil {
			return
		}
		defer session.Close()
		for {
			stream, err := session.AcceptStream()
			if err != nil {
				return
			}
			_ = raw.SetDeadline(time.Time{})
			l.wg.Add(1)
			go func() {
				defer l.wg.Done()
				l.handshake(stream)
			}()
		}
	}()
}

func (l *Listener) handshake(raw net.Conn) {
	_ = raw.SetDeadline(time.Now().Add(10 * time.Second))
	conn, err := serverSession(raw, l.keys)
	if err != nil {
		_ = raw.Close()
		return
	}
	_ = raw.SetDeadline(time.Time{})
	select {
	case l.ready <- conn:
	case <-l.closed:
		_ = conn.Close()
	}
}

func (l *Listener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ready:
		select {
		case <-l.closed:
			_ = c.Close()
			return nil, net.ErrClosed
		default:
			return c, nil
		}
	case <-l.closed:
		return nil, net.ErrClosed
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *Listener) Close() error {
	l.once.Do(func() {
		close(l.closed)
		_ = l.raw.Close()
		if l.http != nil {
			_ = l.http.Close()
		}
		l.mu.Lock()
		for c := range l.active {
			_ = c.Close()
		}
		l.mu.Unlock()
		l.wg.Wait()
	})
	return nil
}

func (l *Listener) Addr() net.Addr { return l.raw.Addr() }

func muxConfig() *smux.Config {
	return &smux.Config{Version: 1, KeepAliveDisabled: true, MaxFrameSize: 32768, MaxReceiveBuffer: 4194304, MaxStreamBuffer: 65536}
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

type managedConn struct {
	net.Conn
	onClose func()
	once    sync.Once
}

func (c *managedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.onClose)
	return err
}

// Client provides the reconstructed peer for interoperation checks and tunnel
// composition. A multiplexed Client can open multiple simultaneous sessions.
type Client struct {
	raw    net.Conn
	wire   *wireConn
	keys   *keys
	mux    *smux.Session
	mu     sync.Mutex
	opened bool
}

func DialClient(ctx context.Context, address string, config Config) (*Client, error) {
	c, err := config.normalized()
	if err != nil {
		return nil, err
	}
	k, err := makeKeys(c.Method, c.Password)
	if err != nil {
		return nil, err
	}
	var raw net.Conn
	if c.Type == "ws" || c.Type == "ws-tls" {
		scheme := "ws"
		if c.Type == "ws-tls" {
			scheme = "wss"
		}
		d := websocket.Dialer{HandshakeTimeout: 10 * time.Second, TLSClientConfig: c.TLSConfig}
		ws, response, e := d.DialContext(ctx, scheme+"://"+address+c.WSPath, nil)
		if response != nil && e != nil {
			_ = response.Body.Close()
		}
		err = e
		if err == nil {
			raw = &websocketConn{Conn: ws}
		}
	} else if c.Type == "tls" {
		raw, err = (&tls.Dialer{Config: c.TLSConfig.Clone()}).DialContext(ctx, "tcp", address)
	} else {
		raw, err = (&net.Dialer{}).DialContext(ctx, "tcp", address)
	}
	if err != nil {
		return nil, err
	}
	cl := &Client{raw: raw, keys: k}
	cl.wire = &wireConn{Conn: raw, keys: k}
	if c.Mux {
		cl.mux, err = smux.Client(cl.wire, muxConfig())
		if err != nil {
			_ = raw.Close()
			return nil, err
		}
	}
	return cl, nil
}

func (c *Client) Open(mode byte) (*Conn, error) {
	c.mu.Lock()
	if c.mux == nil {
		if c.opened {
			c.mu.Unlock()
			return nil, errors.New("non-multiplexed tunnel already opened")
		}
		c.opened = true
	}
	c.mu.Unlock()
	var raw net.Conn = c.wire
	if c.mux != nil {
		s, err := c.mux.OpenStream()
		if err != nil {
			return nil, err
		}
		raw = s
	}
	conn, err := clientSession(raw, c.keys, mode)
	if err != nil {
		_ = raw.Close()
	}
	return conn, err
}

func (c *Client) Close() error {
	if c.mux != nil {
		return c.mux.Close()
	}
	return c.raw.Close()
}
