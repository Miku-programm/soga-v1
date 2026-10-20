package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	tfo "github.com/database64128/tfo-go/v2"
	"github.com/pires/go-proxyproto"
	"github.com/sagernet/sing-box/adapter"
	boxTLS "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/v2ray"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// Xray 26 removed its old HTTP/2 transport. This frontend implements only the
// transport using sing-box's interoperable HTTP/2 implementation. Encrypted
// VLESS bytes are forwarded unchanged to Xray on loopback, where authenticated
// traffic still enters xrayDispatcher and the shared policy/limiter/accountant.
type xrayH2Frontend struct {
	config    Config
	backend   string
	tls       boxTLS.ServerConfig
	transport adapter.V2RayServerTransport
	listener  net.Listener
	mu        sync.Mutex
	active    map[net.Conn]bool
	closed    bool
}

func newXrayH2Frontend(ctx context.Context, logger log.ContextLogger, c Config) (*xrayH2Frontend, error) {
	var raw struct {
		Network      string `json:"network"`
		Security     string `json:"security"`
		HTTPSettings struct {
			Path   string   `json:"path"`
			Host   []string `json:"host"`
			Method string   `json:"method"`
		} `json:"httpSettings"`
		TLSSettings struct {
			ServerName   string   `json:"serverName"`
			ALPN         []string `json:"alpn"`
			MinVersion   string   `json:"minVersion"`
			MaxVersion   string   `json:"maxVersion"`
			CipherSuites string   `json:"cipherSuites"`
			Certificates []struct {
				CertificateFile string   `json:"certificateFile"`
				KeyFile         string   `json:"keyFile"`
				Certificate     []string `json:"certificate"`
				Key             []string `json:"key"`
			} `json:"certificates"`
		} `json:"tlsSettings"`
	}
	if len(c.XrayStream) > 0 {
		if err := json.Unmarshal(c.XrayStream, &raw); err != nil {
			return nil, err
		}
		if raw.Network != "http" && raw.Network != "h2" {
			return nil, nil
		}
	} else if c.Transport == nil || c.Transport.Type != "http" {
		return nil, nil
	}
	if c.Flow != "" {
		return nil, errors.New("proxy: legacy HTTP/2 transport does not support VLESS Vision flow")
	}
	transport := option.V2RayTransportOptions{Type: "http"}
	if c.Transport != nil {
		transport = *c.Transport
	}
	if len(c.XrayStream) > 0 {
		transport.Type = "http"
		transport.HTTPOptions.Path = raw.HTTPSettings.Path
		transport.HTTPOptions.Host = raw.HTTPSettings.Host
		transport.HTTPOptions.Method = raw.HTTPSettings.Method
		switch raw.Security {
		case "", "none":
			c.TLS = nil
		case "tls":
			if c.TLS == nil || !c.TLS.Enabled {
				if len(raw.TLSSettings.Certificates) != 1 {
					return nil, errors.New("proxy: legacy HTTP/2 TLS needs one certificate/key pair")
				}
				pair := raw.TLSSettings.Certificates[0]
				c.TLS = &option.InboundTLSOptions{Enabled: true,
					ServerName: raw.TLSSettings.ServerName, ALPN: raw.TLSSettings.ALPN,
					MinVersion: raw.TLSSettings.MinVersion, MaxVersion: raw.TLSSettings.MaxVersion,
					CertificatePath: pair.CertificateFile, KeyPath: pair.KeyFile,
					Certificate: pair.Certificate, Key: pair.Key}
				if raw.TLSSettings.CipherSuites != "" {
					return nil, errors.New("proxy: explicit legacy HTTP/2 cipher suites require normalized TLS options")
				}
			}
		default:
			return nil, errors.New("proxy: legacy HTTP/2 frontend supports TLS or plaintext security")
		}
	}
	h := &xrayH2Frontend{config: c, active: make(map[net.Conn]bool)}
	var err error
	if c.TLS != nil && c.TLS.Enabled {
		h.tls, err = boxTLS.NewServer(ctx, logger, *c.TLS)
		if err != nil {
			return nil, err
		}
	}
	h.transport, err = v2ray.NewServerTransport(ctx, logger, transport, h.tls, h)
	if err != nil {
		if h.tls != nil {
			_ = h.tls.Close()
		}
		return nil, err
	}
	return h, nil
}

func (h *xrayH2Frontend) start(ctx context.Context) error {
	if h.tls != nil {
		if err := h.tls.Start(); err != nil {
			return err
		}
	}
	var lc net.ListenConfig
	lc.SetMultipathTCP(h.config.TCPMultiPath)
	address := net.JoinHostPort(h.config.Listen, strconv.Itoa(int(h.config.Port)))
	var l net.Listener
	var err error
	if h.config.TCPFastOpen {
		tlc := tfo.ListenConfig{ListenConfig: lc}
		l, err = tlc.Listen(ctx, "tcp", address)
	} else {
		l, err = lc.Listen(ctx, "tcp", address)
	}
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
	h.listener = l
	go h.transport.Serve(l)
	return nil
}

func (h *xrayH2Frontend) NewConnectionEx(ctx context.Context, conn net.Conn, source, _ M.Socksaddr, onClose N.CloseHandlerFunc) {
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		closeDenied(conn, onClose, net.ErrClosed)
		return
	}
	h.active[conn] = true
	h.mu.Unlock()
	go func() {
		var result error
		defer func() {
			_ = conn.Close()
			h.mu.Lock()
			delete(h.active, conn)
			h.mu.Unlock()
			if onClose != nil {
				onClose(result)
			}
		}()
		target, err := (&net.Dialer{}).DialContext(ctx, "tcp", h.backend)
		if err != nil {
			result = err
			return
		}
		defer target.Close()
		if _, err = proxyproto.HeaderProxyFromAddrs(2, source.TCPAddr(), target.LocalAddr()).WriteTo(target); err != nil {
			result = err
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
		_, result = io.Copy(conn, target)
		_ = conn.Close()
		_ = target.Close()
		<-done
	}()
}

func (h *xrayH2Frontend) close() error {
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return nil
	}
	h.closed = true
	conns := make([]net.Conn, 0, len(h.active))
	for c := range h.active {
		conns = append(conns, c)
	}
	h.mu.Unlock()
	for _, c := range conns {
		_ = c.Close()
	}
	if h.listener != nil {
		_ = h.listener.Close()
	}
	if h.tls != nil {
		defer h.tls.Close()
	}
	return h.transport.Close()
}
