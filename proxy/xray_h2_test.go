package proxy

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	boxTLS "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/v2ray"
	M "github.com/sagernet/sing/common/metadata"
)

// The unmodified Xray encryption client emits real encrypted VLESS to a local
// byte bridge. The independent sing-box HTTP/2 client carries those exact bytes
// over TLS/H2 to the public server; no authentication is simulated by the bridge.
func encryptedH2Client(t *testing.T, cfg Config, user User, encryption string, tlsOptions *option.OutboundTLSOptions, sendProxy bool) adapter.Outbound {
	t.Helper()
	ctx := context.Background()
	logger := log.NewNOPFactory().Logger()
	clientTLS, err := boxTLS.NewClient(ctx, logger, "127.0.0.1", *tlsOptions)
	if err != nil {
		t.Fatal(err)
	}
	transport, err := v2ray.NewClientTransport(ctx, h2WireDialer{sendProxy: sendProxy}, M.ParseSocksaddr(net.JoinHostPort("127.0.0.1", fmt.Sprint(cfg.Port))),
		option.V2RayTransportOptions{Type: "http", HTTPOptions: option.V2RayHTTPOptions{Path: "/encrypted-h2", Host: []string{"localhost"}}}, clientTLS)
	if err != nil {
		t.Fatal(err)
	}
	local, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	active := make(map[net.Conn]bool)
	var closed bool
	t.Cleanup(func() {
		local.Close()
		mu.Lock()
		closed = true
		for c := range active {
			c.Close()
		}
		mu.Unlock()
		transport.Close()
	})
	go func() {
		for {
			conn, e := local.Accept()
			if e != nil {
				return
			}
			mu.Lock()
			if closed {
				mu.Unlock()
				conn.Close()
				return
			}
			active[conn] = true
			mu.Unlock()
			go func() {
				defer func() { conn.Close(); mu.Lock(); delete(active, conn); mu.Unlock() }()
				stream, e := transport.DialContext(ctx)
				if e != nil {
					return
				}
				defer stream.Close()
				done := make(chan struct{})
				go func() { io.Copy(stream, conn); stream.Close(); close(done) }()
				io.Copy(conn, stream)
				conn.Close()
				<-done
			}()
		}
	}()
	inner := cfg
	inner.Port = uint16(local.Addr().(*net.TCPAddr).Port)
	return newXrayTestClient(t, inner, user, encryption, jsonValue(t, map[string]any{"network": "tcp", "security": "none"}))
}

type h2WireDialer struct{ sendProxy bool }

func (d h2WireDialer) DialContext(ctx context.Context, network string, dst M.Socksaddr) (net.Conn, error) {
	c, e := (&net.Dialer{}).DialContext(ctx, network, dst.String())
	if e == nil && d.sendProxy {
		_, e = fmt.Fprintf(c, "PROXY TCP4 192.0.2.91 127.0.0.1 43210 %d\r\n", dst.Port)
		if e != nil {
			c.Close()
		}
	}
	return c, e
}

func (h2WireDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("HTTP/2 client uses TCP only")
}

func TestXrayVLESSEncryptedLegacyHTTP2(t *testing.T) {
	target, accepts := echoTCP(t)
	udp := echoUDP(t)
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	decryption := "mlkem768x25519plus.native.600s." + base64.RawURLEncoding.EncodeToString(key.Bytes())
	encryption := "mlkem768x25519plus.native.0rtt." + base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())
	for _, mode := range []string{"options", "xray-stream", "xray-stream-empty-host", "required-proxy"} {
		t.Run(mode, func(t *testing.T) {
			serverTLS, clientTLS := tlsPair(t)
			user := User{ID: 42, UUID: testUUID}
			var denied atomic.Bool
			requests := make(chan Request, 32)
			cfg := Config{Protocol: "vless", Listen: "127.0.0.1", Port: freePort(t, false), Users: []User{user},
				Decryption: decryption, TLS: serverTLS,
				Transport: &option.V2RayTransportOptions{Type: "http", HTTPOptions: option.V2RayHTTPOptions{Path: "/encrypted-h2", Host: []string{"localhost"}}},
				Hook: func(r Request) error {
					requests <- r
					if denied.Load() {
						return errors.New("test policy denial")
					}
					return nil
				}}
			withProxy := mode == "required-proxy"
			cfg.ProxyProtocol, cfg.ForceProxyProtocol = withProxy, withProxy
			if mode == "xray-stream" || mode == "xray-stream-empty-host" {
				httpSettings := map[string]any{"path": "/encrypted-h2"}
				if mode != "xray-stream-empty-host" {
					httpSettings["host"] = []string{"localhost"}
				}
				cfg.XrayStream = jsonValue(t, map[string]any{"network": "http", "security": "tls",
					"httpSettings": httpSettings})
			}
			s, err := Start(context.Background(), cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			out := encryptedH2Client(t, cfg, user, encryption, clientTLS, withProxy)
			for i := 0; i < 3; i++ {
				if err := roundTripTCP(out, target, []byte("encrypted VLESS over real legacy H2"), 5*time.Second); err != nil {
					t.Fatal(err)
				}
			}
			if err := roundTripUDP(out, udp, []byte("encrypted H2 UDP payload")); err != nil {
				t.Fatal(err)
			}
			first := <-requests
			if first.UserID != 42 || withProxy && first.Source != "192.0.2.91:43210" {
				t.Fatalf("authenticated metadata lost: %+v", first)
			}
			traffic := s.TrafficSnapshot()[42]
			if traffic.Upload == 0 || traffic.Download == 0 {
				t.Fatal("encrypted H2 bypassed accounting")
			}
			before := accepts.Load()
			wrong := user
			wrong.UUID = "f1ab9d14-d9df-44e6-ae1f-24230bed553e"
			bad := encryptedH2Client(t, cfg, wrong, encryption, clientTLS, withProxy)
			if err := roundTripTCP(bad, target, []byte("wrong UUID"), time.Second); err == nil || accepts.Load() != before {
				t.Fatal("wrong encrypted VLESS credentials reached the target")
			}
			denied.Store(true)
			if err := roundTripTCP(out, target, []byte("denied request"), time.Second); err == nil || accepts.Load() != before {
				t.Fatal("encrypted H2 bypassed policy denial")
			}
		})
	}
}

func TestXrayEncryptedHTTP2TCPQuota(t *testing.T) {
	target, accepts := echoTCP(t)
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serverTLS, clientTLS := tlsPair(t)
	user := User{ID: 42, UUID: testUUID, TCPLimit: 1}
	cfg := Config{Protocol: "vless", Listen: "127.0.0.1", Port: freePort(t, false), Users: []User{user}, TLS: serverTLS,
		Decryption: "mlkem768x25519plus.native.600s." + base64.RawURLEncoding.EncodeToString(key.Bytes()),
		Transport:  &option.V2RayTransportOptions{Type: "http", HTTPOptions: option.V2RayHTTPOptions{Path: "/encrypted-h2"}}}
	s, err := Start(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	out := encryptedH2Client(t, cfg, user, "mlkem768x25519plus.native.0rtt."+base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()), clientTLS, false)
	held, err := out.DialContext(context.Background(), "tcp", M.ParseSocksaddr(target))
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	held.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err = held.Write([]byte("held")); err != nil {
		t.Fatal(err)
	}
	if _, err = io.ReadFull(held, make([]byte, 4)); err != nil {
		t.Fatal(err)
	}
	before := accepts.Load()
	// The second logical H2 stream belongs to the same physical client peer;
	// user_tcp_limit counts physical peers, so it must remain admitted.
	if err = roundTripTCP(out, target, []byte("same HTTP2 peer"), 2*time.Second); err != nil {
		t.Fatal(err)
	}
	// A distinct HTTP2 client connection is another TCP peer and must be denied.
	second := encryptedH2Client(t, cfg, user, "mlkem768x25519plus.native.0rtt."+base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()), clientTLS, false)
	if err = roundTripTCP(second, target, []byte("second peer"), time.Second); err == nil || accepts.Load() != before+1 {
		t.Fatal("distinct encrypted H2 peer bypassed TCP quota")
	}
}
