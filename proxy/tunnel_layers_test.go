package proxy

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"reconstructed.local/soga/tunnel"
)

// This byte relay inserts a direct-listener PROXY header before the outer TLS
// handshake. The distinct tunnelRelay helper can add an optional header inside
// each authenticated tunnel stream, before the inner business TLS handshake.
func tunnelOuterProxyRelay(t *testing.T, target string) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	active := make(map[net.Conn]bool)
	closed := false
	track := func(c net.Conn) bool {
		mu.Lock()
		defer mu.Unlock()
		if closed {
			_ = c.Close()
			return false
		}
		active[c] = true
		return true
	}
	release := func(c net.Conn) {
		_ = c.Close()
		mu.Lock()
		delete(active, c)
		mu.Unlock()
	}
	t.Cleanup(func() {
		_ = l.Close()
		mu.Lock()
		closed = true
		for c := range active {
			_ = c.Close()
		}
		mu.Unlock()
	})
	go func() {
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			if !track(c) {
				return
			}
			go func() {
				defer release(c)
				up, e := net.DialTimeout("tcp", target, 3*time.Second)
				if e != nil {
					return
				}
				if !track(up) {
					return
				}
				defer release(up)
				if _, e = io.WriteString(up, "PROXY TCP4 198.51.100.28 127.0.0.1 32323 443\r\n"); e != nil {
					return
				}
				done := make(chan struct{})
				go func() {
					_, _ = io.Copy(up, c)
					_ = up.Close()
					close(done)
				}()
				_, _ = io.Copy(c, up)
				_ = c.Close()
				<-done
			}()
		}
	}()
	return l.Addr().String()
}

func TestTunnelLayeredBusinessTransports(t *testing.T) {
	target, accepts := echoTCP(t)
	udpTarget := echoUDP(t)
	for _, tc := range []struct {
		name, transport       string
		innerProxy            bool
		outerProxy, outerHead bool
		required              bool
		encrypted             bool
	}{
		{name: "tls-ws/inner-proxy", transport: "ws", innerProxy: true},
		{name: "tls-grpc/required-outer-no-inner", transport: "grpc", outerProxy: true, outerHead: true, required: true},
		{name: "encrypted-h2/both-proxy-layers", transport: "http", innerProxy: true, outerProxy: true, outerHead: true, required: true, encrypted: true},
		{name: "encrypted-h2/optional-outer-no-headers", transport: "http", outerProxy: true, encrypted: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			outerTLS, _ := tlsPair(t)
			pair, err := tls.X509KeyPair([]byte(outerTLS.Certificate[0]), []byte(outerTLS.Key[0]))
			if err != nil {
				t.Fatal(err)
			}
			roots := x509.NewCertPool()
			if !roots.AppendCertsFromPEM([]byte(outerTLS.Certificate[0])) {
				t.Fatal("invalid outer certificate")
			}
			innerTLS, innerClientTLS := tlsPair(t)
			user := User{ID: 42, UUID: testUUID}
			requests := make(chan Request, 64)
			cfg := Config{
				Protocol: "vless", Listen: "127.0.0.1", Port: freePort(t, false),
				Users: []User{user}, TLS: innerTLS,
				ProxyProtocol: tc.outerProxy, ForceProxyProtocol: tc.required,
				Transport: &option.V2RayTransportOptions{
					Type:             tc.transport,
					WebsocketOptions: option.V2RayWebsocketOptions{Path: "/inner-ws"},
					GRPCOptions:      option.V2RayGRPCOptions{ServiceName: "inner-service"},
					HTTPOptions:      option.V2RayHTTPOptions{Path: "/encrypted-h2", Host: []string{"localhost"}},
				},
				Tunnel: &tunnel.Config{
					Type: "ws-tls", Method: "aes-256-gcm", Password: "outer-only-password",
					WSPath: "/outer-pass", Mux: true, TLSConfig: &tls.Config{Certificates: []tls.Certificate{pair}},
				},
				Hook: func(r Request) error { requests <- r; return nil },
			}
			var encryption string
			if tc.encrypted {
				key, e := ecdh.X25519().GenerateKey(rand.Reader)
				if e != nil {
					t.Fatal(e)
				}
				cfg.Decryption = "mlkem768x25519plus.native.600s." + base64.RawURLEncoding.EncodeToString(key.Bytes())
				encryption = "mlkem768x25519plus.native.0rtt." + base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())
			}
			s, err := Start(context.Background(), cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			wireConfig := *cfg.Tunnel
			wireConfig.TLSConfig = &tls.Config{RootCAs: roots, ServerName: "localhost"}
			if tc.required {
				// Missing direct PROXY fails before outer TLS/WS/tunnel auth;
				// an inner optional PROXY header cannot satisfy this policy.
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				rejected, e := tunnel.DialClient(ctx, s.Addr(), wireConfig)
				cancel()
				if e == nil {
					_ = rejected.Close()
					t.Fatal("required outer PROXY was not enforced")
				}
			}
			targetAddress := s.Addr()
			if tc.outerHead {
				targetAddress = tunnelOuterProxyRelay(t, targetAddress)
			}
			clientConfig := cfg
			clientConfig.Tunnel = nil
			clientConfig.Port = tunnelRelay(t, targetAddress, wireConfig, tc.innerProxy)
			makeClient := func(u User) adapter.Outbound {
				if tc.encrypted {
					return encryptedH2Client(t, clientConfig, u, encryption, innerClientTLS, false)
				}
				return client(t, clientConfig, u, innerClientTLS)
			}
			out := makeClient(user)
			payload := bytes.Repeat([]byte("nested authenticated ciphertext"), 2048)
			if err = roundTripTCP(out, target, payload, 5*time.Second); err != nil {
				t.Fatal(err)
			}
			// Xray's client XUDP writer drops length+666 > buf.Size (8192).
			// Keep this transport-composition test within that client limit;
			// the tunnel wire's full datagram boundary is tested separately.
			for _, size := range []int{1, 128, 4096} {
				if err = roundTripUDP(out, udpTarget, bytes.Repeat([]byte{byte(size % 251)}, size)); err != nil {
					t.Fatalf("UDP payload size %d: %v", size, err)
				}
			}
			expectedSource := ""
			if tc.outerHead {
				expectedSource = "198.51.100.28:32323"
			}
			if tc.innerProxy {
				expectedSource = "192.0.2.77:41414"
			}
			for range 4 {
				select {
				case r := <-requests:
					if r.UserID != user.ID || expectedSource != "" && r.Source != expectedSource {
						t.Fatalf("layered metadata lost: %+v, expected source %q", r, expectedSource)
					}
				case <-time.After(2 * time.Second):
					t.Fatal("missing authenticated TCP/UDP request")
				}
			}
			traffic := s.TrafficSnapshot()[user.ID]
			if traffic.Upload < uint64(len(payload)) || traffic.Download < uint64(len(payload)) {
				t.Fatalf("layered traffic bypassed meter: %+v", traffic)
			}
			before := accepts.Load()
			wrong := user
			wrong.UUID = "f1ab9d14-d9df-44e6-ae1f-24230bed553e"
			if err = roundTripTCP(makeClient(wrong), target, []byte("must-not-pass"), time.Second); err == nil {
				t.Fatal("outer tunnel authentication bypassed inner VLESS authentication")
			}
			if accepts.Load() != before {
				t.Fatal("wrong inner credential reached the destination")
			}
		})
	}
}
