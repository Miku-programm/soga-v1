package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"testing"
	"time"

	"github.com/pires/go-proxyproto"
	"github.com/sagernet/sing-box/option"
	"reconstructed.local/soga/tunnel"
)

func tunnelRelay(t *testing.T, target string, cfg tunnel.Config, pp bool) uint16 {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p, err := net.ListenPacket("udp", l.Addr().String())
	if err != nil {
		_ = l.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close(); _ = p.Close() })
	go func() {
		for {
			incoming, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer incoming.Close()
				cl, err := tunnel.DialClient(context.Background(), target, cfg)
				if err != nil {
					return
				}
				defer cl.Close()
				conn, err := cl.Open(tunnel.TCP)
				if err != nil {
					return
				}
				defer conn.Close()
				if pp {
					_, _ = io.WriteString(conn, "PROXY TCP4 192.0.2.77 127.0.0.1 41414 443\r\n")
				}
				done := make(chan struct{})
				go func() { _, _ = io.Copy(conn, incoming); _ = conn.Close(); close(done) }()
				_, _ = io.Copy(incoming, conn)
				_ = incoming.Close()
				<-done
			}()
		}
	}()
	go func() {
		b := make([]byte, 65535)
		for {
			n, addr, err := p.ReadFrom(b)
			if err != nil {
				return
			}
			packet := append([]byte(nil), b[:n]...)
			go func() {
				cl, err := tunnel.DialClient(context.Background(), target, cfg)
				if err != nil {
					return
				}
				defer cl.Close()
				conn, err := cl.Open(tunnel.UDP)
				if err != nil {
					return
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				if pp {
					var framed bytes.Buffer
					h := proxyproto.HeaderProxyFromAddrs(2, &net.UDPAddr{IP: net.ParseIP("192.0.2.77"), Port: 41414}, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 443})
					_, _ = h.WriteTo(&framed)
					_, _ = framed.Write(packet)
					packet = framed.Bytes()
				}
				if _, err = conn.Write(packet); err != nil {
					return
				}
				reply := make([]byte, 65535)
				n, err = conn.Read(reply)
				if err != nil {
					return
				}
				_, _ = p.WriteTo(reply[:n], addr)
			}()
		}
	}()
	return uint16(l.Addr().(*net.TCPAddr).Port)
}

func TestTunnelFrontendAuthenticatedProtocols(t *testing.T) {
	destination, _ := echoTCP(t)
	udpTarget := echoUDP(t)
	outerServer, outerClient := tlsPair(t)
	cert, err := tls.X509KeyPair([]byte(outerServer.Certificate[0]), []byte(outerServer.Key[0]))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM([]byte(outerClient.Certificate[0]))
	for _, transport := range []string{"tcp", "ws-tls"} {
		for _, protocol := range []string{"vmess", "vless", "trojan", "anytls", "shadowsocks", "ssr"} {
			t.Run(transport+"/"+protocol, func(t *testing.T) {
				seen := make(chan Request, 10)
				user := User{ID: 42, UUID: testUUID, Password: "tunnel-real-protocol"}
				tc := tunnel.Config{Type: transport, Method: "aes-256-gcm", Password: "outer-tunnel-password", WSPath: "/pass", Mux: true, TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}}}
				cfg := Config{Protocol: protocol, Listen: "127.0.0.1", Port: freePort(t, false), Users: []User{user}, Tunnel: &tc,
					AllowPlaintextTLSProtocols: true,
					Hook:                       func(r Request) error { seen <- r; return nil }}
				var clientTLS *option.OutboundTLSOptions
				if protocol == "anytls" {
					cfg.TLS, clientTLS = tlsPair(t)
				}
				if protocol == "shadowsocks" {
					cfg.Method = "aes-128-gcm"
				}
				if protocol == "ssr" {
					cfg.Method = "aes-128-cfb"
					cfg.Password = "carrier"
					cfg.SSRProtocol = "auth_aes128_sha1"
					cfg.SSRSinglePortType = "protocol"
				}
				s, err := Start(context.Background(), cfg)
				if err != nil {
					t.Fatal(err)
				}
				defer s.Close()
				clientTunnel := tc
				clientTunnel.TLSConfig = &tls.Config{RootCAs: roots, ServerName: "localhost"}
				cc := cfg
				cc.Tunnel = nil
				cc.Port = tunnelRelay(t, s.Addr(), clientTunnel, true)
				out := client(t, cc, user, clientTLS)
				if err = roundTripTCP(out, destination, []byte("authenticated through recovered tunnel"), 5*time.Second); err != nil {
					t.Fatal(err)
				}
				if err = roundTripUDP(out, udpTarget, []byte("datagram through recovered tunnel")); err != nil {
					t.Fatal(err)
				}
				for range 2 {
					select {
					case r := <-seen:
						if r.Source != "192.0.2.77:41414" {
							t.Fatalf("source lost: %+v", r)
						}
					case <-time.After(2 * time.Second):
						t.Fatal("missing authenticated request")
					}
				}
				count := s.TrafficSnapshot()[42]
				if count.Upload == 0 || count.Download == 0 {
					t.Fatalf("traffic not accounted: %+v", count)
				}
				if err = s.UpdateUsers(nil); err != nil {
					t.Fatal(err)
				}
				if c, e := net.DialTimeout("tcp", s.Addr(), time.Second); e == nil {
					c.Close()
					t.Fatal("empty users left tunnel port open")
				}
			})
		}
	}
}

func TestTunnelFrontendInvalidConfig(t *testing.T) {
	cfg := Config{Protocol: "vmess", Listen: "127.0.0.1", Port: 443, Users: []User{{ID: 1, UUID: testUUID}}, Tunnel: &tunnel.Config{Type: "tcp", Method: "not-a-cipher", Password: "x"}}
	if err := ValidateConfig(cfg); err == nil {
		t.Fatal("invalid cipher accepted")
	}
	cfg.Tunnel.Method = "aes-128-gcm"
	cfg.Tunnel.Type = "quic"
	if err := ValidateConfig(cfg); err == nil {
		t.Fatal("unrecovered QUIC settings silently accepted")
	}
}

func TestTunnelUDPProxyHeaderPersistsAcrossDatagrams(t *testing.T) {
	target := echoUDP(t)
	tc := tunnel.Config{Type: "tcp", Method: "aes-192-gcm", Password: "session-password", Mux: true}
	seen := make(chan Request, 8)
	cfg := Config{Protocol: "shadowsocks", Method: "aes-128-gcm", Listen: "127.0.0.1", Port: freePort(t, false),
		Users: []User{{ID: 42, Password: "user-password"}}, Tunnel: &tc,
		Hook: func(r Request) error { seen <- r; return nil }}
	server, err := Start(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	cl, err := tunnel.DialClient(context.Background(), server.Addr(), tc)
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	session, err := cl.Open(tunnel.UDP)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	var header bytes.Buffer
	_, err = proxyproto.HeaderProxyFromAddrs(2,
		&net.UDPAddr{IP: net.ParseIP("192.0.2.88"), Port: 51515},
		&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: int(cfg.Port)}).WriteTo(&header)
	if err != nil {
		t.Fatal(err)
	}
	// The original session-level PROXY reader consumes its header once.
	// Send that header as its own logical datagram, with no SS payload.
	if _, err = session.Write(header.Bytes()); err != nil {
		t.Fatal(err)
	}
	relay, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		b := make([]byte, 65535)
		for {
			n, peer, err := relay.ReadFrom(b)
			if err != nil {
				return
			}
			if _, err = session.Write(b[:n]); err != nil {
				return
			}
			n, err = session.Read(b)
			if err != nil {
				return
			}
			if _, err = relay.WriteTo(b[:n], peer); err != nil {
				return
			}
		}
	}()
	defer func() { _ = relay.Close(); _ = session.Close(); <-done }()
	cc := cfg
	cc.Tunnel = nil
	cc.Port = uint16(relay.LocalAddr().(*net.UDPAddr).Port)
	out := client(t, cc, cfg.Users[0], nil)
	for _, payload := range []string{"first encrypted packet", "second packet without another source header"} {
		if err = roundTripUDP(out, target, []byte(payload)); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case request := <-seen:
		if request.Source != "192.0.2.88:51515" {
			t.Fatalf("session source lost: %+v", request)
		}
	case <-time.After(time.Second):
		t.Fatal("no authenticated UDP request")
	}
}
