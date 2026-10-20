package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pires/go-proxyproto"
	M "github.com/sagernet/sing/common/metadata"
	"reconstructed.local/soga/tunnel"
)

type mieruTunnelDialer struct {
	config tunnel.Config
	peer   string
	mu     sync.Mutex
	opened []*tunnel.Client
}

func (d *mieruTunnelDialer) DialContext(ctx context.Context, _, address string) (net.Conn, error) {
	client, err := tunnel.DialClient(ctx, address, d.config)
	if err != nil {
		return nil, err
	}
	d.mu.Lock()
	d.opened = append(d.opened, client)
	d.mu.Unlock()
	conn, err := client.Open(tunnel.TCP)
	if err != nil {
		return nil, err
	}
	if d.peer != "" {
		source := &net.TCPAddr{IP: net.ParseIP(d.peer), Port: 45678}
		_, err = proxyproto.HeaderProxyFromAddrs(2, source, conn.LocalAddr()).WriteTo(conn)
		if err != nil {
			_ = conn.Close()
			return nil, err
		}
	}
	return conn, nil
}

func (d *mieruTunnelDialer) close() {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, c := range d.opened {
		_ = c.Close()
	}
}

func TestMieruTunnelOfficialClient(t *testing.T) {
	inTLS, _ := tlsPair(t)
	pair, err := tls.X509KeyPair([]byte(strings.Join(inTLS.Certificate, "\n")), []byte(strings.Join(inTLS.Key, "\n")))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM([]byte(inTLS.Certificate[0]))
	tcpTarget, _ := echoTCP(t)
	udpTarget := echoUDP(t)
	for _, transport := range []string{"tcp", "tls", "ws", "ws-tls"} {
		for _, mux := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/mux=%t", transport, mux), func(t *testing.T) {
				tc := tunnel.Config{Type: transport, Method: "aes-128-gcm", Password: "tunnel-wire-password",
					WSPath: "/mieru", Mux: mux, TLSConfig: &tls.Config{Certificates: []tls.Certificate{pair}}}
				user := User{ID: 42, Username: "mieru-through-tunnel", Password: "inner-mieru-password"}
				cfg := Config{Protocol: "mieru", Listen: "127.0.0.1", Port: freePort(t, false), Users: []User{user},
					MieruTransport: "TCP", Tunnel: &tc, SubmitRealIP: true}
				s, err := Start(context.Background(), cfg)
				if err != nil {
					t.Fatal(err)
				}
				defer s.Close()
				clientTunnel := tc
				clientTunnel.TLSConfig = &tls.Config{RootCAs: roots, ServerName: "localhost"}
				dialer := &mieruTunnelDialer{config: clientTunnel, peer: "198.51.100.9"}
				defer dialer.close()
				client := newMieruTestClientWithDialer(t, cfg, user, dialer)
				payload := bytes.Repeat([]byte("mieru-tunnel"), 4096)
				if err = roundTripTCP(client, tcpTarget, payload, 5*time.Second); err != nil {
					t.Fatal(err)
				}
				if err = roundTripUDP(client, udpTarget, []byte("udp-associate-over-tunnel")); err != nil {
					t.Fatal(err)
				}
				open, err := client.DialContext(context.Background(), "tcp", M.ParseSocksaddr(tcpTarget))
				if err != nil {
					t.Fatal(err)
				}
				defer open.Close()
				_ = open.SetDeadline(time.Now().Add(5 * time.Second))
				if _, err = open.Write([]byte("keep-online")); err != nil {
					t.Fatal(err)
				}
				if _, err = io.ReadFull(open, make([]byte, len("keep-online"))); err != nil {
					t.Fatal(err)
				}
				if !slices.Contains(s.OnlineSnapshot()[42], "198.51.100.9") {
					t.Fatalf("real source lost: %v", s.OnlineSnapshot())
				}
				traffic := s.TrafficSnapshot()[42]
				if traffic.Upload < uint64(len(payload)) || traffic.Download < uint64(len(payload)) {
					t.Fatalf("missing tunnel accounting: %+v", traffic)
				}
				if transport == "tcp" && !mux {
					bad := user
					bad.Password = "incorrect-inner-password"
					wrong := newMieruTestClientWithDialer(t, cfg, bad, dialer)
					if roundTripTCP(wrong, tcpTarget, []byte("must-fail"), 150*time.Millisecond) == nil {
						t.Fatal("wrong inner credentials accepted")
					}
				}
				if err = s.UpdateUsers(nil); err != nil {
					t.Fatal(err)
				}
				_ = open.SetDeadline(time.Now().Add(time.Second))
				if _, err = open.Read(make([]byte, 1)); err == nil {
					t.Fatal("revoked Mieru connection stayed open")
				}
				if probe, err := net.DialTimeout("tcp", net.JoinHostPort(cfg.Listen, fmt.Sprint(cfg.Port)), time.Second); err == nil {
					_ = probe.Close()
					t.Fatal("empty-user tunnel listener stayed open")
				}
			})
		}
	}
}

func TestMieruTunnelIdlePeerDoesNotBlock(t *testing.T) {
	tc := tunnel.Config{Type: "tcp", Method: "aes-128-gcm", Password: "tunnel-idle-peer"}
	user := User{ID: 42, Username: "parallel-mieru", Password: "inner-password"}
	cfg := Config{Protocol: "mieru", Listen: "127.0.0.1", Port: freePort(t, false),
		Users: []User{user}, MieruTransport: "TCP", Tunnel: &tc}
	s, err := Start(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	idle, err := tunnel.DialClient(context.Background(), s.Addr(), tc)
	if err != nil {
		t.Fatal(err)
	}
	defer idle.Close()
	if _, err = idle.Open(tunnel.TCP); err != nil {
		t.Fatal(err)
	}
	// Let the idle authenticated peer reach the optional PROXY header reader.
	time.Sleep(30 * time.Millisecond)
	dialer := &mieruTunnelDialer{config: tc}
	defer dialer.close()
	client := newMieruTestClientWithDialer(t, cfg, user, dialer)
	target, _ := echoTCP(t)
	if err = roundTripTCP(client, target, []byte("without-proxy-header"), time.Second); err != nil {
		t.Fatalf("idle peer blocked another authenticated session: %v", err)
	}
}
