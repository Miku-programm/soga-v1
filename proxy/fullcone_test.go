package proxy

import (
	"context"
	"errors"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	"net"
	"strings"
	"testing"
	"time"
)

func TestUDPFullConeUnsolicitedSource(t *testing.T) {
	serverTLS, clientTLS := tlsPair(t)
	for _, protocol := range Protocols() {
		t.Run(protocol, func(t *testing.T) {
			u := User{ID: 42, UUID: testUUID, Username: "udp-user", Password: "full-cone-key"}
			cfg := Config{Protocol: protocol, Listen: "127.0.0.1", Port: freePort(t, strings.HasPrefix(protocol, "hysteria")), Users: []User{u}, Method: "aes-128-gcm", UpMbps: 100, DownMbps: 100}
			if protocol == "ssr" {
				cfg.Method = "aes-128-cfb"
				cfg.Password = "outer"
				cfg.SSRProtocol = "auth_chain_a"
				cfg.SSRSinglePortType = "protocol"
			}
			var tls *option.OutboundTLSOptions
			if protocol == "trojan" || protocol == "anytls" || strings.HasPrefix(protocol, "hysteria") {
				cfg.TLS = serverTLS
				tls = clientTLS
			}
			s, err := Start(context.Background(), cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			target, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer target.Close()
			target.SetDeadline(time.Now().Add(3 * time.Second))
			encoding := ""
			if protocol == "vmess" {
				encoding = "packetaddr"
			}
			c, err := client(t, cfg, u, tls, encoding).ListenPacket(context.Background(), M.ParseSocksaddr(target.LocalAddr().String()))
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			timer := time.AfterFunc(3*time.Second, func() { c.Close() })
			defer timer.Stop()
			if _, err = c.WriteTo([]byte("open mapping"), target.LocalAddr()); err != nil {
				t.Fatal(err)
			}
			b := make([]byte, 65535)
			_, proxyAddr, err := target.ReadFrom(b)
			if err != nil {
				t.Fatal(err)
			}
			third, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer third.Close()
			if _, err = third.WriteTo([]byte("third-party-reply"), proxyAddr); err != nil {
				t.Fatal(err)
			}
			n, src, err := c.ReadFrom(b)
			if err != nil {
				t.Fatal("unsolicited UDP source rejected", err)
			}
			if string(b[:n]) != "third-party-reply" || src.String() != third.LocalAddr().String() {
				t.Fatalf("wrong full-cone response %q from %v expected %v", b[:n], src, third.LocalAddr())
			}
			second, _ := net.ResolveUDPAddr("udp", echoUDP(t))
			if _, err = c.WriteTo([]byte("second-destination"), second); err != nil {
				t.Fatal(err)
			}
			n, src, err = c.ReadFrom(b)
			if err != nil || string(b[:n]) != "second-destination" || src.String() != second.String() {
				t.Fatalf("association could not switch destination: %q %v %v", b[:n], src, err)
			}
		})
	}
}

func TestUDPSecondDestinationMustPassPolicy(t *testing.T) {
	serverTLS, clientTLS := tlsPair(t)
	for _, protocol := range Protocols() {
		for _, stage := range []string{"hook", "transform"} {
			t.Run(protocol+"/"+stage, func(t *testing.T) {
				blocked, err := net.ListenPacket("udp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer blocked.Close()
				denied := make(chan struct{}, 4)
				check := func(r Request) error {
					if r.Destination == blocked.LocalAddr().String() {
						select {
						case denied <- struct{}{}:
						default:
						}
						return errors.New("test destination denied")
					}
					return nil
				}
				u := User{ID: 42, UUID: testUUID, Username: "udp-user", Password: "udp-policy-key"}
				cfg := Config{Protocol: protocol, Listen: "127.0.0.1", Port: freePort(t, strings.HasPrefix(protocol, "hysteria")), Users: []User{u}, Method: "aes-128-gcm", UpMbps: 100, DownMbps: 100}
				if stage == "hook" {
					cfg.Hook = check
				} else {
					cfg.Transform = func(_ context.Context, r Request) (Request, error) { return r, check(r) }
				}
				if protocol == "ssr" {
					cfg.Method = "aes-128-cfb"
					cfg.Password = "outer"
					cfg.SSRProtocol = "auth_chain_a"
					cfg.SSRSinglePortType = "protocol"
				}
				var clientTLSOptions *option.OutboundTLSOptions
				if protocol == "trojan" || protocol == "anytls" || strings.HasPrefix(protocol, "hysteria") {
					cfg.TLS = serverTLS
					clientTLSOptions = clientTLS
				}
				s, err := Start(context.Background(), cfg)
				if err != nil {
					t.Fatal(err)
				}
				defer s.Close()
				allowed, _ := net.ResolveUDPAddr("udp", echoUDP(t))
				encoding := ""
				if protocol == "vmess" {
					encoding = "packetaddr"
				}
				c, err := client(t, cfg, u, clientTLSOptions, encoding).ListenPacket(context.Background(), M.ParseSocksaddr(allowed.String()))
				if err != nil {
					t.Fatal(err)
				}
				defer c.Close()
				timer := time.AfterFunc(3*time.Second, func() { c.Close() })
				defer timer.Stop()
				if _, err = c.WriteTo([]byte("allowed"), allowed); err != nil {
					t.Fatal(err)
				}
				b := make([]byte, 4096)
				if n, _, e := c.ReadFrom(b); e != nil || string(b[:n]) != "allowed" {
					t.Fatalf("first target: %q %v", b[:n], e)
				}
				if _, err = c.WriteTo([]byte("must-not-arrive"), blocked.LocalAddr()); err != nil {
					t.Fatal(err)
				}
				select {
				case <-denied:
				case <-time.After(time.Second):
					t.Fatal("second target skipped policy")
				}
				blocked.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
				if n, _, e := blocked.ReadFrom(b); e == nil {
					t.Fatalf("denied target received %q", b[:n])
				} else if ne, ok := e.(net.Error); !ok || !ne.Timeout() {
					t.Fatal(e)
				}
			})
		}
	}
}
