package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/sagernet/sing-box/option"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestProxyProtocolV1AuthenticatedSource(t *testing.T) {
	destination, _ := echoTCP(t)
	for _, name := range []string{"vmess", "vless", "trojan", "anytls", "shadowsocks", "ssr", "vless/http", "trojan/http"} {
		t.Run(name, func(t *testing.T) {
			protocol, transport, _ := strings.Cut(name, "/")
			seen := make(chan Request, 1)
			user := User{ID: 42, UUID: testUUID, Password: "pp-test"}
			cfg := Config{Protocol: protocol, Listen: "127.0.0.1", Port: freePort(t, false), Users: []User{user},
				ProxyProtocol: true, ForceProxyProtocol: true, AllowPlaintextTLSProtocols: true,
				Hook: func(r Request) error { seen <- r; return nil }}
			if protocol == "shadowsocks" {
				cfg.Method = "aes-128-gcm"
			}
			if protocol == "ssr" {
				cfg.Method = "aes-128-cfb"
				cfg.Password = "outer"
				cfg.SSRProtocol = "auth_aes128_sha1"
				cfg.SSRSinglePortType = "protocol"
			}
			var clientTLS *option.OutboundTLSOptions
			if protocol == "anytls" {
				cfg.TLS, clientTLS = tlsPair(t)
			}
			if transport == "http" {
				cfg.Transport = &option.V2RayTransportOptions{Type: "http", HTTPOptions: option.V2RayHTTPOptions{Path: "/test"}}
				cfg.TLS, clientTLS = tlsPair(t)
			}
			s, err := Start(context.Background(), cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			relay, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer relay.Close()
			go func() {
				for {
					incoming, err := relay.Accept()
					if err != nil {
						return
					}
					go func() {
						defer incoming.Close()
						target, err := net.Dial("tcp", s.Addr())
						if err != nil {
							return
						}
						defer target.Close()
						fmt.Fprintf(target, "PROXY TCP4 192.0.2.77 127.0.0.1 41414 %d\r\n", cfg.Port)
						go io.Copy(target, incoming)
						io.Copy(incoming, target)
					}()
				}
			}()
			clientCfg := cfg
			clientCfg.Port = uint16(relay.Addr().(*net.TCPAddr).Port)
			if err = roundTripTCP(client(t, clientCfg, user, clientTLS), destination, []byte("pp-real-protocol"), 3*time.Second); err != nil {
				t.Fatal(err)
			}
			select {
			case req := <-seen:
				if req.Source != "192.0.2.77:41414" {
					t.Fatalf("source not forwarded: %+v", req)
				}
			case <-time.After(time.Second):
				t.Fatal("no authenticated request")
			}
		})
	}
}

func TestTLSFallbackForDocumentedProtocols(t *testing.T) {
	target, _ := echoTCP(t)
	tlsServer, tlsClient := tlsPair(t)
	tlsServer.ALPN = []string{"http/1.1"}
	trust := x509.NewCertPool()
	trust.AppendCertsFromPEM([]byte(tlsServer.Certificate[0]))
	for _, protocol := range []string{"vless", "trojan", "vmess", "anytls"} {
		t.Run(protocol, func(t *testing.T) {
			cfg := Config{Protocol: protocol, Listen: "127.0.0.1", Port: freePort(t, false),
				Users: []User{{ID: 42, UUID: testUUID, Password: "fallback-test"}}, TLS: tlsServer, FallbackAddress: target}
			s, err := Start(context.Background(), cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			conn, err := tls.Dial("tcp", s.Addr(), &tls.Config{ServerName: "localhost", RootCAs: trust, NextProtos: []string{"http/1.1"}})
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(3 * time.Second))
			request := []byte("GET /fallback HTTP/1.1\r\nHost: localhost\r\nUser-Agent: loopback-fallback-verification\r\n\r\n")
			if _, err = conn.Write(request); err != nil {
				t.Fatal(err)
			}
			got := make([]byte, len(request))
			if _, err = io.ReadFull(conn, got); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, request) {
				t.Fatal("fallback corrupted HTTP bytes")
			}
			if len(s.TrafficSnapshot()) != 0 {
				t.Fatal("unauthenticated fallback charged to a user")
			}
			out := client(t, cfg, cfg.Users[0], tlsClient)
			for i := 0; i < 2; i++ {
				if err = roundTripTCP(out, target, []byte("authenticated alongside fallback"), time.Second); err != nil {
					t.Fatal(err)
				}
			}
			if err = roundTripUDP(out, echoUDP(t), []byte("authenticated UDP alongside fallback")); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestProxyProtocolOptionalAndRequiredDirect(t *testing.T) {
	target, accepts := echoTCP(t)
	for _, protocol := range []string{"vless", "anytls"} {
		for _, required := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/%t", protocol, required), func(t *testing.T) {
				user := User{ID: 42, UUID: testUUID, Password: "pp-direct"}
				cfg := Config{Protocol: protocol, Listen: "127.0.0.1", Port: freePort(t, false), Users: []User{user}, ProxyProtocol: true, ForceProxyProtocol: required}
				var clientTLS *option.OutboundTLSOptions
				if protocol == "anytls" {
					cfg.TLS, clientTLS = tlsPair(t)
				}
				s, err := Start(context.Background(), cfg)
				if err != nil {
					t.Fatal(err)
				}
				defer s.Close()
				before := accepts.Load()
				err = roundTripTCP(client(t, cfg, user, clientTLS), target, []byte("optional header direct connection"), time.Second)
				if !required && err != nil {
					t.Fatal(err)
				}
				if required && (err == nil || accepts.Load() != before) {
					t.Fatal("required PROXY header bypassed")
				}
			})
		}
	}
}
