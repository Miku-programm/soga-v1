package proxy

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	anytls "github.com/anytls/sing-anytls"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
)

func TestTransformPinsDestinationAndSelectsRealProxyOutbound(t *testing.T) {
	tcpDestination, _ := echoTCP(t)
	udpDestination := echoUDP(t)
	innerUser := User{ID: 43, UUID: "91c43637-0cdc-46c7-bb6c-cf1b09f52c2c"}
	innerConfig := Config{Protocol: "vless", Listen: "127.0.0.1", Port: freePort(t, false), Users: []User{innerUser}}
	inner, err := Start(context.Background(), innerConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer inner.Close()
	outerUser := User{ID: 42, UUID: testUUID}
	outerConfig := Config{Protocol: "vmess", Listen: "127.0.0.1", Port: freePort(t, false), Users: []User{outerUser},
		Outbounds: []option.Outbound{{
			Type: "vless", Tag: "via-inner", Options: &option.VLESSOutboundOptions{
				ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: innerConfig.Port},
				UUID:          innerUser.UUID,
			},
		}},
		Transform: func(_ context.Context, req Request) (Request, error) {
			req.Outbound = "via-inner"
			if req.Network == "tcp" {
				req.Destination = tcpDestination
			} else {
				req.Destination = udpDestination
			}
			return req, nil
		},
	}
	outer, err := Start(context.Background(), outerConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer outer.Close()
	out := client(t, outerConfig, outerUser, nil)
	if err = roundTripTCP(out, "must-not-resolve.invalid:1234", []byte("through-two-authenticated-servers"), 5*time.Second); err != nil {
		t.Fatal(err)
	}
	if err = roundTripUDP(out, "127.0.0.2:9", []byte("transformed-udp")); err != nil {
		t.Fatal(err)
	}
	if inner.TrafficSnapshot()[43].Upload == 0 || outer.TrafficSnapshot()[42].Upload == 0 {
		t.Fatal("selected outbound did not traverse both real protocol engines")
	}
}

func TestExplicitExternalTLSBackend(t *testing.T) {
	destination, _ := echoTCP(t)
	for _, protocol := range []string{"trojan", "anytls"} {
		t.Run(protocol, func(t *testing.T) {
			user := User{ID: 42, Password: "external-tls-test"}
			cfg := Config{Protocol: protocol, Listen: "127.0.0.1", Port: freePort(t, false),
				Users: []User{user}, AllowPlaintextTLSProtocols: true}
			s, err := Start(context.Background(), cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			var out adapter.Outbound
			if protocol == "anytls" {
				// The production sing-box outbound always requires TLS. Exercise
				// the explicit decrypted backend with its underlying official
				// protocol client and a plain dialer representing a TLS frontend.
				c, e := anytls.NewClient(context.Background(), anytls.ClientConfig{
					Password: user.Password, Logger: log.NewNOPFactory().Logger(),
					DialOut: func(ctx context.Context) (net.Conn, error) { return new(net.Dialer).DialContext(ctx, "tcp", s.Addr()) },
				})
				if e != nil {
					t.Fatal(e)
				}
				defer c.Close()
				out = &plainAnyTLSClient{Adapter: outbound.NewAdapter("anytls", "test", []string{"tcp"}, nil), client: c}
			} else {
				out = client(t, cfg, user, nil)
			}
			if err = roundTripTCP(out, destination, []byte("external-termination-backend"), 5*time.Second); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestWebsocketForwardedIPReachesPolicy(t *testing.T) {
	destination, _ := echoTCP(t)
	seen := make(chan Request, 1)
	user := User{ID: 42, UUID: testUUID}
	cfg := Config{Protocol: "vmess", Listen: "127.0.0.1", Port: freePort(t, false), Users: []User{user},
		Transport: &option.V2RayTransportOptions{Type: "ws", WebsocketOptions: option.V2RayWebsocketOptions{Path: "/forward"}},
		Hook:      func(r Request) error { seen <- r; return nil },
	}
	s, err := Start(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	cfg.Transport = &option.V2RayTransportOptions{Type: "ws", WebsocketOptions: option.V2RayWebsocketOptions{
		Path: "/forward", Headers: badoption.HTTPHeader{"X-Forwarded-For": []string{"192.0.2.123, 127.0.0.1"}},
	}}
	if err = roundTripTCP(client(t, cfg, user, nil), destination, []byte("forwarded-user"), time.Second); err != nil {
		t.Fatal(err)
	}
	select {
	case r := <-seen:
		host, _, err := net.SplitHostPort(r.Source)
		if err != nil || host != "192.0.2.123" {
			t.Fatalf("forwarded source missing: %+v", r)
		}
	case <-time.After(time.Second):
		t.Fatal("policy did not receive request")
	}
}

type plainAnyTLSClient struct {
	outbound.Adapter
	client *anytls.Client
}

func (c *plainAnyTLSClient) DialContext(ctx context.Context, _ string, dst M.Socksaddr) (net.Conn, error) {
	return c.client.CreateProxy(ctx, dst)
}
func (c *plainAnyTLSClient) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("unused in plain-backend TCP test")
}
