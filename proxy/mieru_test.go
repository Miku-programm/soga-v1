package proxy

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	mclient "github.com/enfein/mieru/v3/apis/client"
	apicommon "github.com/enfein/mieru/v3/apis/common"
	"github.com/enfein/mieru/v3/apis/model"
	"github.com/enfein/mieru/v3/apis/trafficpattern"
	"github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	M "github.com/sagernet/sing/common/metadata"
	"google.golang.org/protobuf/proto"
)

type mieruTestClient struct {
	outbound.Adapter
	client mclient.Client
}

func newMieruTestClient(t *testing.T, cfg Config, user User) adapter.Outbound {
	return newMieruTestClientWithDialer(t, cfg, user, nil)
}

func newMieruTestClientWithDialer(t *testing.T, cfg Config, user User, dialer apicommon.Dialer) adapter.Outbound {
	t.Helper()
	c := mclient.NewClient()
	p := appctlpb.TransportProtocol_TCP
	if cfg.MieruTransport == "UDP" {
		p = appctlpb.TransportProtocol_UDP
	}
	var pattern *appctlpb.TrafficPattern
	if cfg.TrafficPattern != "" {
		var err error
		pattern, err = trafficpattern.Decode(cfg.TrafficPattern)
		if err != nil {
			t.Fatal(err)
		}
	}
	err := c.Store(&mclient.ClientConfig{Dialer: dialer, Profile: &appctlpb.ClientProfile{
		ProfileName:    proto.String("loopback-test"),
		TrafficPattern: pattern,
		User:           &appctlpb.User{Name: proto.String(user.Username), Password: proto.String(user.Password)},
		Servers: []*appctlpb.ServerEndpoint{{
			IpAddress:    proto.String("127.0.0.1"),
			PortBindings: []*appctlpb.PortBinding{{Port: proto.Int32(int32(cfg.Port)), Protocol: &p}},
		}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err = c.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Stop() })
	return &mieruTestClient{Adapter: outbound.NewAdapter("mieru", "test", []string{"tcp", "udp"}, nil), client: c}
}
func TestMieruUDPAndHintTrafficPattern(t *testing.T) {
	tcpTarget, _ := echoTCP(t)
	udpTarget := echoUDP(t)
	for _, transport := range []string{"TCP", "UDP"} {
		t.Run(transport, func(t *testing.T) {
			u := User{ID: 42, Username: "hint-user", Password: "pattern-password"}
			cfg := Config{Protocol: "mieru", Listen: "127.0.0.1", Port: freePort(t, transport == "UDP"), Users: []User{u}, MieruTransport: transport, MieruForceUserHint: true,
				TrafficPattern: trafficpattern.Encode(&appctlpb.TrafficPattern{Seed: proto.Int32(12345), Padding: &appctlpb.PaddingPattern{MaxMiddlePaddingLen: proto.Int32(32), MaxEndPaddingLen: proto.Int32(64)}})}
			s, err := Start(context.Background(), cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			out := client(t, cfg, u, nil)
			if err = roundTripTCP(out, tcpTarget, bytes.Repeat([]byte("pattern"), 1000), 5*time.Second); err != nil {
				t.Fatal(err)
			}
			if err = roundTripUDP(out, udpTarget, []byte("hint+pattern+udp")); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestMieruTCPListenerOptions(t *testing.T) {
	tcpTarget, _ := echoTCP(t)
	udpTarget := echoUDP(t)
	for _, mode := range []string{"mptcp", "tfo", "both"} {
		t.Run(mode, func(t *testing.T) {
			u := User{ID: 42, Username: "socket-user", Password: "socket-test-password"}
			cfg := Config{Protocol: "mieru", Listen: "127.0.0.1", Port: freePort(t, false),
				Users: []User{u}, MieruTransport: "TCP",
				TCPMultiPath: mode != "tfo", TCPFastOpen: mode != "mptcp"}
			s, err := Start(context.Background(), cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			out := client(t, cfg, u, nil)
			if err = roundTripTCP(out, tcpTarget, bytes.Repeat([]byte(mode), 1024), 5*time.Second); err != nil {
				t.Fatal(err)
			}
			if err = roundTripUDP(out, udpTarget, []byte("mieru-socket-options")); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func (c *mieruTestClient) DialContext(ctx context.Context, network string, dst M.Socksaddr) (net.Conn, error) {
	addr := model.NetAddrSpec{Net: network}
	if err := addr.AddrSpec.From(dst.String()); err != nil {
		return nil, err
	}
	return c.client.DialContext(ctx, addr)
}

func (c *mieruTestClient) ListenPacket(ctx context.Context, dst M.Socksaddr) (net.PacketConn, error) {
	stream, err := c.DialContext(ctx, "udp", dst)
	if err != nil {
		return nil, err
	}
	return apicommon.NewUDPAssociateWrapper(apicommon.NewPacketOverStreamTunnel(stream)), nil
}
