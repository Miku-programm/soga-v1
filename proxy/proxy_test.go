package proxy

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	"reconstructed.local/soga/proxy/ssrcore"
)

const testUUID = "c5b179a5-fc32-4efa-85de-4667252ded44"

func tlsPair(t *testing.T) (*option.InboundTLSOptions, *option.OutboundTLSOptions) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"},
		DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	k, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	cert := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: k}))
	return &option.InboundTLSOptions{Enabled: true, Certificate: []string{cert}, Key: []string{keyPEM}},
		&option.OutboundTLSOptions{Enabled: true, ServerName: "localhost", Certificate: []string{cert}}
}

func freePort(t *testing.T, udp bool) uint16 {
	t.Helper()
	if udp {
		p, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := p.LocalAddr().(*net.UDPAddr).Port
		p.Close()
		return uint16(port)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return uint16(port)
}

func echoTCP(t *testing.T) (string, *atomic.Int64) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	count := new(atomic.Int64)
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			count.Add(1)
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	return l.Addr().String(), count
}

func echoUDP(t *testing.T) string {
	t.Helper()
	p, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.Close() })
	go func() {
		b := make([]byte, 65536)
		for {
			n, addr, err := p.ReadFrom(b)
			if err != nil {
				return
			}
			_, _ = p.WriteTo(b[:n], addr)
		}
	}()
	return p.LocalAddr().String()
}

func client(t *testing.T, cfg Config, user User, tls *option.OutboundTLSOptions, packetEncoding ...string) adapter.Outbound {
	t.Helper()
	if cfg.Protocol == "mieru" {
		return newMieruTestClient(t, cfg, user)
	}
	server := option.ServerOptions{Server: "127.0.0.1", ServerPort: cfg.Port}
	tlsContainer := option.OutboundTLSOptionsContainer{TLS: tls}
	var opts any
	switch cfg.Protocol {
	case "ssr":
		opts = &ssrcore.OutboundOptions{Server: "127.0.0.1", ServerPort: cfg.Port, Method: cfg.Method, Password: cfg.Password, Protocol: cfg.SSRProtocol, Obfs: cfg.SSRObfs, ObfsParam: cfg.SSRObfsParam, ProtocolParam: fmt.Sprintf("%d:%s", user.ID, user.Password)}
	case "vmess":
		o := &option.VMessOutboundOptions{ServerOptions: server, UUID: user.UUID, AlterId: user.AlterID, Security: "aes-128-gcm", OutboundTLSOptionsContainer: tlsContainer, Transport: cfg.Transport}
		if len(packetEncoding) > 0 {
			o.PacketEncoding = packetEncoding[0]
		}
		opts = o
	case "vless":
		opts = &option.VLESSOutboundOptions{ServerOptions: server, UUID: user.UUID, Flow: cfg.Flow, OutboundTLSOptionsContainer: tlsContainer, Transport: cfg.Transport}
	case "trojan":
		opts = &option.TrojanOutboundOptions{ServerOptions: server, Password: user.Password, OutboundTLSOptionsContainer: tlsContainer, Transport: cfg.Transport}
	case "shadowsocks":
		password := user.Password
		if strings.HasPrefix(cfg.Method, "2022-") {
			password = cfg.Password + ":" + password
		}
		o := &option.ShadowsocksOutboundOptions{ServerOptions: server, Method: cfg.Method, Password: password}
		if cfg.SSObfs != "" && cfg.SSObfs != "plain" {
			mode := strings.TrimPrefix(cfg.SSObfs, "simple_obfs_")
			o.Plugin = "obfs-local"
			o.PluginOptions = "obfs=" + mode + ";obfs-host=" + cfg.SSHost
		}
		opts = o
	case "anytls":
		opts = &option.AnyTLSOutboundOptions{ServerOptions: server, Password: user.Password, OutboundTLSOptionsContainer: tlsContainer}
	case "hysteria":
		opts = &option.HysteriaOutboundOptions{ServerOptions: server, AuthString: user.Password, UpMbps: cfg.UpMbps, DownMbps: cfg.DownMbps, Obfs: cfg.ObfsPassword, OutboundTLSOptionsContainer: tlsContainer}
	case "hysteria2":
		o := &option.Hysteria2OutboundOptions{ServerOptions: server, Password: user.Password, OutboundTLSOptionsContainer: tlsContainer}
		if cfg.ObfsPassword != "" {
			o.Obfs = &option.Hysteria2Obfs{Type: "salamander", Password: cfg.ObfsPassword}
		}
		opts = o
	default:
		t.Fatalf("no test client for %s", cfg.Protocol)
	}
	ctx := protocolContext(context.Background(), newMeter(), nil, nil, NewLimiter(), "", 0)
	b, err := box.New(box.Options{Context: ctx, Options: option.Options{
		Log:       &option.LogOptions{Disabled: true},
		Outbounds: []option.Outbound{{Type: cfg.Protocol, Tag: "client", Options: opts}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { b.Close() })
	if err = b.Start(); err != nil {
		t.Fatal(err)
	}
	o, ok := b.Outbound().Outbound("client")
	if !ok {
		t.Fatal("client outbound missing")
	}
	return o
}

func roundTripTCP(out adapter.Outbound, destination string, payload []byte, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	c, err := out.DialContext(ctx, "tcp", M.ParseSocksaddr(destination))
	if err != nil {
		return err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(timeout))
	if _, err = c.Write(payload); err != nil {
		return err
	}
	got := make([]byte, len(payload))
	if _, err = io.ReadFull(c, got); err != nil {
		return err
	}
	if !bytes.Equal(got, payload) {
		return errors.New("payload mismatch")
	}
	return nil
}

func roundTripUDP(out adapter.Outbound, destination string, payload []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	dst, err := net.ResolveUDPAddr("udp", destination)
	if err != nil {
		return err
	}
	c, err := out.ListenPacket(ctx, M.ParseSocksaddr(destination))
	if err != nil {
		return err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err = c.WriteTo(payload, dst); err != nil {
		return err
	}
	// Some encrypted PacketConn clients decrypt in the caller's buffer; it
	// therefore must hold framing/salt/authentication bytes as well as payload.
	b := make([]byte, 65535)
	n, _, err := c.ReadFrom(b)
	if err != nil {
		return err
	}
	if !bytes.Equal(payload, b[:n]) {
		return errors.New("UDP payload mismatch")
	}
	return nil
}

func TestProtocolsAuthenticateAndRelayTCPUDP(t *testing.T) {
	tcpDestination, targetConnections := echoTCP(t)
	udpDestination := echoUDP(t)
	serverTLS, clientTLS := tlsPair(t)
	for _, protocol := range Protocols() {
		t.Run(protocol, func(t *testing.T) {
			user := User{ID: 42, UUID: testUUID, Username: "test-user", Password: "test-password-never-deploy"}
			cfg := Config{Protocol: protocol, Listen: "127.0.0.1", Port: freePort(t, strings.HasPrefix(protocol, "hysteria")),
				Users: []User{user}, Method: "aes-128-gcm", UpMbps: 100, DownMbps: 100}
			if protocol == "ssr" {
				cfg.Method, cfg.Password, cfg.SSRProtocol, cfg.SSRSinglePortType = "aes-128-cfb", "outer-password", "auth_aes128_sha1", "protocol"
			}
			var outboundTLS *option.OutboundTLSOptions
			if protocol == "trojan" || protocol == "anytls" || strings.HasPrefix(protocol, "hysteria") {
				cfg.TLS, outboundTLS = serverTLS, clientTLS
			}
			s, err := Start(context.Background(), cfg)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { s.Close() })
			out := client(t, cfg, user, outboundTLS)
			payload := bytes.Repeat([]byte("real-protocol-payload-"), 100)
			if err = roundTripTCP(out, tcpDestination, payload, 5*time.Second); err != nil {
				t.Fatalf("TCP: %v", err)
			}
			if err = roundTripUDP(out, udpDestination, payload[:100]); err != nil {
				t.Fatalf("UDP: %v", err)
			}
			stats := s.TrafficSnapshot()[42]
			if stats.Upload < uint64(len(payload)+100) || stats.Download < uint64(len(payload)+100) {
				t.Fatalf("authenticated traffic missing: %+v", stats)
			}
			before := targetConnections.Load()
			badUser := user
			badUser.UUID = "91c43637-0cdc-46c7-bb6c-cf1b09f52c2c"
			badUser.Password = "incorrect-password"
			if err = roundTripTCP(client(t, cfg, badUser, outboundTLS), tcpDestination, []byte("must fail"), time.Second); err == nil {
				t.Fatal("incorrect credentials relayed traffic")
			}
			if targetConnections.Load() != before {
				t.Fatal("incorrect credentials reached target")
			}
		})
	}
}

func TestUsersUpdateRevokesOldCredentialsAndKeepsCounters(t *testing.T) {
	destination, _ := echoTCP(t)
	first := User{ID: 42, UUID: testUUID}
	cfg := Config{Protocol: "vmess", Listen: "127.0.0.1", Port: freePort(t, false), Users: []User{first}}
	s, err := Start(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	out := client(t, cfg, first, nil)
	if err = roundTripTCP(out, destination, []byte("before"), 3*time.Second); err != nil {
		t.Fatal(err)
	}
	before := s.TrafficSnapshot()[42]
	second := User{ID: 43, UUID: "91c43637-0cdc-46c7-bb6c-cf1b09f52c2c"}
	if err = s.UpdateUsers([]User{second}); err != nil {
		t.Fatal(err)
	}
	if err = roundTripTCP(out, destination, []byte("revoked"), time.Second); err == nil {
		t.Fatal("revoked credentials worked")
	}
	if err = roundTripTCP(client(t, cfg, second, nil), destination, []byte("after"), 3*time.Second); err != nil {
		t.Fatal(err)
	}
	if s.TrafficSnapshot()[42] != before {
		t.Fatal("old counters changed during update/rejected auth")
	}
	if err = s.UpdateUsers(nil); err != nil {
		t.Fatal(err)
	}
	conn, err := net.DialTimeout("tcp", s.Addr(), time.Second)
	if err == nil {
		conn.Close()
		t.Fatal("zero users must close listener")
	}
}

func TestHookRejectsBeforeTargetDial(t *testing.T) {
	destination, connections := echoTCP(t)
	user := User{ID: 42, UUID: testUUID}
	called := make(chan Request, 1)
	cfg := Config{Protocol: "vless", Listen: "127.0.0.1", Port: freePort(t, false), Users: []User{user},
		Hook: func(r Request) error { called <- r; return errors.New("test deny") }}
	s, err := Start(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	err = roundTripTCP(client(t, cfg, user, nil), destination, []byte("denied"), time.Second)
	if err == nil {
		t.Fatal("denied request succeeded")
	}
	select {
	case r := <-called:
		if r.UserID != 42 || r.Network != "tcp" || r.Destination != destination {
			t.Fatalf("wrong policy metadata: %+v", r)
		}
	case <-time.After(time.Second):
		t.Fatal("policy hook was not called")
	}
	if connections.Load() != 0 {
		t.Fatal("denied target was dialed")
	}
}

func TestOnlineIPsTrackActiveAuthenticatedConnections(t *testing.T) {
	destination, _ := echoTCP(t)
	user := User{ID: 42, UUID: testUUID}
	cfg := Config{Protocol: "vless", Listen: "127.0.0.1", Port: freePort(t, false), Users: []User{user}}
	s, err := Start(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	c, err := client(t, cfg, user, nil).DialContext(context.Background(), "tcp", M.ParseSocksaddr(destination))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err = c.Write([]byte("online")); err != nil {
		t.Fatal(err)
	}
	if _, err = io.ReadFull(c, make([]byte, 6)); err != nil {
		t.Fatal(err)
	}
	if got := s.OnlineSnapshot()[42]; len(got) != 1 || got[0] != "127.0.0.1" {
		t.Fatalf("online IP: %v", got)
	}
	c.Close()
	deadline := time.Now().Add(3 * time.Second)
	for len(s.OnlineSnapshot()[42]) != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond * 10)
	}
	if len(s.OnlineSnapshot()) != 0 {
		t.Fatal("online IP remained after disconnect")
	}
}

func TestVMessVLESSTrojanTransports(t *testing.T) {
	destination, _ := echoTCP(t)
	serverTLS, clientTLS := tlsPair(t)
	for _, protocol := range []string{"vmess", "vless", "trojan"} {
		for _, transport := range []string{"ws", "http", "grpc"} {
			t.Run(protocol+"/"+transport, func(t *testing.T) {
				user := User{ID: 42, UUID: testUUID, Password: "transport-test-password"}
				tr := &option.V2RayTransportOptions{Type: transport,
					WebsocketOptions: option.V2RayWebsocketOptions{Path: "/test"},
					HTTPOptions:      option.V2RayHTTPOptions{Path: "/test"},
					GRPCOptions:      option.V2RayGRPCOptions{ServiceName: "test"},
				}
				cfg := Config{Protocol: protocol, Listen: "127.0.0.1", Port: freePort(t, false), Users: []User{user}, Transport: tr, TLS: serverTLS}
				s, err := Start(context.Background(), cfg)
				if err != nil {
					t.Fatal(err)
				}
				defer s.Close()
				if err = roundTripTCP(client(t, cfg, user, clientTLS), destination, []byte("transport-"+protocol+"-"+transport), 5*time.Second); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestInvalidConfigurationFailsClosed(t *testing.T) {
	for _, protocol := range []string{"fake", "not-a-protocol"} {
		_, err := Start(context.Background(), Config{Protocol: protocol, Listen: "127.0.0.1", Port: 1})
		if err == nil {
			t.Fatalf("unsupported %s accepted", protocol)
		}
	}
}
