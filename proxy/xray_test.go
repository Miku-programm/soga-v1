package proxy

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	M "github.com/sagernet/sing/common/metadata"
	_ "github.com/xtls/xray-core/app/dispatcher"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf"
)

type xrayTestClient struct {
	outbound.Adapter
	instance *core.Instance
}

func newXrayTestClient(t *testing.T, cfg Config, user User, encryption string, stream json.RawMessage) adapter.Outbound {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"log": map[string]any{"loglevel": "none"},
		"outbounds": []any{map[string]any{
			"protocol": "vless", "tag": "proxy",
			"settings":       map[string]any{"address": "127.0.0.1", "port": cfg.Port, "id": user.UUID, "encryption": encryption, "flow": cfg.Flow},
			"streamSettings": stream,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	var config conf.Config
	if err = json.Unmarshal(raw, &config); err != nil {
		t.Fatal(err)
	}
	built, err := config.Build()
	if err != nil {
		t.Fatal(err)
	}
	instance, err := core.New(built)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { instance.Close() })
	if err = instance.Start(); err != nil {
		t.Fatal(err)
	}
	return &xrayTestClient{Adapter: outbound.NewAdapter("vless", "test", []string{"tcp", "udp"}, nil), instance: instance}
}

func (c *xrayTestClient) DialContext(ctx context.Context, network string, dst M.Socksaddr) (net.Conn, error) {
	destination, err := xnet.ParseDestination(network + ":" + dst.String())
	if err != nil {
		return nil, err
	}
	return core.Dial(ctx, c.instance, destination)
}

func (c *xrayTestClient) ListenPacket(ctx context.Context, _ M.Socksaddr) (net.PacketConn, error) {
	return core.DialUDP(ctx, c.instance)
}

func jsonValue(t *testing.T, value any) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestXrayVLESSEncryptionAndXHTTP(t *testing.T) {
	tcpDestination, _ := echoTCP(t)
	udpDestination := echoUDP(t)
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	decryption := "mlkem768x25519plus.native.600s." + base64.RawURLEncoding.EncodeToString(key.Bytes())
	encryption := "mlkem768x25519plus.native.0rtt." + base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())
	for _, transport := range []string{"tcp", "xhttp"} {
		for _, encrypted := range []bool{false, true} {
			name := transport + "/plain"
			if encrypted {
				name = transport + "/encrypted"
			}
			t.Run(name, func(t *testing.T) {
				user := User{ID: 42, UUID: testUUID}
				stream := jsonValue(t, map[string]any{"network": transport, "security": "none",
					"xhttpSettings": map[string]any{"path": "/protocol-test", "mode": "auto"}})
				cfg := Config{Protocol: "vless", Listen: "127.0.0.1", Port: freePort(t, false), Users: []User{user}, XrayStream: stream, Decryption: "none"}
				clientEncryption := "none"
				if encrypted {
					cfg.Decryption, clientEncryption = decryption, encryption
				}
				s, err := Start(context.Background(), cfg)
				if err != nil {
					t.Fatal(err)
				}
				defer s.Close()
				out := newXrayTestClient(t, cfg, user, clientEncryption, stream)
				if err = roundTripTCP(out, tcpDestination, []byte("real-xray-vless-"+name), 5*time.Second); err != nil {
					t.Fatal(err)
				}
				if err = roundTripUDP(out, udpDestination, []byte("real-xray-udp-"+name)); err != nil {
					t.Fatal(err)
				}
				if s.TrafficSnapshot()[42].Upload == 0 || s.TrafficSnapshot()[42].Download == 0 {
					t.Fatal("Xray traffic bypassed user accounting")
				}
			})
		}
	}
}

func TestXrayVLESSRealityVision(t *testing.T) {
	destination, _ := echoTCP(t)
	udpDestination := echoUDP(t)
	serverTLS, _ := tlsPair(t)
	cert, err := tls.X509KeyPair([]byte(serverTLS.Certificate[0]), []byte(serverTLS.Key[0]))
	if err != nil {
		t.Fatal(err)
	}
	fallback, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13,
		NextProtos: []string{"h2", "http/1.1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer fallback.Close()
	go func() {
		for {
			c, err := fallback.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(io.Discard, c) }()
		}
	}()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	user := User{ID: 42, UUID: testUUID}
	cfg := Config{Protocol: "vless", Listen: "127.0.0.1", Port: freePort(t, false), Users: []User{user}, Flow: "xtls-rprx-vision",
		XrayStream: jsonValue(t, map[string]any{
			"network": "tcp", "security": "reality",
			"realitySettings": map[string]any{"dest": fallback.Addr().String(), "serverNames": []string{"localhost"},
				"privateKey": base64.RawURLEncoding.EncodeToString(key.Bytes()), "shortIds": []string{"1234567890abcdef"}},
		})}
	s, err := Start(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	clientStream := jsonValue(t, map[string]any{
		"network": "tcp", "security": "reality",
		"realitySettings": map[string]any{"serverName": "localhost", "fingerprint": "chrome",
			"publicKey": base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()), "shortId": "1234567890abcdef"},
	})
	out := newXrayTestClient(t, cfg, user, "none", clientStream)
	if err = roundTripTCP(out, destination, []byte("real-reality-vision"), 8*time.Second); err != nil {
		t.Fatal(err)
	}
	if s.TrafficSnapshot()[42].Upload == 0 {
		t.Fatal("REALITY bypassed accounting")
	}
	if err = roundTripUDP(out, udpDestination, []byte("reality-udp")); err != nil {
		t.Fatal(err)
	}
}
