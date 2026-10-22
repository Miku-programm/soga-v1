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

	M "github.com/sagernet/sing/common/metadata"
)

// startReality runs a VLESS Reality + Vision listener for the given users and
// returns the client stream settings that reach it.
func startReality(t *testing.T, users []User) (Config, json.RawMessage, *Server) {
	t.Helper()
	serverTLS, _ := tlsPair(t)
	cert, err := tls.X509KeyPair([]byte(serverTLS.Certificate[0]), []byte(serverTLS.Key[0]))
	if err != nil {
		t.Fatal(err)
	}
	dest, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13, NextProtos: []string{"h2", "http/1.1"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dest.Close() })
	go func() {
		for {
			c, err := dest.Accept()
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
	cfg := Config{Protocol: "vless", Listen: "127.0.0.1", Port: freePort(t, false), Users: users, Flow: "xtls-rprx-vision",
		XrayStream: jsonValue(t, map[string]any{
			"network": "tcp", "security": "reality",
			"realitySettings": map[string]any{"dest": dest.Addr().String(), "serverNames": []string{"localhost"},
				"privateKey": base64.RawURLEncoding.EncodeToString(key.Bytes()), "shortIds": []string{"1234567890abcdef"}},
		})}
	s, err := Start(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	clientStream := jsonValue(t, map[string]any{
		"network": "tcp", "security": "reality",
		"realitySettings": map[string]any{"serverName": "localhost", "fingerprint": "chrome",
			"publicKey": base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()), "shortId": "1234567890abcdef"},
	})
	return cfg, clientStream, s
}

// A panel user update must not restart the Xray core: Reality sessions of
// unchanged users keep flowing, removed users are cut, new users get in.
func TestXrayLiveUserUpdateKeepsRealitySessions(t *testing.T) {
	destination, _ := echoTCP(t)
	keep := User{ID: 42, UUID: testUUID}
	gone := User{ID: 43, UUID: "91c43637-0cdc-46c7-bb6c-cf1b09f52c2c"}
	cfg, clientStream, s := startReality(t, []User{keep, gone})
	before := s.box
	open := func(u User) net.Conn {
		// core.Dial binds the connection to ctx, so it must outlive the session.
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		c, err := newXrayTestClient(t, cfg, u, "none", clientStream).DialContext(ctx, "tcp", M.ParseSocksaddr(destination))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		return c
	}
	echo := func(c net.Conn, payload string) error {
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := c.Write([]byte(payload)); err != nil {
			return err
		}
		_, err := io.ReadFull(c, make([]byte, len(payload)))
		return err
	}
	kept, dropped := open(keep), open(gone)
	for i, c := range []net.Conn{kept, dropped} {
		if err := echo(c, "reality-before"); err != nil {
			t.Fatalf("session %d before update: %v", i, err)
		}
	}
	added := User{ID: 44, UUID: "0f0e0d0c-0b0a-4908-8706-050403020100"}
	if err := s.UpdateUsers([]User{keep, added}); err != nil {
		t.Fatal(err)
	}
	if s.box != before {
		t.Fatal("user update restarted the Xray core")
	}
	if err := echo(kept, "reality-after"); err != nil {
		t.Fatal("unchanged user's Reality session was cut:", err)
	}
	_ = dropped.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := dropped.Write([]byte("gone")); err == nil {
		if _, err = io.ReadFull(dropped, make([]byte, 4)); err == nil {
			t.Fatal("removed user's session survived the update")
		}
	}
	if err := roundTripTCP(newXrayTestClient(t, cfg, gone, "none", clientStream), destination, []byte("revoked"), 3*time.Second); err == nil {
		t.Fatal("removed user can still authenticate")
	}
	if err := roundTripTCP(newXrayTestClient(t, cfg, added, "none", clientStream), destination, []byte("welcome"), 8*time.Second); err != nil {
		t.Fatal("added user rejected:", err)
	}
}

// The core's idle policy must follow tcp_timeout instead of its 300 s default.
func TestXrayPolicyFollowsTCPTimeout(t *testing.T) {
	timeouts := xrayPolicy(7200).Level[0].Timeout
	if timeouts.ConnectionIdle.Value != 7200 || timeouts.Handshake.Value != xrayHandshakeSeconds ||
		timeouts.UplinkOnly.Value != xrayUplinkDrainSeconds || timeouts.DownlinkOnly.Value != xrayDownlinkDrainSeconds {
		t.Fatalf("policy = %+v", timeouts)
	}
	if got := xrayPolicy(0).Level[0].Timeout.ConnectionIdle.Value; got != xrayIdleFallback {
		t.Fatalf("unset tcp timeout gave idle %d", got)
	}
}
