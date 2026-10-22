package proxy

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

func echoOnce(t *testing.T, c net.PacketConn, target net.Addr, payload string) error {
	t.Helper()
	if _, err := c.WriteTo([]byte(payload), target); err != nil {
		return err
	}
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	b := make([]byte, 4096)
	n, _, err := c.ReadFrom(b)
	if err != nil {
		return err
	}
	if string(b[:n]) != payload {
		return errors.New("unexpected echo " + string(b[:n]))
	}
	return nil
}

func TestUDPDecisionReusedForLaterPackets(t *testing.T) {
	var calls atomic.Int32
	u := User{ID: 42, UUID: testUUID, Username: "udp-decision", Password: "udp-decision-key"}
	cfg := Config{Protocol: "shadowsocks", Listen: "127.0.0.1", Port: freePort(t, false), Users: []User{u}, Method: "aes-128-gcm",
		Transform: func(_ context.Context, r Request) (Request, error) {
			if r.Network == "udp" {
				calls.Add(1)
			}
			return r, nil
		}}
	target := echoUDP(t)
	s, err := Start(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	c, err := client(t, cfg, u, nil).ListenPacket(context.Background(), M.ParseSocksaddr(target))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	addr, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		t.Fatal(err)
	}
	const packets = 20
	for i := 0; i < packets; i++ {
		if err := echoOnce(t, c, addr, "ping"); err != nil {
			t.Fatalf("packet %d: %v", i, err)
		}
	}
	// One decision for the association and one for its first packet; later
	// packets to the same destination reuse the cached decision.
	if got := calls.Load(); got > 3 {
		t.Fatalf("transform ran %d times for %d packets to one destination", got, packets)
	}
}

func TestUDPPacketCheckRunsOnReusedDecision(t *testing.T) {
	denied := make(chan struct{}, 4)
	u := User{ID: 43, UUID: testUUID, Username: "udp-packet-check", Password: "udp-packet-check-key"}
	cfg := Config{Protocol: "shadowsocks", Listen: "127.0.0.1", Port: freePort(t, false), Users: []User{u}, Method: "aes-128-gcm",
		DetectPacketMaxLen: 64,
		Transform: func(_ context.Context, r Request) (Request, error) {
			r.PacketCheck = func(packet []byte) error {
				if bytes.Contains(packet, []byte("forbidden")) {
					select {
					case denied <- struct{}{}:
					default:
					}
					return errors.New("test payload denied")
				}
				return nil
			}
			return r, nil
		}}
	target := echoUDP(t)
	s, err := Start(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	c, err := client(t, cfg, u, nil).ListenPacket(context.Background(), M.ParseSocksaddr(target))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	addr, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := echoOnce(t, c, addr, "allowed"); err != nil {
			t.Fatalf("allowed packet %d: %v", i, err)
		}
	}
	if _, err := c.WriteTo([]byte("forbidden payload"), addr); err != nil {
		t.Fatal(err)
	}
	select {
	case <-denied:
	case <-time.After(2 * time.Second):
		t.Fatal("reused UDP decision skipped the payload check")
	}
	_ = c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	b := make([]byte, 4096)
	if n, _, err := c.ReadFrom(b); err == nil && string(b[:n]) == "forbidden payload" {
		t.Fatal("denied payload reached the target")
	}
}
