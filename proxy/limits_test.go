package proxy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

func TestExternalAdmissionAndRelease(t *testing.T) {
	target, accepts := echoTCP(t)
	var acquired, released atomic.Int64
	var deny atomic.Bool
	user := User{ID: 42, UUID: testUUID, DeviceLimit: 2, IPLimit: 3}
	cfg := Config{Protocol: "vless", Listen: "127.0.0.1", Port: freePort(t, false), Users: []User{user},
		GlobalAdmission: func(ctx context.Context, a AdmissionRequest) (func(), error) {
			if a.UserID != 42 || a.IP != "127.0.0.1" || a.DeviceID != "ip:127.0.0.1" || a.IPLimit != 3 || a.DeviceLimit != 2 {
				t.Errorf("wrong external identity: %+v", a)
			}
			if deny.Load() {
				return nil, errors.New("quota")
			}
			acquired.Add(1)
			return func() { released.Add(1) }, nil
		}}
	s, err := Start(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	out := client(t, cfg, user, nil)
	if err = roundTripTCP(out, target, []byte("global admission"), time.Second); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for released.Load() != 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if acquired.Load() != 1 || released.Load() != 1 {
		t.Fatal("external slot not released exactly once")
	}
	deny.Store(true)
	before := accepts.Load()
	if err = roundTripTCP(out, target, []byte("deny"), time.Second); err == nil || accepts.Load() != before {
		t.Fatal("global quota bypass")
	}
}

func TestCIDAndIPLimitsAreIndependent(t *testing.T) {
	l := NewLimiter()
	if err := l.SetUserLimits(User{ID: 42, DeviceLimit: 1, IPLimit: 2}); err != nil {
		t.Fatal(err)
	}
	one := Request{UserID: 42, Source: "192.0.2.1:1", DeviceID: "9", deviceLimitByCID: true}
	closeOne, err := l.acquire(one, true)
	if err != nil {
		t.Fatal(err)
	}
	defer closeOne()
	two := one
	two.Source = "192.0.2.2:2"
	closeTwo, err := l.acquire(two, true)
	if err != nil {
		t.Fatal("same CID on second IP rejected", err)
	}
	defer closeTwo()
	two.DeviceID = "10"
	if c, err := l.acquire(two, true); err == nil {
		c()
		t.Fatal("second CID was accepted")
	}
	udp := Request{UserID: 42, Source: "192.0.2.1:3", deviceLimitByCID: true}
	c, err := l.acquire(udp, false)
	if err != nil {
		t.Fatal("UDP invented a device", err)
	}
	c()
	udp.Source = "192.0.2.3:3"
	if c, err = l.acquire(udp, false); err == nil {
		c()
		t.Fatal("UDP bypassed independent IP limit")
	}
}

func TestTCPIdleTimeoutResetsOnPayload(t *testing.T) {
	target, _ := echoTCP(t)
	user := User{ID: 42, UUID: testUUID}
	cfg := Config{Protocol: "vless", Listen: "127.0.0.1", Port: freePort(t, false), Users: []User{user}, TCPTimeoutSeconds: 1}
	s, err := Start(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	c, err := client(t, cfg, user, nil).DialContext(context.Background(), "tcp", M.ParseSocksaddr(target))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	for i := 0; i < 3; i++ {
		if _, err = c.Write([]byte("alive")); err != nil {
			t.Fatal(err)
		}
		if _, err = io.ReadFull(c, make([]byte, 5)); err != nil {
			t.Fatal(err)
		}
		if i < 2 {
			time.Sleep(550 * time.Millisecond)
		}
	}
	start := time.Now()
	if _, err = c.Read(make([]byte, 1)); err == nil {
		t.Fatal("idle session not closed")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("idle timeout was not enforced")
	}
}

func TestTCPAdmissionSharedAcrossListeners(t *testing.T) {
	destination, _ := echoTCP(t)
	user := User{ID: 42, UUID: testUUID, TCPLimit: 1, DeviceLimit: 1}
	shared := NewLimiter()
	cfg := Config{Protocol: "vless", Listen: "127.0.0.1", Port: freePort(t, false), Users: []User{user}, Limiter: shared}
	first, err := Start(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	firstClient := client(t, cfg, user, nil)
	c, err := firstClient.DialContext(context.Background(), "tcp", M.ParseSocksaddr(destination))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	c.Write([]byte("held"))
	if _, err = io.ReadFull(c, make([]byte, 4)); err != nil {
		t.Fatal(err)
	}
	cfg.Port = freePort(t, false)
	second, err := Start(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	secondClient := client(t, cfg, user, nil)
	if err = roundTripTCP(secondClient, destination, []byte("must be denied"), time.Second); err == nil {
		t.Fatal("shared TCP limit was bypassed by second listener")
	}
	c.Close()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if err = roundTripTCP(secondClient, destination, []byte("after-close"), time.Second); err == nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("TCP permit not released after connection close")
}

func TestIPAdmissionAndMultiplexedPeerReferences(t *testing.T) {
	limits := NewLimiter()
	if err := limits.SetUserLimits(User{ID: 42, DeviceLimit: 1, TCPLimit: 1}); err != nil {
		t.Fatal(err)
	}
	request := Request{UserID: 42, Source: "192.0.2.1:1234", Network: "tcp"}
	release, err := limits.acquire(request, true)
	if err != nil {
		t.Fatal(err)
	}
	secondStream, err := limits.acquire(request, true)
	if err != nil {
		t.Fatalf("same multiplexed TCP peer counted twice: %v", err)
	}
	request.Source = "192.0.2.2:1234"
	if allowed, err := limits.acquire(request, false); err == nil {
		allowed()
		t.Fatal("second device allowed")
	}
	release()
	if allowed, err := limits.acquire(request, false); err == nil {
		allowed()
		t.Fatal("one live multiplexed reference was lost")
	}
	secondStream()
	last, err := limits.acquire(request, false)
	if err != nil {
		t.Fatalf("closed IP permit retained: %v", err)
	}
	last()
	last() // callback/Close can both run; releasing twice must be harmless.
}

func TestPayloadRateLimitsAreEnforced(t *testing.T) {
	destination, _ := echoTCP(t)
	for _, node := range []bool{false, true} {
		name := "user"
		if node {
			name = "node"
		}
		t.Run(name, func(t *testing.T) {
			user := User{ID: 42, UUID: testUUID}
			cfg := Config{Protocol: "vless", Listen: "127.0.0.1", Port: freePort(t, false)}
			if node {
				cfg.NodeSpeedLimit = 2
			} else {
				user.SpeedLimit = 2
			}
			cfg.Users = []User{user}
			s, err := Start(context.Background(), cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			start := time.Now()
			if err = roundTripTCP(client(t, cfg, user, nil), destination, bytes.Repeat([]byte("x"), 128*1024), 5*time.Second); err != nil {
				t.Fatal(err)
			}
			// 256KiB bidirectional total, 64KiB initial burst, 250kB/s.
			if elapsed := time.Since(start); elapsed < 600*time.Millisecond {
				t.Fatalf("2 Mbps aggregate limit not applied: %v", elapsed)
			}
		})
	}
}

func TestRateWaitCancellation(t *testing.T) {
	limits := NewLimiter()
	if err := limits.SetUserLimits(User{ID: 42, SpeedLimit: 0.001}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := limits.wait(ctx, 42, 128*1024); err == nil {
		t.Fatal("canceled wait succeeded")
	}
}

func TestZeroPrefixAndRealIPReporting(t *testing.T) {
	limits := NewLimiter()
	if err := limits.SetIPPrefixes(0, 0); err != nil {
		t.Fatal(err)
	}
	if err := limits.SetUserLimits(User{ID: 42, DeviceLimit: 1}); err != nil {
		t.Fatal(err)
	}
	release1, err := limits.acquire(Request{UserID: 42, Source: "192.0.2.1:1"}, false)
	if err != nil {
		t.Fatal(err)
	}
	defer release1()
	release2, err := limits.acquire(Request{UserID: 42, Source: "198.51.100.1:2"}, false)
	if err != nil {
		t.Fatalf("/0 should group all IPv4: %v", err)
	}
	defer release2()
	m := newMeter()
	m.prefix4, m.prefix6 = 0, 0
	done := m.connect(42, "[2001:db8::1234]:123")
	if ip := m.onlineSnapshot()[42]; len(ip) != 1 || ip[0] != "::" {
		t.Fatalf("IPv6 /0: %v", ip)
	}
	done()
	m.submitRealIP = true
	done = m.connect(42, "[2001:db8::1234]:123")
	defer done()
	if ip := m.onlineSnapshot()[42]; len(ip) != 1 || ip[0] != "2001:db8::1234" {
		t.Fatalf("actual IP: %v", ip)
	}
}

var _ net.Conn = (*meterConn)(nil)
