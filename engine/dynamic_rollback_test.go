package engine

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"reconstructed.local/soga/config"
	"reconstructed.local/soga/panel"
	"reconstructed.local/soga/proxy"
)

func TestFailedUpdateRestoresActiveDynamicLimit(t *testing.T) {
	for _, mode := range []string{"bind_conflict", "closed_listener_user_update"} {
		t.Run(mode, func(t *testing.T) {
			reservation, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			port := reservation.Addr().(*net.TCPAddr).Port
			reservation.Close()
			echo, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer echo.Close()
			go func() {
				for {
					conn, err := echo.Accept()
					if err != nil {
						return
					}
					go func() { defer conn.Close(); _, _ = io.Copy(conn, conn) }()
				}
			}()
			api := &policyPanel{
				node:  panel.Node{Config: panel.NodeConfig{Port: port}},
				users: []panel.User{{ID: 23, UUID: fixtureUUID}},
			}
			c := config.Defaults()
			c.ServerType, c.Listen = "vmess", "127.0.0.1"
			c.CheckInterval, c.SubmitInterval, c.RandomIntervalRange = 3600, 3600, 0
			c.DyLimitEnable = true
			c.DyLimitTriggerTime, c.DyLimitTime = 1, 600
			c.DyLimitTriggerSpeed, c.DyLimitSpeed = 1, 2
			c.DyLimitDuration, c.DyLimitWhiteUserId = "", nil
			c.IpUserCacheSaveDir = t.TempDir()
			n, err := StartNode(context.Background(), Options{
				Config: c, NodeID: "8", API: api,
				Paths:  Paths{StateDir: t.TempDir()},
				Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
			})
			if err != nil {
				t.Fatal(err)
			}
			defer n.Close(context.Background())
			address, key := n.Addresses()[0], n.key
			// Trigger the real controller with a complete 1-second window.
			// No sleeps or private limiter-state assertions establish the limit.
			at := time.Now().Add(-2 * time.Second)
			n.mu.Lock()
			err = n.dynamic.Observe(at, map[int64]proxy.Traffic{23: {}})
			if err == nil {
				err = n.dynamic.Observe(at.Add(time.Second), map[int64]proxy.Traffic{23: {Upload: 250000}})
			}
			until := n.dynamic.RestrictedUntil(23)
			n.mu.Unlock()
			if err != nil || !until.After(time.Now()) {
				t.Fatal("could not establish dynamic restriction", until, err)
			}

			if mode == "bind_conflict" {
				busy, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer busy.Close()
				api.node.Config.Port = busy.Addr().(*net.TCPAddr).Port
			} else {
				// An unavailable existing core makes UpdateUsers return an error.
				// The engine must recreate it with the last accepted users.
				if err := n.servers[0].Close(); err != nil {
					t.Fatal(err)
				}
				api.users = []panel.User{{ID: 23, UUID: fixtureUUID, SpeedLimit: 100}}
			}
			if err := n.Sync(context.Background()); err == nil {
				t.Fatal("broken replacement unexpectedly succeeded")
			}
			if !n.ready.Load() || n.key != key || n.Addresses()[0] != address {
				t.Fatal("last working listener was not restored")
			}
			n.mu.Lock()
			retained := n.dynamic.RestrictedUntil(23)
			n.mu.Unlock()
			if !retained.Equal(until) {
				t.Fatal("rollback changed temporary restriction expiry")
			}
			// Check the enforcement, not only the controller's expiry flag:
			// 128 KiB each way at aggregate 2 Mbps, minus the 64 KiB burst,
			// needs at least ~0.78 seconds. The old bug relays it unthrottled.
			start := time.Now()
			err = vmessExchange(address, echo.Addr().String(), fixtureUUID, bytes.Repeat([]byte{0x5a}, 128*1024))
			elapsed := time.Since(start)
			if err != nil {
				t.Fatal("recovered listener did not relay payload", err)
			}
			if elapsed < 600*time.Millisecond {
				t.Fatalf("dynamic limit lost after rollback: payload completed in %s", elapsed)
			}
		})
	}
}
