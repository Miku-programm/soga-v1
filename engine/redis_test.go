package engine

import (
	"context"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"reconstructed.local/soga/config"
	"reconstructed.local/soga/proxy"
	"reconstructed.local/soga/redislimit"
)

func TestRedisMigrationKeepsExplicitNewFalse(t *testing.T) {
	for _, tc := range []struct {
		text            string
		enabled, legacy bool
		addr            string
	}{
		{"redis_enable=true\nredis_addr=127.0.0.1:6379", true, true, "127.0.0.1:6379"},
		{"redis_enable=true\nredis_addr=127.0.0.1:6379\nredis_ip_limit_enable=false", false, false, ""},
		{"redis_enable=true\nredis_addr=127.0.0.1:6379\nredis_ip_limit_enable=true\nredis_ip_limit_addr=127.0.0.2:6379", true, false, "127.0.0.2:6379"},
	} {
		loaded, err := config.Load(strings.NewReader(tc.text), config.LoadOptions{})
		if err != nil {
			t.Fatal(err)
		}
		opts, enabled, legacy, err := redisOptions(loaded.Config, loaded.Explicit)
		if err != nil || enabled != tc.enabled || legacy != tc.legacy || opts.Addr != tc.addr {
			t.Fatalf("%+v: %+v,%v,%v,%v", tc, opts, enabled, legacy, err)
		}
	}
}

func TestUnavailableRedisKeepsLocalAdmission(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	listener.Close()
	manager, err := redislimit.New(redislimit.Options{Addr: addr, Timeout: 20 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	n := &Node{redis: manager, opts: Options{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}}
	release, err := n.globalAdmission(context.Background(), proxy.AdmissionRequest{UserID: 1, IP: "192.0.2.1", DeviceID: "ip:192.0.2.1", IPLimit: 1, DeviceLimit: 1})
	if err != nil || release == nil {
		t.Fatal("Redis outage prevented local admission or lost recovery lease", err)
	}
	release()
}
