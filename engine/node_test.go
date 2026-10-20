package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	vmess "github.com/sagernet/sing-vmess"
	M "github.com/sagernet/sing/common/metadata"

	"reconstructed.local/soga/accounting"
	"reconstructed.local/soga/config"
	"reconstructed.local/soga/panel"
)

const fixtureUUID = "2d15433b-392e-4522-b9cc-4b3a0a2c714f"

func TestPanelManagedNodeLifecycle(t *testing.T) {
	ctx := context.Background()
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	var destinations atomic.Int64
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			destinations.Add(1)
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	reservation, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := reservation.Addr().(*net.TCPAddr).Port
	_ = reservation.Close()
	var mu sync.Mutex
	remoteUsers := []panel.User{{ID: 23, UUID: fixtureUUID}}
	failTraffic, failUsers := false, false
	var reports [][]panel.Traffic
	var audits []panel.AuditLog
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Header.Get("API-KEY") != "test-secret" || r.Header.Get("NODE-ID") != "7" {
			t.Error("incorrect authentication headers")
			http.Error(w, "auth", 403)
			return
		}
		switch r.URL.Path {
		case "/api/v1/node":
			fmt.Fprintf(w, `{"basic":{},"config":{"port":%d,"stream_type":"tcp"}}`, port)
		case "/api/v1/users":
			if failUsers {
				http.Error(w, "transient failure", 503)
				return
			}
			_ = json.NewEncoder(w).Encode(remoteUsers)
		case "/api/v1/white_list", "/api/v1/audit_rules":
			fmt.Fprint(w, "[]")
		case "/api/v1/traffic":
			var batch []panel.Traffic
			if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
				t.Error(err)
			}
			reports = append(reports, batch)
			if failTraffic {
				http.Error(w, "transient failure", 503)
				return
			}
			fmt.Fprint(w, `{"code":0}`)
		case "/api/v1/audit_logs":
			_ = json.NewDecoder(r.Body).Decode(&audits)
			fmt.Fprint(w, `{"code":0}`)
		default:
			if r.Method != http.MethodPost {
				t.Errorf("unexpected request: %s", r.URL.Path)
			}
			fmt.Fprint(w, `{"code":0}`)
		}
	}))
	defer remote.Close()
	c := config.Defaults()
	c.Type, c.ServerType, c.WebapiUrl, c.WebapiKey, c.Listen = "soga-v1", "vmess", remote.URL, "test-secret", "127.0.0.1"
	c.CheckInterval, c.SubmitInterval, c.RandomIntervalRange = 3600, 3600, 0
	dir := t.TempDir()
	c.IpUserCacheSaveDir = dir
	block := filepath.Join(dir, "blockList")
	routes := filepath.Join(dir, "routes.toml")
	n, err := StartNode(ctx, Options{Config: c, NodeID: "7",
		Paths:  Paths{StateDir: dir, BlockList: block, Routes: routes},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		closeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		if err := n.Close(closeCtx); err != nil {
			t.Error(err)
		}
	}()
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	payload := bytes.Repeat([]byte("managed-node-payload"), 1024)
	exchange := func(uuid string, wanted bool) {
		t.Helper()
		err := vmessExchange(address, echo.Addr().String(), uuid, payload)
		if (err == nil) != wanted {
			t.Fatalf("relay success=%v expected=%v error=%v", err == nil, wanted, err)
		}
	}
	exchange(fixtureUUID, true)
	exchange("fb05b2d2-aa74-4e6c-a6d8-b18dad3c7ab0", false)
	if destinations.Load() != 1 {
		t.Fatal("wrong credential reached target")
	}
	mu.Lock()
	failTraffic = true
	mu.Unlock()
	if err := n.Push(ctx); err == nil {
		t.Fatal("failed report acknowledged")
	}
	durable, err := accounting.Open(filepath.Join(dir, "node-7-traffic.json"))
	if err != nil || len(durable.Batch()) != 1 || durable.Batch()[0].Upload < int64(len(payload)) {
		t.Fatal("pending report not durably stored", durable, err)
	}
	mu.Lock()
	failTraffic = false
	mu.Unlock()
	if err := n.Push(ctx); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	if len(reports) != 2 || len(reports[0]) != 1 || reports[0][0] != reports[1][0] ||
		reports[0][0].ID != 23 || reports[0][0].Download < int64(len(payload)) {
		t.Error("retry did not preserve exact acknowledged bytes", reports)
	}
	failUsers = true
	mu.Unlock()
	if err := n.Sync(ctx); err == nil {
		t.Fatal("failed users fetch accepted")
	}
	exchange(fixtureUUID, true)
	mu.Lock()
	failUsers = false
	remoteUsers = []panel.User{}
	mu.Unlock()
	if err := n.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	exchange(fixtureUUID, false)
	mu.Lock()
	remoteUsers = []panel.User{{ID: 23, UUID: fixtureUUID}}
	mu.Unlock()
	if err := n.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	exchange(fixtureUUID, true)
	before := destinations.Load()
	if err := os.WriteFile(block, []byte("ip:127.0.0.1/32\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := n.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	exchange(fixtureUUID, false)
	if destinations.Load() != before {
		t.Fatal("blocked request reached target")
	}
	if err := n.Push(ctx); err != nil {
		t.Fatal(err)
	}
	if len(n.ledger.Batch()) != 0 {
		t.Fatal("acknowledged traffic remains pending")
	}
	if err := os.WriteFile(block, nil, 0600); err != nil {
		t.Fatal(err)
	}
	routeText := fmt.Sprintf("enable=true\n[[routes]]\nrules=['ip:192.0.2.0/24']\n[[routes.Outs]]\ntype='redirect'\nserver='127.0.0.1'\nport=%d\n", echo.Addr().(*net.TCPAddr).Port)
	if err := os.WriteFile(routes, []byte(routeText), 0600); err != nil {
		t.Fatal(err)
	}
	if err := n.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if err := vmessExchange(address, "192.0.2.55:90", fixtureUUID, payload); err != nil {
		t.Fatal("configured redirect did not reach local target", err)
	}
	before = destinations.Load()
	exchange(fixtureUUID, false)
	if destinations.Load() != before {
		t.Fatal("unmatched route reached target")
	}
	// A malformed replacement must keep the last validated listener and route.
	if err := os.WriteFile(routes, []byte("enable=true\n[[routes]]"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := n.Sync(ctx); err == nil {
		t.Fatal("invalid route accepted")
	}
	if err := vmessExchange(address, "192.0.2.55:90", fixtureUUID, payload); err != nil {
		t.Fatal("invalid route update discarded working listener", err)
	}
	if err := os.WriteFile(routes, []byte(routeText), 0600); err != nil {
		t.Fatal(err)
	}
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	mu.Lock()
	port = busy.Addr().(*net.TCPAddr).Port
	mu.Unlock()
	if err := n.Sync(ctx); err == nil {
		t.Fatal("bind conflict accepted")
	}
	if err := vmessExchange(address, "192.0.2.55:90", fixtureUUID, payload); err != nil {
		t.Fatal("failed bind did not restore previous listener", err)
	}
}

func vmessExchange(address, target, uuid string, payload []byte) error {
	raw, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		return err
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(2 * time.Second))
	client, err := vmess.NewClient(uuid, "aes-128-gcm", 0)
	if err != nil {
		return err
	}
	conn, err := client.DialConn(raw, M.ParseSocksaddr(target))
	if err != nil {
		return err
	}
	if _, err = conn.Write(payload); err != nil {
		return err
	}
	got := make([]byte, len(payload))
	if _, err = io.ReadFull(conn, got); err != nil {
		return err
	}
	if !bytes.Equal(payload, got) {
		return fmt.Errorf("payload mismatch")
	}
	return nil
}
