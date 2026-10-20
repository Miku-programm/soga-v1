package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"reconstructed.local/soga/config"
	"reconstructed.local/soga/panel"
)

func TestMultiportOwnershipRemovalAndAccounting(t *testing.T) {
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
	var reservations []net.Listener
	var ports []int
	for range 2 {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		reservations = append(reservations, l)
		ports = append(ports, l.Addr().(*net.TCPAddr).Port)
	}
	secondUUID := "e3a2acb7-53cc-4b88-a512-4297acbff5df"
	users := []panel.User{{ID: 1, Port: ports[0], UUID: fixtureUUID}, {ID: 2, Port: ports[1], UUID: secondUUID}}
	var mu sync.Mutex
	reports := map[int64]int64{}
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch r.URL.Path {
		case "/api/v1/node":
			_ = json.NewEncoder(w).Encode(panel.Node{Config: panel.NodeConfig{Port: ports[0], MultiUserPorts: true, StreamType: "tcp"}})
		case "/api/v1/users":
			_ = json.NewEncoder(w).Encode(users)
		case "/api/v1/white_list", "/api/v1/audit_rules":
			fmt.Fprint(w, "[]")
		case "/api/v1/traffic":
			var traffic []panel.Traffic
			if err := json.NewDecoder(r.Body).Decode(&traffic); err != nil {
				t.Error(err)
			}
			for _, row := range traffic {
				reports[row.ID] += row.Upload
			}
			fmt.Fprint(w, `{"code":0}`)
		default:
			fmt.Fprint(w, `{"code":0}`)
		}
	}))
	defer remote.Close()
	for _, l := range reservations {
		l.Close()
	}
	c := config.Defaults()
	c.Type, c.ServerType, c.WebapiUrl, c.Listen = "soga-v1", "vmess", remote.URL, "127.0.0.1"
	c.DomainSniff = nil
	c.IpUserCacheSaveDir = t.TempDir()
	c.CheckInterval, c.SubmitInterval, c.RandomIntervalRange = 3600, 3600, 0
	n, err := StartNode(context.Background(), Options{Config: c, NodeID: "8", Paths: Paths{StateDir: t.TempDir()}, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		ctx, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if err := n.Close(ctx); err != nil {
			t.Error(err)
		}
	}()
	address := func(port int) string { return net.JoinHostPort("127.0.0.1", strconv.Itoa(port)) }
	payload := []byte("different-port-accounting")
	for i, uuid := range []string{fixtureUUID, secondUUID} {
		if err := vmessExchange(address(ports[i]), echo.Addr().String(), uuid, payload); err != nil {
			t.Fatal(err)
		}
	}
	if err := vmessExchange(address(ports[1]), echo.Addr().String(), fixtureUUID, payload); err == nil {
		t.Fatal("user authenticated on another user's port")
	}
	mu.Lock()
	users = users[1:]
	mu.Unlock()
	if err := n.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if conn, err := net.DialTimeout("tcp", address(ports[0]), time.Second); err == nil {
		conn.Close()
		t.Fatal("removed user's port remains open")
	}
	if err := vmessExchange(address(ports[1]), echo.Addr().String(), secondUUID, payload); err != nil {
		t.Fatal(err)
	}
	if err := n.Push(context.Background()); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if reports[1] < int64(len(payload)) || reports[2] < 2*int64(len(payload)) {
		t.Fatal("billing lost across multiport rebuild", reports)
	}
}
