package engine

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"testing"

	"reconstructed.local/soga/config"
	"reconstructed.local/soga/panel"
	"reconstructed.local/soga/proxy"
)

func TestSSRRouteFromPanelManagedVMess(t *testing.T) {
	free := func() uint16 {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		return uint16(l.Addr().(*net.TCPAddr).Port)
	}
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	port := free()
	inner, err := proxy.Start(context.Background(), proxy.Config{Protocol: "ssr", Listen: "127.0.0.1", Port: port,
		Method: "aes-128-cfb", Password: "outer", SSRProtocol: "auth_aes128_sha1", SSRObfs: "tls1.2_ticket_auth",
		SSRSinglePortType: "protocol", Users: []proxy.User{{ID: 81, Password: "inner"}}})
	if err != nil {
		t.Fatal(err)
	}
	defer inner.Close()
	dir := t.TempDir()
	routes := filepath.Join(dir, "routes.toml")
	text := fmt.Sprintf(`enable=true
[[routes]]
rules=["*"]
health_check=false
[[routes.Outs]]
type="ssr"
server="127.0.0.1"
port=%d
cipher="aes-128-cfb"
password="outer"
protocol="auth_aes128_sha1"
protocol_param="81:inner"
obfs="tls1.2_ticket_auth"
obfs_param="cdn.example"
`, port)
	if err = os.WriteFile(routes, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	api := &policyPanel{node: panel.Node{Config: panel.NodeConfig{Port: int(free())}}}
	c := config.Defaults()
	c.ServerType, c.Listen = "vmess", "127.0.0.1"
	c.IpUserCacheSaveDir = dir
	c.CheckInterval, c.SubmitInterval, c.RandomIntervalRange = 3600, 3600, 0
	n, err := StartNode(context.Background(), Options{Config: c, NodeID: "3", API: api, Paths: Paths{StateDir: dir, Routes: routes}, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close(context.Background())
	payload := []byte("route mapping uses authenticated SSR outbound")
	if err = vmessExchange(n.Addresses()[0], echo.Addr().String(), fixtureUUID, payload); err != nil {
		t.Fatal(err)
	}
	if inner.TrafficSnapshot()[81].Upload < uint64(len(payload)) {
		t.Fatal("SSR route was bypassed", inner.TrafficSnapshot())
	}
}
