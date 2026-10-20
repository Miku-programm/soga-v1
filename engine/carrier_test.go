package engine

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	simpleclient "github.com/sagernet/sing-box/transport/simple-obfs"
	"github.com/sagernet/sing-shadowsocks/shadowaead"
	M "github.com/sagernet/sing/common/metadata"
	"reconstructed.local/soga/config"
	"reconstructed.local/soga/panel"
	"reconstructed.local/soga/proxy/ssrcore"
)

func TestCarrierAssemblyBillingAndUserRemoval(t *testing.T) {
	reserved, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := reserved.Addr().(*net.TCPAddr).Port
	reserved.Close()
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
	users := []panel.User{
		{ID: 42, Password: "first", Method: "aes-128-cfb", Protocol: "auth_chain_a", Obfs: "plain"},
		{ID: 43, Password: "second", Method: "chacha20", Protocol: "origin", Obfs: "http_simple"},
		{ID: 100, IsMultiUser: 1, Port: 23456, Password: "replaced-key", Method: "aes-128-gcm", Protocol: "origin", Obfs: "simple_obfs_http"},
		{ID: 99, IsMultiUser: 1, Port: 34567, Password: "carrier-key", Method: "aes-128-gcm", Protocol: "origin", Obfs: "simple_obfs_http"},
	}
	api := &policyPanel{users: users, node: panel.Node{Config: panel.NodeConfig{MultiUserPorts: true, OnlyMultiUserPorts: true, LegacySogaPort: port}}}
	c := config.Defaults()
	c.ServerType, c.Listen = "ssr", "127.0.0.1"
	c.CheckInterval, c.SubmitInterval, c.RandomIntervalRange = 3600, 3600, 0
	n, err := StartNode(context.Background(), Options{Config: c, NodeID: "2", API: api, Paths: Paths{StateDir: t.TempDir()}, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close(context.Background())
	if len(n.Addresses()) != 1 {
		t.Fatal(n.Addresses())
	}
	method, err := shadowaead.New("aes-128-gcm", nil, "carrier-key")
	if err != nil {
		t.Fatal(err)
	}
	exchange := func(u panel.User) error {
		host, err := ssrcore.HostForUser(ssrcore.User{ID: u.ID, Password: u.Password, Method: u.Method, Protocol: u.Protocol, Obfs: u.Obfs}, c.MuRegex, c.MuSuffix)
		if err != nil {
			return err
		}
		raw, err := net.Dial("tcp", n.Addresses()[0])
		if err != nil {
			return err
		}
		defer raw.Close()
		raw.SetDeadline(time.Now().Add(time.Second))
		conn, err := method.DialConn(simpleclient.NewHTTPObfs(raw, host, "80"), M.ParseSocksaddr(echo.Addr().String()))
		if err != nil {
			return err
		}
		want := bytes.Repeat([]byte("per-user billing over shared key"), 100)
		if _, err = conn.Write(want); err != nil {
			return err
		}
		got := make([]byte, len(want))
		_, err = io.ReadFull(conn, got)
		if err == nil && !bytes.Equal(got, want) {
			t.Error("payload changed")
		}
		return err
	}
	for _, u := range users[:2] {
		if err = exchange(u); err != nil {
			t.Fatal(err)
		}
	}
	if err = n.Push(context.Background()); err != nil {
		t.Fatal(err)
	}
	if api.traffic[42] == 0 || api.traffic[43] == 0 || api.traffic[99] != 0 || api.traffic[100] != 0 {
		t.Fatal("incorrect carrier billing", api.traffic)
	}
	api.users = users[1:]
	if err = n.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err = exchange(users[0]); err == nil {
		t.Fatal("removed user's Host still accepted")
	}
	if err = exchange(users[1]); err != nil {
		t.Fatal(err)
	}
	if p, err := net.ListenPacket("udp", n.Addresses()[0]); err != nil {
		t.Fatal("unrequested mu UDP listening", err)
	} else {
		p.Close()
	}
}
