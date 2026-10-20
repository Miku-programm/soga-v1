package engine

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log/slog"
	"net"
	"os"
	"testing"
	"time"

	vmess "github.com/sagernet/sing-vmess"
	M "github.com/sagernet/sing/common/metadata"
	"reconstructed.local/soga/certificates"
	"reconstructed.local/soga/config"
	"reconstructed.local/soga/panel"
)

func TestPanelInlineTLSAndInvalidRotationRollback(t *testing.T) {
	dir := t.TempDir()
	paths, err := certificates.Resolve(context.Background(), certificates.Options{Mode: "self", Domain: "localhost", KeyLength: "ec-256", StateDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	cert, err := os.ReadFile(paths.CertFile)
	if err != nil {
		t.Fatal(err)
	}
	key, err := os.ReadFile(paths.KeyFile)
	if err != nil {
		t.Fatal(err)
	}
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
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	api := &policyPanel{node: panel.Node{Config: panel.NodeConfig{Port: port, TLSType: "tls", Certificate: string(cert), CertificateKey: string(key), CertMode: "remote"}}}
	c := config.Defaults()
	c.ServerType, c.Listen, c.CertDomain = "vmess", "127.0.0.1", "localhost"
	c.CheckInterval, c.SubmitInterval, c.RandomIntervalRange = 3600, 3600, 0
	c.IpUserCacheSaveDir = dir
	n, err := StartNode(context.Background(), Options{Config: c, NodeID: "4", API: api, Paths: Paths{StateDir: dir}, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close(context.Background())
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(cert)
	exchange := func() {
		t.Helper()
		raw, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", n.Addresses()[0], &tls.Config{RootCAs: pool, ServerName: "localhost"})
		if err != nil {
			t.Fatal(err)
		}
		defer raw.Close()
		raw.SetDeadline(time.Now().Add(2 * time.Second))
		client, err := vmess.NewClient(fixtureUUID, "aes-128-gcm", 0)
		if err != nil {
			t.Fatal(err)
		}
		conn, err := client.DialConn(raw, M.ParseSocksaddr(echo.Addr().String()))
		if err != nil {
			t.Fatal(err)
		}
		want := []byte("panel supplied trusted TLS pair")
		if _, err = conn.Write(want); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, len(want))
		if _, err = io.ReadFull(conn, got); err != nil || !bytes.Equal(got, want) {
			t.Fatal(err)
		}
	}
	exchange()
	api.node.Config.CertificateKey = "not a private key"
	if err = n.Sync(context.Background()); err == nil {
		t.Fatal("invalid panel cert rotation accepted")
	}
	exchange()
}
