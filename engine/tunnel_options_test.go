package engine

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	vmess "github.com/sagernet/sing-vmess"
	M "github.com/sagernet/sing/common/metadata"

	"reconstructed.local/soga/certificates"
	"reconstructed.local/soga/config"
	"reconstructed.local/soga/panel"
	"reconstructed.local/soga/proxy"
	"reconstructed.local/soga/tunnel"
)

func TestTunnelOuterTLSActualHandshakeAndPersistentCertificate(t *testing.T) {
	c := config.Defaults()
	c.TunnelEnable, c.TunnelType, c.TunnelPassword = true, "tls-tunnel", "outer-shared-secret"
	c.CertMode, c.CertDomain, c.CertKeyLength = "self", "localhost", "ec-256"
	c.TlsMinVersion, c.TlsMaxVersion, c.TlsAlpn = "1.2", "1.2", []string{"http/1.1"}
	c.TunnelWsPath, c.TunnelMux = "/outer-pass", true
	p := Paths{StateDir: t.TempDir()}
	outer, err := buildTunnel(context.Background(), c, nil, p, []string{"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"})
	if err != nil {
		t.Fatal(err)
	}
	if outer.Password != c.TunnelPassword || outer.WSPath != c.TunnelWsPath || !outer.Mux {
		t.Fatal("lost tunnel settings")
	}
	again, err := buildTunnel(context.Background(), c, nil, p, nil)
	if err != nil || !bytes.Equal(outer.TLSConfig.Certificates[0].Certificate[0], again.TLSConfig.Certificates[0].Certificate[0]) {
		t.Fatalf("persistent certificate not reused: %v", err)
	}
	roots := x509.NewCertPool()
	leaf, err := x509.ParseCertificate(outer.TLSConfig.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	roots.AddCert(leaf)
	serverSide, clientSide := net.Pipe()
	defer serverSide.Close()
	defer clientSide.Close()
	_ = serverSide.SetDeadline(time.Now().Add(5 * time.Second))
	_ = clientSide.SetDeadline(time.Now().Add(5 * time.Second))
	server := tls.Server(serverSide, outer.TLSConfig)
	client := tls.Client(clientSide, &tls.Config{RootCAs: roots, ServerName: "localhost",
		MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12,
		CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA}, NextProtos: []string{"http/1.1"}})
	done := make(chan error, 1)
	go func() {
		if err := server.Handshake(); err != nil {
			done <- err
			return
		}
		_, err := server.Write([]byte("outer TLS"))
		done <- err
	}()
	if err := client.Handshake(); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, len("outer TLS"))
	if _, err := io.ReadFull(client, b); err != nil || string(b) != "outer TLS" {
		t.Fatalf("TLS payload %q: %v", b, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	state := client.ConnectionState()
	if state.Version != tls.VersionTLS12 || state.CipherSuite != tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA || state.NegotiatedProtocol != "http/1.1" {
		t.Fatalf("TLS settings ignored: %#v", state)
	}
}

func TestTunnelCustomCertificatesAndValidationBeforeIssuance(t *testing.T) {
	c := config.Defaults()
	c.TunnelEnable, c.TunnelType, c.TunnelPassword = true, "ws-tls-tunnel", "secret"
	c.CertDomain = "localhost"
	p := Paths{StateDir: t.TempDir(), ACMEExecutable: filepath.Join(t.TempDir(), "must-not-run")}
	local, err := certificates.Resolve(context.Background(), certificates.Options{
		Mode: "self", Domain: "localhost", KeyLength: "ec-256", StateDir: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	c.CertFile, c.KeyFile = local.CertFile, local.KeyFile
	if _, err := buildTunnel(context.Background(), c, nil, p, nil); err != nil {
		t.Fatalf("custom certificate was not used: %v", err)
	}
	c.CertFile, c.KeyFile = "", ""
	c.TunnelType = "quic-tunnel"
	if _, err := buildTunnel(context.Background(), c, nil, p, nil); err == nil || !strings.Contains(err.Error(), "QUIC") {
		t.Fatalf("unsupported QUIC transport reached ACME: %v", err)
	}
	c.TunnelType = "ws-tls-tunnel"
	c.TunnelMethod = "invalid-cipher"
	if _, err := buildTunnel(context.Background(), c, nil, p, nil); err == nil || !strings.Contains(err.Error(), "cipher") {
		t.Fatalf("cipher not checked before ACME: %v", err)
	}
	c.TunnelMethod = "aes-128-gcm"
	c.TlsMinVersion, c.TlsMaxVersion = "1.3", "1.2"
	if _, err := buildTunnel(context.Background(), c, nil, p, nil); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("invalid TLS range reached ACME: %v", err)
	}
	entries, err := os.ReadDir(p.StateDir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("invalid configuration wrote certificate state: %v %v", entries, err)
	}
	c.TunnelType, c.TunnelMethod = "tcp-tunnel", "aes-256-gcm"
	if result, err := buildTunnel(context.Background(), c, nil, p, nil); err != nil || result.TLSConfig != nil {
		t.Fatalf("plain tunnel required a certificate: %v", err)
	}
}

func TestBuildProxyTunnelRetainsInnerTLSAndTransport(t *testing.T) {
	ctx := context.Background()
	innerPaths, err := certificates.Resolve(ctx, certificates.Options{
		Mode: "self", Domain: "inner.localhost", KeyLength: "ec-256", StateDir: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := os.ReadFile(innerPaths.CertFile)
	key, _ := os.ReadFile(innerPaths.KeyFile)
	reserve, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := reserve.Addr().(*net.TCPAddr).Port
	reserve.Close()
	c := config.Defaults()
	c.ServerType = "vmess"
	c.TunnelEnable, c.TunnelType, c.TunnelPassword = true, "tls-tunnel", "outer-shared-secret"
	c.CertMode, c.CertDomain, c.CertKeyLength = "self", "outer.localhost", "ec-256"
	c.TlsAlpn = []string{"http/1.1"}
	p := Paths{StateDir: t.TempDir()}
	node := panel.Node{Config: panel.NodeConfig{Port: port, TLSType: "tls",
		Certificate: string(cert), CertificateKey: string(key), StreamType: "ws", Path: "/inner"}}
	users := []panel.User{{ID: 17, UUID: fixtureUUID}}
	cfg, err := buildProxy(ctx, c, nil, p, node, users, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Transport == nil || cfg.Transport.Type != "ws" || cfg.Transport.WebsocketOptions.Path != "/inner" {
		t.Fatal("tunnel removed the inner WebSocket transport")
	}
	if cfg.TLS == nil || !cfg.TLS.Enabled || len(cfg.TLS.Certificate) != 1 || cfg.TLS.Certificate[0] != string(cert) {
		t.Fatal("tunnel removed or replaced the panel-provided inner TLS certificate")
	}
	outerLeaf, err := x509.ParseCertificate(cfg.Tunnel.TLSConfig.Certificates[0].Certificate[0])
	if err != nil || outerLeaf.VerifyHostname("outer.localhost") != nil || outerLeaf.VerifyHostname("inner.localhost") == nil {
		t.Fatalf("outer TLS reused inner certificate: %v", err)
	}

	// Exercise the complete engine-produced configuration with both TLS layers.
	// WS retention above is separate from this ordinary inner TCP protocol test.
	node.Config.StreamType = "tcp"
	cfg, err = buildProxy(ctx, c, nil, p, node, users, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		conn, err := echo.Accept()
		if err == nil {
			defer conn.Close()
			_, _ = io.Copy(conn, conn)
		}
	}()
	server, err := proxy.Start(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	clientSettings := *cfg.Tunnel
	outerRoots := x509.NewCertPool()
	outerRoots.AddCert(outerLeaf)
	clientSettings.TLSConfig = &tls.Config{RootCAs: outerRoots, ServerName: "outer.localhost"}
	client, err := tunnel.DialClient(ctx, server.Addr(), clientSettings)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	raw, err := client.Open(tunnel.TCP)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(8 * time.Second))
	innerRoots := x509.NewCertPool()
	innerRoots.AppendCertsFromPEM(cert)
	secured := tls.Client(raw, &tls.Config{RootCAs: innerRoots, ServerName: "inner.localhost"})
	vc, err := vmess.NewClient(fixtureUUID, "aes-128-gcm", 0)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := vc.DialConn(secured, M.ParseSocksaddr(echo.Addr().String()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	payload := []byte("engine: independent outer and inner TLS")
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, reply); err != nil || !bytes.Equal(reply, payload) {
		t.Fatalf("nested TLS VMess exchange %q: %v", reply, err)
	}
}
