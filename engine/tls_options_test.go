package engine

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"
	"reflect"
	"strconv"
	"testing"
	"time"

	"reconstructed.local/soga/certificates"
	"reconstructed.local/soga/config"
	"reconstructed.local/soga/panel"
	"reconstructed.local/soga/proxy"
)

func TestDocumentedTLSCipherList(t *testing.T) {
	want := []string{"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"}
	for _, raw := range []string{
		"0xcca8:0xc030:0xc02f",
		"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		" 0xcca8,0xc030,0xc02f,0xcca8 ",
	} {
		got, err := tlsCipherNames(raw)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatal(raw, got, err)
		}
	}
	for _, raw := range []string{"0xffff", "bogus", "0x12345"} {
		if _, err := tlsCipherNames(raw); err == nil {
			t.Fatal("unknown cipher accepted", raw)
		}
	}
}

func TestExplicitLegacyCipherNegotiatesActualTLS(t *testing.T) {
	dir := t.TempDir()
	paths, err := certificates.Resolve(context.Background(), certificates.Options{Mode: "self", Domain: "localhost", KeyLength: "ec-256", StateDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := os.ReadFile(paths.CertFile)
	key, _ := os.ReadFile(paths.KeyFile)
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(cert)
	for _, protocol := range []string{"vmess", "trojan", "anytls"} {
		t.Run(protocol, func(t *testing.T) {
			reserve, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			port := reserve.Addr().(*net.TCPAddr).Port
			reserve.Close()
			c := config.Defaults()
			c.ServerType, c.CertDomain = protocol, "localhost"
			c.TlsMinVersion, c.TlsMaxVersion, c.TlsCipherSuites = "1.2", "1.2", "0xc009"
			cfg, err := buildProxy(context.Background(), c, nil, Paths{StateDir: dir},
				panel.Node{Config: panel.NodeConfig{Port: port, TLSType: "tls", Certificate: string(cert), CertificateKey: string(key)}},
				[]panel.User{{ID: 1, UUID: fixtureUUID, Password: "legacy-cipher-test"}}, "127.0.0.1")
			if err != nil {
				t.Fatal(err)
			}
			server, err := proxy.Start(context.Background(), cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)),
				&tls.Config{RootCAs: pool, ServerName: "localhost", MinVersion: tls.VersionTLS12,
					MaxVersion: tls.VersionTLS12, CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA}})
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if conn.ConnectionState().CipherSuite != tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA {
				t.Fatal("explicit legacy cipher not negotiated")
			}
		})
	}
}
