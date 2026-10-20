package panel

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestXiaoV2NodeNormalizationAndReports(t *testing.T) {
	var traffic bool
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("node_type") != "v2node" || r.URL.Query().Get("node_id") != "3" {
			t.Error("wrong v2node query", r.URL.RawQuery)
		}
		switch r.URL.Path {
		case uniPath + "/config":
			fmt.Fprint(w, `{"protocol":"vless","server_port":443,"network":"splithttp","network_settings":{"path":"/x","mode":"auto"},"tls":1,"tls_settings":{"cert_mode":"remote","tls_cert":"CERT-PEM","tls_key":"PRIVATE-PEM","server_names":["host.example"]},"encryption":"mlkem768x25519plus","encryption_settings":{"mode":"native","ticket":"600s","server_padding":"100-200","private_key":"private"},"routes":[{"id":8,"action":"block","match":["domain:bad.example","ip:10.0.0.0/8"]},{"id":9,"action":"dns","match":["domain:internal.example"],"action_value":"udp://127.0.0.1:5353"},{"id":10,"action":"dns","match":["full:ignored.example"],"action_value":""},{"id":11,"action":"other","match":["full:ignored.example"]}]}`)
		case uniPath + "/push":
			traffic = true
			fmt.Fprint(w, `{"data":true}`)
		default:
			t.Error("unexpected path", r.URL.Path)
		}
	}))
	defer s.Close()
	c, err := NewUniProxy(Options{Type: "xiaov2board", SubType: "v2node", NodeType: "vless", BaseURL: s.URL, NodeID: "3"})
	if err != nil {
		t.Fatal(err)
	}
	n, err := c.FetchNode(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(n.UnsupportedOptions) != 0 || n.Config.StreamType != "xhttp" || n.Config.Path != "/x" ||
		n.Config.Certificate != "CERT-PEM" || n.Config.CertificateKey != "PRIVATE-PEM" ||
		n.Config.Decryption != "mlkem768x25519plus.native.600s.100-200.private" ||
		len(n.Policy.Rules) != 2 || n.Policy.Rules[0].ID != 8 || len(n.DNSRules) != 1 ||
		n.DNSRules[0].Servers[0] != "udp://127.0.0.1:5353" {
		t.Fatalf("%+v", n)
	}
	if err := c.ReportTraffic(context.Background(), []Traffic{{ID: 4, Upload: 7}}); err != nil || !traffic {
		t.Fatal(err, traffic)
	}
}

func TestXiaoV2NodeAliasesValidationAndNone(t *testing.T) {
	for _, tc := range []struct {
		protocol, body string
		wantError      bool
	}{
		{"shadowsocks", `{"protocol":"shadowsocks","server_port":1234,"cipher":"aes-128-gcm","network_settings":{"path":"/obfs","host":"example.com"},"tls":1,"tls_settings":{"cert_mode":"none"}}`, false},
		{"trojan", `{"protocol":"trojan","server_port":1234,"tls":1,"tls_settings":{"cert_mode":"none"}}`, false},
		{"anytls", `{"protocol":"anytls","server_port":1234,"tls":1,"tls_settings":{"cert_mode":"none"}}`, false},
		{"hysteria", `{"protocol":"hysteria2","server_port":1234,"obfs_password":"secret","tls":1}`, false},
		{"vless", `{"server_port":1234}`, true},
		{"vless", `{"protocol":"vmess","server_port":1234}`, true},
		{"vless", `{"protocol":"vless","server_port":1234,"tls":1,"tls_settings":{"cert_mode":"remote","tls_cert":"onlycert"}}`, true},
	} {
		t.Run(tc.protocol+tc.body, func(t *testing.T) {
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, tc.body) }))
			defer s.Close()
			c, err := NewUniProxy(Options{Type: "xiaov2board", SubType: "v2node", NodeType: tc.protocol, BaseURL: s.URL, NodeID: "3"})
			if err != nil {
				t.Fatal(err)
			}
			n, err := c.FetchNode(context.Background())
			if (err != nil) != tc.wantError {
				t.Fatalf("%+v %v", n, err)
			}
			if err == nil && tc.protocol == "shadowsocks" && (n.Config.Obfs != "http" || n.Config.Path != "/obfs" || n.Config.TLSType != "none") {
				t.Fatal(n)
			}
			if err == nil && (tc.protocol == "trojan" || tc.protocol == "anytls") && (n.Config.TLSType != "none" || n.Config.CertMode != "none") {
				t.Fatal(n)
			}
			if err == nil && tc.protocol == "hysteria" && n.Config.ObfsPassword != "secret" {
				t.Fatal(n)
			}
		})
	}
	if _, err := NewUniProxy(Options{Type: "xboard", SubType: "v2node"}); err == nil {
		t.Fatal("accepted unsupported subtype")
	}
}
