package panel

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestV2RaySocksRealityAndAck(t *testing.T) {
	bad := false
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/web_api/" || r.URL.Query().Get("node_type") != "v2ray" || r.URL.Query().Get("token") != "secret" {
			t.Error("bad V2RaySocks request")
		}
		if r.Method == "POST" {
			if bad {
				fmt.Fprint(w, `{"msg":"error","ret":500}`)
			} else {
				fmt.Fprint(w, `{"msg":"ok","ret":200}`)
			}
			return
		}
		if r.URL.Query().Get("act") == "user" {
			fmt.Fprint(w, `{"msg":"ok","data":[{"id":3,"uuid":"u","dt":2,"st":3}]}`)
			return
		}
		fmt.Fprint(w, `{"inbounds":[{"port":443,"protocol":"vless","settings":{"decryption":"none","clients":[{"flow":"xtls-rprx-vision"}]},"streamSettings":{"network":"tcp","security":"reality","realitySettings":{"serverNames":["example.com"],"privateKey":"key","shortIds":["ab"],"dest":"example.com:443"}}}],"outbounds":[{"protocol":"freedom"}],"routing":{"rules":[]}}`)
	}))
	defer s.Close()
	c, err := NewClient(Options{Type: "v2raysocks", BaseURL: s.URL, NodeType: "vless", NodeID: "1", APIKey: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	n, err := c.FetchNode(context.Background())
	if err != nil || n.Config.PrivateKey != "key" || n.Config.Flow != "xtls-rprx-vision" || n.Config.Dest != "example.com:443" || len(n.UnsupportedOptions) > 0 {
		t.Fatal(n, err)
	}
	u, err := c.FetchUsers(context.Background())
	if err != nil || u[0].UUID != "u" || u[0].DeviceLimit != 2 {
		t.Fatal(u, err)
	}
	if err := c.ReportTraffic(context.Background(), []Traffic{{3, 2, 4}}); err != nil {
		t.Fatal(err)
	}
	bad = true
	if err := c.ReportTraffic(context.Background(), nil); err == nil {
		t.Fatal("negative ACK accepted")
	}
}
func TestXiaoV2BoardWire(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("node_type") != "v2ray" {
			t.Error("wrong node_type")
		}
		switch r.URL.Path {
		case uniPath + "/config":
			fmt.Fprint(w, `{"server_port":80,"network":"ws","networkSettings":{"path":"/x"},"tls":0}`)
		case uniPath + "/user":
			fmt.Fprint(w, `{"users":[{"id":2,"uuid":"u"}]}`)
		case uniPath + "/alive":
			fmt.Fprint(w, `{"data":true}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer s.Close()
	c, err := NewClient(Options{Type: "xiaov2board", BaseURL: s.URL, NodeType: "vmess", NodeID: "1"})
	if err != nil {
		t.Fatal(err)
	}
	n, err := c.FetchNode(context.Background())
	if err != nil || n.Config.Path != "/x" {
		t.Fatal(n, err)
	}
	if _, err = c.FetchUsers(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err = c.ReportAliveIPs(context.Background(), []AliveIP{{2, []string{"::1"}}}); err != nil {
		t.Fatal(err)
	}
	if err = c.ReportStatus(context.Background(), Status{}); !errors.Is(err, ErrUnsupported) {
		t.Fatal(err)
	}
}

func TestV2RaySocksProxyTagSelection(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		port       int
		wantError  bool
	}{
		{"proxy-after-api", `{"inbounds":[{"tag":"api","port":10001,"protocol":"dokodemo-door"},{"tag":"proxy","port":2345,"streamSettings":{"network":"ws","wsSettings":{"path":"/proxy"}}}],"routing":{"rules":[{"outboundTag":"block","domain":["full:blocked.example"]}]}}`, 2345, false},
		{"first-matching-tag", `{"inbounds":[{"tag":"proxy","port":2345},{"tag":"proxy","port":3456}]}`, 2345, false},
		{"no-proxy-tag", `{"inbounds":[{"tag":"api","port":10001},{"tag":"other","port":3456}]}`, 0, true},
		{"explicit-wrong-single-tag", `{"inbounds":[{"tag":"api","port":10001}]}`, 0, true},
		{"single-untagged-compatibility", `{"inbounds":[{"port":3456}]}`, 3456, false},
		{"protocol-conflict", `{"inbounds":[{"tag":"proxy","port":2345,"protocol":"trojan"}]}`, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, tc.body) }))
			defer srv.Close()
			c, e := NewV2RaySocks(Options{BaseURL: srv.URL, NodeID: "1", NodeType: "vmess"})
			if e != nil {
				t.Fatal(e)
			}
			n, e := c.FetchNode(context.Background())
			if (e != nil) != tc.wantError {
				t.Fatal(n, e)
			}
			if e == nil && n.Config.Port != tc.port {
				t.Fatal(n.Config)
			}
			if tc.name == "proxy-after-api" && (n.Policy == nil || len(n.Policy.Rules) != 1 || n.Policy.Rules[0].Rule != "full:blocked.example" || n.Config.Path != "/proxy") {
				t.Fatal(n)
			}
		})
	}
}
