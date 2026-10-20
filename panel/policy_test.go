package panel

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSSPanelPolicyPrefixesAndIgnoredType(t *testing.T) {
	rules := []DetectRule{{ID: 1, Regex: `example\.com`, Type: 99}, {ID: 2, Regex: "domain:example.com", Type: 1}, {ID: 3, Regex: "ip:10.0.0.0/8"}, {ID: 4, Regex: "keyword:ads"}, {ID: 5, Regex: "geosite:cn"}, {ID: 6, Regex: "port:25"}, {ID: 7, Regex: "unknown:literal"}}
	p := SSPanelPolicy(rules)
	if p.Mode != "reject" || len(p.Rules) != 7 {
		t.Fatal(p)
	}
	for i, r := range rules {
		want := r.Regex
		if i == 0 || i == 6 {
			want = "regexp:" + want
		}
		if p.Rules[i].Rule != want || p.Rules[i].ID != int64(r.ID) {
			t.Fatal(p.Rules)
		}
	}
}
func TestSSPanelLegacySSRAndCarriers(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/mod_mu/nodes/1/info":
			fmt.Fprint(w, `{"ret":1,"data":{"server":"host","mu_only":1,"custom_config":{"offset_port_node":"9000","mu_port":"9001","mu_password":"outer","mu_encryption":"aes-128-cfb","mu_protocol":"auth_aes128_md5","mu_obfs":"plain"}}}`)
		case "/mod_mu/users":
			fmt.Fprint(w, `{"ret":1,"data":[{"id":4,"passwd":"inner","port":1004,"method":"aes-256-cfb","protocol":"origin","obfs":"plain","is_multi_user":0,"node_connector":3},{"id":5,"passwd":"outer","port":9002,"method":"aes-128-cfb","protocol":"auth_aes128_md5","obfs":"plain","is_multi_user":2}]}`)
		case "/mod_mu/func/detect_rules":
			fmt.Fprint(w, `{"ret":1,"data":[{"id":0,"regex":"full:bad.example","type":3}]}`)
		default:
			t.Errorf("unexpected path%s", r.URL.Path)
		}
	}))
	defer srv.Close()
	c, e := NewSSPanel(Options{BaseURL: srv.URL, NodeID: "1", NodeType: "ssr"})
	if e != nil {
		t.Fatal(e)
	}
	n, e := c.FetchNode(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	if !n.Config.MultiUserPorts || !n.Config.OnlyMultiUserPorts || len(n.Carriers) != 1 || n.Carriers[0].Port != 9001 || n.Carriers[0].IsMultiUser != 2 || n.Policy.Rules[0].Rule != "full:bad.example" {
		t.Fatalf("%+v", n)
	}
	users, e := c.FetchUsers(context.Background())
	if e != nil || len(users) != 2 || users[0].DeviceLimit != 3 || users[1].IsMultiUser != 2 {
		t.Fatalf("%+v %v", users, e)
	}
	if users[0].UUID != SSPanelLegacyUUID(4, "inner") {
		t.Fatal(users)
	}
	cfg, e := parseLegacySSPanel("shadowsocksr", "host;port=1234#offset|soga_port=444|soga_port=555")
	if e != nil || cfg.LegacyPort != 1234 || cfg.LegacySogaPort != 444 || !cfg.MultiUserPorts {
		t.Fatalf("%+v %v", cfg, e)
	}
}
func TestProxyPolicyReportZeroID(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var v ProxyAuditLog
		if e := json.NewDecoder(r.Body).Decode(&v); e != nil {
			t.Error(e)
		}
		if v.RuleID != 0 || v.UserID != 4 || v.Reason != "无" || v.Target != "example.com:443" {
			t.Errorf("%+v", v)
		}
		fmt.Fprint(w, `{"code":200,"status":"success"}`)
	}))
	defer s.Close()
	c, e := NewProxyPanel(Options{BaseURL: s.URL, NodeID: "1", NodeType: "vmess"})
	if e != nil {
		t.Fatal(e)
	}
	if e = c.ReportPolicyDenials(context.Background(), []PolicyDenial{{UserID: 4, RuleID: 0, Target: "example.com:443"}}); e != nil {
		t.Fatal(e)
	}
}

func TestSSPanelPortPrecedenceAndTrojanOffset(t *testing.T) {
	for _, tc := range []struct {
		protocol, custom string
		port             int
	}{
		{"vmess", `{"offset_port_user":"9001","offset_port_node":"9002","v2_port":"9003","alter_id":"4","servicename":"svc"}`, 9003},
		{"vmess", `{"offset_port_user":"9001","offset_port_node":"0"}`, 9001},
		{"trojan", `{"offset_port_user":"9001","offset_port_node":"9002","trojan_port":"9004"}`, 9004},
		{"trojan", `{"offset_port_user":"9001","offset_port_node":"9002"}`, 9002},
	} {
		t.Run(tc.protocol+tc.custom, func(t *testing.T) {
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/mod_mu/func/detect_rules" {
					fmt.Fprint(w, `{"ret":1,"data":[]}`)
				} else {
					fmt.Fprintf(w, `{"ret":1,"data":{"custom_config":%s}}`, tc.custom)
				}
			}))
			defer s.Close()
			c, err := NewSSPanel(Options{BaseURL: s.URL, NodeID: "1", NodeType: tc.protocol})
			if err != nil {
				t.Fatal(err)
			}
			n, err := c.FetchNode(context.Background())
			if err != nil || n.Config.Port != tc.port {
				t.Fatalf("%+v %v", n, err)
			}
			if tc.port == 9003 && (n.Config.AlterID != 4 || n.Config.ServiceName != "svc") {
				t.Fatal(n)
			}
		})
	}
	for _, tc := range []struct {
		server string
		port   int
	}{{"example.com", 443}, {"example.com;port=443#8443", 8443}, {"example.com;port=443", 443}, {"example.com;port=0", 443}} {
		cfg, err := parseLegacySSPanel("trojan", tc.server)
		if err != nil || cfg.Port != tc.port {
			t.Fatal(tc, cfg, err)
		}
	}
}
