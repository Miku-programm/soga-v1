package panel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestProxyPanelVMessWire(t *testing.T) {
	reports := map[string]json.RawMessage{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		stamp, err := strconv.ParseInt(r.Header.Get("timestamp"), 10, 64)
		if err != nil || time.Now().Unix()-stamp > 3 || r.Header.Get("key") != "secret" {
			t.Error("bad ProxyPanel auth")
		}
		if r.Method == "POST" {
			var raw json.RawMessage
			if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
				t.Error(err)
			}
			reports[r.URL.Path] = raw
			fmt.Fprint(w, `{"status":"success","code":200,"data":null}`)
			return
		}
		switch r.URL.Path {
		case "/api/v2ray/v1/node/3":
			fmt.Fprint(w, `{"status":"success","code":200,"data":{"v2_port":443,"v2_net":"ws","v2_type":"none","v2_host":"host","v2_path":"/ws","v2_tls":true,"v2_alter_id":2,"speed_limit":1250000}}`)
		case "/api/v2ray/v1/nodeRule/3":
			fmt.Fprint(w, `{"status":"success","code":200,"data":{"mode":"all","rules":[]}}`)
		case "/api/v2ray/v1/userList/3":
			fmt.Fprint(w, `{"status":"success","code":200,"data":[{"uid":9,"vmess_uid":"uuid","speed_limit":250000}],"updateTime":123}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	api, err := NewClient(Options{Type: "proxypanel", BaseURL: server.URL, APIKey: "secret", NodeID: "3", NodeType: "vmess"})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	node, err := api.FetchNode(ctx)
	if err != nil || node.Config.AlterID != 2 || node.Config.Path != "/ws" || node.Basic.SpeedLimit != 10 {
		t.Fatal(node, err)
	}
	users, err := api.FetchUsers(ctx)
	if err != nil || users[0].UUID != "uuid" || users[0].SpeedLimit != 2 {
		t.Fatal(users, err)
	}
	if err := api.ReportTraffic(ctx, []Traffic{{9, 2, 3}}); err != nil {
		t.Fatal(err)
	}
	if got := string(reports["/api/v2ray/v1/userTraffic/3"]); got != `[{"uid":9,"upload":2,"download":3}]` {
		t.Fatal(got)
	}
	if err := api.ReportAliveIPs(ctx, []AliveIP{{9, []string{"::1"}}}); err != nil {
		t.Fatal(err)
	}
	if err := api.ReportStatus(ctx, Status{}); err != nil {
		t.Fatal(err)
	}
	if err := api.(*ProxyPanel).ReportPolicyLog(ctx, ProxyAuditLog{UserID: 9, RuleID: 7, Reason: "match"}); err != nil {
		t.Fatal(err)
	}
	if err := api.ReportAuditLogs(ctx, nil); !errors.Is(err, ErrUnsupported) {
		t.Fatal(err)
	}
}

func TestSSPanelWireAndModernConfig(t *testing.T) {
	reports := map[string]json.RawMessage{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("key") != "secret" || r.URL.Query().Get("node_id") != "4" {
			t.Error("bad SSPanel query")
		}
		if r.Method == "POST" {
			var raw json.RawMessage
			if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
				t.Error(err)
			}
			reports[r.URL.Path] = raw
			fmt.Fprint(w, `{"ret":1,"msg":"ok"}`)
			return
		}
		switch r.URL.Path {
		case "/mod_mu/nodes/4/info":
			fmt.Fprint(w, `{"ret":1,"data":{"sort":11,"node_speedlimit":20,"server":"node.example","custom_config":{"offset_port_node":"8443","security":"tls","network":"ws","host":"example.com","ws-opts":{"path":"/path","headers":{"Host":"cdn.example"}}}}}`)
		case "/mod_mu/users":
			fmt.Fprint(w, `{"ret":1,"data":[{"id":9,"uuid":"uuid","node_speedlimit":5,"node_iplimit":2}]}`)
		case "/mod_mu/func/detect_rules":
			fmt.Fprint(w, `{"ret":1,"data":[]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	api, err := NewClient(Options{Type: "sspanel-uim", BaseURL: server.URL, APIKey: "secret", NodeID: "4", NodeType: "vmess"})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	node, err := api.FetchNode(ctx)
	if err != nil || node.Config.Port != 8443 || node.Config.Host != "cdn.example" || node.Config.ServerNames[0] != "example.com" || node.Config.Path != "/path" {
		t.Fatal(node, err)
	}
	users, err := api.FetchUsers(ctx)
	if err != nil || len(users) != 1 || users[0].DeviceLimit != 2 {
		t.Fatal(users, err)
	}
	if err := api.ReportTraffic(ctx, []Traffic{{9, 2, 3}}); err != nil {
		t.Fatal(err)
	}
	if got := string(reports["/mod_mu/users/traffic"]); got != `{"data":[{"user_id":9,"u":2,"d":3}]}` {
		t.Fatal(got)
	}
	if err := api.ReportAliveIPs(ctx, []AliveIP{{9, []string{"::1"}}}); err != nil {
		t.Fatal(err)
	}
	if got := string(reports["/mod_mu/users/aliveip"]); got != `{"data":[{"user_id":9,"ip":"::1"}]}` {
		t.Fatal(got)
	}
	if err := api.ReportAuditLogs(ctx, []AuditLog{{9, 3}, {9, 3}}); err != nil {
		t.Fatal(err)
	}
	if got := string(reports["/mod_mu/users/detectlog"]); got != `{"data":[{"user_id":9,"list_id":3}]}` {
		t.Fatal(got)
	}
}

func TestLegacySSPanelParsing(t *testing.T) {
	cfg, err := parseLegacySSPanel("vmess", "1.2.3.4;443;0;ws;tls;path=/ray|server=public.example|host=tls.example|inside_port=8443")
	if err != nil || cfg.Port != 8443 || cfg.Path != "/ray" || cfg.TLSType != "tls" {
		t.Fatal(cfg, err)
	}
	cfg, err = parseLegacySSPanel("trojan", "node.example;port=443|host=tls.example")
	if err != nil || cfg.Port != 443 || cfg.Host != "tls.example" {
		t.Fatal(cfg, err)
	}
	if cfg, err := parseLegacySSPanel("trojan", "node.example;port=443#8443"); err != nil || cfg.Port != 8443 {
		t.Fatal(cfg, err)
	}
}

func TestLegacyPanelBadAcknowledgements(t *testing.T) {
	for _, kind := range []string{"proxypanel", "sspanel-uim"} {
		t.Run(kind, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, `{"status":"fail","code":200,"ret":0}`) }))
			defer server.Close()
			api, err := NewClient(Options{Type: kind, BaseURL: server.URL, NodeType: "vmess", NodeID: "1"})
			if err != nil {
				t.Fatal(err)
			}
			if err := api.ReportTraffic(context.Background(), nil); err == nil {
				t.Fatal("failure envelope acknowledged")
			}
			if _, err := api.FetchUsers(context.Background()); err == nil {
				t.Fatal("failure users envelope accepted")
			}
			if strings.Contains(fmt.Sprint(err), "token=") {
				t.Fatal(err)
			}
		})
	}
}

func TestProxyPanelSSRSingleAndMultiplePorts(t *testing.T) {
	for _, single := range []int{0, 1} {
		t.Run(strconv.Itoa(single), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/api/ssr/v1/node/2":
					fmt.Fprintf(w, `{"status":"success","code":200,"data":{"port":"443","single":%d,"passwd":"outer","method":"aes-128-cfb","protocol":"auth_aes128_sha1","protocol_param":"32","obfs":"plain","obfs_param":"","is_udp":1}}`, single)
				case "/api/ssr/v1/nodeRule/2":
					fmt.Fprint(w, `{"status":"success","code":200,"data":{"mode":"all","rules":[]}}`)
				case "/api/ssr/v1/userList/2":
					fmt.Fprint(w, `{"status":"success","code":200,"data":[{"uid":5,"port":1443,"passwd":"inner","method":"aes-256-cfb","protocol":"origin","obfs":"plain","enable":1},{"uid":6,"enable":0}]}`)
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			c, err := NewProxyPanel(Options{BaseURL: server.URL, NodeID: "2", NodeType: "ssr"})
			if err != nil {
				t.Fatal(err)
			}
			n, err := c.FetchNode(context.Background())
			if err != nil || n.Config.MultiUserPorts != (single == 0) || n.Config.Password != "outer" || n.Config.ProtocolParam != "32" {
				t.Fatal(n, err)
			}
			if single == 1 && n.Config.SinglePortType != "protocol" {
				t.Fatal(n)
			}
			u, err := c.FetchUsers(context.Background())
			if err != nil || len(u) != 1 || u[0].ID != 5 || u[0].Password != "inner" || u[0].Port != 1443 || u[0].ProtocolID != 1443 || u[0].Method != "aes-256-cfb" {
				t.Fatal(u, err)
			}
		})
	}
}
