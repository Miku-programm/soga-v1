package panel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWHMCSPluginWire(t *testing.T) {
	reports := map[string]string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if r.URL.Path != "/prefix/web_api/" || q.Get("token") != "a & b" || q.Get("node_id") != "9" || q.Get("node_type") != "v2ray" {
			t.Errorf("bad request path/auth: %s", r.URL.Path)
		}
		if r.Method == "POST" {
			var data json.RawMessage
			if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
				t.Error(err)
			}
			reports[q.Get("act")] = string(data)
			// No invented application ACK: original wrapper ignores this body.
			fmt.Fprint(w, "ok")
			return
		}
		switch q.Get("act") {
		case "config":
			fmt.Fprint(w, `{"inbounds":[{"port":443,"protocol":"vmess","streamingSettings":{"network":"ws","security":"tls","wsSettings":{"path":"/ws"}}}],"routing":{"rules":[]}}`)
		case "user":
			fmt.Fprint(w, `{"msg":"ok","data":[{"id":2,"uuid":"abc","secret":"unused","password":"unused","st":10001,"dt":-1}]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	api, err := NewClient(Options{Type: "whmcs", BaseURL: server.URL + "/prefix/", APIKey: "a & b", NodeID: "9", NodeType: "v2ray"})
	if err != nil {
		t.Fatal(err)
	}
	c := api.(*WHMCS)
	ctx := context.Background()
	n, err := c.FetchNode(ctx)
	if err != nil || n.Config.Path != "/ws" || n.Config.AlterID != 0 || n.Config.TLSType != "tls" || n.Config.Port != 443 {
		t.Fatal(n, err)
	}
	users, err := c.FetchUsers(ctx)
	if err != nil || len(users) != 1 || users[0].UUID != "abc" || users[0].Password != "" || users[0].SpeedLimit != 10000 || users[0].DeviceLimit != 0 {
		t.Fatal(users, err)
	}
	for _, err := range []error{
		c.ReportTraffic(ctx, []Traffic{{2, 9007199254740993, 4}}),
		c.ReportAliveIPs(ctx, []AliveIP{{2, []string{"127.0.0.1", "::1"}}}),
		c.ReportStatus(ctx, Status{CPU: 20.7, Mem: Usage{Total: 100, Used: 33}, Disk: Usage{Total: 10, Used: 4}, Uptime: 25}),
		c.ReportIllegalUsers(ctx, []int64{2}),
	} {
		if err != nil {
			t.Fatal(err)
		}
	}
	want := map[string]string{
		"submit":      `[{"uid":2,"u":9007199254740993,"d":4}]`,
		"onlineusers": `[{"uid":2,"ip":"127.0.0.1"},{"uid":2,"ip":"::1"}]`,
		"nodestatus":  `{"cpu":"21%","mem":"33%","net":"","disk":"40%","uptime":25}`,
		"illegal":     `[{"uid":2}]`,
	}
	for action, value := range want {
		if reports[action] != value {
			t.Fatalf("%s: %s", action, reports[action])
		}
	}
	if err := c.ReportAuditLogs(ctx, nil); !errors.Is(err, ErrUnsupported) {
		t.Fatal(err)
	}
}

func TestWHMCSCredentialsAndRejection(t *testing.T) {
	for _, protocol := range []string{"shadowsocks", "trojan"} {
		t.Run(protocol, func(t *testing.T) {
			status := 200
			body := `{"msg":"ok","data":[{"id":4,"uuid":"uuid","secret":"secret","password":"password","dt":3,"st":-1}]}`
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Query().Get("node_type") != protocol {
					t.Error("incorrect protocol name")
				}
				w.WriteHeader(status)
				fmt.Fprint(w, body)
			}))
			defer s.Close()
			c, err := NewWHMCS(Options{BaseURL: s.URL, NodeID: "1", NodeType: protocol})
			if err != nil {
				t.Fatal(err)
			}
			users, err := c.FetchUsers(context.Background())
			password := "password"
			if protocol == "shadowsocks" {
				password = "secret"
			}
			if err != nil || users[0].Password != password || users[0].SpeedLimit != 0 || users[0].DeviceLimit != 3 {
				t.Fatal(users, err)
			}
			body = `{"msg":"failed","data":[]}`
			if _, err = c.FetchUsers(context.Background()); err == nil {
				t.Fatal("failed message accepted")
			}
			body = `{"inbounds":[]}`
			if _, err = c.FetchNode(context.Background()); err == nil {
				t.Fatal("empty inbound accepted")
			}
			status = 500
			if err := c.ReportTraffic(context.Background(), nil); err == nil {
				t.Fatal("failed HTTP report accepted")
			}
		})
	}
}
