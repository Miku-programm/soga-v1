package panel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPPanelV1Wire(t *testing.T) {
	seen := map[string]json.RawMessage{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("secret_key") != "secret&key" || q.Get("server_id") != "9" || q.Get("protocol") != "vless" {
			t.Error("bad PPanel query")
		}
		switch r.URL.Path {
		case "/custom/v1/server/config":
			fmt.Fprint(w, `{"basic":{"pull_interval":21,"push_interval":22},"protocol":"vless","config":{"port":443,"transport":"grpc","transport_config":{"service_name":"myservice"},"security":"reality","security_config":{"sni":"example.com","reality_server_addr":"example.com","reality_server_port":443,"reality_private_key":"key","reality_short_id":"ab"},"flow":"xtls-rprx-vision"}}`)
		case "/custom/v1/server/user":
			fmt.Fprint(w, `{"users":[{"id":7,"uuid":"myuuid","speed_limit":20,"device_limit":1}]}`)
		default:
			if r.Method != "POST" {
				t.Error("unexpected GET")
			}
			var raw json.RawMessage
			if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
				t.Error(err)
			}
			seen[r.URL.Path] = raw
			fmt.Fprint(w, `{"code":200,"msg":"success","data":null}`)
		}
	}))
	defer server.Close()
	api, err := NewClient(Options{Type: "ppanel", BaseURL: server.URL + "/custom/", APIKey: "secret&key", NodeID: "9", NodeType: "vless"})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	node, err := api.FetchNode(ctx)
	if err != nil || node.Config.ServiceName != "myservice" || node.Config.Dest != "example.com:443" || node.Basic.PushInterval != 22 {
		t.Fatal(node, err)
	}
	users, err := api.FetchUsers(ctx)
	if err != nil || len(users) != 1 || users[0].Password != "myuuid" || users[0].DeviceLimit != 1 {
		t.Fatal(users, err)
	}
	if err := api.ReportTraffic(ctx, []Traffic{{7, 15, 26}}); err != nil {
		t.Fatal(err)
	}
	if got := string(seen["/custom/v1/server/push"]); got != `{"traffic":[{"uid":7,"upload":15,"download":26}]}` {
		t.Fatal(got)
	}
	if err := api.ReportAliveIPs(ctx, []AliveIP{{7, []string{"::1", "127.0.0.1"}}}); err != nil {
		t.Fatal(err)
	}
	if got := string(seen["/custom/v1/server/online"]); got != `{"users":[{"uid":7,"ip":"::1"},{"uid":7,"ip":"127.0.0.1"}]}` {
		t.Fatal(got)
	}
	if err := api.ReportStatus(ctx, Status{CPU: 12.5, Mem: Usage{100, 25}, Disk: Usage{100, 50}}); err != nil {
		t.Fatal(err)
	}
	if got := string(seen["/custom/v1/server/status"]); !strings.Contains(got, `"mem":25`) || !strings.Contains(got, `"disk":50`) {
		t.Fatal(got)
	}
	if err := api.ReportAuditLogs(ctx, nil); !errors.Is(err, ErrUnsupported) {
		t.Fatal(err)
	}
}

func TestPPanelFailureEnvelope(t *testing.T) {
	for _, body := range []string{`{}`, `{"code":0}`, `{"code":403,"msg":"denied"}`} {
		t.Run(body, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) }))
			defer server.Close()
			api, err := NewClient(Options{Type: "ppanel", BaseURL: server.URL, NodeID: "9", NodeType: "vmess"})
			if err != nil {
				t.Fatal(err)
			}
			if err := api.ReportTraffic(context.Background(), nil); err == nil {
				t.Fatal("invalid PPanel ACK accepted")
			}
			if _, err := api.FetchNode(context.Background()); err == nil {
				t.Fatal("error envelope parsed as node")
			}
		})
	}
}
