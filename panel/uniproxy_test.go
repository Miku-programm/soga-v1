package panel

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestUniProxyXboardWire(t *testing.T) {
	var push map[string][2]int64
	var alive map[string][]string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("token") != "a+b&secret" || r.URL.Query().Get("node_id") != "42" || r.URL.Query().Get("node_type") != "vless" {
			t.Errorf("auth query wrong")
		}
		if r.Header.Get("API-KEY") != "" {
			t.Error("soga-v1 header leaked to UniProxy")
		}
		switch r.URL.Path {
		case "/prefix/api/v1/server/UniProxy/config":
			fmt.Fprint(w, `{"protocol":"vless","server_port":443,"network":"ws","networkSettings":{"path":"/hello","headers":{"Host":"host"}},"tls":2,"tls_settings":{"server_name":"example.com","server_port":"8443","private_key":"private","short_id":"abcd"},"flow":"xtls-rprx-vision","base_config":{"pull_interval":10,"push_interval":15},"custom_routes":[{"action":"reject"}]}`)
		case "/prefix/api/v1/server/UniProxy/user":
			fmt.Fprint(w, `{"users":[{"id":2,"uuid":"uuid","speed_limit":5,"device_limit":2}]}`)
		case "/prefix/api/v1/server/UniProxy/push":
			if err := json.NewDecoder(r.Body).Decode(&push); err != nil {
				t.Error(err)
			}
			fmt.Fprint(w, `{"status":"success","data":true}`)
		case "/prefix/api/v1/server/UniProxy/alive":
			if err := json.NewDecoder(r.Body).Decode(&alive); err != nil {
				t.Error(err)
			}
			fmt.Fprint(w, `{"data":true}`)
		case "/prefix/api/v1/server/UniProxy/alivelist":
			fmt.Fprint(w, `{"alive":{"2":3}}`)
		case "/prefix/api/v1/server/UniProxy/status":
			fmt.Fprint(w, `{"data":true,"code":0}`)
		default:
			t.Errorf("unexpected endpoint %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	api, err := NewClient(Options{Type: "xboard", BaseURL: server.URL + "/prefix", APIKey: "a+b&secret", NodeID: "42", NodeType: "vless", HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	node, err := api.FetchNode(ctx)
	if err != nil || node.Config.Dest != "example.com:8443" || node.Config.TLSType != "reality" || node.Config.PrivateKey != "private" || node.Config.Path != "/hello" || node.Config.Host != "host" || node.Basic.PushInterval != 15 || len(node.UnsupportedOptions) != 1 {
		t.Fatalf("node=%+v err=%v", node, err)
	}
	users, err := api.FetchUsers(ctx)
	if err != nil || len(users) != 1 || users[0].Password != "uuid" || users[0].DeviceLimit != 2 {
		t.Fatalf("users=%v err=%v", users, err)
	}
	if err := api.ReportTraffic(ctx, []Traffic{{2, 20, 30}, {2, 4, 5}, {3, 7, 8}}); err != nil {
		t.Fatal(err)
	}
	if push["2"] != [2]int64{24, 35} || push["3"] != [2]int64{7, 8} {
		t.Fatal(push)
	}
	if err := api.ReportAliveIPs(ctx, []AliveIP{{2, []string{"::1"}}}); err != nil || len(alive["2"]) != 1 {
		t.Fatal(err, alive)
	}
	counts, err := api.(*UniProxy).FetchAliveCounts(ctx)
	if err != nil || counts[2] != 3 {
		t.Fatal(counts, err)
	}
	if err := api.ReportStatus(ctx, Status{}); err != nil {
		t.Fatal(err)
	}
	if _, err := api.FetchAuditRules(ctx); !errors.Is(err, ErrUnsupported) {
		t.Fatal(err)
	}
	if _, err := api.FetchWhiteList(ctx); !errors.Is(err, ErrUnsupported) {
		t.Fatal(err)
	}
	if err := api.ReportAuditLogs(ctx, nil); !errors.Is(err, ErrUnsupported) {
		t.Fatal(err)
	}
	if err := api.ReportTraffic(ctx, []Traffic{{2, math.MaxInt64, 0}, {2, 1, 0}}); err == nil {
		t.Fatal("overflow accepted")
	}
}

func TestUniProxyTransportErrorRedactsQueryToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	server.Close()
	api, err := NewClient(Options{Type: "xboard", BaseURL: server.URL, APIKey: "must-not-appear", NodeID: "1", NodeType: "vmess"})
	if err != nil {
		t.Fatal(err)
	}
	for _, call := range []func() error{
		func() error { _, err := api.FetchUsers(context.Background()); return err },
		func() error { return api.ReportTraffic(context.Background(), nil) },
	} {
		err := call()
		if err == nil || strings.Contains(err.Error(), "must-not-appear") || strings.Contains(err.Error(), "token=") {
			t.Fatalf("unsafe transport error %v", err)
		}
	}
}

func TestUniProxyV2BoardSS2022(t *testing.T) {
	id := "12345678-1234-1234-1234-123456789abc"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case uniPath + "/config":
			fmt.Fprint(w, `{"server_port":4567,"cipher":"2022-blake3-aes-128-gcm","server_key":"serverbase64","base_config":{"pull_interval":60,"push_interval":60}}`)
		case uniPath + "/user":
			fmt.Fprintf(w, `{"users":[{"id":1,"uuid":%q}]}`, id)
		default:
			t.Fatal("unsupported operation performed a request")
		}
	}))
	defer server.Close()
	api, err := NewClient(Options{Type: "v2board", BaseURL: server.URL, NodeID: "1", NodeType: "ss"})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := api.FetchUsers(ctx); err == nil {
		t.Fatal("SS credentials generated before cipher was known")
	}
	node, err := api.FetchNode(ctx)
	if err != nil || node.Config.Password != "serverbase64" {
		t.Fatal(node, err)
	}
	users, err := api.FetchUsers(ctx)
	if err != nil || users[0].Password != base64.StdEncoding.EncodeToString([]byte(id[:16])) {
		t.Fatal(users, err)
	}
	if err := api.ReportAliveIPs(ctx, nil); !errors.Is(err, ErrUnsupported) {
		t.Fatal(err)
	}
	if err := api.ReportStatus(ctx, Status{}); !errors.Is(err, ErrUnsupported) {
		t.Fatal(err)
	}
}

func TestUniProxyRejectsFalseAck(t *testing.T) {
	for _, body := range []string{`{}`, `{"data":false}`, `{"data":true,"code":9}`, `null`} {
		t.Run(body, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) }))
			defer server.Close()
			api, err := NewClient(Options{Type: "xboard", BaseURL: server.URL, NodeID: "1", NodeType: "vmess"})
			if err != nil {
				t.Fatal(err)
			}
			if err := api.ReportTraffic(context.Background(), nil); err == nil {
				t.Fatal("invalid ACK accepted")
			}
		})
	}
}
