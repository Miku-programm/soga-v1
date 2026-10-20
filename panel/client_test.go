package panel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
)

func newTestClient(t *testing.T, handler http.HandlerFunc) (*Client, *httptest.Server) {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	client, err := NewSogaV1(Options{BaseURL: server.URL + "/custom/", APIKey: "secret", NodeID: "42", NodeType: "vless", HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	return client, server
}

func TestSogaV1WireAndSnapshots(t *testing.T) {
	var usersRequests int
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("API-KEY") != "secret" || r.Header.Get("NODE-ID") != "42" || r.Header.Get("NODE-TYPE") != "vless" {
			t.Errorf("wrong authentication headers: %v", r.Header)
		}
		switch r.URL.Path {
		case "/custom/api/v1/node":
			fmt.Fprint(w, `{"basic":{"pull_interval":13},"config":{"port":443,"stream_type":"ws","tls_type":"reality","server_names":["host"],"short_ids":["ab"],"private_key":"key","path":"/路径","xhttp_settings":{"extra":{"scMaxEachPostBytes":"10-20"}},"future_field":{"x":7}}}`)
		case "/custom/api/v1/users":
			usersRequests++
			if usersRequests == 1 {
				w.Header().Set("ETag", `"users1"`)
				fmt.Fprint(w, `[{"id":1,"uuid":"u1","speed_limit":1.5},{"id":2,"password":"p2"}]`)
			} else if usersRequests == 2 {
				if r.Header.Get("If-None-Match") != `"users1"` {
					t.Error("missing ETag request header")
				}
				w.WriteHeader(http.StatusNotModified)
			} else {
				fmt.Fprint(w, `[{"id":2,"password":"changed"},{"id":3,"username":"新增","tcp_limit":4}]`)
			}
		case "/custom/api/v1/audit_rules":
			fmt.Fprint(w, `[{"id":7,"rule":"domain:example.test"}]`)
		case "/custom/api/v1/white_list":
			fmt.Fprint(w, `["example.test","127.0.0.1"]`)
		default:
			http.NotFound(w, r)
		}
	})
	ctx := context.Background()
	node, err := client.FetchNode(ctx)
	if err != nil || node.Config.Port != 443 || node.Basic.PullInterval != 13 || node.Config.Path != "/路径" || !strings.Contains(string(node.RawConfig), "future_field") || !strings.Contains(string(node.Config.XHTTPSettings), "10-20") {
		t.Fatalf("node = %#v, %v", node, err)
	}
	users, err := client.FetchUsers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var store UserStore
	delta, err := store.Replace(users)
	if err != nil || len(delta.Added) != 2 {
		t.Fatalf("initial delta=%+v err=%v", delta, err)
	}
	users[0].UUID = "poison"
	cached, err := client.FetchUsers(ctx)
	if err != nil || cached[0].UUID != "u1" {
		t.Fatalf("cached=%v err=%v", cached, err)
	}
	delta, err = store.Replace(cached)
	if err != nil || len(delta.Added)+len(delta.Updated)+len(delta.Removed) != 0 {
		t.Fatalf("unchanged delta=%+v err=%v", delta, err)
	}
	users, err = client.FetchUsers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	delta, err = store.Replace(users)
	if err != nil || len(delta.Added) != 1 || delta.Added[0].ID != 3 || len(delta.Updated) != 1 || delta.Updated[0].ID != 2 || len(delta.Removed) != 1 || delta.Removed[0].ID != 1 {
		t.Fatalf("changed delta=%+v err=%v", delta, err)
	}
	before := store.Snapshot()
	if _, err := store.Replace([]User{{ID: 2}, {ID: 2}}); err == nil || !reflect.DeepEqual(before, store.Snapshot()) {
		t.Fatal("duplicate snapshot mutated store")
	}
	delta, err = store.Replace([]User{})
	if err != nil || len(delta.Removed) != 2 {
		t.Fatalf("empty snapshot=%v %v", delta, err)
	}
	audit, err := client.FetchAuditRules(ctx)
	if err != nil || len(audit) != 1 || audit[0].ID != 7 {
		t.Fatalf("audit=%v err=%v", audit, err)
	}
	white, err := client.FetchWhiteList(ctx)
	if err != nil || len(white) != 2 {
		t.Fatalf("white=%v err=%v", white, err)
	}
}

func TestSogaV1Reports(t *testing.T) {
	payloads := make(map[string]json.RawMessage)
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.Header.Get("Content-Type") != "application/json" || r.Header.Get("API-KEY") != "secret" || r.Header.Get("If-None-Match") != "" {
			t.Errorf("bad report request %s %v", r.Method, r.Header)
		}
		var raw json.RawMessage
		if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
			t.Error(err)
		}
		payloads[r.URL.Path] = raw
		fmt.Fprint(w, `{"code":0,"message":""}`)
	})
	ctx := context.Background()
	for _, err := range []error{
		client.ReportTraffic(ctx, []Traffic{{ID: 7, Upload: 9007199254740993, Download: 27}}),
		client.ReportAliveIPs(ctx, []AliveIP{{ID: 7, IPs: []string{"127.0.0.1", "::1"}}}),
		client.ReportAuditLogs(ctx, []AuditLog{{7, 2}, {7, 2}, {8, 2}}),
		client.ReportStatus(ctx, Status{CPU: 0.2, Mem: Usage{Total: 100, Used: 42}, Uptime: 300}),
	} {
		if err != nil {
			t.Fatal(err)
		}
	}
	if got := string(payloads["/custom/api/v1/traffic"]); got != `[{"id":7,"u":9007199254740993,"d":27}]` {
		t.Fatalf("traffic bytes changed: %s", got)
	}
	if got := string(payloads["/custom/api/v1/audit_log"]); got != `[{"user_id":7,"audit_id":2},{"user_id":8,"audit_id":2}]` {
		t.Fatalf("dedup: %s", got)
	}
	if err := client.ReportTraffic(ctx, nil); err != nil || string(payloads["/custom/api/v1/traffic"]) != "[]" {
		t.Fatal("nil report must be an array", err)
	}
}

func TestSogaV1FailureContracts(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		status     int
	}{
		{"noCode", `{}`, 200}, {"null", `null`, 200}, {"malformed", `{"code":`, 200}, {"refused", `{"code":2,"message":"no"}`, 200}, {"http", `{"code":0}`, 500}, {"wrongSuccessStatus", `{"code":0}`, 201},
	} {
		t.Run(tc.name, func(t *testing.T) {
			count := 0
			client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				count++
				w.WriteHeader(tc.status)
				fmt.Fprint(w, tc.body)
			})
			err := client.ReportTraffic(context.Background(), []Traffic{{ID: 1, Upload: 2}})
			if err == nil || count != 1 {
				t.Fatalf("error=%v requests=%d", err, count)
			}
			if tc.name == "refused" {
				var apiErr *APIError
				if !errors.As(err, &apiErr) || apiErr.Code != 2 {
					t.Fatal(err)
				}
			}
		})
	}
	for _, body := range []string{"null", `{}`, `{"users":[]}`, `[] true`} {
		t.Run("users_"+body, func(t *testing.T) {
			client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) })
			if _, err := client.FetchUsers(context.Background()); err == nil {
				t.Fatal("invalid users accepted")
			}
		})
	}
	t.Run("uncached304", func(t *testing.T) {
		client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(304) })
		if _, err := client.FetchUsers(context.Background()); err == nil {
			t.Fatal("uncached 304 accepted")
		}
	})
	t.Run("cancel", func(t *testing.T) {
		client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) { t.Error("cancelled request reached server") })
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := client.FetchUsers(ctx); !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	})
}

func TestETagInvalidResponseDoesNotReplaceSnapshot(t *testing.T) {
	var requests int
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		requests++
		switch requests {
		case 1:
			w.Header().Set("ETag", `"valid"`)
			fmt.Fprint(w, `[{"id":1}]`)
		case 2:
			w.Header().Set("ETag", `"invalid"`)
			fmt.Fprint(w, `null`)
		default:
			if r.Header.Get("If-None-Match") != `"valid"` {
				t.Error("invalid response replaced ETag")
			}
			w.WriteHeader(304)
		}
	})
	if _, err := client.FetchUsers(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := client.FetchUsers(context.Background()); err == nil {
		t.Fatal("null accepted")
	}
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			users, err := client.FetchUsers(context.Background())
			if err != nil || len(users) != 1 {
				t.Errorf("users=%v err=%v", users, err)
			}
		}()
	}
	wg.Wait()
}
