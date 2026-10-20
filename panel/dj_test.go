package panel

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDJFormSnapshotAndPendingTraffic(t *testing.T) {
	calls := 0
	bad := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			t.Errorf("wrong form method/type")
		}
		r.ParseForm()
		if r.Form.Get("secret") != "token" {
			t.Errorf("auth")
		}
		if r.URL.RawQuery != "" {
			t.Errorf("query credentials")
		}
		switch r.URL.Path {
		case "/sub_server/get_config":
			calls++
			if calls == 1 {
				fmt.Fprint(w, `{"inbounds":[{"port":1},{"port":8443,"settings":{"clients":[{"id":"uuid","email":"test@example.com","alterId":4}]}}]}`)
			} else {
				fmt.Fprint(w, `{"inbounds":[{}, {"port":8443,"settings":{"clients":[]}}]}`)
			}
		case "/sub_server/submit_traffic":
			var got map[string]struct{ Upload, Download int64 }
			if err := json.Unmarshal([]byte(r.Form.Get("email_traffic")), &got); err != nil {
				t.Error(err)
			}
			if v := got["test@example.com"]; v.Upload != 9 || v.Download != 12 {
				t.Errorf("traffic %+v", got)
			}
			if bad {
				w.WriteHeader(503)
			}
		case "/sub_server/submit_info":
			var got map[string]json.RawMessage
			if err := json.Unmarshal([]byte(r.Form.Get("status")), &got); err != nil {
				t.Error(err)
			}
			if string(got["v2"]) != `{"code":0}` {
				t.Errorf("DJ v2 indicator: %s", got["v2"])
			}
			if string(got["uptime"]) != "30" {
				t.Errorf("status %s", got["uptime"])
			}
		default:
			t.Errorf("path %s", r.URL.Path)
		}
	}))
	defer srv.Close()
	api, err := NewClient(Options{Type: "dj", BaseURL: srv.URL, APIKey: "token", NodeID: "1", NodeType: "vmess"})
	if err != nil {
		t.Fatal(err)
	}
	c := api.(*DJ)
	ctx := context.Background()
	n, err := c.FetchNode(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n.Config.Port != 8443 || n.Config.Path != "/ws" || n.Config.TLSType != "tls" || n.Config.AlterID != -1 {
		t.Fatalf("node %+v", n)
	}
	users, err := c.FetchUsers(ctx)
	if err != nil || len(users) != 1 || calls != 1 {
		t.Fatalf("users %+v %v calls%d", users, err, calls)
	}
	if users[0].ID != 1431318336 || users[0].AlterID != 4 {
		t.Fatalf("user %+v", users[0])
	}
	users, err = c.FetchUsers(ctx)
	if err != nil || len(users) != 0 || calls != 2 {
		t.Fatalf("removed users %+v %v", users, err)
	}
	rows := []Traffic{{ID: 1431318336, Upload: 4, Download: 5}, {ID: 1431318336, Upload: 5, Download: 7}}
	if err = c.ReportTraffic(ctx, rows); err != nil {
		t.Fatal(err)
	}
	bad = true
	if err = c.ReportTraffic(ctx, rows); err == nil {
		t.Fatal("HTTP failure acknowledged")
	}
	if err = c.ReportTraffic(ctx, []Traffic{{ID: 5, Upload: 1}}); err == nil {
		t.Fatal("unknown identity discarded")
	}
	if err = c.ReportStatus(ctx, Status{Uptime: 30}); err != nil {
		t.Fatal(err)
	}
}
func TestDJRejectMissingInboundAndDuplicates(t *testing.T) {
	for _, body := range []string{`{"inbounds":[{"port":1}]}`, `{"inbounds":[{}, {"port":8443,"settings":{"clients":[{"id":"a","email":"same"},{"id":"b","email":"same"}]}}]}`} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) }))
		c, _ := NewDJ(Options{BaseURL: srv.URL, NodeID: "1", NodeType: "vmess"})
		_, err := c.FetchUsers(context.Background())
		srv.Close()
		if err == nil {
			t.Fatal("malformed config accepted", body)
		}
	}
	if _, err := NewDJ(Options{NodeType: "trojan"}); err == nil || !strings.Contains(err.Error(), "VMess") {
		t.Fatal(err)
	}
}
