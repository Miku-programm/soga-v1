package panel

import (
	"context"
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSSPanelPasswordCarrierSelection(t *testing.T) {
	users := []User{
		{ID: 1, Port: 1001, Method: "aes-128-gcm", Protocol: "origin", Obfs: "plain"},
		{ID: 2, IsMultiUser: 1, Port: 1002, Method: "aes-128-cfb", Protocol: "origin", Obfs: "plain"},
		{ID: 3, IsMultiUser: 1, Port: 1003, Method: "aes-128-gcm", Protocol: "origin", Obfs: "http_simple"},
		{ID: 4, IsMultiUser: 2, Port: 1004, Method: "aes-256-gcm", Protocol: "origin", Obfs: "plain", Password: "carrier-key"},
		{ID: 5, IsMultiUser: 2, Port: 1005, Method: "aes-128-gcm", Protocol: "origin", Obfs: "plain"},
	}
	cfg := NodeConfig{MultiUserPorts: true}
	if e := applySSPanelPasswordCarrier(&cfg, users); e != nil {
		t.Fatal(e)
	}
	if cfg.Port != 1004 || cfg.Cipher != "aes-256-gcm" || cfg.Password != "carrier-key" || cfg.MultiUserPorts {
		t.Fatal(cfg)
	}
	if e := applySSPanelPasswordCarrier(&cfg, users[:3]); e == nil {
		t.Fatal("accepted without a valid carrier")
	}
	users[3].Port = 65536
	if e := applySSPanelPasswordCarrier(&cfg, users); e == nil {
		t.Fatal("accepted invalid first carrier port")
	}
	for _, method := range []string{"aes-128-gcm", "aes-192-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm"} {
		if !ssPanelAEADMethod(method) {
			t.Fatal(method)
		}
	}
}
func TestSSPanelPasswordCarrierWebAndExplicitPort(t *testing.T) {
	for _, custom := range []string{`{}`, `{"offset_port_node":4321,"mu_encryption":"aes-128-gcm","mu_password":"mu-key"}`, `{"offset_port_node":4322,"method":"aes-256-gcm","server_key":"server-key","mu_encryption":"bad"}`} {
		t.Run(custom, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/mod_mu/nodes/1/info":
					fmt.Fprintf(w, `{"ret":1,"data":{"sort":1,"server":"host;port=1234#2345","custom_config":%s}}`, custom)
				case "/mod_mu/users":
					fmt.Fprint(w, `{"ret":1,"data":[{"id":1,"port":9999,"method":"aes-128-gcm","passwd":"normal"},{"id":2,"port":1234,"method":"aes-128-gcm","passwd":"carrier","protocol":"origin","obfs":"plain","is_multi_user":2}]}`)
				case "/mod_mu/func/detect_rules":
					fmt.Fprint(w, `{"ret":1,"data":[]}`)
				default:
					t.Error(r.URL.Path)
					http.NotFound(w, r)
				}
			}))
			defer srv.Close()
			c, e := NewSSPanel(Options{BaseURL: srv.URL, NodeID: "1", NodeType: "ss"})
			if e != nil {
				t.Fatal(e)
			}
			n, e := c.FetchNode(context.Background())
			if e != nil {
				t.Fatal(e)
			}
			if n.Config.MultiUserPorts {
				t.Fatal("opened ordinary per-user ports")
			}
			switch custom {
			case `{}`:
				if n.Config.Port != 1234 || n.Config.Password != "carrier" {
					t.Fatal(n.Config)
				}
			case `{"offset_port_node":4321,"mu_encryption":"aes-128-gcm","mu_password":"mu-key"}`:
				if n.Config.Port != 4321 || n.Config.Password != "mu-key" {
					t.Fatal(n.Config)
				}
			default:
				if n.Config.Port != 4322 || n.Config.Password != "server-key" {
					t.Fatal(n.Config)
				}
			}
		})
	}
}
func TestSSPanelPasswordCarrierDatabase(t *testing.T) {
	columns := strings.Split(ssUserFields, ", ")
	c := newFixtureDB(t, "sspanel-uim", "shadowsocks", []sqlStep{
		{op: "query", query: ssNodeQuery, columns: []string{"server", "node_speedlimit", "mu_only"}, rows: [][]driver.Value{{"host;port=1234#2345", float64(5), int64(0)}}},
		{op: "query", query: ssNodeEligibility, columns: []string{"limit", "used", "group", "class"}, rows: [][]driver.Value{{int64(0), int64(0), int64(0), int64(0)}}},
		{op: "query", query: "select count(*) from information_schema.columns where table_schema = ? and table_name = 'user' and column_name = 'uuid'", columns: []string{"count"}, rows: [][]driver.Value{{int64(0)}}},
		{op: "query", query: "select " + ssUserFields + " from user where enable = 1 and expire_in > ? and u + d < transfer_enable and (class >= ? or is_admin = 1)", columns: columns, rows: [][]driver.Value{
			{int64(1), "normal", int64(0), int64(0), int64(10000), float64(0), int64(0), int64(9999), "aes-128-gcm", "origin", "", "plain", "", int64(0)},
			{int64(2), "carrier", int64(0), int64(0), int64(10000), float64(0), int64(0), int64(1234), "aes-128-gcm", "origin", "", "plain", "", int64(2)},
		}},
		{op: "query", query: ssDetectQuery, columns: []string{"id", "regex", "type"}},
	})
	n, e := c.FetchNode(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	if n.Config.Port != 1234 || n.Config.Password != "carrier" || n.Config.MultiUserPorts {
		t.Fatal(n.Config)
	}
	var raw map[string]any
	if e = json.Unmarshal(n.RawConfig, &raw); e != nil || raw["server"] != "host;port=1234#2345" {
		t.Fatal(raw, e)
	}
}
