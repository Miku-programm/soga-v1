package panel

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	mysql "github.com/go-sql-driver/mysql"
)

// SOGA_TEST_MYSQL_DSN enables this real-server integration test. It must name a
// disposable loopback TCP server whose synthetic account may create/drop test
// databases and triggers. Only newly generated soga_live_* databases are touched;
// an existing DB selected by the DSN is never used as a fixture or dropped.
// Example: test:password@tcp(127.0.0.1:3307)/?parseTime=true
func TestMySQLLive(t *testing.T) {
	dsn := os.Getenv("SOGA_TEST_MYSQL_DSN")
	if dsn == "" {
		t.Skip("SOGA_TEST_MYSQL_DSN is unset: real MySQL/MariaDB integration was NOT executed")
	}
	cfg, err := mysql.ParseDSN(dsn)
	if err != nil {
		t.Fatal("invalid SOGA_TEST_MYSQL_DSN")
	}
	host, portText, err := net.SplitHostPort(cfg.Addr)
	if err != nil || cfg.Net != "tcp" || (host != "localhost" && !net.ParseIP(host).IsLoopback()) {
		t.Fatal("live tests require a disposable loopback TCP MySQL server")
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal("invalid test server port")
	}
	cfg.DBName = ""
	cfg.ParseTime = true
	cfg.Timeout, cfg.ReadTimeout, cfg.WriteTimeout = 5*time.Second, 15*time.Second, 15*time.Second
	admin, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { admin.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err = admin.PingContext(ctx); err != nil {
		t.Fatalf("real database unavailable: %v", err)
	}
	var version string
	if err = admin.QueryRowContext(ctx, "SELECT VERSION()").Scan(&version); err != nil {
		t.Fatal(err)
	}
	t.Log("real database version:", version)
	for _, kind := range []string{"sspanel-uim", "whmcs"} {
		for _, protocol := range []string{"vmess", "trojan", "shadowsocks", "shadowsocksr"} {
			t.Run(kind+"/"+protocol, func(t *testing.T) {
				var random [8]byte
				if _, err := rand.Read(random[:]); err != nil {
					t.Fatal(err)
				}
				database := "soga_live_" + hex.EncodeToString(random[:])
				liveExec(t, ctx, admin, "CREATE DATABASE `"+database+"` CHARACTER SET utf8mb4")
				t.Cleanup(func() {
					cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
					defer stop()
					if _, err := admin.ExecContext(cleanup, "DROP DATABASE `"+database+"`"); err != nil {
						t.Errorf("remove generated database %s: %v", database, err)
					}
				})
				client, err := NewMySQL(Options{Type: kind, NodeType: protocol, NodeID: "7"}, MySQLOptions{
					Host: host, Port: port, Database: database, User: cfg.User, Password: cfg.Passwd,
					TrafficRate: 1.5, MaxOpenConns: 2, MaxIdleConns: 2,
					LocalNode: NodeConfig{Port: 18000, Method: "aes-128-cfb", Password: "synthetic-carrier",
						Protocol: "auth_chain_b", Obfs: "plain"},
				})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { client.Close() })
				seedLivePanel(t, ctx, client.db, kind, protocol)
				liveFetch(t, ctx, client, kind, protocol)
				liveTraffic(t, ctx, client, kind, protocol)
				if kind == "sspanel-uim" {
					liveReports(t, ctx, client)
					liveEligibility(t, ctx, client, protocol)
				} else {
					for name, err := range map[string]error{
						"online": client.ReportAliveIPs(ctx, []AliveIP{{ID: 101, IPs: []string{"192.0.2.1"}}}),
						"audit":  client.ReportAuditLogs(ctx, []AuditLog{{UserID: 101, AuditID: 9}}),
						"status": client.ReportStatus(ctx, Status{Uptime: 100}),
					} {
						if !errors.Is(err, ErrUnsupported) {
							t.Fatalf("WHMCS %s should remain unsupported: %v", name, err)
						}
					}
				}
			})
		}
	}
}

func liveExec(t *testing.T, ctx context.Context, db *sql.DB, query string, args ...any) {
	t.Helper()
	if _, err := db.ExecContext(ctx, query, args...); err != nil {
		t.Fatalf("synthetic fixture SQL %q: %v", query, err)
	}
}

func liveNumber(t *testing.T, ctx context.Context, db *sql.DB, query string, args ...any) int64 {
	t.Helper()
	var n int64
	if err := db.QueryRowContext(ctx, query, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func seedLivePanel(t *testing.T, ctx context.Context, db *sql.DB, kind, protocol string) {
	t.Helper()
	for _, ddl := range []string{
		"CREATE TABLE user (id BIGINT PRIMARY KEY, pid BIGINT NOT NULL UNIQUE, passwd VARCHAR(128), uuid VARCHAR(64), u BIGINT NOT NULL DEFAULT 10, d BIGINT NOT NULL DEFAULT 20, t BIGINT NOT NULL DEFAULT 0, transfer_enable BIGINT NOT NULL DEFAULT 100000, enable INT NOT NULL DEFAULT 1, expire_in DATETIME NOT NULL DEFAULT '2099-01-01 00:00:00', class INT NOT NULL DEFAULT 3, node_group INT NOT NULL DEFAULT 3, is_admin INT NOT NULL DEFAULT 0, node_speedlimit DOUBLE NOT NULL DEFAULT 32, speedlimitss BIGINT NOT NULL DEFAULT 48, node_connector BIGINT NOT NULL DEFAULT 2, port BIGINT NOT NULL, method VARCHAR(64) NOT NULL DEFAULT 'aes-128-cfb', protocol VARCHAR(64) NOT NULL DEFAULT 'origin', protocol_param VARCHAR(128) NOT NULL DEFAULT '', obfs VARCHAR(64) NOT NULL DEFAULT 'plain', obfs_param VARCHAR(128) NOT NULL DEFAULT '', is_multi_user INT NOT NULL DEFAULT 0) ENGINE=InnoDB",
		"CREATE TABLE ss_node (id BIGINT PRIMARY KEY, server TEXT NOT NULL, node_speedlimit DOUBLE NOT NULL DEFAULT 12, mu_only INT NOT NULL DEFAULT 0, node_bandwidth_limit BIGINT NOT NULL DEFAULT 1000000, node_bandwidth BIGINT NOT NULL DEFAULT 100, node_group BIGINT NOT NULL DEFAULT 2, node_class BIGINT NOT NULL DEFAULT 2, traffic_rate DOUBLE NOT NULL DEFAULT 1.5) ENGINE=InnoDB",
		"CREATE TABLE detect_list (id BIGINT PRIMARY KEY, regex TEXT, `type` INT) ENGINE=InnoDB",
		"CREATE TABLE ss_node_online_log (node_id BIGINT, online_user BIGINT, log_time BIGINT) ENGINE=InnoDB",
		"CREATE TABLE alive_ip (nodeid BIGINT, userid BIGINT, ip VARCHAR(45), datetime BIGINT) ENGINE=InnoDB",
		"CREATE TABLE detect_log (user_id BIGINT, list_id BIGINT, datetime BIGINT, node_id BIGINT) ENGINE=InnoDB",
		"CREATE TABLE ss_node_info (node_id BIGINT, uptime BIGINT, `load` VARCHAR(128), log_time BIGINT) ENGINE=InnoDB",
		"CREATE TABLE user_traffic_log (user_id BIGINT, u BIGINT, d BIGINT, node_id BIGINT, rate DOUBLE, traffic VARCHAR(64), log_time BIGINT) ENGINE=InnoDB",
	} {
		liveExec(t, ctx, db, ddl)
	}
	for _, id := range []int64{101, 202} {
		liveExec(t, ctx, db, "INSERT INTO user(id,pid,passwd,uuid,port) VALUES(?,?,?,?,?)", id, id*10+1,
			fmt.Sprintf("synthetic-password-%d", id), fmt.Sprintf("00000000-0000-4000-8000-%012d", id), 10000+id)
	}
	liveExec(t, ctx, db, "INSERT INTO user(id,pid,passwd,uuid,port,enable) VALUES(303,3031,'disabled','disabled',10303,0)")
	liveExec(t, ctx, db, "INSERT INTO user(id,pid,passwd,uuid,port,transfer_enable) VALUES(404,4041,'exhausted','exhausted',10404,30)")
	server := "node.example;18000;0;tcp;none"
	if protocol == "trojan" {
		server = "node.example;port=18000|host=node.example"
	} else if protocol == "shadowsocks" || protocol == "shadowsocksr" {
		server = "node.example"
	}
	liveExec(t, ctx, db, "INSERT INTO ss_node(id,server) VALUES(7,?)", server)
	liveExec(t, ctx, db, "INSERT INTO detect_list(id,regex,`type`) VALUES(9,'blocked[.]example',1)")
	if kind == "sspanel-uim" {
		// Actual SSPanel SS carrier selection needs an AEAD+origin+plain carrier.
		liveExec(t, ctx, db, "INSERT INTO user(id,pid,passwd,uuid,port,method,is_multi_user) VALUES(900,9001,'synthetic-carrier','00000000-0000-4000-8000-000000000900',19000,'aes-128-gcm',1)")
	} else {
		liveExec(t, ctx, db, "INSERT INTO user(id,pid,passwd,uuid,port) VALUES(505,5051,NULL,NULL,10505)")
	}
}

func liveFetch(t *testing.T, ctx context.Context, c *MySQL, kind, protocol string) {
	t.Helper()
	node, err := c.FetchNode(ctx)
	if err != nil {
		t.Fatal("FetchNode:", err)
	}
	if kind == "whmcs" && node.Config.Port != 18000 {
		t.Fatalf("WHMCS local node port=%d", node.Config.Port)
	}
	if kind == "sspanel-uim" && protocol == "shadowsocks" &&
		(node.Config.Port != 19000 || node.Config.Password != "synthetic-carrier" || node.Config.Method != "aes-128-gcm") {
		t.Fatalf("SSPanel SS carrier was not selected: %+v", node.Config)
	}
	users, err := c.FetchUsers(ctx)
	if err != nil {
		t.Fatal("FetchUsers:", err)
	}
	wantCount := 2
	if kind == "sspanel-uim" {
		wantCount = 3
	}
	if len(users) != wantCount {
		t.Fatalf("eligible users=%d want %d: %+v", len(users), wantCount, users)
	}
	wantID := int64(101)
	if kind == "whmcs" && protocol == "shadowsocksr" {
		wantID = 1011
	}
	var found *User
	for i := range users {
		if users[i].ID == wantID {
			found = &users[i]
		}
	}
	if found == nil {
		t.Fatalf("missing billing ID %d", wantID)
	}
	if kind == "whmcs" && protocol == "shadowsocksr" && found.ProtocolID != 10101 {
		t.Fatalf("WHMCS SSR protocol UID=%d (billing ID must remain pid=%d)", found.ProtocolID, found.ID)
	}
	if protocol == "vmess" && found.UUID != "00000000-0000-4000-8000-000000000101" {
		t.Fatal("UUID row conversion changed")
	}
	if protocol == "trojan" && found.Password != "00000000-0000-4000-8000-000000000101" {
		t.Fatal("Trojan password row conversion changed")
	}
}

func liveTraffic(t *testing.T, ctx context.Context, c *MySQL, kind, protocol string) {
	t.Helper()
	one, two := int64(101), int64(202)
	if kind == "whmcs" && protocol == "shadowsocksr" {
		one, two = 1011, 2021
	}
	if err := c.ReportTraffic(ctx, []Traffic{{ID: one, Upload: 3, Download: 5}, {ID: one, Upload: 2, Download: 4}, {ID: two, Upload: 7, Download: 11}}); err != nil {
		t.Fatal("traffic commit:", err)
	}
	for _, row := range []struct{ id, up, down int64 }{{101, 17, 33}, {202, 20, 36}} {
		if liveNumber(t, ctx, c.db, "SELECT u FROM user WHERE id=?", row.id) != row.up ||
			liveNumber(t, ctx, c.db, "SELECT d FROM user WHERE id=?", row.id) != row.down ||
			liveNumber(t, ctx, c.db, "SELECT t FROM user WHERE id=?", row.id) == 0 {
			t.Fatal("committed traffic has wrong u/d/rate or timestamp")
		}
	}
	if kind == "sspanel-uim" {
		if liveNumber(t, ctx, c.db, "SELECT node_bandwidth FROM ss_node WHERE id=7") != 132 ||
			liveNumber(t, ctx, c.db, "SELECT online_user FROM ss_node_online_log") != 2 ||
			liveNumber(t, ctx, c.db, "SELECT COUNT(*) FROM user_traffic_log") != 2 ||
			liveNumber(t, ctx, c.db, "SELECT u FROM user_traffic_log WHERE user_id=101") != 5 {
			t.Fatal("raw node bandwidth, online count or traffic log changed")
		}
	}
	// Reject the second update after the first has really changed an InnoDB row.
	liveExec(t, ctx, c.db, "CREATE TRIGGER fail_second_user BEFORE UPDATE ON user FOR EACH ROW BEGIN IF NEW.id=202 THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='synthetic rollback'; END IF; END")
	if err := c.ReportTraffic(ctx, []Traffic{{ID: one, Upload: 100, Download: 200}, {ID: two, Upload: 1, Download: 1}}); err == nil {
		t.Fatal("expected real SQL failure on second traffic update")
	}
	if liveNumber(t, ctx, c.db, "SELECT u FROM user WHERE id=101") != 17 ||
		liveNumber(t, ctx, c.db, "SELECT d FROM user WHERE id=202") != 36 {
		t.Fatal("traffic failure did not roll back both users")
	}
	liveExec(t, ctx, c.db, "DROP TRIGGER fail_second_user")
	if kind == "sspanel-uim" {
		liveExec(t, ctx, c.db, "CREATE TRIGGER fail_traffic_log BEFORE INSERT ON user_traffic_log FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='synthetic log rollback'")
		if err := c.ReportTraffic(ctx, []Traffic{{ID: one, Upload: 20, Download: 30}}); err == nil {
			t.Fatal("expected SQL traffic-log failure after charging user")
		}
		if liveNumber(t, ctx, c.db, "SELECT u FROM user WHERE id=101") != 17 ||
			liveNumber(t, ctx, c.db, "SELECT node_bandwidth FROM ss_node WHERE id=7") != 132 ||
			liveNumber(t, ctx, c.db, "SELECT COUNT(*) FROM user_traffic_log") != 2 ||
			liveNumber(t, ctx, c.db, "SELECT COUNT(*) FROM ss_node_online_log") != 1 {
			t.Fatal("late log failure left partially committed accounting")
		}
		liveExec(t, ctx, c.db, "DROP TRIGGER fail_traffic_log")
	}
}

func liveReports(t *testing.T, ctx context.Context, c *MySQL) {
	t.Helper()
	if err := c.ReportAliveIPs(ctx, []AliveIP{{ID: 101, IPs: []string{"192.0.2.1", "2001:db8::1"}}}); err != nil {
		t.Fatal(err)
	}
	if liveNumber(t, ctx, c.db, "SELECT COUNT(*) FROM alive_ip WHERE nodeid=7 AND userid=101") != 2 {
		t.Fatal("online IP commit missing")
	}
	liveExec(t, ctx, c.db, "CREATE TRIGGER fail_alive BEFORE INSERT ON alive_ip FOR EACH ROW BEGIN IF NEW.ip='reject' THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='synthetic alive rollback'; END IF; END")
	if err := c.ReportAliveIPs(ctx, []AliveIP{{ID: 202, IPs: []string{"192.0.2.2", "reject"}}}); err == nil {
		t.Fatal("expected second-IP SQL rejection")
	}
	if liveNumber(t, ctx, c.db, "SELECT COUNT(*) FROM alive_ip") != 2 {
		t.Fatal("online IP transaction did not roll back")
	}
	liveExec(t, ctx, c.db, "DROP TRIGGER fail_alive")
	if err := c.ReportAuditLogs(ctx, []AuditLog{{UserID: 101, AuditID: 9}, {UserID: 101, AuditID: 9}, {UserID: 202, AuditID: 9}}); err != nil {
		t.Fatal(err)
	}
	if liveNumber(t, ctx, c.db, "SELECT COUNT(*) FROM detect_log WHERE node_id=7") != 2 {
		t.Fatal("audit transaction commit/dedup failed")
	}
	liveExec(t, ctx, c.db, "CREATE TRIGGER fail_audit BEFORE INSERT ON detect_log FOR EACH ROW BEGIN IF NEW.user_id=202 THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='synthetic audit rollback'; END IF; END")
	if err := c.ReportAuditLogs(ctx, []AuditLog{{UserID: 101, AuditID: 10}, {UserID: 202, AuditID: 10}}); err == nil {
		t.Fatal("expected second audit SQL rejection")
	}
	if liveNumber(t, ctx, c.db, "SELECT COUNT(*) FROM detect_log") != 2 {
		t.Fatal("audit transaction did not roll back")
	}
	liveExec(t, ctx, c.db, "DROP TRIGGER fail_audit")
	if err := c.ReportStatus(ctx, Status{Uptime: 100, Loads: [3]float64{.1, 1.25, 3}}); err != nil {
		t.Fatal(err)
	}
	var load string
	if err := c.db.QueryRowContext(ctx, "SELECT `load` FROM ss_node_info WHERE node_id=7 AND uptime=100").Scan(&load); err != nil || load != "0.10 1.25 3.00" {
		t.Fatalf("status commit: %q %v", load, err)
	}
	liveExec(t, ctx, c.db, "CREATE TRIGGER fail_status BEFORE INSERT ON ss_node_info FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='synthetic status rejection'")
	if err := c.ReportStatus(ctx, Status{Uptime: 200}); err == nil ||
		liveNumber(t, ctx, c.db, "SELECT COUNT(*) FROM ss_node_info") != 1 {
		t.Fatal("status rejection was hidden or partially committed")
	}
	liveExec(t, ctx, c.db, "DROP TRIGGER fail_status")
}

func liveEligibility(t *testing.T, ctx context.Context, c *MySQL, protocol string) {
	t.Helper()
	if protocol == "vmess" || protocol == "trojan" {
		liveExec(t, ctx, c.db, "ALTER TABLE user DROP COLUMN uuid")
		users, err := c.FetchUsers(ctx)
		if err != nil {
			t.Fatal("legacy schema without uuid:", err)
		}
		for _, u := range users {
			if u.ID == 101 && u.UUID != SSPanelLegacyUUID(101, "synthetic-password-101") {
				t.Fatal("legacy UUID fallback differs on real schema introspection")
			}
		}
	}
	for _, row := range []string{
		"(701,7011,'expired',10701,'2000-01-01',3,3,0)",
		"(702,7021,'low-class',10702,'2099-01-01',1,3,0)",
		"(703,7031,'low-group',10703,'2099-01-01',3,1,0)",
		"(704,7041,'admin',10704,'2099-01-01',0,0,1)",
	} {
		liveExec(t, ctx, c.db, "INSERT INTO user(id,pid,passwd,port,expire_in,class,node_group,is_admin) VALUES"+row)
	}
	users, err := c.FetchUsers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, u := range users {
		ids = append(ids, strconv.FormatInt(u.ID, 10))
		if u.ID >= 701 && u.ID <= 703 {
			t.Fatalf("ineligible user %d leaked through actual SQL predicates", u.ID)
		}
	}
	if !strings.Contains(","+strings.Join(ids, ",")+",", ",704,") {
		t.Fatal("admin override was lost")
	}
	liveExec(t, ctx, c.db, "UPDATE ss_node SET node_bandwidth=node_bandwidth_limit WHERE id=7")
	users, err = c.FetchUsers(ctx)
	if err != nil || len(users) != 0 {
		t.Fatalf("exhausted node should have no users: %d %v", len(users), err)
	}
}
