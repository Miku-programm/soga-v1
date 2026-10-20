package panel

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"math"
	"reflect"
	"strings"
	"sync"
	"testing"
)

// A local database/sql driver fixture verifies complete query/transaction
// boundaries. No external panel/database or target binary is contacted.
type sqlStep struct {
	op, query string
	args      []any
	columns   []string
	rows      [][]driver.Value
	err       error
}
type sqlFixture struct {
	t     *testing.T
	mu    sync.Mutex
	steps []sqlStep
}

func (f *sqlFixture) next(op, q string, args []driver.NamedValue) (sqlStep, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.steps) == 0 {
		f.t.Errorf("unexpected %s %q", op, q)
		return sqlStep{}, errors.New("unexpected operation")
	}
	s := f.steps[0]
	f.steps = f.steps[1:]
	if s.op != op || s.query != q {
		f.t.Errorf("got %s %q want %s %q", op, q, s.op, s.query)
	}
	if s.args != nil {
		if len(s.args) != len(args) {
			f.t.Errorf("args=%v want%v", args, s.args)
		} else {
			for i, x := range s.args {
				if x != nil && !reflect.DeepEqual(x, args[i].Value) {
					f.t.Errorf("arg[%d]=%#v want%#v", i, args[i].Value, x)
				}
			}
		}
	}
	return s, s.err
}

type fixtureConnector struct{ f *sqlFixture }

func (c fixtureConnector) Connect(context.Context) (driver.Conn, error) { return fixtureConn{c.f}, nil }
func (c fixtureConnector) Driver() driver.Driver                        { return fixtureDriver{c.f} }

type fixtureDriver struct{ f *sqlFixture }

func (d fixtureDriver) Open(string) (driver.Conn, error) { return fixtureConn{d.f}, nil }

type fixtureConn struct{ f *sqlFixture }

func (c fixtureConn) Close() error { return nil }
func (c fixtureConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unexpected prepare")
}
func (c fixtureConn) Begin() (driver.Tx, error) {
	return c.BeginTx(context.Background(), driver.TxOptions{})
}
func (c fixtureConn) BeginTx(context.Context, driver.TxOptions) (driver.Tx, error) {
	_, e := c.f.next("begin", "", nil)
	return fixtureTx{c.f}, e
}
func (c fixtureConn) QueryContext(_ context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	s, e := c.f.next("query", q, args)
	if e != nil {
		return nil, e
	}
	return &fixtureRows{columns: s.columns, rows: s.rows}, nil
}
func (c fixtureConn) ExecContext(_ context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	_, e := c.f.next("exec", q, args)
	return driver.RowsAffected(1), e
}

type fixtureTx struct{ f *sqlFixture }

func (t fixtureTx) Commit() error   { _, e := t.f.next("commit", "", nil); return e }
func (t fixtureTx) Rollback() error { _, e := t.f.next("rollback", "", nil); return e }

type fixtureRows struct {
	columns []string
	rows    [][]driver.Value
}

func (r *fixtureRows) Columns() []string { return r.columns }
func (r *fixtureRows) Close() error      { return nil }
func (r *fixtureRows) Next(dest []driver.Value) error {
	if len(r.rows) == 0 {
		return io.EOF
	}
	copy(dest, r.rows[0])
	r.rows = r.rows[1:]
	return nil
}
func newFixtureDB(t *testing.T, kind, protocol string, steps []sqlStep) *MySQL {
	t.Helper()
	f := &sqlFixture{t: t, steps: steps}
	db := sql.OpenDB(fixtureConnector{f})
	t.Cleanup(func() {
		db.Close()
		f.mu.Lock()
		defer f.mu.Unlock()
		if len(f.steps) != 0 {
			t.Errorf("unconsumed SQL steps: %+v", f.steps)
		}
	})
	return &MySQL{db: db, opts: Options{Type: kind, NodeType: protocol}, settings: MySQLOptions{TrafficRate: 1.5, Database: "panel"}, nodeID: 7}
}
func TestMySQLTrafficAtomicRateAndRawBandwidth(t *testing.T) {
	c := newFixtureDB(t, "sspanel-uim", "vmess", []sqlStep{{op: "query", query: ssTrafficLogProbe, args: []any{"panel"}, columns: []string{"table_name"}}, {op: "begin"}, {op: "query", query: ssTrafficRate, args: []any{int64(7)}, columns: []string{"traffic_rate"}, rows: [][]driver.Value{{1.5}}}, {op: "exec", query: "update user set u = u + ?, d = d + ?, t = ? where id = ?", args: []any{int64(4), int64(7), nil, int64(8)}}, {op: "exec", query: ssBandwidthUpdate, args: []any{int64(8), int64(7)}}, {op: "exec", query: ssOnlineInsert, args: []any{int64(7), int64(1), nil}}, {op: "commit"}})
	if err := c.ReportTraffic(context.Background(), []Traffic{{ID: 8, Upload: 3, Download: 5}}); err != nil {
		t.Fatal(err)
	}
}
func TestMySQLTrafficRollbackAndCommitFailure(t *testing.T) {
	for _, fail := range []string{"exec", "commit"} {
		t.Run(fail, func(t *testing.T) {
			boom := errors.New("fixture fail")
			steps := []sqlStep{{op: "begin"}, {op: "exec", query: "update user set u = u + ?, d = d + ?, t = ? where pid = ?", args: []any{int64(3), int64(4), nil, int64(21)}}}
			if fail == "exec" {
				steps[1].err = boom
				steps = append(steps, sqlStep{op: "rollback"})
			} else {
				steps = append(steps, sqlStep{op: "commit", err: boom})
			}
			c := newFixtureDB(t, "whmcs", "shadowsocksr", steps)
			items := []Traffic{{ID: 21, Upload: 2, Download: 3}}
			if err := c.ReportTraffic(context.Background(), items); !errors.Is(err, boom) {
				t.Fatal(err)
			}
			if items[0].Upload != 2 || items[0].Download != 3 {
				t.Fatal("caller outbox modified")
			}
		})
	}
}
func TestMySQLRejectOverflowBeforeWrite(t *testing.T) {
	c := newFixtureDB(t, "whmcs", "vmess", nil)
	for _, v := range [][]Traffic{{{ID: 1, Upload: -1}}, {{ID: 1, Upload: math.MaxInt64, Download: 1}}, {{ID: 0, Upload: 1}}} {
		if err := c.ReportTraffic(context.Background(), v); err == nil {
			t.Fatal("invalid traffic accepted")
		}
	}
	if _, e := billedBytes(2, math.Inf(1)); e == nil {
		t.Fatal("infinite rate")
	}
	if _, e := billedBytes(math.MaxInt64, 2); e == nil {
		t.Fatal("billed overflow")
	}
}
func TestMySQLWHMCSQueriesAndNullCredentials(t *testing.T) {
	for _, p := range []string{"vmess", "trojan", "shadowsocks", "shadowsocksr"} {
		t.Run(p, func(t *testing.T) {
			q := whmcsUUIDUsers
			cols := []string{"id", "u", "d", "transfer_enable", "uuid"}
			r := []driver.Value{int64(9), int64(0), int64(0), int64(99), "cred"}
			bad := []driver.Value{int64(10), int64(0), int64(0), int64(99), nil}
			if p == "shadowsocks" {
				q = whmcsSSUsers
				cols = append(cols, "speedlimitss")
				r = append(r, int64(50000))
				bad = append(bad, int64(0))
			}
			if p == "shadowsocksr" {
				q = whmcsSSRUsers
				cols = []string{"pid", "u", "d", "transfer_enable", "port", "passwd"}
				r = []driver.Value{int64(9), int64(0), int64(0), int64(99), int64(1001), "cred"}
				bad = []driver.Value{int64(10), int64(0), int64(0), int64(99), int64(1002), nil}
			}
			c := newFixtureDB(t, "whmcs", p, []sqlStep{{op: "query", query: q, columns: cols, rows: [][]driver.Value{r, bad}}})
			u, e := c.FetchUsers(context.Background())
			if e != nil || len(u) != 1 || u[0].ID != 9 {
				t.Fatalf("%+v %v", u, e)
			}
			if p == "shadowsocks" && u[0].SpeedLimit != 10000 {
				t.Fatal(u)
			}
			if p == "shadowsocksr" && (u[0].Port != 1001 || u[0].ProtocolID != 1001) {
				t.Fatal(u)
			}
		})
	}
}
func TestMySQLAliveAndAuditTransactions(t *testing.T) {
	c := newFixtureDB(t, "sspanel-uim", "vmess", []sqlStep{{op: "begin"}, {op: "exec", query: ssAliveInsert, args: []any{int64(7), int64(11), "2001:db8::1", nil}}, {op: "commit"}, {op: "begin"}, {op: "exec", query: ssDetectInsert, args: []any{int64(11), int64(0), nil, int64(7)}}, {op: "commit"}})
	ctx := context.Background()
	if e := c.ReportAliveIPs(ctx, []AliveIP{{ID: 11, IPs: []string{"2001:db8::1"}}}); e != nil {
		t.Fatal(e)
	}
	if e := c.ReportPolicyDenials(ctx, []PolicyDenial{{UserID: 11, RuleID: 0}, {UserID: 11, RuleID: 0}}); e != nil {
		t.Fatal(e)
	}
}

func TestMySQLSSRProtocolUIDRejectsInvalidPort(t *testing.T) {
	for _, port := range []int64{0, -1, 1 << 32} {
		c := newFixtureDB(t, "whmcs", "shadowsocksr", []sqlStep{{
			op: "query", query: whmcsSSRUsers,
			columns: []string{"pid", "u", "d", "transfer_enable", "port", "passwd"},
			rows:    [][]driver.Value{{int64(17), int64(0), int64(0), int64(100), port, "secret"}},
		}})
		if _, err := c.FetchUsers(context.Background()); err == nil {
			t.Fatalf("accepted protocol UID %d", port)
		}
	}
}
func TestSSPanelLegacyUUID(t *testing.T) {
	if got := SSPanelLegacyUUID(1, "abc"); got != "42547b9c-ef12-3a10-9dea-2df0ce7ea5f3" {
		t.Fatal(got)
	}
	if SSPanelLegacyUUID(1, "密碼") == SSPanelLegacyUUID(1, "密码") {
		t.Fatal("Unicode input collapsed")
	}
}
func TestMySQLConstructionAndPool(t *testing.T) {
	c, e := NewMySQL(Options{Type: "whmcs", NodeType: "vmess", NodeID: "1"}, MySQLOptions{Host: "localhost", Database: "panel", User: "user", Password: "secret"})
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	if c.db.Stats().MaxOpenConnections != 4 {
		t.Fatal(c.db.Stats())
	}
	_, e = NewMySQL(Options{Type: "whmcs", NodeType: "vmess", NodeID: "1"}, MySQLOptions{Host: "localhost", Database: "panel", User: "user", Password: "secret", Port: -1})
	if e == nil || strings.Contains(e.Error(), "secret") {
		t.Fatal(e)
	}
}

func TestMySQLStatusFormatting(t *testing.T) {
	c := newFixtureDB(t, "sspanel-uim", "vmess", []sqlStep{{op: "exec", query: ssStatusInsert, args: []any{int64(7), int64(100), "0.10 1.25 3.00", nil}}})
	if e := c.ReportStatus(context.Background(), Status{Uptime: 100, Loads: [3]float64{.1, 1.25, 3}}); e != nil {
		t.Fatal(e)
	}
}

func TestMySQLTrafficLogFailureRollsBackCharges(t *testing.T) {
	boom := errors.New("log insert rejected")
	c := newFixtureDB(t, "sspanel-uim", "vmess", []sqlStep{{op: "query", query: ssTrafficLogProbe, args: []any{"panel"}, columns: []string{"table_name"}, rows: [][]driver.Value{{"user_traffic_log"}}}, {op: "begin"}, {op: "query", query: ssTrafficRate, columns: []string{"rate"}, rows: [][]driver.Value{{2.0}}}, {op: "exec", query: "update user set u = u + ?, d = d + ?, t = ? where id = ?"}, {op: "exec", query: ssTrafficLogInsert, args: []any{int64(9), int64(512), int64(256), int64(7), 2.0, "1.50KB", nil}, err: boom}, {op: "rollback"}})
	if e := c.ReportTraffic(context.Background(), []Traffic{{ID: 9, Upload: 512, Download: 256}}); !errors.Is(e, boom) {
		t.Fatal(e)
	}
}
func TestHumanTrafficBoundaries(t *testing.T) {
	for _, v := range []struct {
		n    uint64
		want string
	}{{0, "0B"}, {1023, "1023B"}, {1024, "1.00KB"}, {1 << 20, "1.00MB"}, {1 << 30, "1.00GB"}, {1 << 40, "1.00TB"}, {1 << 50, "1024.00TB"}} {
		if got := humanTraffic(v.n); got != v.want {
			t.Fatalf("%d:%s", v.n, got)
		}
	}
}
