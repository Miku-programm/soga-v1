package panel

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"sort"
	"time"
)

// These strings are independently recovered from the binary's encrypted
// constants; evidence records include each helper/callback and original bytes.
const ssTrafficRate = "select traffic_rate from ss_node where id = ?"
const ssBandwidthUpdate = "update ss_node set node_bandwidth = node_bandwidth + ? where id = ?"
const ssOnlineInsert = "insert into ss_node_online_log(node_id,online_user,log_time) values(?,?,?)"
const ssAliveInsert = "insert into alive_ip(nodeid,userid,ip,datetime) values(?, ?, ?, ?)"
const ssDetectInsert = "insert into detect_log(user_id,list_id,datetime,node_id) values(?,?,?,?)"
const ssDetectQuery = "select id, regex, `type` from detect_list"

func (c *MySQL) transaction(ctx context.Context, action func(*sql.Tx) error) error {
	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = action(tx); err != nil {
		return err
	}
	return tx.Commit()
}
func billedBytes(value int64, rate float64) (int64, error) {
	x := float64(value) * rate
	if value < 0 || math.IsNaN(rate) || math.IsInf(rate, 0) || rate < 0 || x >= float64(math.MaxInt64) {
		return 0, errors.New("invalid or overflowing billed traffic")
	}
	return int64(x), nil
}
func (c *MySQL) ReportTraffic(ctx context.Context, items []Traffic) error {
	rows, err := aggregateTraffic(items)
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		return nil
	}
	var total int64
	for id, r := range rows {
		if id <= 0 {
			return errors.New("traffic user ID must be positive")
		}
		if r[0] > math.MaxInt64-r[1] || total > math.MaxInt64-r[0]-r[1] {
			return errors.New("total traffic overflow")
		}
		total += r[0] + r[1]
	}
	hasTrafficLog := false
	if c.opts.Type == "sspanel-uim" {
		var table string
		err := c.db.QueryRowContext(ctx, ssTrafficLogProbe, c.settings.Database).Scan(&table)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		hasTrafficLog = err == nil
	}
	// Atomicity is an intentional reconstruction improvement: the original
	// SSPanel launches separate writes. We acknowledge only after all writes
	// commit, so a caller can retain its complete outbox on a rollback.
	return c.transaction(ctx, func(tx *sql.Tx) error {
		rate := c.settings.TrafficRate
		if c.opts.Type == "sspanel-uim" {
			if err := tx.QueryRowContext(ctx, ssTrafficRate, c.nodeID).Scan(&rate); err != nil {
				return fmt.Errorf("SSPanel traffic rate: %w", err)
			}
		}
		key := "id"
		if c.opts.Type == "whmcs" && c.opts.NodeType == "shadowsocksr" {
			key = "pid"
		}
		// Parameterized per-user updates preserve the recovered u/d increments and
		// t assignment, while avoiding a generated CASE statement and SQL literals.
		query := "update user set u = u + ?, d = d + ?, t = ? where " + key + " = ?"
		timestamp := int64(uint32(time.Now().Unix()))
		ids := make([]int64, 0, len(rows))
		for id := range rows {
			ids = append(ids, id)
		}
		sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
		for _, id := range ids {
			r := rows[id]
			u, err := billedBytes(r[0], rate)
			if err != nil {
				return err
			}
			d, err := billedBytes(r[1], rate)
			if err != nil {
				return err
			}
			if _, err = tx.ExecContext(ctx, query, u, d, timestamp, id); err != nil {
				return fmt.Errorf("update user traffic: %w", err)
			}
			if hasTrafficLog {
				total, err := billedBytes(r[0]+r[1], rate)
				if err != nil {
					return err
				}
				if _, err = tx.ExecContext(ctx, ssTrafficLogInsert, id, r[0], r[1], c.nodeID, rate, humanTraffic(uint64(total)), timestamp); err != nil {
					return err
				}
			}
		}
		if c.opts.Type == "sspanel-uim" {
			if _, err := tx.ExecContext(ctx, ssBandwidthUpdate, total, c.nodeID); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, ssOnlineInsert, c.nodeID, len(rows), timestamp); err != nil {
				return err
			}
		}
		return nil
	})
}
func (c *MySQL) ReportAliveIPs(ctx context.Context, items []AliveIP) error {
	if c.opts.Type != "sspanel-uim" {
		return ErrUnsupported
	}
	if len(items) == 0 {
		return nil
	}
	return c.transaction(ctx, func(tx *sql.Tx) error {
		now := int64(uint32(time.Now().Unix()))
		for _, u := range items {
			for _, ip := range u.IPs {
				if _, err := tx.ExecContext(ctx, ssAliveInsert, c.nodeID, u.ID, ip, now); err != nil {
					return err
				}
			}
		}
		return nil
	})
}
func (c *MySQL) ReportAuditLogs(ctx context.Context, items []AuditLog) error {
	if c.opts.Type != "sspanel-uim" {
		return ErrUnsupported
	}
	if len(items) == 0 {
		return nil
	}
	return c.transaction(ctx, func(tx *sql.Tx) error {
		now := int64(uint32(time.Now().Unix()))
		seen := map[AuditLog]bool{}
		for _, v := range items {
			if seen[v] {
				continue
			}
			seen[v] = true
			if _, err := tx.ExecContext(ctx, ssDetectInsert, v.UserID, v.AuditID, now, c.nodeID); err != nil {
				return err
			}
		}
		return nil
	})
}
func (c *MySQL) FetchDetectRules(ctx context.Context) ([]DetectRule, error) {
	if c.opts.Type != "sspanel-uim" {
		return nil, ErrUnsupported
	}
	rows, err := c.db.QueryContext(ctx, ssDetectQuery)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]DetectRule, 0)
	for rows.Next() {
		var id, kind sql.NullInt64
		var pattern sql.NullString
		if err := rows.Scan(&id, &pattern, &kind); err != nil {
			return nil, err
		}
		result = append(result, DetectRule{ID: int(id.Int64), Regex: pattern.String, Type: int(kind.Int64)})
	}
	return result, rows.Err()
}
func (c *MySQL) ReportPolicyDenials(ctx context.Context, items []PolicyDenial) error {
	logs := make([]AuditLog, 0, len(items))
	for _, v := range items {
		logs = append(logs, AuditLog{UserID: v.UserID, AuditID: int(v.RuleID)})
	}
	return c.ReportAuditLogs(ctx, logs)
}

const ssStatusInsert = "insert into ss_node_info(node_id, uptime, `load`, log_time)values(?,?,?,?)"

func (c *MySQL) ReportStatus(ctx context.Context, s Status) error {
	if c.opts.Type != "sspanel-uim" {
		return ErrUnsupported
	}
	for _, v := range s.Loads {
		if math.IsNaN(v) || math.IsInf(v, 0) || v < 0 {
			return errors.New("invalid system load")
		}
	}
	load := fmt.Sprintf("%.2f %.2f %.2f", s.Loads[0], s.Loads[1], s.Loads[2])
	_, err := c.db.ExecContext(ctx, ssStatusInsert, c.nodeID, s.Uptime, load, int64(uint32(time.Now().Unix())))
	return err
}

const ssTrafficLogProbe = "SELECT table_name FROM information_schema.TABLES WHERE table_name='user_traffic_log' AND table_schema=?"
const ssTrafficLogInsert = "insert into user_traffic_log(user_id,u,d,node_id,rate,traffic,log_time) values(?,?,?,?,?,?,?)"

// LTaVAEf@15b29a0 uses binary units but the literal suffixes KB/MB/GB/TB.
func humanTraffic(n uint64) string {
	if n < 1024 {
		return fmt.Sprintf("%dB", n)
	}
	v := float64(n)
	suffix := "KB"
	v *= 1.0 / 1024
	if n >= 1<<20 {
		v *= 1.0 / 1024
		suffix = "MB"
	}
	if n >= 1<<30 {
		v *= 1.0 / 1024
		suffix = "GB"
	}
	if n >= 1<<40 {
		v *= 1.0 / 1024
		suffix = "TB"
	}
	return fmt.Sprintf("%.2f%s", v, suffix)
}
