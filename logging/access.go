// Package logging implements independent runtime and access log sinks.
package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"reconstructed.local/soga/config"
)

type Record struct {
	Time     string `json:"time"`
	Network  string `json:"network"`
	NodeID   int64  `json:"node_id"`
	UserID   int64  `json:"user_id"`
	UserIP   string `json:"user_ip"`
	Host     string `json:"host"`
	DestIP   string `json:"dest_ip"`
	DestPort uint16 `json:"dest_port"`
}
type Access struct {
	c        config.Config
	queue    chan Record
	stop     chan struct{}
	done     chan struct{}
	once     sync.Once
	mu       sync.RWMutex
	closed   bool
	local    *Rotating
	client   *http.Client
	endpoint string
	table    string
	onError  func(error)
}

func NewAccess(ctx context.Context, c config.Config, onError func(error)) (*Access, error) {
	if !c.AccessLogEnable {
		return nil, nil
	}
	if onError == nil {
		onError = func(error) {}
	}
	a := &Access{c: c, stop: make(chan struct{}), done: make(chan struct{}), onError: onError,
		client: &http.Client{Timeout: 10 * time.Second}}
	switch c.AccessLogMode {
	case "local":
		if c.AccessLogDir == "" || c.AccessLogRetentionHours < 0 {
			return nil, errors.New("invalid access log directory/retention")
		}
		var err error
		a.local, err = NewRotating(c.AccessLogDir, "soga-access-", true, int(c.AccessLogRetentionHours))
		if err != nil {
			return nil, err
		}
	case "clickhouse":
		if c.AccessLogClickhouseBatchSize <= 0 || c.AccessLogClickhouseBatchSize > 1_000_000 {
			return nil, errors.New("invalid ClickHouse batch size")
		}
		endpoint := c.AccessLogClickhouseAddr
		if !strings.Contains(endpoint, "://") {
			endpoint = "http://" + endpoint
		}
		u, err := url.Parse(endpoint)
		if err != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Scheme != "http" && u.Scheme != "https") {
			return nil, errors.New("invalid ClickHouse HTTP address")
		}
		if u.Port() == "" {
			port := "8123"
			if u.Scheme == "https" {
				port = "8443"
			}
			u.Host = net.JoinHostPort(u.Hostname(), port)
		}
		a.endpoint = u.String()
		database, err := identifier(c.AccessLogClickhouseDatabase)
		if err != nil {
			return nil, err
		}
		table, err := identifier(c.AccessLogClickhouseTable)
		if err != nil {
			return nil, err
		}
		a.table = database + "." + table
		if c.AccessLogClickhouseAutoCreate {
			if err := a.post(ctx, "CREATE DATABASE IF NOT EXISTS "+database, nil); err != nil {
				a.onError(err)
			}
			sql := "CREATE TABLE IF NOT EXISTS " + a.table + " (time DateTime, network LowCardinality(String), node_id Int32, user_id Int64, user_ip String, host String, dest_ip String, dest_port UInt16) ENGINE = MergeTree PARTITION BY toYYYYMMDD(time) ORDER BY (time, user_id)"
			if err := a.post(ctx, sql, nil); err != nil {
				a.onError(err)
			}
		}
	default:
		return nil, fmt.Errorf("unknown access_log_mode %q", c.AccessLogMode)
	}
	a.queue = make(chan Record, 4096)
	go a.run()
	return a, nil
}
func identifier(s string) (string, error) {
	if s == "" || strings.ContainsAny(s, "\x00\r\n") {
		return "", errors.New("invalid ClickHouse identifier")
	}
	return "`" + strings.ReplaceAll(strings.ReplaceAll(s, "\\", "\\\\"), "`", "\\`") + "`", nil
}

// Write never delays forwarding. A saturated queue drops the new record.
func (a *Access) Write(r Record) {
	if a == nil {
		return
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.closed {
		return
	}
	if r.Time == "" {
		r.Time = time.Now().Format("2006-01-02 15:04:05")
	}
	select {
	case a.queue <- r:
	default:
	}
}
func (a *Access) Close(ctx context.Context) error {
	if a == nil {
		return nil
	}
	a.once.Do(func() { a.mu.Lock(); a.closed = true; close(a.stop); a.mu.Unlock() })
	select {
	case <-a.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (a *Access) run() {
	defer close(a.done)
	if a.local != nil {
		defer a.local.Close()
	}
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	var batch []Record
	flush := func() {
		if len(batch) == 0 {
			return
		}
		var err error
		if a.local != nil {
			for _, r := range batch {
				line := fmt.Sprintf("%s|%s|%d|%d|%s|%s|%s|%d\n", safe(r.Time), safe(r.Network), r.NodeID, r.UserID, safe(r.UserIP), safe(r.Host), safe(r.DestIP), r.DestPort)
				if _, e := io.WriteString(a.local, line); e != nil {
					err = errors.Join(err, e)
				}
			}
		} else {
			var data bytes.Buffer
			enc := json.NewEncoder(&data)
			for _, r := range batch {
				if e := enc.Encode(r); e != nil {
					err = e
					break
				}
			}
			if err == nil {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				err = a.post(ctx, "INSERT INTO "+a.table+" FORMAT JSONEachRow", data.Bytes())
				cancel()
			}
		}
		batch = nil
		if err != nil {
			a.onError(err)
		}
	}
	for {
		select {
		case r := <-a.queue:
			batch = append(batch, r)
			size := int(a.c.AccessLogClickhouseBatchSize)
			if a.local != nil {
				size = 1
			}
			if len(batch) >= size {
				flush()
			}
		case <-tick.C:
			flush()
		case <-a.stop:
			for {
				select {
				case r := <-a.queue:
					batch = append(batch, r)
				default:
					flush()
					return
				}
			}
		}
	}
}
func safe(s string) string {
	return strings.NewReplacer("\r", "\\r", "\n", "\\n", "|", "\\x7c").Replace(s)
}
func (a *Access) post(ctx context.Context, query string, data []byte) error {
	u, err := url.Parse(a.endpoint)
	if err != nil {
		return errors.New("invalid ClickHouse endpoint")
	}
	q := u.Query()
	q.Set("query", query)
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("X-ClickHouse-User", a.c.AccessLogClickhouseUser)
	req.Header.Set("X-ClickHouse-Key", a.c.AccessLogClickhousePassword)
	resp, err := a.client.Do(req)
	if err != nil {
		return errors.New("ClickHouse request failed")
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("ClickHouse HTTP status %d", resp.StatusCode)
	}
	return nil
}

type Rotating struct {
	mu             sync.Mutex
	dir, prefix    string
	hourly         bool
	retention      int
	file           *os.File
	name           string
	closed         bool
	stop, done     chan struct{}
	maintenanceErr error
}

func NewRotating(dir, prefix string, hourly bool, retention int) (*Rotating, error) {
	if dir == "" || retention < 0 || strings.ContainsAny(prefix, "/\\") {
		return nil, errors.New("invalid log rotation settings")
	}
	if err := os.MkdirAll(dir, 0750); err != nil {
		return nil, err
	}
	r := &Rotating{dir: dir, prefix: prefix, hourly: hourly, retention: retention,
		stop: make(chan struct{}), done: make(chan struct{})}
	r.mu.Lock()
	err := r.rotate(time.Now())
	r.mu.Unlock()
	if err != nil {
		if r.file != nil {
			_ = r.file.Close()
		}
		return nil, err
	}
	go r.maintain()
	return r, nil
}

func (r *Rotating) maintain() {
	defer close(r.done)
	for {
		now := time.Now()
		next := time.Date(now.Year(), now.Month(), now.Day(), now.Hour()+1, 0, 1, 0, now.Location())
		timer := time.NewTimer(time.Until(next))
		select {
		case <-r.stop:
			timer.Stop()
			return
		case now = <-timer.C:
			r.mu.Lock()
			if !r.closed {
				r.maintenanceErr = errors.Join(r.rotate(now), r.prune(now))
			}
			r.mu.Unlock()
		}
	}
}
func (r *Rotating) layout() string {
	if r.hourly {
		return "2006-01-02 15:00:00"
	}
	return "2006-01-02"
}
func (r *Rotating) rotate(now time.Time) error {
	name := r.prefix + now.Format(r.layout()) + ".log"
	if name == r.name && r.file != nil {
		return nil
	}
	f, err := os.OpenFile(filepath.Join(r.dir, name), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640)
	if err != nil {
		return err
	}
	if r.file != nil {
		_ = r.file.Close()
	}
	r.file, r.name = f, name
	return r.prune(now)
}
func (r *Rotating) prune(now time.Time) error {
	if r.retention == 0 {
		return nil
	}
	base := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	cutoff := base.AddDate(0, 0, -r.retention)
	if r.hourly {
		base = base.Add(time.Duration(now.Hour()) * time.Hour)
		cutoff = base.Add(-time.Duration(r.retention) * time.Hour)
	}
	files, err := os.ReadDir(r.dir)
	if err != nil {
		return err
	}
	for _, entry := range files {
		name := entry.Name()
		if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || !strings.HasPrefix(name, r.prefix) || !strings.HasSuffix(name, ".log") || name == r.name {
			continue
		}
		stamp := strings.TrimSuffix(strings.TrimPrefix(name, r.prefix), ".log")
		t, err := time.ParseInLocation(r.layout(), stamp, now.Location())
		if err != nil || t.Format(r.layout()) != stamp {
			continue
		}
		if t.Before(cutoff) {
			if err := os.Remove(filepath.Join(r.dir, name)); err != nil {
				return err
			}
		}
	}
	return nil
}
func (r *Rotating) Write(data []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return 0, os.ErrClosed
	}
	if err := r.rotate(time.Now()); err != nil {
		return 0, err
	}
	n, err := r.file.Write(data)
	err = errors.Join(err, r.maintenanceErr)
	r.maintenanceErr = nil
	return n, err
}
func (r *Rotating) Close() error {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		<-r.done
		return nil
	}
	r.closed = true
	close(r.stop)
	err := r.file.Close()
	r.file = nil
	err = errors.Join(err, r.maintenanceErr)
	r.mu.Unlock()
	<-r.done
	return err
}

// FormatRecord is useful to external integrations without exposing credentials.
func FormatRecord(network string, node, user int64, source, host, destination string) Record {
	ip, _, err := net.SplitHostPort(source)
	if err != nil {
		ip = source
	}
	dest, port, _ := net.SplitHostPort(destination)
	p, _ := strconv.ParseUint(port, 10, 16)
	return Record{Network: network, NodeID: node, UserID: user, UserIP: ip, Host: host, DestIP: dest, DestPort: uint16(p)}
}
