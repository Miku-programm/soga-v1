// Package logging implements independent runtime and access log sinks.
package logging

import (
	"bufio"
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
	"sync/atomic"
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

// localSink is the file side of local mode. *Rotating implements it; tests
// substitute a stub to count batches.
type localSink interface {
	WriteAt(at time.Time, data []byte) (int, error)
	Close() error
	period(t time.Time) int64
}

const (
	// localBatchRecords bounds how many records are buffered before a file write.
	localBatchRecords = 256
	// localBufferSize is the size of the in-memory buffer in front of the file.
	localBufferSize = 64 << 10
	// localIdleFlush is how long a partial batch waits once the queue is idle.
	localIdleFlush = 100 * time.Millisecond
	timeLayout     = "2006-01-02 15:04:05"
)

type Access struct {
	c         config.Config
	queue     chan Record
	stop      chan struct{}
	done      chan struct{}
	once      sync.Once
	mu        sync.RWMutex
	closed    bool
	sink      localSink
	clock     func() time.Time
	idleFlush time.Duration
	client    *http.Client
	endpoint  string
	table     string
	onError   func(error)
}

func NewAccess(ctx context.Context, c config.Config, onError func(error)) (*Access, error) {
	if !c.AccessLogEnable {
		return nil, nil
	}
	if onError == nil {
		onError = func(error) {}
	}
	a := &Access{c: c, stop: make(chan struct{}), done: make(chan struct{}), onError: onError,
		idleFlush: localIdleFlush, client: &http.Client{Timeout: 10 * time.Second}}
	switch c.AccessLogMode {
	case "local":
		if c.AccessLogDir == "" || c.AccessLogRetentionHours < 0 {
			return nil, errors.New("invalid access log directory/retention")
		}
		local, err := NewRotating(c.AccessLogDir, "soga-access-", true, int(c.AccessLogRetentionHours))
		if err != nil {
			return nil, err
		}
		a.sink = local
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

// Enabled reports whether a record written now would be accepted. Callers can
// use it to skip building a Record (FormatRecord) when the sink is nil or closed.
func (a *Access) Enabled() bool {
	if a == nil {
		return false
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	return !a.closed
}

// Log is Write(FormatRecord(...)) that skips the formatting work entirely when
// the sink is nil or closed.
func (a *Access) Log(network string, node, user int64, source, host, destination string) {
	if !a.Enabled() {
		return
	}
	a.Write(FormatRecord(network, node, user, source, host, destination))
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
		r.Time = timestamp(time.Now())
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
func (a *Access) now() time.Time {
	if a.clock != nil {
		return a.clock()
	}
	return time.Now()
}
func (a *Access) run() {
	defer close(a.done)
	if a.sink != nil {
		a.runLocal()
		return
	}
	a.runClickHouse()
}

// hourWriter routes buffered bytes to the rotation period they were queued
// in, so that a flush that happens after the hour changed still lands in the
// file of the records' own hour.
type hourWriter struct {
	sink localSink
	at   time.Time
}

func (h *hourWriter) Write(p []byte) (int, error) { return h.sink.WriteAt(h.at, p) }

func (a *Access) runLocal() {
	defer func() {
		if err := a.sink.Close(); err != nil {
			a.onError(err)
		}
	}()
	sink := &hourWriter{sink: a.sink}
	w := bufio.NewWriterSize(sink, localBufferSize)
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	var (
		line    []byte
		pending int
		period  int64
		idle    *time.Timer
		idleC   <-chan time.Time
	)
	flush := func() {
		if idleC != nil {
			idle.Stop()
			idleC = nil
		}
		if pending == 0 {
			return
		}
		pending = 0
		if err := w.Flush(); err != nil {
			w.Reset(sink)
			a.onError(err)
		}
	}
	add := func(r Record) {
		now := a.now()
		if p := a.sink.period(now); p != period {
			flush()
			period, sink.at = p, now
		}
		line = appendRecord(line[:0], r)
		if _, err := w.Write(line); err != nil {
			w.Reset(sink)
			a.onError(err)
			return
		}
		pending++
		if pending >= localBatchRecords {
			flush()
		}
	}
	for {
		select {
		case r := <-a.queue:
			add(r)
		drain:
			for i := 0; i < localBatchRecords; i++ {
				select {
				case r := <-a.queue:
					add(r)
				default:
					break drain
				}
			}
			if pending > 0 && idleC == nil && a.idleFlush > 0 {
				idle = time.NewTimer(a.idleFlush)
				idleC = idle.C
			}
		case <-idleC:
			idleC = nil
			flush()
		case <-tick.C:
			flush()
		case <-a.stop:
			for {
				select {
				case r := <-a.queue:
					add(r)
				default:
					flush()
					return
				}
			}
		}
	}
}
func (a *Access) runClickHouse() {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	var batch []Record
	flush := func() {
		if len(batch) == 0 {
			return
		}
		var err error
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
		batch = nil
		if err != nil {
			a.onError(err)
		}
	}
	for {
		select {
		case r := <-a.queue:
			batch = append(batch, r)
			if len(batch) >= int(a.c.AccessLogClickhouseBatchSize) {
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

type cachedStamp struct {
	sec  int64
	text string
}

var stampCache atomic.Pointer[cachedStamp]

// timestamp formats now in the record layout, reusing the previous result
// while the wall-clock second is unchanged.
func timestamp(now time.Time) string {
	sec := now.Unix()
	if c := stampCache.Load(); c != nil && c.sec == sec {
		return c.text
	}
	s := &cachedStamp{sec: sec, text: now.Format(timeLayout)}
	stampCache.Store(s)
	return s.text
}

// appendRecord appends the local-mode line for r, identical to the former
// fmt.Sprintf("%s|%s|%d|%d|%s|%s|%s|%d\n", ...) output.
func appendRecord(b []byte, r Record) []byte {
	b = append(b, safe(r.Time)...)
	b = append(b, '|')
	b = append(b, safe(r.Network)...)
	b = append(b, '|')
	b = strconv.AppendInt(b, r.NodeID, 10)
	b = append(b, '|')
	b = strconv.AppendInt(b, r.UserID, 10)
	b = append(b, '|')
	b = append(b, safe(r.UserIP)...)
	b = append(b, '|')
	b = append(b, safe(r.Host)...)
	b = append(b, '|')
	b = append(b, safe(r.DestIP)...)
	b = append(b, '|')
	b = strconv.AppendUint(b, uint64(r.DestPort), 10)
	return append(b, '\n')
}
func formatLine(r Record) string { return string(appendRecord(nil, r)) }

var safeReplacer = strings.NewReplacer("\r", "\\r", "\n", "\\n", "|", "\\x7c")

func safe(s string) string {
	return safeReplacer.Replace(s)
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
	cur            int64
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

// period identifies the file t belongs to (local day, plus hour when hourly)
// without formatting; it is always positive.
func (r *Rotating) period(t time.Time) int64 {
	p := int64(t.Year())<<9 | int64(t.YearDay())
	if r.hourly {
		p = p<<5 | int64(t.Hour())
	}
	return p
}
func (r *Rotating) rotate(now time.Time) error {
	p := r.period(now)
	if p == r.cur && r.file != nil {
		return nil
	}
	name := r.prefix + now.Format(r.layout()) + ".log"
	f, err := os.OpenFile(filepath.Join(r.dir, name), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640)
	if err != nil {
		return err
	}
	if r.file != nil {
		_ = r.file.Close()
	}
	r.file, r.name, r.cur = f, name, p
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

// Write appends data to the file of the current period.
func (r *Rotating) Write(data []byte) (int, error) {
	return r.WriteAt(time.Now(), data)
}

// WriteAt appends data to the file of the period containing at, rotating
// (forwards or backwards) when necessary.
func (r *Rotating) WriteAt(at time.Time, data []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return 0, os.ErrClosed
	}
	if err := r.rotate(at); err != nil {
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
