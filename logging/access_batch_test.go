package logging

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"reconstructed.local/soga/config"
)

// legacyLine is the formatter the local mode used before the strconv rewrite.
func legacyLine(r Record) string {
	return fmt.Sprintf("%s|%s|%d|%d|%s|%s|%s|%d\n", safe(r.Time), safe(r.Network), r.NodeID, r.UserID, safe(r.UserIP), safe(r.Host), safe(r.DestIP), r.DestPort)
}

func TestFormatLineMatchesLegacyFormat(t *testing.T) {
	records := []Record{
		{Time: "2026-10-20 10:03:22", Network: "tcp", NodeID: 7, UserID: 9, UserIP: "192.0.2.1", Host: "example.test|\ninjected", DestIP: "192.0.2.2", DestPort: 443},
		{},
		{Time: "2026-01-01 00:00:00", Network: "udp", NodeID: -1, UserID: -9223372036854775808, UserIP: "::1", Host: "a\r\nb", DestIP: "2001:db8::1", DestPort: 65535},
		{Network: "|", NodeID: 9223372036854775807, Host: "\\x7c", DestPort: 1},
	}
	for _, r := range records {
		if got, want := formatLine(r), legacyLine(r); got != want {
			t.Fatalf("formatLine=%q want %q", got, want)
		}
	}
	golden := "2026-10-20 10:03:22|tcp|7|9|192.0.2.1|example.test\\x7c\\ninjected|192.0.2.2|443\n"
	if got := formatLine(records[0]); got != golden {
		t.Fatalf("formatLine=%q want %q", got, golden)
	}
}

func TestSafeEscaping(t *testing.T) {
	cases := map[string]string{
		"":              "",
		"plain.example": "plain.example",
		"a|b":           "a\\x7cb",
		"a\r\nb":        "a\\r\\nb",
		"|\n|\r":        "\\x7c\\n\\x7c\\r",
		"\\x7c":         "\\x7c",
	}
	for in, want := range cases {
		if got := safe(in); got != want {
			t.Errorf("safe(%q)=%q want %q", in, got, want)
		}
	}
}

func TestTimestampCache(t *testing.T) {
	base := time.Date(2026, 10, 20, 10, 3, 22, 500_000_000, time.Local)
	for _, now := range []time.Time{base, base.Add(100 * time.Millisecond), base.Add(time.Second), base.Add(-time.Hour), base} {
		if got, want := timestamp(now), now.Format("2006-01-02 15:04:05"); got != want {
			t.Fatalf("timestamp(%v)=%q want %q", now, got, want)
		}
	}
}

type stubWrite struct {
	at   time.Time
	data []byte
}

// stubSink counts the batches local mode hands to the file layer.
type stubSink struct {
	mu     sync.Mutex
	writes []stubWrite
	closed bool
}

func (s *stubSink) WriteAt(at time.Time, data []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.writes = append(s.writes, stubWrite{at: at, data: append([]byte(nil), data...)})
	return len(data), nil
}
func (s *stubSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	return nil
}
func (s *stubSink) period(t time.Time) int64 { return (&Rotating{hourly: true}).period(t) }
func (s *stubSink) snapshot() (calls int, lines int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, w := range s.writes {
		lines += bytes.Count(w.data, []byte("\n"))
	}
	return len(s.writes), lines
}

func newTestAccess(t *testing.T, sink localSink, clock func() time.Time, idleFlush time.Duration) *Access {
	t.Helper()
	a := &Access{sink: sink, clock: clock, idleFlush: idleFlush, queue: make(chan Record, 4096),
		stop: make(chan struct{}), done: make(chan struct{}), onError: func(err error) { t.Error(err) }}
	go a.run()
	return a
}

func waitFor(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met before timeout")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestLocalBatchesOneWritePerTick(t *testing.T) {
	sink := &stubSink{}
	a := newTestAccess(t, sink, nil, time.Hour) // idle flushing disabled: only the tick or size flushes
	for i := 0; i < 200; i++ {
		a.Write(Record{Network: "tcp", NodeID: 1, UserID: int64(i), Host: "h"})
	}
	time.Sleep(300 * time.Millisecond)
	if calls, _ := sink.snapshot(); calls != 0 {
		t.Fatalf("records flushed before the tick: %d writes", calls)
	}
	waitFor(t, 3*time.Second, func() bool { calls, _ := sink.snapshot(); return calls >= 1 })
	if calls, lines := sink.snapshot(); calls != 1 || lines != 200 {
		t.Fatalf("writes=%d lines=%d, want one batch of 200", calls, lines)
	}
	for i := 0; i < 300; i++ {
		a.Write(Record{Network: "tcp", NodeID: 1, UserID: int64(i), Host: "h"})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := a.Close(ctx); err != nil {
		t.Fatal(err)
	}
	calls, lines := sink.snapshot()
	if lines != 500 || calls < 2 || calls > 4 {
		t.Fatalf("writes=%d lines=%d after close", calls, lines)
	}
	if !sink.closed {
		t.Fatal("sink not closed")
	}
}

func TestLocalIdleFlush(t *testing.T) {
	sink := &stubSink{}
	a := newTestAccess(t, sink, nil, 20*time.Millisecond)
	a.Write(Record{Network: "tcp"})
	waitFor(t, 500*time.Millisecond, func() bool { _, lines := sink.snapshot(); return lines == 1 })
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := a.Close(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestLocalHourBoundaryKeepsRecordsInOwnHour(t *testing.T) {
	var mu sync.Mutex
	now := time.Date(2026, 10, 20, 10, 59, 59, 0, time.Local)
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	sink := &stubSink{}
	a := newTestAccess(t, sink, clock, time.Hour)
	for i := 0; i < 3; i++ {
		a.Write(Record{Time: "first", UserID: int64(i)})
	}
	time.Sleep(200 * time.Millisecond) // let the loop pick the records up under the 10:59 clock
	mu.Lock()
	now = now.Add(time.Second)
	mu.Unlock()
	for i := 0; i < 2; i++ {
		a.Write(Record{Time: "second", UserID: int64(i)})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := a.Close(ctx); err != nil {
		t.Fatal(err)
	}
	sink.mu.Lock()
	defer sink.mu.Unlock()
	var first, second string
	for _, w := range sink.writes {
		switch w.at.Hour() {
		case 10:
			first += string(w.data)
		case 11:
			second += string(w.data)
		default:
			t.Fatalf("batch routed to hour %v", w.at)
		}
	}
	if strings.Count(first, "first|") != 3 || strings.Contains(first, "second|") {
		t.Fatalf("hour 10 batches %q", first)
	}
	if strings.Count(second, "second|") != 2 || strings.Contains(second, "first|") {
		t.Fatalf("hour 11 batches %q", second)
	}
}

func TestRotatingWriteAtPlacesDataPerHour(t *testing.T) {
	dir := t.TempDir()
	r, err := NewRotating(dir, "soga-access-", true, 0)
	if err != nil {
		t.Fatal(err)
	}
	t1 := time.Now()
	t2 := t1.Add(time.Hour)
	for _, w := range []struct {
		at   time.Time
		data string
	}{{t1, "a\n"}, {t2, "b\n"}, {t1, "c\n"}, {t2, "d\n"}} {
		if _, err := r.WriteAt(w.at, []byte(w.data)); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	check := func(at time.Time, want string) {
		t.Helper()
		data, err := os.ReadFile(filepath.Join(dir, "soga-access-"+at.Format("2006-01-02 15:00:00")+".log"))
		if err != nil || string(data) != want {
			t.Fatalf("file for %v: %q %v", at, data, err)
		}
	}
	check(t1, "a\nc\n")
	check(t2, "b\nd\n")
	if _, err := r.Write([]byte("x")); err == nil {
		t.Fatal("write after close succeeded")
	}
}

func TestLocalEndToEndAcrossHour(t *testing.T) {
	dir := t.TempDir()
	rot, err := NewRotating(dir, "soga-access-", true, 0)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	t1 := time.Now()
	now := t1
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	a := newTestAccess(t, rot, clock, time.Hour)
	a.Write(Record{Time: "x", Host: "one"})
	time.Sleep(200 * time.Millisecond)
	mu.Lock()
	now = t1.Add(time.Hour)
	mu.Unlock()
	a.Write(Record{Time: "x", Host: "two"})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := a.Close(ctx); err != nil {
		t.Fatal(err)
	}
	one, err := os.ReadFile(filepath.Join(dir, "soga-access-"+t1.Format("2006-01-02 15:00:00")+".log"))
	if err != nil || string(one) != "x||0|0||one||0\n" {
		t.Fatalf("hour file %q %v", one, err)
	}
	two, err := os.ReadFile(filepath.Join(dir, "soga-access-"+t1.Add(time.Hour).Format("2006-01-02 15:00:00")+".log"))
	if err != nil || string(two) != "x||0|0||two||0\n" {
		t.Fatalf("next hour file %q %v", two, err)
	}
}

func TestLocalCloseFlushesPendingRecords(t *testing.T) {
	dir := t.TempDir()
	c := config.Defaults()
	c.AccessLogEnable = true
	c.AccessLogDir = dir
	c.AccessLogRetentionHours = 72
	a, err := NewAccess(context.Background(), c, func(err error) { t.Error(err) })
	if err != nil {
		t.Fatal(err)
	}
	const n = 600 // more than one size-triggered batch plus a partial one
	for i := 0; i < n; i++ {
		a.Write(Record{Time: "2026-10-20 10:03:22", Network: "tcp", NodeID: 7, UserID: int64(i), UserIP: "192.0.2.1", Host: "example.test", DestIP: "192.0.2.2", DestPort: 443})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := a.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if a.Enabled() {
		t.Fatal("closed sink reports enabled")
	}
	files, err := filepath.Glob(filepath.Join(dir, "soga-access-*.log"))
	if err != nil || len(files) != 1 {
		t.Fatal(files, err)
	}
	data, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	if len(lines) != n {
		t.Fatalf("lines=%d want %d", len(lines), n)
	}
	for i, line := range lines {
		want := "2026-10-20 10:03:22|tcp|7|" + strconv.Itoa(i) + "|192.0.2.1|example.test|192.0.2.2|443"
		if line != want {
			t.Fatalf("line %d = %q want %q (order or content lost)", i, line, want)
		}
	}
	a.Write(Record{Network: "tcp"}) // after Close: must be a no-op
	a.Log("tcp", 1, 2, "192.0.2.1:1", "h", "192.0.2.2:2")
}

func TestEnabledAndLogOnNil(t *testing.T) {
	var a *Access
	if a.Enabled() {
		t.Fatal("nil access enabled")
	}
	a.Log("tcp", 1, 2, "192.0.2.1:1", "h", "192.0.2.2:2")
	a.Write(Record{})
	if err := a.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestLogFormatsAndQueues(t *testing.T) {
	sink := &stubSink{}
	a := newTestAccess(t, sink, nil, time.Hour)
	if !a.Enabled() {
		t.Fatal("open sink disabled")
	}
	a.Log("tcp", 7, 9, "192.0.2.1:5000", "example.test", "192.0.2.2:443")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := a.Close(ctx); err != nil {
		t.Fatal(err)
	}
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if len(sink.writes) != 1 {
		t.Fatalf("writes=%d", len(sink.writes))
	}
	line := string(sink.writes[0].data)
	if !strings.HasSuffix(line, "|tcp|7|9|192.0.2.1|example.test|192.0.2.2|443\n") || len(line) != len("2026-10-20 10:03:22|tcp|7|9|192.0.2.1|example.test|192.0.2.2|443\n") {
		t.Fatalf("line=%q", line)
	}
}

func TestConcurrentWritesAreOrderedPerGoroutine(t *testing.T) {
	sink := &stubSink{}
	a := newTestAccess(t, sink, nil, localIdleFlush)
	const workers, perWorker = 8, 400 // 3200 < queue capacity, so nothing is dropped
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				a.Write(Record{Network: "tcp", NodeID: int64(w), UserID: int64(i), Host: "h|" + strconv.Itoa(i)})
				if i%50 == 0 {
					a.Enabled()
				}
			}
		}(w)
	}
	wg.Wait()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := a.Close(ctx); err != nil {
		t.Fatal(err)
	}
	sink.mu.Lock()
	defer sink.mu.Unlock()
	var all []byte
	for _, w := range sink.writes {
		all = append(all, w.data...)
	}
	lines := strings.Split(strings.TrimSuffix(string(all), "\n"), "\n")
	if len(lines) != workers*perWorker {
		t.Fatalf("lines=%d want %d", len(lines), workers*perWorker)
	}
	next := make([]int, workers)
	for _, line := range lines {
		fields := strings.Split(line, "|")
		if len(fields) != 8 { // the escaped pipe in Host must not add a column
			t.Fatalf("bad line %q", line)
		}
		w, _ := strconv.Atoi(fields[2])
		i, _ := strconv.Atoi(fields[3])
		if w < 0 || w >= workers || i != next[w] {
			t.Fatalf("line %q out of order: want user %d for node %d", line, next[w], w)
		}
		next[w]++
	}
}
