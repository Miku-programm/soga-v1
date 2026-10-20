package logging

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"reconstructed.local/soga/config"
)

func TestLocalLogFormatAndRetention(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	old := filepath.Join(dir, "soga-access-"+now.Add(-100*time.Hour).Format("2006-01-02 15:00:00")+".log")
	keep := filepath.Join(dir, "unrelated.log")
	_ = os.WriteFile(old, []byte("old"), 0600)
	_ = os.WriteFile(keep, []byte("keep"), 0600)
	c := config.Defaults()
	c.AccessLogEnable = true
	c.AccessLogDir = dir
	c.AccessLogRetentionHours = 72
	a, err := NewAccess(context.Background(), c, func(err error) { t.Error(err) })
	if err != nil {
		t.Fatal(err)
	}
	a.Write(Record{Time: "2026-10-20 10:03:22", Network: "tcp", NodeID: 7, UserID: 9, UserIP: "192.0.2.1", Host: "example.test|\ninjected", DestIP: "192.0.2.2", DestPort: 443})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := a.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Fatal("expired owned file retained", err)
	}
	if data, err := os.ReadFile(keep); err != nil || string(data) != "keep" {
		t.Fatal("unrelated file removed")
	}
	files, err := filepath.Glob(filepath.Join(dir, "soga-access-*.log"))
	if err != nil || len(files) != 1 {
		t.Fatal(files, err)
	}
	data, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	want := "2026-10-20 10:03:22|tcp|7|9|192.0.2.1|example.test\\x7c\\ninjected|192.0.2.2|443\n"
	if string(data) != want {
		t.Fatalf("log=%q", data)
	}
}

func TestClickHouseWireAndFailureDoesNotBlock(t *testing.T) {
	var mu sync.Mutex
	var queries []string
	var rows []Record
	fail := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Header.Get("X-ClickHouse-User") != "alice" || r.Header.Get("X-ClickHouse-Key") != "private-password" {
			t.Error("wrong authentication")
		}
		queries = append(queries, r.URL.Query().Get("query"))
		if strings.HasPrefix(r.URL.Query().Get("query"), "INSERT") {
			dec := json.NewDecoder(r.Body)
			for {
				var row Record
				err := dec.Decode(&row)
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Error(err)
					break
				}
				rows = append(rows, row)
			}
		}
		if fail {
			http.Error(w, "private-password", 500)
			return
		}
		fmt.Fprint(w, "")
	}))
	defer server.Close()
	c := config.Defaults()
	c.AccessLogEnable = true
	c.AccessLogMode = "clickhouse"
	c.AccessLogClickhouseAddr = server.URL
	c.AccessLogClickhouseUser = "alice"
	c.AccessLogClickhousePassword = "private-password"
	c.AccessLogClickhouseBatchSize = 2
	errs := make(chan error, 8)
	a, err := NewAccess(context.Background(), c, func(e error) { errs <- e })
	if err != nil {
		t.Fatal(err)
	}
	a.Write(Record{Network: "udp", NodeID: 7, UserID: 3, Host: "test", DestIP: "192.0.2.1", DestPort: 53})
	a.Write(Record{Network: "tcp", NodeID: 7, UserID: 4, Host: "test2", DestIP: "192.0.2.2", DestPort: 80})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := a.Close(ctx); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	if len(queries) != 3 || len(rows) != 2 || !strings.Contains(queries[1], "PARTITION BY toYYYYMMDD(time)") || strings.Contains(queries[1], " TTL ") {
		t.Error(queries, rows)
	}
	fail = true
	mu.Unlock()
	a, err = NewAccess(context.Background(), c, func(e error) { errs <- e })
	if err != nil {
		t.Fatal("server failure blocked startup", err)
	}
	a.Write(Record{Network: "tcp"})
	if err := a.Close(ctx); err != nil {
		t.Fatal(err)
	}
	close(errs)
	count := 0
	for err := range errs {
		count++
		if strings.Contains(err.Error(), "private-password") {
			t.Fatal("credential in error")
		}
	}
	if count != 3 {
		t.Fatal("failed batches not reported", count)
	}
}
