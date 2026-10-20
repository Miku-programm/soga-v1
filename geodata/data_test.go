package geodata

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"reconstructed.local/soga/policy"
)

func TestPinnedDatasetsAndRejectedUpdate(t *testing.T) {
	g, err := Load("", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if items, ok := g.Domains("google"); !ok || len(items) == 0 {
		t.Fatal("google category missing")
	}
	if items, _, ok := g.Prefixes("cn"); !ok || len(items) == 0 {
		t.Fatal("CN prefix data missing")
	}
	dir := t.TempDir()
	// Minimal legal wire records: geosite("test", full example.test) and
	// geoip("test", 192.0.2.0/24).
	s := []byte{10, 30, 10, 4, 't', 'e', 's', 't', 18, 22, 8, 3, 18, 18}
	s = append(s, []byte("exact.example.test")...)
	// Build lengths from content to avoid testing a malformed fixture.
	domain := append([]byte{8, 3, 18, 18}, []byte("exact.example.test")...)
	entry := append([]byte{10, 4, 't', 'e', 's', 't', 18, byte(len(domain))}, domain...)
	s = append([]byte{10, byte(len(entry))}, entry...)
	i := []byte{10, 18, 10, 4, 't', 'e', 's', 't', 18, 10, 10, 4, 192, 0, 2, 0, 16, 24}
	i[1] = byte(len(i) - 2)
	i[9] = 8
	var bad atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/site" {
			_, _ = w.Write(s)
			return
		}
		if bad.Load() {
			_, _ = w.Write([]byte{255})
			return
		}
		_, _ = w.Write(i)
	}))
	defer server.Close()
	if _, err = Update(context.Background(), server.URL+"/site", server.URL+"/ip", dir); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(dir, "active.json"))
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := Prepare(context.Background(), server.URL+"/site", server.URL+"/ip")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = policy.Compile("geosite:required-but-absent", candidate.Data); err == nil {
		t.Fatal("missing active category accepted")
	}
	unchanged, _ := os.ReadFile(filepath.Join(dir, "active.json"))
	if string(unchanged) != string(before) {
		t.Fatal("unpublished candidate changed active data")
	}
	bad.Store(true)
	if _, err = Update(context.Background(), server.URL+"/site", server.URL+"/ip", dir); err == nil {
		t.Fatal("malformed update accepted")
	}
	after, _ := os.ReadFile(filepath.Join(dir, "active.json"))
	if string(before) != string(after) {
		t.Fatal("failed update changed manifest")
	}
	loaded, err := Load("", "", dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := loaded.Domains("test"); !ok {
		t.Fatal("persisted snapshot missing")
	}
}
