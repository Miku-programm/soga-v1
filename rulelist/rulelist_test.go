package rulelist

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
)

func TestLocalCommentsDuplicatesAndForbiddenPorts(t *testing.T) {
	got, err := ReadLocal(strings.NewReader("\n # comment\n domain:a # note\n domain:a\nport:25#x\n"), []string{"25", "30-40"})
	want := []string{"domain:a", "domain:a", "port:25", "port:25", "port:30-40"}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q, %v; want %q", got, err, want)
	}
}

func TestLocalReadLineFragmentsAreNotJoined(t *testing.T) {
	text := strings.Repeat("x", 4097) + "\n"
	for _, input := range []io.Reader{
		strings.NewReader(text),
		bufio.NewReaderSize(strings.NewReader(text), 8192),
	} {
		got, err := ReadLocal(input, nil)
		if err != nil || len(got) != 2 || len(got[0]) != 4096 || got[1] != "x" {
			t.Fatalf("expected 4096-byte and one-byte fragments, got lengths %v, err %v", lengths(got), err)
		}
	}
}

func lengths(s []string) []int {
	result := make([]int, len(s))
	for i := range s {
		result[i] = len(s[i])
	}
	return result
}

func TestLocalLoadFailureAndRemoteSelectionPreserveSnapshot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blockList")
	if err := os.WriteFile(path, []byte("domain:example.test\n"), 0600); err != nil {
		t.Fatal(err)
	}
	var s Store
	if changed, err := s.LoadLocal(path, "", []string{"25"}); err != nil || !changed {
		t.Fatal(changed, err)
	}
	want := s.Snapshot()
	copy := s.Snapshot()
	copy[0] = "corrupted"
	if !reflect.DeepEqual(s.Snapshot(), want) {
		t.Fatal("snapshot alias escaped")
	}
	if changed, err := s.LoadLocal(path+".missing", "https://unused.invalid", []string{"80"}); err != nil || changed {
		t.Fatal(changed, err)
	}
	if changed, err := s.LoadLocal(path+".missing", "", nil); err == nil || changed {
		t.Fatal("expected open failure without update", changed, err)
	}
	if !reflect.DeepEqual(s.Snapshot(), want) {
		t.Fatal("failed load changed snapshot")
	}
}

func TestRemoteKeepsCommentsAndDoesNotCheckHTTPStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, " # comment \n domain:a # note \n\n")
	}))
	defer server.Close()
	var s Store
	got, err := s.Get(context.Background(), server.URL, server.Client())
	want := []string{"# comment", "domain:a # note"}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatal(got, err)
	}
	if len(s.Snapshot()) != 0 {
		t.Fatal("remote path unexpectedly published local snapshot")
	}
}

type brokenReader struct{ read bool }

func (b *brokenReader) Read(p []byte) (int, error) {
	if b.read {
		return 0, errors.New("synthetic read failure")
	}
	b.read = true
	return copy(p, "domain:first\n"), nil
}

func TestPartialLocalReadRetainsRules(t *testing.T) {
	got, err := ReadLocal(&brokenReader{}, []string{"25"})
	if err == nil || !reflect.DeepEqual(got, []string{"domain:first", "port:25"}) {
		t.Fatal(got, err)
	}
}

func TestSnapshotAndReloadConcurrent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules")
	if err := os.WriteFile(path, []byte("full:example.test\n"), 0600); err != nil {
		t.Fatal(err)
	}
	var s Store
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				_, _ = s.LoadLocal(path, "", nil)
				_ = s.Snapshot()
			}
		}()
	}
	wg.Wait()
	if !reflect.DeepEqual(s.Snapshot(), []string{"full:example.test"}) {
		t.Fatal(s.Snapshot())
	}
}
