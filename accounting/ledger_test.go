package accounting

import (
	"os"
	"path/filepath"
	"testing"

	"reconstructed.local/soga/panel"
)

func TestRetryRestartAndAcknowledgementPreserveNewBytes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "traffic.json")
	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Observe(map[int64]Counters{7: {100, 40}}); err != nil {
		t.Fatal(err)
	}
	batch := l.Batch()
	// A failed HTTP report does not call Acknowledge.
	if err := l.Observe(map[int64]Counters{7: {130, 60}}); err != nil {
		t.Fatal(err)
	}
	if err := l.Acknowledge(batch); err != nil {
		t.Fatal(err)
	}
	rows := l.Batch()
	if len(rows) != 1 || rows[0] != (panel.Traffic{ID: 7, Upload: 30, Download: 20}) {
		t.Fatal(rows)
	}
	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.Observe(map[int64]Counters{7: {5, 6}}); err != nil {
		t.Fatal(err)
	}
	rows = reopened.Batch()
	if rows[0] != (panel.Traffic{ID: 7, Upload: 35, Download: 26}) {
		t.Fatal(rows)
	}
	if err := reopened.Acknowledge(rows); err != nil || len(reopened.Batch()) != 0 {
		t.Fatal(err)
	}
}

func TestFailedPersistenceDoesNotAdvanceBaseline(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("not a directory"), 0600); err != nil {
		t.Fatal(err)
	}
	l := &Ledger{path: filepath.Join(blocker, "state.json"), pending: map[int64]Counters{}, last: map[int64]Counters{}}
	if err := l.Observe(map[int64]Counters{1: {8, 9}}); err == nil || len(l.Batch()) != 0 {
		t.Fatal("failed persistence was acknowledged")
	}
	l.path = filepath.Join(dir, "state.json")
	if err := l.Observe(map[int64]Counters{1: {8, 9}}); err != nil {
		t.Fatal(err)
	}
	if got := l.Batch(); len(got) != 1 || got[0].Upload != 8 {
		t.Fatal(got)
	}
	if err := l.Observe(map[int64]Counters{1: {0, 0}}); err == nil {
		t.Fatal("silent counter reset")
	}
	l.ResetSource()
	if err := l.Observe(map[int64]Counters{1: {2, 3}}); err != nil {
		t.Fatal(err)
	}
	if got := l.Batch(); got[0].Upload != 10 || got[0].Download != 12 {
		t.Fatal(got)
	}
}
