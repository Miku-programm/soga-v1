// Package accounting provides durable pending traffic for the reconstruction.
// The panel API has no idempotency key: an accepted request whose response is lost
// can be retried and counted twice. This is at-least-once, not exactly-once delivery.
package accounting

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"reconstructed.local/soga/panel"
)

type Counters struct {
	Upload   uint64 `json:"upload"`
	Download uint64 `json:"download"`
}

type diskState struct {
	Version int                `json:"version"`
	Pending map[int64]Counters `json:"pending"`
}

type Ledger struct {
	mu      sync.Mutex
	path    string
	pending map[int64]Counters
	last    map[int64]Counters
}

// Open loads pending totals. Cumulative source counters are process-local and
// start fresh after a server restart, so they are not restored from this file.
func Open(path string) (*Ledger, error) {
	l := &Ledger{path: path, pending: map[int64]Counters{}, last: map[int64]Counters{}}
	if path == "" {
		return l, nil
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return l, nil
	}
	if err != nil {
		return nil, err
	}
	var state diskState
	if err = json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("traffic ledger: %w", err)
	}
	if state.Version != 1 || state.Pending == nil {
		return nil, errors.New("traffic ledger: unsupported state")
	}
	for id := range state.Pending {
		if id <= 0 {
			return nil, errors.New("traffic ledger: invalid user ID")
		}
	}
	l.pending = state.Pending
	return l, nil
}

// Observe saves the delta before advancing its in-memory baseline. A failed
// file write leaves both the baseline and pending state unchanged for retry.
func (l *Ledger) Observe(current map[int64]Counters) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	next := clone(l.pending)
	for id, total := range current {
		if id <= 0 {
			return errors.New("traffic ledger: nonpositive user ID")
		}
		old := l.last[id]
		if total.Upload < old.Upload || total.Download < old.Download {
			return errors.New("traffic counters decreased: reset baseline explicitly after replacing the server")
		}
		value := next[id]
		up, down := total.Upload-old.Upload, total.Download-old.Download
		if math.MaxUint64-value.Upload < up || math.MaxUint64-value.Download < down {
			return errors.New("traffic counter overflow")
		}
		value.Upload += up
		value.Download += down
		if value.Upload != 0 || value.Download != 0 {
			next[id] = value
		}
	}
	if err := l.save(next); err != nil {
		return err
	}
	baseline := clone(l.last)
	for id, value := range current {
		baseline[id] = value
	}
	l.pending, l.last = next, baseline
	return nil
}

// ResetSource must follow an Observe of the closed old server's final counters.
func (l *Ledger) ResetSource() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.last = map[int64]Counters{}
}

func (l *Ledger) Batch() []panel.Traffic {
	l.mu.Lock()
	defer l.mu.Unlock()
	ids := make([]int64, 0, len(l.pending))
	for id := range l.pending {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	rows := make([]panel.Traffic, 0, len(ids))
	for _, id := range ids {
		c := l.pending[id]
		rows = append(rows, panel.Traffic{ID: id,
			Upload:   int64(min(c.Upload, uint64(math.MaxInt64))),
			Download: int64(min(c.Download, uint64(math.MaxInt64)))})
	}
	return rows
}

// Acknowledge subtracts exactly the transmitted batch, retaining later deltas.
// Call it only when the panel explicitly accepted that batch.
func (l *Ledger) Acknowledge(batch []panel.Traffic) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	next := clone(l.pending)
	for _, row := range batch {
		value, exists := next[row.ID]
		if !exists || row.Upload < 0 || row.Download < 0 ||
			uint64(row.Upload) > value.Upload || uint64(row.Download) > value.Download {
			return errors.New("traffic acknowledgement exceeds pending data")
		}
		value.Upload -= uint64(row.Upload)
		value.Download -= uint64(row.Download)
		if value.Upload == 0 && value.Download == 0 {
			delete(next, row.ID)
		} else {
			next[row.ID] = value
		}
	}
	if err := l.save(next); err != nil {
		return err
	}
	l.pending = next
	return nil
}

func clone(src map[int64]Counters) map[int64]Counters {
	dst := make(map[int64]Counters, len(src))
	for key, value := range src {
		dst[key] = value
	}
	return dst
}

func (l *Ledger) save(next map[int64]Counters) error {
	if l.path == "" {
		return nil
	}
	data, err := json.MarshalIndent(diskState{Version: 1, Pending: next}, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(l.path)
	if err = os.MkdirAll(dir, 0750); err != nil {
		return err
	}
	file, err := os.CreateTemp(dir, ".traffic-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if _, err = file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	if err = file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	if err = os.Rename(file.Name(), l.path); err != nil {
		return err
	}
	// Directory fsync is unavailable on some filesystems/Windows. The data
	// file itself is synced above; don't claim stronger crash guarantees.
	if parent, err := os.Open(dir); err == nil {
		_ = parent.Sync()
		_ = parent.Close()
	}
	return nil
}
