//go:build linux

package hoststats

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestDJActualSocketAndNetworkCounters(t *testing.T) {
	s := New()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	status, err := s.Read(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	extra, err := s.ReadDJExtras(status.Loads)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"tcp_count", "udp_count"} {
		var count int
		if err := json.Unmarshal(extra[key], &count); err != nil || count < 1 {
			t.Fatal(key, count, err)
		}
	}
	var totals map[string]uint64
	if err := json.Unmarshal(extra["net_traffic"], &totals); err != nil || len(totals) != 2 {
		t.Fatal(totals, err)
	}
	if _, ok := totals["sent"]; !ok {
		t.Fatal("missing sent")
	}
	if _, ok := totals["recv"]; !ok {
		t.Fatal("missing recv")
	}
	var loads [3]float64
	if err := json.Unmarshal(extra["loads"], &loads); err != nil || loads != status.Loads {
		t.Fatal(loads, err)
	}
	var rate map[string]uint64
	if err := json.Unmarshal(extra["net_io"], &rate); err != nil || len(rate) != 2 {
		t.Fatal(rate, err)
	}
	// An optional absent IPv6 table is harmless; headers and blank lines do
	// not represent sockets.
	path := filepath.Join(t.TempDir(), "tcp")
	if err := os.WriteFile(path, []byte("sl local_address rem_address\n0 one two\n\n1 three four\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if n, err := socketCount(path, path+".missing"); err != nil || n != 2 {
		t.Fatal(n, err)
	}
}
