//go:build linux

package hoststats

import "testing"

func TestActualHostCounters(t *testing.T) {
	s := New()
	for range 2 {
		status, err := s.Read(t.TempDir())
		if err != nil || status.Mem.Total == 0 || status.Disk.Total == 0 || status.Uptime == 0 ||
			status.Mem.Used > status.Mem.Total || status.Disk.Used > status.Disk.Total ||
			status.CPU < 0 || status.CPU > 100 {
			t.Fatal(status, err)
		}
	}
	if _, err := s.Read("/path-that-does-not-exist/soga-stats"); err == nil {
		t.Fatal("missing disk path did not fail")
	}
}
