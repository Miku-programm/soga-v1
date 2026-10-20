//go:build linux

// Package hoststats reads actual host counters for panel status reports.
package hoststats

import (
	"bufio"
	"errors"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
	"reconstructed.local/soga/panel"
)

type Sampler struct {
	mu          sync.Mutex
	total, idle uint64
	sent, recv  uint64
	netAt       time.Time
}

func New() *Sampler {
	s := new(Sampler)
	s.total, s.idle, _ = readCPU()
	s.sent, s.recv, _ = readNetwork()
	s.netAt = time.Now()
	return s
}

func readCPU() (uint64, uint64, error) {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0, 0, err
	}
	first, _, _ := strings.Cut(string(data), "\n")
	fields := strings.Fields(first)
	if len(fields) < 5 || fields[0] != "cpu" {
		return 0, 0, errors.New("invalid /proc/stat")
	}
	var total, idle uint64
	// Guest time is already accounted in user/nice, so only fields 1..8 count.
	for i, v := range fields[1:min(len(fields), 9)] {
		n, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			return 0, 0, err
		}
		total += n
		if i == 3 || i == 4 {
			idle += n
		}
	}
	return total, idle, nil
}

func (s *Sampler) Read(path string) (panel.Status, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var result panel.Status
	total, idle, err := readCPU()
	if err != nil {
		return result, err
	}
	if total > s.total && idle >= s.idle {
		busy := float64(total-s.total) - float64(idle-s.idle)
		result.CPU = max(0, min(100, 100*busy/float64(total-s.total)))
	}
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return result, err
	}
	mem := map[string]uint64{}
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		f := strings.Fields(scanner.Text())
		if len(f) < 2 {
			continue
		}
		n, err := strconv.ParseUint(f[1], 10, 64)
		if err != nil {
			return result, err
		}
		if len(f) > 2 && f[2] == "kB" {
			n *= 1024
		}
		mem[strings.TrimSuffix(f[0], ":")] = n
	}
	result.Mem.Total = mem["MemTotal"]
	available, ok := mem["MemAvailable"]
	if !ok {
		available = mem["MemFree"] + mem["Buffers"] + mem["Cached"]
	}
	result.Mem.Used = result.Mem.Total - min(result.Mem.Total, available)
	result.Swap.Total = mem["SwapTotal"]
	result.Swap.Used = result.Swap.Total - min(result.Swap.Total, mem["SwapFree"])
	var fs unix.Statfs_t
	if path == "" {
		path = "/"
	}
	if err := unix.Statfs(path, &fs); err != nil {
		return result, err
	}
	result.Disk.Total = fs.Blocks * uint64(fs.Bsize)
	result.Disk.Used = (fs.Blocks - fs.Bfree) * uint64(fs.Bsize)
	data, err = os.ReadFile("/proc/uptime")
	if err != nil {
		return result, err
	}
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return result, errors.New("empty /proc/uptime")
	}
	seconds, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return result, err
	}
	result.Uptime = uint64(seconds)
	data, err = os.ReadFile("/proc/loadavg")
	if err != nil {
		return result, err
	}
	loads := strings.Fields(string(data))
	if len(loads) < 3 {
		return result, errors.New("invalid /proc/loadavg")
	}
	for i := range result.Loads {
		result.Loads[i], err = strconv.ParseFloat(loads[i], 64)
		if err != nil {
			return result, err
		}
	}
	s.total, s.idle = total, idle
	return result, nil
}
