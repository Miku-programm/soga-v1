//go:build linux

package hoststats

import (
	"bufio"
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"strings"
	"time"
)

// ReadDJExtras matches the original DJ wire units: net_io is bytes/second,
// net_traffic is cumulative bytes across all interfaces, including loopback.
// Socket counts include every row in the IPv4 and IPv6 proc socket tables.
func (s *Sampler) ReadDJExtras(loads [3]float64) (map[string]json.RawMessage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sent, recv, err := readNetwork()
	if err != nil {
		return nil, err
	}
	tcp, err := socketCount("/proc/net/tcp", "/proc/net/tcp6")
	if err != nil {
		return nil, err
	}
	udp, err := socketCount("/proc/net/udp", "/proc/net/udp6")
	if err != nil {
		return nil, err
	}
	now := time.Now()
	elapsed := now.Sub(s.netAt).Seconds()
	var up, down uint64
	if !s.netAt.IsZero() && elapsed > 0 {
		if sent >= s.sent {
			up = uint64(float64(sent-s.sent) / elapsed)
		}
		if recv >= s.recv {
			down = uint64(float64(recv-s.recv) / elapsed)
		}
	}
	values := map[string]any{
		"loads": loads, "net_io": map[string]uint64{"up": up, "down": down},
		"net_traffic": map[string]uint64{"sent": sent, "recv": recv},
		"tcp_count":   tcp, "udp_count": udp,
	}
	result := map[string]json.RawMessage{}
	for key, value := range values {
		raw, err := json.Marshal(value)
		if err != nil {
			return nil, err
		}
		result[key] = raw
	}
	s.sent, s.recv, s.netAt = sent, recv, now
	return result, nil
}

func readNetwork() (uint64, uint64, error) {
	f, err := os.Open("/proc/net/dev")
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()
	var sent, recv uint64
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		_, counters, ok := strings.Cut(scanner.Text(), ":")
		if !ok {
			continue
		}
		fields := strings.Fields(counters)
		if len(fields) < 16 {
			return 0, 0, errors.New("invalid /proc/net/dev")
		}
		rx, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil {
			return 0, 0, err
		}
		tx, err := strconv.ParseUint(fields[8], 10, 64)
		if err != nil {
			return 0, 0, err
		}
		sent += tx
		recv += rx
	}
	return sent, recv, scanner.Err()
}
func socketCount(paths ...string) (int, error) {
	count := 0
	for _, path := range paths {
		f, err := os.Open(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return 0, err
		}
		scanner := bufio.NewScanner(f)
		header := scanner.Scan()
		if !header {
			f.Close()
			return 0, errors.New("socket table has no header")
		}
		for scanner.Scan() {
			if strings.TrimSpace(scanner.Text()) != "" {
				count++
			}
		}
		err = scanner.Err()
		f.Close()
		if err != nil {
			return 0, err
		}
	}
	return count, nil
}
