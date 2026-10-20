package tunnel

import (
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

const (
	TCP byte = 1
	UDP byte = 2
)

// Conn is an authenticated tunnel logical connection. UDP Read/Write preserve
// one datagram per call; the bytes are the original proxy-protocol payload.
type Conn struct {
	net.Conn
	Mode    byte
	readMu  sync.Mutex
	writeMu sync.Mutex
}

func serverSession(c net.Conn, k *keys) (*Conn, error) {
	var header [17]byte
	if _, err := io.ReadFull(c, header[:]); err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare(header[:16], k.verify[:]) != 1 {
		return nil, errors.New("invalid tunnel verification")
	}
	if header[16] != TCP && header[16] != UDP {
		return nil, errors.New("unsupported tunnel connection mode")
	}
	return &Conn{Conn: c, Mode: header[16]}, nil
}

func clientSession(c net.Conn, k *keys, mode byte) (*Conn, error) {
	if mode != TCP && mode != UDP {
		return nil, errors.New("unsupported tunnel connection mode")
	}
	header := append(append([]byte(nil), k.verify[:]...), mode)
	if err := writeAll(c, header); err != nil {
		return nil, err
	}
	return &Conn{Conn: c, Mode: mode}, nil
}

func (c *Conn) Read(p []byte) (int, error) {
	if c.Mode == TCP {
		return c.Conn.Read(p)
	}
	if len(p) == 0 {
		return 0, nil
	}
	c.readMu.Lock()
	defer c.readMu.Unlock()
	var h [2]byte
	if _, err := io.ReadFull(c.Conn, h[:]); err != nil {
		return 0, err
	}
	size := int(binary.BigEndian.Uint16(h[:]))
	n, err := io.ReadFull(c.Conn, p[:min(size, len(p))])
	if err != nil {
		return n, err
	}
	if size > n {
		_, err = io.CopyN(io.Discard, c.Conn, int64(size-n))
		if err == nil {
			err = io.ErrShortBuffer
		}
	}
	return n, err
}

func (c *Conn) Write(p []byte) (int, error) {
	if c.Mode == TCP {
		return c.Conn.Write(p)
	}
	if len(p) > 65535 {
		return 0, errors.New("tunnel UDP datagram exceeds 65535 bytes")
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	packet := make([]byte, len(p)+2)
	binary.BigEndian.PutUint16(packet, uint16(len(p)))
	copy(packet[2:], p)
	if err := writeAll(c.Conn, packet); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Bounded, task-specific replay policy. The source calls a replay helper before
// key setup; its exact retention policy is not claimed to be recovered.
type replayCache struct {
	mu      sync.Mutex
	entries map[string]time.Time
}

func (r *replayCache) accept(salt []byte) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	key := string(salt)
	if expiry, ok := r.entries[key]; ok && expiry.After(now) {
		return false
	}
	if r.entries == nil {
		r.entries = make(map[string]time.Time)
	}
	if len(r.entries) >= 65536 {
		for k, expiry := range r.entries {
			if !expiry.After(now) {
				delete(r.entries, k)
			}
		}
		// Fail closed rather than silently evicting live replay protection.
		if len(r.entries) >= 65536 {
			return false
		}
	}
	r.entries[key] = now.Add(10 * time.Minute)
	return true
}
