// Package tunnel reconstructs the tunnel framing observed in the supplied
// soga 2.17.0 artifact. It is newly written code, not recovered original source.
package tunnel

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/sha3"
)

// The initialized value at 0x5099930, decoded statically from 0x11da700.
var domain, _ = hex.DecodeString("d8b8c066c10e8b0d1b1ba3ad1f7de1525625d03f9d9f682f1bd6097b13a22b38")

type keys struct {
	master []byte
	verify [16]byte
	method string
}

func makeKeys(method, password string) (*keys, error) {
	var n int
	switch method {
	case "aes-128-gcm":
		n = 16
	case "aes-192-gcm":
		n = 24
	case "aes-256-gcm", "chacha20-ietf-poly1305":
		n = 32
	default:
		return nil, fmt.Errorf("unsupported tunnel cipher %q", method)
	}
	if password == "" {
		return nil, errors.New("tunnel password is empty")
	}
	// 0x10aae60 uses EVP_BytesToKey-style successive hashes. All observed
	// ciphers need at most 32 bytes, so only the first SHA3-512 digest is used.
	sum := sha3.Sum512([]byte(password))
	k := &keys{master: append([]byte(nil), sum[:n]...), method: method}
	_, err := io.ReadFull(hkdf.New(sha3.New512, k.master, domain, []byte(password)), k.verify[:])
	return k, err
}

func (k *keys) aead(salt []byte) (cipher.AEAD, []byte, error) {
	key := make([]byte, len(k.master))
	if _, err := io.ReadFull(hkdf.New(sha3.New512, k.master, salt, domain), key); err != nil {
		return nil, nil, err
	}
	if k.method == "chacha20-ietf-poly1305" {
		a, err := chacha20poly1305.New(key)
		return a, key, err
	}
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	a, err := cipher.NewGCM(b)
	return a, key, err
}

type direction struct {
	aead  cipher.AEAD
	nonce []byte
	shake sha3.ShakeHash
}

func (k *keys) direction(salt []byte) (*direction, error) {
	a, key, err := k.aead(salt)
	if err != nil {
		return nil, err
	}
	h := sha3.NewShake128()
	_, _ = h.Write(salt)
	_, _ = h.Write(key)
	return &direction{a, append([]byte(nil), salt...), h}, nil
}

func (d *direction) next() {
	for i := range d.nonce {
		d.nonce[i]++
		if d.nonce[i] != 0 {
			break
		}
	}
}

func (d *direction) number() uint16 {
	var b [2]byte
	_, _ = io.ReadFull(d.shake, b[:])
	return binary.BigEndian.Uint16(b[:])
}

// wireConn has separate read/write state, matching Cb7vj3KQA8 at 0x37150d8.
// Each direction sends one random 12-byte salt, then authenticated length/body
// records. Nonces increment little endian after each AEAD operation.
type wireConn struct {
	net.Conn
	keys     *keys
	replay   *replayCache
	readMu   sync.Mutex
	writeMu  sync.Mutex
	reader   *direction
	writer   *direction
	pending  []byte
	readErr  error
	writeErr error
}

func (c *wireConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if c.readErr != nil {
		return 0, c.readErr
	}
	if c.reader == nil {
		salt := make([]byte, 12)
		if _, err := io.ReadFull(c.Conn, salt); err != nil {
			c.readErr = err
			return 0, err
		}
		d, err := c.keys.direction(salt)
		if err != nil {
			c.readErr = err
			return 0, err
		}
		c.reader = d
		// Reserve only after the first authenticated header, below.
	}
	for len(c.pending) == 0 {
		d := c.reader
		header := make([]byte, 2+d.aead.Overhead())
		if _, err := io.ReadFull(c.Conn, header); err != nil {
			c.readErr = err
			return 0, err
		}
		plain, err := d.aead.Open(header[:0], d.nonce, header, nil)
		if err != nil {
			c.readErr = err
			return 0, err
		}
		if c.replay != nil {
			if !c.replay.accept(d.nonce) {
				c.readErr = errors.New("replayed tunnel salt")
				return 0, c.readErr
			}
			c.replay = nil
		}
		d.next()
		padding := int(d.number() % 128)
		size := int(binary.BigEndian.Uint16(plain) ^ d.number())
		if size < padding {
			c.readErr = errors.New("tunnel record length is shorter than padding")
			return 0, c.readErr
		}
		body := make([]byte, size+d.aead.Overhead())
		if _, err = io.ReadFull(c.Conn, body); err != nil {
			c.readErr = err
			return 0, err
		}
		body, err = d.aead.Open(body[:0], d.nonce, body, nil)
		if err != nil {
			c.readErr = err
			return 0, err
		}
		d.next()
		c.pending = body[:size-padding]
	}
	n := copy(p, c.pending)
	c.pending = c.pending[n:]
	return n, nil
}

func (c *wireConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	var prefix []byte
	if c.writer == nil {
		prefix = make([]byte, 12)
		if _, err := io.ReadFull(rand.Reader, prefix); err != nil {
			return 0, err
		}
		d, err := c.keys.direction(prefix)
		if err != nil {
			return 0, err
		}
		c.writer = d
	}
	written := 0
	for len(p) > 0 {
		d := c.writer
		padding := int(d.number() % 128)
		// Avoid uint16 length overflow when adding padding. This emits smaller
		// valid frames than the artifact's unsafe 65535-byte split boundary.
		n := min(len(p), 65535-padding)
		var header [2]byte
		binary.BigEndian.PutUint16(header[:], uint16(n+padding)^d.number())
		out := d.aead.Seal(prefix, d.nonce, header[:], nil)
		d.next()
		body := make([]byte, n+padding)
		copy(body, p[:n])
		if _, err := io.ReadFull(rand.Reader, body[n:]); err != nil {
			c.writeErr = err
			return written, err
		}
		out = d.aead.Seal(out, d.nonce, body, nil)
		d.next()
		if err := writeAll(c.Conn, out); err != nil {
			c.writeErr = err
			return written, err
		}
		prefix = nil
		written += n
		p = p[n:]
	}
	return written, nil
}

func writeAll(w io.Writer, p []byte) error {
	for len(p) != 0 {
		n, err := w.Write(p)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		p = p[n:]
	}
	return nil
}
