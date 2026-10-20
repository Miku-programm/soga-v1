// Package simpleobfs implements the simple-obfs wire framing. This is not TLS
// encryption or WebSocket framing; callers must authenticate and decrypt the
// enclosed Shadowsocks stream.
package simpleobfs

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

type Options struct {
	Protocol, Mode, Host, Path string
}

type Metadata struct {
	Host, Path string
}

func Validate(o Options) error {
	if o.Protocol != "http" && o.Protocol != "tls" {
		return fmt.Errorf("unknown simple-obfs protocol %q", o.Protocol)
	}
	switch o.Mode {
	case "", "relaxed", "strict", "strict_path", "strict_host":
	default:
		return fmt.Errorf("unknown simple-obfs mode %q", o.Mode)
	}
	return nil
}

// Server consumes only the first framing header. Deadlines remain controlled
// by the caller. Buffered payload is preserved, including data read ahead.
func Server(conn net.Conn, o Options) (net.Conn, Metadata, error) {
	if err := Validate(o); err != nil {
		return nil, Metadata{}, err
	}
	var (
		wrapped net.Conn
		meta    Metadata
		err     error
	)
	if o.Protocol == "http" {
		wrapped, meta, err = serverHTTP(conn)
	} else {
		wrapped, meta, err = serverTLS(conn)
	}
	if err != nil {
		return nil, meta, err
	}
	if o.Mode == "strict" || o.Mode == "strict_host" {
		if normalizeHost(meta.Host) != normalizeHost(o.Host) {
			return nil, meta, errors.New("simple-obfs host mismatch")
		}
	}
	if o.Protocol == "http" && (o.Mode == "strict" || o.Mode == "strict_path") {
		path := o.Path
		if path == "" {
			path = "/"
		}
		if meta.Path != path {
			return nil, meta, errors.New("simple-obfs path mismatch")
		}
	}
	return wrapped, meta, nil
}

func normalizeHost(host string) string {
	if name, _, err := net.SplitHostPort(host); err == nil {
		host = name
	}
	return strings.ToLower(strings.TrimSuffix(host, "."))
}

func serverHTTP(conn net.Conn) (net.Conn, Metadata, error) {
	reader := bufio.NewReaderSize(conn, 32768)
	var header []byte
	for {
		line, err := reader.ReadSlice('\n')
		if err != nil {
			return nil, Metadata{}, fmt.Errorf("simple-obfs HTTP header: %w", err)
		}
		if len(header)+len(line) > 32768 {
			return nil, Metadata{}, errors.New("simple-obfs HTTP header too large")
		}
		header = append(header, line...)
		if bytes.Equal(line, []byte("\r\n")) {
			break
		}
	}
	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(header)))
	if err != nil {
		return nil, Metadata{}, fmt.Errorf("simple-obfs HTTP request: %w", err)
	}
	if req.ProtoMajor != 1 || req.ProtoMinor != 1 || !strings.EqualFold(req.Header.Get("Upgrade"), "websocket") {
		return nil, Metadata{}, errors.New("invalid simple-obfs HTTP upgrade")
	}
	return &httpConn{Conn: conn, reader: reader, first: true}, Metadata{Host: req.Host, Path: req.RequestURI}, nil
}

type httpConn struct {
	net.Conn
	reader *bufio.Reader
	mu     sync.Mutex
	first  bool
}

func (c *httpConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

func (c *httpConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(p) == 0 {
		return 0, nil
	}
	if !c.first {
		return c.Conn.Write(p)
	}
	header := []byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
	packet := append(header, p...)
	n, err := writeAll(c.Conn, packet)
	if n >= len(header) {
		c.first = false
		return n - len(header), err
	}
	return 0, err
}

func serverTLS(conn net.Conn) (net.Conn, Metadata, error) {
	var header [5]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return nil, Metadata{}, err
	}
	if header[0] != 0x16 || header[1] != 3 || header[2] != 1 {
		return nil, Metadata{}, errors.New("invalid simple-obfs TLS record")
	}
	body := make([]byte, int(binary.BigEndian.Uint16(header[3:])))
	if _, err := io.ReadFull(conn, body); err != nil {
		return nil, Metadata{}, err
	}
	host, ticket, sessionID, err := parseHello(body)
	if err != nil {
		return nil, Metadata{}, err
	}
	if ticket == nil {
		return nil, Metadata{}, errors.New("simple-obfs ClientHello has no session ticket payload")
	}
	return &tlsConn{Conn: conn, pending: ticket, sessionID: sessionID, first: true}, Metadata{Host: host}, nil
}

// ParseClientHelloSNI accepts a complete TLS handshake, starting with the
// ClientHello type and three-byte length (without the TLS record header).
func ParseClientHelloSNI(handshake []byte) (string, error) {
	host, _, _, err := parseHello(handshake)
	return host, err
}

func parseHello(body []byte) (host string, ticket, sessionID []byte, err error) {
	fail := func() (string, []byte, []byte, error) {
		return "", nil, nil, errors.New("malformed simple-obfs ClientHello")
	}
	if len(body) < 39 || body[0] != 1 || int(body[1])<<16|int(body[2])<<8|int(body[3]) != len(body)-4 {
		return fail()
	}
	pos := 39
	sidLen := int(body[38])
	if sidLen > 32 || pos+sidLen+2 > len(body) {
		return fail()
	}
	sessionID = append([]byte(nil), body[pos:pos+sidLen]...)
	pos += sidLen
	cipherLen := int(binary.BigEndian.Uint16(body[pos:]))
	pos += 2
	if cipherLen == 0 || cipherLen%2 != 0 || pos+cipherLen+1 > len(body) {
		return fail()
	}
	pos += cipherLen
	compLen := int(body[pos])
	pos++
	if compLen == 0 || pos+compLen+2 > len(body) {
		return fail()
	}
	pos += compLen
	extLen := int(binary.BigEndian.Uint16(body[pos:]))
	pos += 2
	if extLen != len(body)-pos {
		return fail()
	}
	for pos < len(body) {
		if pos+4 > len(body) {
			return fail()
		}
		kind, size := binary.BigEndian.Uint16(body[pos:]), int(binary.BigEndian.Uint16(body[pos+2:]))
		pos += 4
		if pos+size > len(body) {
			return fail()
		}
		data := body[pos : pos+size]
		switch kind {
		case 35:
			if ticket != nil {
				return fail()
			}
			ticket = make([]byte, size)
			copy(ticket, data)
		case 0:
			if size < 2 || int(binary.BigEndian.Uint16(data)) != size-2 {
				return fail()
			}
			for i := 2; i < len(data); {
				if i+3 > len(data) {
					return fail()
				}
				nameType, n := data[i], int(binary.BigEndian.Uint16(data[i+1:]))
				i += 3
				if i+n > len(data) {
					return fail()
				}
				if nameType == 0 {
					if host != "" || n == 0 {
						return fail()
					}
					host = string(data[i : i+n])
				}
				i += n
			}
		}
		pos += size
	}
	return
}

type tlsConn struct {
	net.Conn
	readMu, writeMu sync.Mutex
	pending         []byte
	remaining       int
	sessionID       []byte
	first           bool
}

func (c *tlsConn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if len(p) == 0 {
		return 0, nil
	}
	if len(c.pending) != 0 {
		n := copy(p, c.pending)
		c.pending = c.pending[n:]
		return n, nil
	}
	for c.remaining == 0 {
		var header [5]byte
		if _, err := io.ReadFull(c.Conn, header[:]); err != nil {
			return 0, err
		}
		if header[0] != 0x17 || header[1] != 3 || header[2] != 3 {
			return 0, errors.New("invalid simple-obfs application record")
		}
		c.remaining = int(binary.BigEndian.Uint16(header[3:]))
		if c.remaining > 16384 {
			return 0, errors.New("simple-obfs application record too large")
		}
	}
	if len(p) > c.remaining {
		p = p[:c.remaining]
	}
	n, err := c.Conn.Read(p)
	c.remaining -= n
	return n, err
}

func (c *tlsConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	written := 0
	for len(p) != 0 {
		size := min(len(p), 16384)
		var header []byte
		if c.first {
			header = make([]byte, 107)
			copy(header, []byte{0x16, 3, 1, 0, 91, 2, 0, 0, 87, 3, 3})
			binary.BigEndian.PutUint32(header[11:], uint32(time.Now().Unix()))
			if _, err := rand.Read(header[15:43]); err != nil {
				return written, err
			}
			header[43] = 32
			copy(header[44:76], c.sessionID)
			copy(header[76:], []byte{0xcc, 0xa8, 0, 0, 0, 0xff, 1, 0, 1, 0, 0, 0x17, 0, 0, 0, 0x0b, 0, 2, 1, 0})
			copy(header[96:], []byte{0x14, 3, 3, 0, 1, 1, 0x16, 3, 3})
			binary.BigEndian.PutUint16(header[105:], uint16(size))
		} else {
			header = []byte{0x17, 3, 3, byte(size >> 8), byte(size)}
		}
		n, err := writeAll(c.Conn, append(header, p[:size]...))
		if n > len(header) {
			written += n - len(header)
		}
		if err != nil {
			return written, err
		}
		c.first = false
		p = p[size:]
	}
	return written, nil
}

func writeAll(w io.Writer, p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		n, err := w.Write(p)
		total += n
		p = p[n:]
		if err != nil {
			return total, err
		}
		if n == 0 {
			return total, io.ErrShortWrite
		}
	}
	return total, nil
}
