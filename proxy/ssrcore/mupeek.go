package ssrcore

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"

	"reconstructed.local/soga/proxy/simpleobfs"
)

type replayConn struct {
	net.Conn
	reader io.Reader
}

func (c *replayConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

// peekObfsHost only inspects routing metadata. Every consumed byte is replayed
// unchanged to the SSR codec so its authentication and framing still run.
func peekObfsHost(c net.Conn, method string) (net.Conn, string, error) {
	const maxHello = 65536
	if method == "http_simple" || method == "http_post" {
		r := bufio.NewReader(c)
		var header []byte
		for {
			line, err := r.ReadSlice('\n')
			header = append(header, line...)
			if len(header) > maxHello {
				return nil, "", errors.New("ssr: mu HTTP header too large")
			}
			if err != nil && err != bufio.ErrBufferFull {
				return nil, "", err
			}
			if bytes.HasSuffix(header, []byte("\r\n\r\n")) {
				break
			}
		}
		host := ""
		for _, line := range strings.Split(string(header), "\r\n")[1:] {
			k, v, ok := strings.Cut(line, ":")
			if ok && strings.EqualFold(k, "Host") {
				if host != "" {
					return nil, "", errors.New("ssr: duplicate mu Host header")
				}
				host = strings.TrimSpace(v)
			}
		}
		if host == "" {
			return nil, "", errors.New("ssr: missing mu Host header")
		}
		return &replayConn{Conn: c, reader: io.MultiReader(bytes.NewReader(header), r)}, canonicalHost(host), nil
	}
	if method == "tls1.2_ticket_auth" || method == "tls1.2_ticket_fastauth" {
		var consumed, handshake []byte
		for len(consumed) < maxHello {
			var header [5]byte
			if _, err := io.ReadFull(c, header[:]); err != nil {
				return nil, "", err
			}
			size := int(binary.BigEndian.Uint16(header[3:]))
			if header[0] != 22 || header[1] != 3 || size == 0 || len(consumed)+5+size > maxHello {
				return nil, "", errors.New("ssr: invalid mu ClientHello record")
			}
			body := make([]byte, size)
			if _, err := io.ReadFull(c, body); err != nil {
				return nil, "", err
			}
			consumed = append(consumed, header[:]...)
			consumed = append(consumed, body...)
			handshake = append(handshake, body...)
			if len(handshake) >= 4 {
				need := 4 + (int(handshake[1]) << 16) + (int(handshake[2]) << 8) + int(handshake[3])
				if need > maxHello {
					return nil, "", errors.New("ssr: mu ClientHello too large")
				}
				if len(handshake) >= need {
					host, err := simpleobfs.ParseClientHelloSNI(handshake[:need])
					if err != nil {
						return nil, "", err
					}
					if host == "" {
						return nil, "", errors.New("ssr: missing mu SNI")
					}
					return &replayConn{Conn: c, reader: io.MultiReader(bytes.NewReader(consumed), c)}, canonicalHost(host), nil
				}
			}
		}
	}
	return nil, "", errors.New("ssr: obfs single-port requires HTTP or TLS host metadata")
}

func canonicalHost(s string) string {
	if host, _, err := net.SplitHostPort(s); err == nil {
		s = host
	}
	return strings.TrimSuffix(strings.ToLower(s), ".")
}
