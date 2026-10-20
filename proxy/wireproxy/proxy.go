// Package wireproxy decodes explicitly enabled HAProxy PROXY v1/v2 metadata.
// It never decodes or authenticates the following proxy protocol payload.
package wireproxy

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net"
	"time"

	"github.com/pires/go-proxyproto"
)

func Connection(conn net.Conn, required bool) (net.Conn, error) {
	policy := proxyproto.USE
	if required {
		policy = proxyproto.REQUIRE
	}
	p := proxyproto.NewConn(conn, proxyproto.WithPolicy(policy), proxyproto.SetReadHeaderTimeout(5*time.Second))
	if _, err := p.Read(nil); err != nil {
		return nil, err
	}
	return p, nil
}

func Datagram(payload []byte, source net.Addr, required bool) ([]byte, net.Addr, error) {
	prefix := []byte("\r\n\r\n\x00\r\nQUIT\n")
	if !bytes.HasPrefix(payload, prefix) {
		if required {
			return nil, nil, errors.New("required UDP PROXY v2 header absent")
		}
		return payload, source, nil
	}
	reader := bufio.NewReader(bytes.NewReader(payload))
	header, err := proxyproto.Read(reader)
	if err != nil {
		return nil, nil, err
	}
	if header.Version != 2 {
		return nil, nil, errors.New("UDP requires PROXY v2")
	}
	if !header.Command.IsLocal() {
		if _, _, ok := header.UDPAddrs(); !ok {
			return nil, nil, errors.New("PROXY v2 packet must contain UDP addresses")
		}
		source = header.SourceAddr
	}
	rest, err := io.ReadAll(reader)
	return rest, source, err
}
