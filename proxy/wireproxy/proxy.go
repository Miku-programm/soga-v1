// Package wireproxy decodes explicitly enabled HAProxy PROXY v1/v2 metadata.
// It never decodes or authenticates the following proxy protocol payload.
package wireproxy

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/pires/go-proxyproto"
)

// Trusted lists the peers whose PROXY metadata is honoured. A PROXY header
// replaces the client address used for IP limits, invalid-access blocking and
// UDP session ownership, so it must only be accepted from known relays. An
// empty list honours every peer, which keeps the historical behaviour.
type Trusted []netip.Prefix

// ParseTrusted reads comma- or whitespace-separated IP addresses and CIDRs.
func ParseTrusted(text string) (Trusted, error) {
	var trusted Trusted
	for _, item := range strings.FieldsFunc(text, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' }) {
		if ip, err := netip.ParseAddr(item); err == nil {
			ip = ip.Unmap()
			trusted = append(trusted, netip.PrefixFrom(ip, ip.BitLen()))
			continue
		}
		prefix, err := netip.ParsePrefix(item)
		if err != nil {
			return nil, fmt.Errorf("invalid trusted PROXY source %q", item)
		}
		if prefix.Addr().Is4In6() {
			prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
		}
		trusted = append(trusted, prefix.Masked())
	}
	return trusted, nil
}

// Allows reports whether PROXY metadata from peer may be used.
func (t Trusted) Allows(peer net.Addr) bool {
	if len(t) == 0 {
		return true
	}
	ip, ok := peerAddr(peer)
	if !ok {
		return false
	}
	for _, prefix := range t {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}

// Policy selects how a connection from peer is treated. Untrusted peers keep
// their real address: an optional header they send is consumed and ignored,
// and they are refused outright when a header is required.
func (t Trusted) Policy(peer net.Addr, required bool) (proxyproto.Policy, error) {
	if !t.Allows(peer) {
		if required {
			return proxyproto.REJECT, proxyproto.ErrInvalidUpstream
		}
		return proxyproto.IGNORE, nil
	}
	if required {
		return proxyproto.REQUIRE, nil
	}
	return proxyproto.USE, nil
}

// ConnPolicy adapts Policy to proxyproto.Listener. ErrInvalidUpstream makes
// the listener drop the refused connection and keep accepting.
func (t Trusted) ConnPolicy(required bool) proxyproto.ConnPolicyFunc {
	return func(options proxyproto.ConnPolicyOptions) (proxyproto.Policy, error) {
		return t.Policy(options.Upstream, required)
	}
}

func peerAddr(peer net.Addr) (netip.Addr, bool) {
	switch a := peer.(type) {
	case *net.TCPAddr:
		ip, ok := netip.AddrFromSlice(a.IP)
		return ip.Unmap(), ok
	case *net.UDPAddr:
		ip, ok := netip.AddrFromSlice(a.IP)
		return ip.Unmap(), ok
	case nil:
		return netip.Addr{}, false
	}
	addrPort, err := netip.ParseAddrPort(peer.String())
	if err != nil {
		return netip.Addr{}, false
	}
	return addrPort.Addr().Unmap(), true
}

func Connection(conn net.Conn, required bool, trusted Trusted) (net.Conn, error) {
	policy, err := trusted.Policy(conn.RemoteAddr(), required)
	if err != nil {
		return nil, err
	}
	p := proxyproto.NewConn(conn, proxyproto.WithPolicy(policy), proxyproto.SetReadHeaderTimeout(5*time.Second))
	if _, err := p.Read(nil); err != nil {
		return nil, err
	}
	return p, nil
}

func Datagram(payload []byte, source net.Addr, required bool, trusted Trusted) ([]byte, net.Addr, error) {
	allowed := trusted.Allows(source)
	if required && !allowed {
		return nil, nil, errors.New("UDP PROXY header from an untrusted source")
	}
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
		if allowed {
			source = header.SourceAddr
		}
	}
	rest, err := io.ReadAll(reader)
	return rest, source, err
}
