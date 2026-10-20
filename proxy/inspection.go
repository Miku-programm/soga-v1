package proxy

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/sniff"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// Inspection is a bounded peek of authenticated, decrypted payload. The short
// timeout avoids deadlocking protocols whose server speaks first. A failed
// sniff never drops or changes bytes. 300 ms is a reconstruction policy.
const inspectionTimeout = 300 * time.Millisecond

type inspectionOptions struct {
	protocols  []string
	redirect   bool
	maxPacket  int
	cidMode    bool
	admission  func(context.Context, AdmissionRequest) (func(), error)
	tcpTimeout time.Duration
}

func (o inspectionOptions) active() bool { return len(o.protocols) > 0 || o.maxPacket > 0 }

func (o inspectionOptions) stream(ctx context.Context, conn net.Conn, metadata *adapter.InboundContext) (net.Conn, []byte) {
	if !o.active() || sniff.Skip(metadata) {
		return conn, nil
	}
	var parsers []sniff.StreamSniffer
	for _, name := range o.protocols {
		switch name {
		case "http":
			parsers = append(parsers, sniff.HTTPHost)
		case "tls":
			parsers = append(parsers, sniff.TLSClientHello)
		}
	}
	b := buf.NewSize(max(16384, o.maxPacket))
	_ = sniff.PeekStream(ctx, metadata, conn, nil, b, inspectionTimeout, parsers...)
	var first []byte
	if o.maxPacket > 0 {
		first = append([]byte(nil), b.Bytes()[:min(b.Len(), o.maxPacket)]...)
	}
	metadata.Domain = strings.TrimSuffix(strings.ToLower(metadata.Domain), ".")
	if b.Len() > 0 {
		conn = bufio.NewCachedConn(conn, b)
	}
	b.Release()
	return conn, first
}

func (o inspectionOptions) packet(ctx context.Context, metadata *adapter.InboundContext, packet []byte) []byte {
	if metadata.Domain != "" {
		return nil
	}
	for _, name := range o.protocols {
		if name == "quic" {
			_ = sniff.QUICClientHello(ctx, metadata, packet)
		}
	}
	metadata.Domain = strings.TrimSuffix(strings.ToLower(metadata.Domain), ".")
	if o.maxPacket > 0 {
		return append([]byte(nil), packet[:min(len(packet), o.maxPacket)]...)
	}
	return nil
}

func (o inspectionOptions) firstPacket(ctx context.Context, conn N.PacketConn, metadata *adapter.InboundContext) (N.PacketConn, []byte, error) {
	if !o.active() {
		return conn, nil, nil
	}
	// A datagram is atomic; preserve the whole packet even if the inspection cap
	// is smaller. Keep the upstream framing/headroom interfaces through Upstream.
	type packet struct {
		data *buf.Buffer
		dest M.Socksaddr
	}
	var packets []packet
	var first []byte
	if err := conn.SetReadDeadline(time.Now().Add(inspectionTimeout)); err != nil {
		// Some authenticated multiplexed UDP streams have no socket deadline.
		// Keep exactly one pending read, so a timed-out peek cannot steal or
		// reorder the first packet when routing continues.
		conn = &inspectionPacketConn{PacketConn: conn, closed: make(chan struct{})}
		_ = conn.SetReadDeadline(time.Now().Add(inspectionTimeout))
	}
	for len(packets) < 8 {
		b := buf.NewPacket()
		dst, err := conn.ReadPacket(b)
		if err != nil {
			b.Release()
			if len(packets) == 0 {
				_ = conn.SetReadDeadline(time.Time{})
				if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
					return conn, nil, nil
				}
				return conn, nil, err
			}
			break
		}
		packets = append(packets, packet{b, dst})
		if len(packets) == 1 && dst.IsValid() {
			metadata.Destination = dst
		}
		if dst.IsValid() && dst != metadata.Destination {
			break
		}
		payload := o.packet(ctx, metadata, b.Bytes())
		if len(packets) == 1 {
			first = payload
		}
		if metadata.Domain != "" || metadata.SniffContext == nil {
			break
		}
	}
	_ = conn.SetReadDeadline(time.Time{})
	metadata.SniffContext = nil
	for i := len(packets) - 1; i >= 0; i-- {
		p := packets[i]
		conn = bufio.NewCachedPacketConn(conn, p.data, p.dest)
		p.data.Release()
	}
	return conn, first, nil
}

type inspectionPacketResult struct {
	b   *buf.Buffer
	dst M.Socksaddr
	err error
}
type inspectionPacketConn struct {
	N.PacketConn
	readMu    sync.Mutex
	mu        sync.Mutex
	deadline  time.Time
	pending   chan inspectionPacketResult
	closed    chan struct{}
	closeOnce sync.Once
}

func (c *inspectionPacketConn) Upstream() any { return c.PacketConn }
func (c *inspectionPacketConn) SetReadDeadline(deadline time.Time) error {
	c.mu.Lock()
	c.deadline = deadline
	c.mu.Unlock()
	return nil
}
func (c *inspectionPacketConn) ReadPacket(b *buf.Buffer) (M.Socksaddr, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if c.pending == nil {
		c.pending = make(chan inspectionPacketResult)
		ch := c.pending
		go func() {
			packet := buf.NewPacket()
			dst, err := c.PacketConn.ReadPacket(packet)
			select {
			case ch <- inspectionPacketResult{packet, dst, err}:
			case <-c.closed:
				packet.Release()
			}
		}()
	}
	c.mu.Lock()
	deadline := c.deadline
	c.mu.Unlock()
	var timeout <-chan time.Time
	if !deadline.IsZero() {
		timer := time.NewTimer(max(0, time.Until(deadline)))
		defer timer.Stop()
		timeout = timer.C
	}
	select {
	case result := <-c.pending:
		c.pending = nil
		defer result.b.Release()
		if result.err != nil {
			return result.dst, result.err
		}
		_, err := b.Write(result.b.Bytes())
		return result.dst, err
	case <-timeout:
		return M.Socksaddr{}, &net.OpError{Op: "inspect", Net: "udp", Err: inspectionDeadline{}}
	case <-c.closed:
		return M.Socksaddr{}, net.ErrClosed
	}
}
func (c *inspectionPacketConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return c.PacketConn.Close()
}

type inspectionDeadline struct{}

func (inspectionDeadline) Error() string   { return "inspection deadline exceeded" }
func (inspectionDeadline) Timeout() bool   { return true }
func (inspectionDeadline) Temporary() bool { return true }

func (o inspectionOptions) destination(metadata adapter.InboundContext) string {
	dst := metadata.Destination
	if o.redirect && dst.Addr.IsValid() && metadata.Domain != "" && M.IsDomainName(metadata.Domain) {
		dst = M.Socksaddr{Fqdn: metadata.Domain, Port: dst.Port}
	}
	return dst.String()
}
