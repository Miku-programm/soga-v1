package proxy

import (
	"errors"
	"net"
	"os"
	"sync"
	"time"

	xcommon "github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net/cnc"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

var errNoHalfClose = errors.New("proxy: stream cannot half-close")

// xrayLinkConn is the decoded inbound stream handed to the shared router.
// Half-close is supported only on pipe-backed links (Mux and XUDP
// sub-streams): closing the pipe keeps buffered data and delivers EOF to the
// peer, whereas interrupting it, as a full close does, discards the tail of
// a response. The direct VLESS link cannot half-close, so sing falls back to
// a full close there and the client still sees the remote end.
type xrayLinkConn struct {
	*cnc.Connection
	link *transport.Link
}

func (s *xrayLinkConn) CloseWrite() error {
	if _, ok := s.link.Writer.(*pipe.Writer); ok {
		return xcommon.Close(s.link.Writer)
	}
	return errNoHalfClose
}

// The core's connection ignores read deadlines, so the sniffing peek would
// block until the client sends: a server-first protocol relayed over Reality
// would never connect. sniffDeadlineConn honours a deadline for reads issued
// while one is set by running that read in a goroutine, and reads directly,
// without any goroutine, once no deadline is set and nothing is in flight.
type sniffDeadlineConn struct {
	net.Conn
	mu       sync.Mutex
	deadline time.Time
	pending  chan sniffReadResult // non-nil while a background read is in flight
	buffered []byte               // delivered by a background read, not yet consumed
	err      error                // error that followed buffered bytes
}

type sniffReadResult struct {
	data []byte
	err  error
}

func newSniffDeadlineConn(conn net.Conn) *sniffDeadlineConn { return &sniffDeadlineConn{Conn: conn} }

func (c *sniffDeadlineConn) Upstream() any { return c.Conn }

// WriterReplaceable lets sing reach the stream's CloseWrite; writes are not
// touched by this wrapper.
func (c *sniffDeadlineConn) WriterReplaceable() bool { return true }

func (c *sniffDeadlineConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.deadline = t
	c.mu.Unlock()
	return nil
}

func (c *sniffDeadlineConn) SetDeadline(t time.Time) error {
	_ = c.SetReadDeadline(t)
	return c.Conn.SetWriteDeadline(t)
}

func (c *sniffDeadlineConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	if len(c.buffered) > 0 {
		n := copy(p, c.buffered)
		c.buffered = c.buffered[n:]
		c.mu.Unlock()
		return n, nil
	}
	if c.err != nil {
		err := c.err
		c.err = nil
		c.mu.Unlock()
		return 0, err
	}
	pending, deadline := c.pending, c.deadline
	if pending == nil && deadline.IsZero() {
		c.mu.Unlock()
		return c.Conn.Read(p)
	}
	if pending == nil {
		pending = make(chan sniffReadResult, 1)
		c.pending = pending
		size := len(p)
		go func() {
			b := make([]byte, size)
			n, err := c.Conn.Read(b)
			pending <- sniffReadResult{b[:n], err}
		}()
	}
	c.mu.Unlock()
	var expired <-chan time.Time
	if !deadline.IsZero() {
		timer := time.NewTimer(time.Until(deadline))
		defer timer.Stop()
		expired = timer.C
	}
	select {
	case result := <-pending:
		c.mu.Lock()
		c.pending = nil
		n := copy(p, result.data)
		c.buffered = result.data[n:]
		if n > 0 && result.err != nil {
			c.err = result.err
			result.err = nil
		}
		c.mu.Unlock()
		return n, result.err
	case <-expired:
		return 0, os.ErrDeadlineExceeded
	}
}
