package proxy

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/pires/go-proxyproto"
)

// defaultRelayIdle bounds a relayed TCP session that moves no bytes in either
// direction when the configuration carries no tcp timeout.
const defaultRelayIdle = 15 * time.Minute

var errRelayIdle = errors.New("proxy: relay idle timeout")

// relayIdle converts the configured TCPTimeoutSeconds into the idle bound used
// by relay. Zero or negative keeps the default.
func relayIdle(seconds int) time.Duration {
	if seconds > 0 {
		return time.Duration(seconds) * time.Second
	}
	return defaultRelayIdle
}

// relayEnd is one side of a relay with its transport unwrapped as far as the
// kernel fast path allows.
type relayEnd struct {
	conn net.Conn     // as handed in: owns Close and deadlines
	raw  *net.TCPConn // underlying TCP socket when known
}

func newRelayEnd(c net.Conn) *relayEnd {
	e := &relayEnd{conn: c}
	switch v := c.(type) {
	case *net.TCPConn:
		e.raw = v
	case *proxyproto.Conn:
		// The caller has already consumed the PROXY header. Bytes the header
		// reader buffered behind it are reachable only through the wrapper:
		// its WriteTo flushes them and then runs io.Copy from the raw socket,
		// which splices when the peer is a TCP socket too. After that first
		// copy call has returned the buffer is empty, so later calls use the
		// raw socket. Writes never involve the buffer.
		if tcp, ok := v.TCPConn(); ok {
			e.raw = tcp
		}
	}
	return e
}

// relayer is the state shared by the two directions of one relay.
type relayer struct {
	idle    time.Duration
	a, b    net.Conn
	mu      sync.Mutex
	last    time.Time     // last observed byte movement in either direction
	changed chan struct{} // closed and replaced whenever a copy call returns
	closed  bool
	err     error
}

func (r *relayer) touch() {
	r.mu.Lock()
	r.last = time.Now()
	r.mu.Unlock()
}

func (r *relayer) report(n int64) {
	r.mu.Lock()
	if n > 0 {
		r.last = time.Now()
	}
	close(r.changed)
	r.changed = make(chan struct{})
	r.mu.Unlock()
}

func (r *relayer) active() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return time.Since(r.last) < r.idle
}

func (r *relayer) changes() <-chan struct{} {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.changed
}

// fail records the first error and closes both sides once. Errors the peer
// direction raises afterwards are consequences of that close and are dropped.
func (r *relayer) fail(err error) {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return
	}
	r.closed = true
	r.err = err
	r.mu.Unlock()
	_ = r.a.Close()
	_ = r.b.Close()
}

// activityReader reports byte movement for directions that cannot use the
// kernel fast path, where every read passes through user space anyway.
type activityReader struct {
	r io.Reader
	s *relayer
}

func (a *activityReader) Read(p []byte) (int, error) {
	n, err := a.r.Read(p)
	if n > 0 {
		a.s.touch()
	}
	return n, err
}

type relayDirection struct {
	r     *relayer
	from  *relayEnd
	to    *relayEnd
	other *relayDirection
	first io.Reader // source for the first copy call
	rest  io.Reader // source for later calls
	w     io.Writer
	done  chan struct{}
}

func newRelayDirection(r *relayer, from, to *relayEnd) *relayDirection {
	d := &relayDirection{r: r, from: from, to: to, done: make(chan struct{})}
	if from.raw != nil && to.raw != nil {
		// Both ends are TCP sockets: io.Copy hands the transfer to the kernel
		// (splice on Linux). Progress is then visible only when a copy call
		// returns, which the per-call read deadline forces at least once per
		// idle period.
		d.first, d.rest, d.w = from.conn, from.raw, to.raw
		return d
	}
	src := &activityReader{r: from.conn, s: r}
	d.first, d.rest, d.w = src, src, to.conn
	if to.raw != nil {
		d.w = to.raw
	}
	return d
}

// poke makes a copy call in this direction return at its next read so that
// its progress gets reported.
func (d *relayDirection) poke() {
	_ = d.from.conn.SetReadDeadline(time.Now().Add(-time.Second))
}

func (d *relayDirection) copy() error {
	src := d.first
	for {
		_ = d.from.conn.SetReadDeadline(time.Now().Add(d.r.idle))
		n, err := io.Copy(d.w, src)
		src = d.rest
		d.r.report(n)
		if err == nil {
			return nil
		}
		if !isTimeout(err) {
			return err
		}
		if d.r.active() {
			continue
		}
		// Nothing was reported for a full idle period, but the peer direction
		// may still be inside a long copy call: make it return and report.
		changed := d.r.changes()
		d.other.poke()
		timer := time.NewTimer(d.r.idle)
		select {
		case <-changed:
		case <-d.other.done:
		case <-timer.C:
		}
		timer.Stop()
		if d.r.active() {
			continue
		}
		return errRelayIdle
	}
}

func (d *relayDirection) run() {
	defer close(d.done)
	err := d.copy()
	if err != nil {
		d.r.fail(err)
		return
	}
	// Clean EOF: pass the half-close on so the peer can finish answering.
	// Transports without a write-side shutdown end the relay as a whole.
	if d.to.raw != nil {
		_ = d.to.raw.CloseWrite()
		return
	}
	if cw, ok := d.to.conn.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
		return
	}
	d.r.fail(nil)
}

func isTimeout(err error) bool {
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// relay copies bytes between a and b in both directions until both sides have
// reached EOF, an error occurs, ctx ends, or no byte has moved in either
// direction for idle (zero selects defaultRelayIdle). An EOF on one side is
// forwarded as a TCP half-close where the other side supports it. Both
// connections are closed before relay returns. Nothing is decoded or counted
// here; accounting happens in the protocol layers behind the relay.
//
// When both sides are TCP sockets (directly or behind a *proxyproto.Conn) the
// copy uses plain io.Copy on the sockets so the kernel fast path applies. Idle
// detection then relies on the read deadline interrupting each copy call once
// per idle period; a peer that stops both reading and sending is therefore
// closed between idle and twice idle after its last byte.
func relay(ctx context.Context, a, b net.Conn, idle time.Duration) error {
	if idle <= 0 {
		idle = defaultRelayIdle
	}
	r := &relayer{idle: idle, a: a, b: b, last: time.Now(), changed: make(chan struct{})}
	ea, eb := newRelayEnd(a), newRelayEnd(b)
	ab, ba := newRelayDirection(r, ea, eb), newRelayDirection(r, eb, ea)
	ab.other, ba.other = ba, ab
	stop := context.AfterFunc(ctx, func() { r.fail(ctx.Err()) })
	defer stop()
	go ab.run()
	ba.run()
	<-ab.done
	r.fail(nil)
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.err
}
