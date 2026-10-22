package proxy

import (
	"context"
	"net"
	"sync"
	"time"
)

// handshakeTimeout bounds the wait for a client's first protocol frame after
// transport setup, so idle sockets and scanners cannot hold a goroutine and
// its buffers indefinitely. The deadline is cleared once the client has
// authenticated. A variable so tests can shorten it.
var handshakeTimeout = 10 * time.Second

type handshakeGuardKey struct{}

// handshakeGuard travels in the context from transport setup to the
// post-authentication handler. It clears the pre-authentication deadline and
// identifies the physical connection, so a user removed by a live update can
// have every session closed, including multiplexed ones.
type handshakeGuard struct {
	conn net.Conn // transport connection carrying the deadline
	raw  net.Conn // accepted connection, closed to end the session
	once sync.Once
}

func armHandshake(ctx context.Context, conn, raw net.Conn) context.Context {
	_ = conn.SetReadDeadline(time.Now().Add(handshakeTimeout))
	return context.WithValue(ctx, handshakeGuardKey{}, &handshakeGuard{conn: conn, raw: raw})
}

// handshakeDone clears the deadline and reports the accepted connection.
func handshakeDone(ctx context.Context) net.Conn {
	g, ok := ctx.Value(handshakeGuardKey{}).(*handshakeGuard)
	if !ok {
		return nil
	}
	g.once.Do(func() { _ = g.conn.SetReadDeadline(time.Time{}) })
	return g.raw
}
