package redislimit

import (
	"bufio"
	"context"
	"crypto/sha1"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

type redisError string

func (e redisError) Error() string { return string(e) }

type connection struct {
	net.Conn
	reader *bufio.Reader
}
type client struct {
	options    Options
	mu         sync.Mutex
	idle       []*connection
	closed     bool
	scriptSHA  string
	retryAfter time.Time
	lastError  error
}

func newClient(o Options) *client {
	digest := sha1.Sum([]byte(script))
	return &client{options: o, scriptSHA: hex.EncodeToString(digest[:])}
}
func (c *client) get(ctx context.Context) (*connection, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, ErrClosed
	}
	if time.Now().Before(c.retryAfter) {
		err := c.lastError
		c.mu.Unlock()
		return nil, err
	}
	n := len(c.idle)
	if n > 0 {
		v := c.idle[n-1]
		c.idle = c.idle[:n-1]
		c.mu.Unlock()
		return v, nil
	}
	c.mu.Unlock()
	dialer := net.Dialer{Timeout: c.options.Timeout}
	var raw net.Conn
	var err error
	if c.options.TLS {
		config := &tls.Config{MinVersion: tls.VersionTLS12}
		if c.options.TLSConfig != nil {
			config = c.options.TLSConfig.Clone()
		}
		if config.MinVersion == 0 {
			config.MinVersion = tls.VersionTLS12
		}
		raw, err = (&tls.Dialer{NetDialer: &dialer, Config: config}).DialContext(ctx, "tcp", c.options.Addr)
	} else {
		raw, err = dialer.DialContext(ctx, "tcp", c.options.Addr)
	}
	if err != nil {
		return nil, fmt.Errorf("Redis connect: %w", err)
	}
	v := &connection{Conn: raw, reader: bufio.NewReader(raw)}
	fail := func(err error) (*connection, error) { raw.Close(); return nil, err }
	if c.options.Password != "" {
		if _, err = c.command(ctx, v, "AUTH", c.options.Password); err != nil {
			return fail(fmt.Errorf("Redis authentication: %w", err))
		}
	}
	if _, err = c.command(ctx, v, "SELECT", strconv.Itoa(c.options.DB)); err != nil {
		return fail(fmt.Errorf("Redis select DB: %w", err))
	}
	info, err := c.command(ctx, v, "INFO", "server")
	if err != nil {
		return fail(fmt.Errorf("Redis version check: %w", err))
	}
	major := 0
	if s, ok := info.(string); ok {
		for _, line := range strings.Split(s, "\n") {
			if strings.HasPrefix(line, "redis_version:") {
				major, _ = strconv.Atoi(strings.Split(strings.TrimSpace(strings.TrimPrefix(line, "redis_version:")), ".")[0])
			}
		}
	}
	if major < 8 {
		return fail(fmt.Errorf("Redis 8 or newer required (reported major %d)", major))
	}
	return v, nil
}
func (c *client) put(v *connection) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || len(c.idle) >= 8 {
		v.Close()
	} else {
		c.idle = append(c.idle, v)
	}
}
func (c *client) close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	for _, v := range c.idle {
		v.Close()
	}
	c.idle = nil
}
func (c *client) command(ctx context.Context, v *connection, args ...string) (any, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	deadline := time.Now().Add(c.options.Timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := v.SetDeadline(deadline); err != nil {
		return nil, err
	}
	stopped := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { _ = v.SetDeadline(time.Now()); close(stopped) })
	defer func() {
		if !stop() {
			<-stopped
		}
	}()
	var b strings.Builder
	fmt.Fprintf(&b, "*%d\r\n", len(args))
	for _, arg := range args {
		fmt.Fprintf(&b, "$%d\r\n", len(arg))
		b.WriteString(arg)
		b.WriteString("\r\n")
	}
	if _, err := io.WriteString(v, b.String()); err != nil {
		return nil, err
	}
	return readRESP(v.reader, 0)
}
func (c *client) eval(ctx context.Context, keys, args []string) (result any, err error) {
	defer func() {
		if err != nil && !errors.Is(err, context.Canceled) {
			c.mu.Lock()
			delay := min(250*time.Millisecond, c.options.LeaseTTL/6)
			c.retryAfter = time.Now().Add(delay)
			c.lastError = err
			c.mu.Unlock()
		}
	}()
	ctx, cancel := context.WithTimeout(ctx, c.options.Timeout)
	defer cancel()
	v, err := c.get(ctx)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			v.Close()
		} else {
			c.put(v)
		}
	}()
	cmd := append([]string{"EVALSHA", c.scriptSHA, strconv.Itoa(len(keys))}, keys...)
	cmd = append(cmd, args...)
	result, err = c.command(ctx, v, cmd...)
	var re redisError
	if errors.As(err, &re) && strings.HasPrefix(string(re), "NOSCRIPT ") {
		cmd[0], cmd[1] = "EVAL", script
		result, err = c.command(ctx, v, cmd...)
	}
	return
}
func readRESP(r *bufio.Reader, depth int) (any, error) {
	if depth > 4 {
		return nil, errors.New("Redis response nesting limit")
	}
	line, err := r.ReadSlice('\n')
	if err != nil {
		return nil, err
	}
	if len(line) < 3 || line[len(line)-2] != '\r' {
		return nil, errors.New("invalid Redis response")
	}
	payload := string(line[1 : len(line)-2])
	switch line[0] {
	case '+':
		return payload, nil
	case '-':
		return nil, redisError(payload)
	case ':':
		return strconv.ParseInt(payload, 10, 64)
	case '$':
		n, err := strconv.Atoi(payload)
		if err != nil || n < -1 || n > 1024*1024 {
			return nil, errors.New("invalid Redis bulk size")
		}
		if n == -1 {
			return nil, nil
		}
		b := make([]byte, n+2)
		if _, err = io.ReadFull(r, b); err != nil {
			return nil, err
		}
		if b[n] != '\r' || b[n+1] != '\n' {
			return nil, errors.New("invalid Redis bulk terminator")
		}
		return string(b[:n]), nil
	case '*':
		n, err := strconv.Atoi(payload)
		if err != nil || n < -1 || n > 1024 {
			return nil, errors.New("invalid Redis array size")
		}
		if n == -1 {
			return nil, nil
		}
		out := make([]any, n)
		for i := range out {
			out[i], err = readRESP(r, depth+1)
			if err != nil {
				return nil, err
			}
		}
		return out, nil
	default:
		return nil, errors.New("unknown Redis response type")
	}
}
