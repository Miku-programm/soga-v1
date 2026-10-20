// Package redislimit shares IP/device quotas between independent nodes.
// The caller must enforce its local quota and may fail open on Redis errors.
package redislimit

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed limiter.lua
var script string

var ErrQuotaExceeded = errors.New("Redis global quota exceeded")
var ErrClosed = errors.New("Redis limiter closed")

type QuotaError struct {
	Kind  string
	Limit int
}

func (e *QuotaError) Error() string {
	return fmt.Sprintf("%s: %s limit %d", ErrQuotaExceeded, e.Kind, e.Limit)
}
func (e *QuotaError) Unwrap() error { return ErrQuotaExceeded }

type Options struct {
	Addr, Password            string
	DB                        int
	TLS                       bool
	TLSConfig                 *tls.Config
	Expiry, Timeout, LeaseTTL time.Duration
	Namespace                 string
}

type Request struct {
	UserID               int64
	IP, DeviceID         string
	IPLimit, DeviceLimit int
}

type Manager struct {
	options   Options
	client    *client
	mu        sync.Mutex
	leases    map[*lease]struct{}
	closed    bool
	cancel    context.CancelFunc
	done      chan struct{}
	closeDone chan struct{}
}

type lease struct {
	manager  *Manager
	request  Request
	token    string
	mu       sync.Mutex
	released bool
	stop     func() bool
}

// New validates local configuration. Redis is contacted by Acquire, allowing
// the application to start with local enforcement while Redis is unavailable.
func New(o Options) (*Manager, error) {
	if _, _, err := net.SplitHostPort(o.Addr); err != nil {
		return nil, fmt.Errorf("Redis address: %w", err)
	}
	if o.DB < 0 {
		return nil, errors.New("Redis DB must be nonnegative")
	}
	if o.Expiry == 0 {
		o.Expiry = 60 * time.Second
	}
	if o.Timeout == 0 {
		o.Timeout = 2 * time.Second
	}
	if o.LeaseTTL == 0 {
		o.LeaseTTL = 30 * time.Second
	}
	if o.Expiry < time.Millisecond || o.Timeout < time.Millisecond || o.LeaseTTL < 30*time.Millisecond {
		return nil, errors.New("Redis expiry/timeout must be at least 1 ms and lease TTL at least 30 ms")
	}
	if o.Namespace == "" {
		o.Namespace = "soga:limits:v1"
	}
	if strings.ContainsAny(o.Namespace, "{}\r\n") {
		return nil, errors.New("Redis namespace cannot contain braces or newlines")
	}
	if o.TLSConfig != nil {
		o.TLSConfig = o.TLSConfig.Clone()
	}
	ctx, cancel := context.WithCancel(context.Background())
	m := &Manager{options: o, client: newClient(o), leases: make(map[*lease]struct{}), cancel: cancel, done: make(chan struct{}), closeDone: make(chan struct{})}
	go m.renew(ctx)
	return m, nil
}

// Acquire returns an idempotent release function, including on Redis
// availability errors. Keep that release function when falling back locally:
// the manager will register the live connection once Redis recovers.
// Quota denials return a nil release function and must reject the connection.
func (m *Manager) Acquire(ctx context.Context, r Request) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if r.UserID < 0 || r.IPLimit < 0 || r.DeviceLimit < 0 {
		return nil, errors.New("invalid Redis quota request")
	}
	if r.IPLimit > 0 && r.IP == "" {
		return nil, errors.New("limited IP identity is empty")
	}
	// Empty DeviceID intentionally disables CID counting for SSR UDP.
	if r.DeviceID == "" {
		r.DeviceLimit = 0
	}
	if r.IPLimit == 0 && r.DeviceLimit == 0 {
		return func() {}, nil
	}
	tokenBytes := make([]byte, 24)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, err
	}
	l := &lease{manager: m, request: r, token: hex.EncodeToString(tokenBytes)}
	m.mu.Lock()
	closed := m.closed
	m.mu.Unlock()
	if closed {
		return nil, ErrClosed
	}
	err := m.apply(ctx, l, "acquire")
	if errors.Is(err, ErrQuotaExceeded) {
		return nil, err
	}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		l.release()
		return nil, ErrClosed
	}
	m.leases[l] = struct{}{}
	m.mu.Unlock()
	l.mu.Lock()
	l.stop = context.AfterFunc(ctx, l.release)
	l.mu.Unlock()
	return l.release, err
}

func hash(s string) string { b := sha256.Sum256([]byte(s)); return hex.EncodeToString(b[:]) }

func (m *Manager) apply(ctx context.Context, l *lease, op string) error {
	r := l.request
	base := m.options.Namespace + ":{" + strconv.FormatInt(r.UserID, 10) + "}:"
	ip, device := hash(r.IP), hash(r.DeviceID)
	if r.IPLimit == 0 {
		ip = ""
	}
	if r.DeviceLimit == 0 {
		device = ""
	}
	keys := []string{base + "ip", base + "ip:" + ip, base + "device", base + "device:" + device}
	args := []string{op, l.token, strconv.FormatInt(m.options.LeaseTTL.Milliseconds(), 10), strconv.FormatInt(m.options.Expiry.Milliseconds(), 10), ip, strconv.Itoa(r.IPLimit), device, strconv.Itoa(r.DeviceLimit)}
	v, err := m.client.eval(ctx, keys, args)
	if err != nil {
		return err
	}
	n, ok := v.(int64)
	if !ok {
		return errors.New("invalid Redis limiter response")
	}
	switch n {
	case 0:
		return nil
	case 1:
		return &QuotaError{"IP", r.IPLimit}
	case 2:
		return &QuotaError{"device", r.DeviceLimit}
	default:
		return errors.New("invalid Redis limiter status")
	}
}

func (l *lease) release() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.released {
		return
	}
	l.released = true
	if l.stop != nil {
		l.stop()
	}
	m := l.manager
	m.mu.Lock()
	delete(m.leases, l)
	m.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), m.options.Timeout)
	defer cancel()
	_ = m.apply(ctx, l, "release")
}

func (m *Manager) snapshot() []*lease {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*lease, 0, len(m.leases))
	for l := range m.leases {
		out = append(out, l)
	}
	return out
}

// boundedParallel avoids an outage creating one timeout per live connection.
func boundedParallel(items []*lease, fn func(*lease)) {
	var wg sync.WaitGroup
	work := make(chan *lease)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for l := range work {
				fn(l)
			}
		}()
	}
	for _, l := range items {
		work <- l
	}
	close(work)
	wg.Wait()
}
func (m *Manager) renew(ctx context.Context) {
	defer close(m.done)
	tick := time.NewTicker(m.options.LeaseTTL / 3)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		boundedParallel(m.snapshot(), func(l *lease) {
			l.mu.Lock()
			defer l.mu.Unlock()
			if l.released || ctx.Err() != nil {
				return
			}
			_ = m.apply(ctx, l, "renew")
		})
	}
}

func (m *Manager) Close() error {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		<-m.closeDone
		return nil
	}
	m.closed = true
	m.cancel()
	m.mu.Unlock()
	<-m.done
	boundedParallel(m.snapshot(), func(l *lease) { l.release() })
	m.client.close()
	close(m.closeDone)
	return nil
}
