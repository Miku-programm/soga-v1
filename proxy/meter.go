package proxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"reconstructed.local/soga/proxy/ssrcore"
)

type meter struct {
	mu           sync.Mutex
	traffic      map[int64]Traffic
	online       map[int64]map[string]int
	prefix4      int
	prefix6      int
	submitRealIP bool
}

func newMeter() *meter {
	return &meter{traffic: make(map[int64]Traffic), online: make(map[int64]map[string]int), prefix4: 32, prefix6: 128}
}

func (m *meter) add(id int64, upload, download int) {
	if id <= 0 {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	t := m.traffic[id]
	t.Upload += uint64(upload)
	t.Download += uint64(download)
	m.traffic[id] = t
}

func (m *meter) connect(id int64, source string) func() {
	ip, _, err := net.SplitHostPort(source)
	if err != nil {
		ip = source
	}
	if !m.submitRealIP {
		ip = maskIP(ip, m.prefix4, m.prefix6)
	}
	m.mu.Lock()
	if m.online[id] == nil {
		m.online[id] = make(map[string]int)
	}
	m.online[id][ip]++
	m.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			m.mu.Lock()
			defer m.mu.Unlock()
			m.online[id][ip]--
			if m.online[id][ip] <= 0 {
				delete(m.online[id], ip)
			}
			if len(m.online[id]) == 0 {
				delete(m.online, id)
			}
		})
	}
}

func (m *meter) trafficSnapshot() map[int64]Traffic {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[int64]Traffic, len(m.traffic))
	for id, t := range m.traffic {
		out[id] = t
	}
	return out
}

func (m *meter) onlineSnapshot() map[int64][]string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[int64][]string, len(m.online))
	for id, ips := range m.online {
		for ip := range ips {
			out[id] = append(out[id], ip)
		}
		slices.Sort(out[id])
	}
	return out
}

type guardedRouter struct {
	adapter.Router
	meter          *meter
	hook           func(Request) error
	transform      func(context.Context, Request) (Request, error)
	outbound       adapter.OutboundManager
	connection     adapter.ConnectionManager
	limiter        *Limiter
	protocol       string
	mieruTransport string
	udpTimeout     time.Duration
	inspection     inspectionOptions
}

func (r *guardedRouter) admit(ctx context.Context, req Request) (context.Context, func(), error) {
	if req.Unattributed {
		child, cancel := context.WithCancel(ctx)
		return child, cancel, nil
	}
	tcp := true
	switch r.protocol {
	case "hysteria", "hysteria2":
		tcp = false
	case "mieru":
		tcp = !strings.EqualFold(r.mieruTransport, "udp")
	case "shadowsocks", "ss-service", "ssr":
		tcp = req.Network == "tcp"
	}
	release, err := r.limiter.acquire(req, tcp)
	if err != nil {
		return ctx, nil, err
	}
	child, cancel := context.WithCancel(ctx)
	var globalRelease func()
	if r.inspection.admission != nil {
		globalRelease, err = r.inspection.admission(child, r.limiter.admissionRequest(req))
		if err != nil {
			cancel()
			release()
			return ctx, nil, err
		}
	}
	offline := r.meter.connect(req.UserID, req.Source)
	var once sync.Once
	return child, func() {
		once.Do(func() {
			cancel()
			release()
			if globalRelease != nil {
				globalRelease()
			}
			offline()
		})
	}, nil
}

func (r *guardedRouter) request(ctx context.Context, metadata adapter.InboundContext, network string, payload ...[]byte) (Request, error) {
	id, err := strconv.ParseInt(metadata.User, 10, 64)
	unattributed, _ := ctx.Value(unattributedContextKey{}).(bool)
	unattributed = unattributed || ssrcore.UnattributedTraffic(ctx)
	if err != nil || id < 0 || (id == 0 && !unattributed) {
		return Request{}, errors.New("proxy: missing authenticated user identity")
	}
	req := Request{UserID: id, Network: network, Source: metadata.Source.String(), Destination: r.inspection.destination(metadata), SniffedDomain: metadata.Domain, Unattributed: unattributed}
	req.deviceLimitByCID = r.inspection.cidMode
	if clientID, ok := ssrcore.AuthenticatedClientID(ctx); ok && r.inspection.cidMode {
		req.DeviceID = strconv.FormatUint(uint64(clientID), 10)
	}
	if len(payload) > 0 {
		req.FirstPacket = payload[0]
	}
	if r.hook != nil {
		err = r.hook(req)
	}
	if err == nil && r.transform != nil {
		device := req.DeviceID
		req, err = r.transform(ctx, req)
		if err == nil && (req.UserID != id || req.Source != metadata.Source.String() || req.Network != network || req.DeviceID != device || req.Unattributed != unattributed) {
			err = errors.New("proxy: transform must preserve authenticated user, source and network")
		}
		if err == nil && !M.ParseSocksaddr(req.Destination).IsValid() {
			err = errors.New("proxy: transform returned invalid destination")
		}
	}
	req.deviceLimitByCID = r.inspection.cidMode
	if err == nil && req.Outbound != "" {
		if _, found := r.outbound.Outbound(req.Outbound); !found {
			err = fmt.Errorf("proxy: unknown outbound %q", req.Outbound)
		}
	}
	return req, err
}

type unattributedContextKey struct{}

func requestMeterID(req Request) int64 {
	if req.Unattributed {
		return 0
	}
	return req.UserID
}

func closeDenied(conn interface{ Close() error }, onClose N.CloseHandlerFunc, err error) {
	_ = conn.Close()
	if onClose != nil {
		onClose(err)
	}
}

func (r *guardedRouter) RouteConnectionEx(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	metadata.Domain, metadata.SniffContext = "", nil
	conn, first := r.inspection.stream(ctx, conn, &metadata)
	req, err := r.request(ctx, metadata, "tcp", first)
	if err != nil {
		closeDenied(conn, onClose, err)
		return
	}
	ctx, done, err := r.admit(ctx, req)
	if err != nil {
		closeDenied(conn, onClose, err)
		return
	}
	counted := &meterConn{Conn: conn, meter: r.meter, id: requestMeterID(req), done: done, ctx: ctx, limiter: r.limiter}
	counted.startIdle(r.inspection.tcpTimeout)
	metadata.Destination = M.ParseSocksaddr(req.Destination)
	metadata.Network = "tcp"
	callback := func(err error) {
		done()
		if onClose != nil {
			onClose(err)
		}
	}
	if req.Outbound != "" {
		out, _ := r.outbound.Outbound(req.Outbound)
		metadata.Outbound, metadata.RouteOutbound = req.Outbound, req.Outbound
		r.connection.NewConnection(ctx, out, counted, metadata, callback)
	} else {
		r.Router.RouteConnectionEx(ctx, counted, metadata, callback)
	}
}

func (r *guardedRouter) RouteConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext) error {
	done := make(chan error, 1)
	r.RouteConnectionEx(ctx, conn, metadata, func(err error) { done <- err })
	return <-done
}

func (r *guardedRouter) RoutePacketConnectionEx(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	metadata.Domain, metadata.SniffContext = "", nil
	conn, first, err := r.inspection.firstPacket(ctx, conn, &metadata)
	if err != nil {
		closeDenied(conn, onClose, err)
		return
	}
	req, err := r.request(ctx, metadata, "udp", first)
	if err != nil {
		closeDenied(conn, onClose, err)
		return
	}
	ctx, done, err := r.admit(ctx, req)
	if err != nil {
		closeDenied(conn, onClose, err)
		return
	}
	counted := &meterPacketConn{PacketConn: conn, meter: r.meter, req: req, router: r, ctx: ctx, metadata: metadata, done: done, originalDestinations: make(map[M.Socksaddr]M.Socksaddr), decisions: make(map[M.Socksaddr]udpDecision)}
	metadata.Destination = M.ParseSocksaddr(req.Destination)
	metadata.Network = "udp"
	if r.udpTimeout > 0 {
		metadata.UDPTimeout = r.udpTimeout
	}
	callback := func(err error) {
		done()
		if onClose != nil {
			onClose(err)
		}
	}
	if req.Outbound != "" {
		out, _ := r.outbound.Outbound(req.Outbound)
		metadata.Outbound, metadata.RouteOutbound = req.Outbound, req.Outbound
		r.connection.NewPacketConnection(ctx, out, counted, metadata, callback)
	} else {
		r.Router.RoutePacketConnectionEx(ctx, counted, metadata, callback)
	}
}

func (r *guardedRouter) RoutePacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext) error {
	done := make(chan error, 1)
	r.RoutePacketConnectionEx(ctx, conn, metadata, func(err error) { done <- err })
	return <-done
}

type meterConn struct {
	net.Conn
	meter       *meter
	id          int64
	done        func()
	ctx         context.Context
	limiter     *Limiter
	idleMu      sync.Mutex
	idle        *time.Timer
	idleTimeout time.Duration
	closed      bool
}

func (c *meterConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.touch()
	}
	if paceErr := c.limiter.wait(c.ctx, c.id, n); paceErr != nil {
		return 0, paceErr
	}
	c.meter.add(c.id, n, 0)
	return n, err
}
func (c *meterConn) Write(p []byte) (int, error) {
	if err := c.limiter.wait(c.ctx, c.id, len(p)); err != nil {
		return 0, err
	}
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.touch()
	}
	c.meter.add(c.id, 0, n)
	return n, err
}
func (c *meterConn) Close() error {
	c.idleMu.Lock()
	c.closed = true
	if c.idle != nil {
		c.idle.Stop()
	}
	c.idleMu.Unlock()
	c.done()
	return c.Conn.Close()
}

func (c *meterConn) startIdle(timeout time.Duration) {
	if timeout <= 0 {
		return
	}
	c.idleMu.Lock()
	c.idleTimeout = timeout
	c.idle = time.AfterFunc(timeout, func() { c.Close() })
	c.idleMu.Unlock()
}
func (c *meterConn) touch() {
	c.idleMu.Lock()
	if c.idle != nil && !c.closed {
		c.idle.Reset(c.idleTimeout)
	}
	c.idleMu.Unlock()
}

type meterPacketConn struct {
	N.PacketConn
	meter                *meter
	req                  Request
	router               *guardedRouter
	ctx                  context.Context
	metadata             adapter.InboundContext
	mu                   sync.Mutex
	originalDestinations map[M.Socksaddr]M.Socksaddr
	decisions            map[M.Socksaddr]udpDecision
	done                 func()
}

func (c *meterPacketConn) ReadPacket(b *buf.Buffer) (M.Socksaddr, error) {
	dst, err := c.PacketConn.ReadPacket(b)
	if err != nil {
		return dst, err
	}
	if dst.IsValid() {
		routed, routeErr := c.route(dst, b.Bytes())
		if routeErr != nil {
			_ = c.Close()
			return dst, routeErr
		}
		dst = routed
	}
	if err := c.router.limiter.wait(c.ctx, requestMeterID(c.req), b.Len()); err != nil {
		return dst, err
	}
	c.meter.add(requestMeterID(c.req), b.Len(), 0)
	return dst, nil
}
// A UDP association repeats the full per-destination decision (sniffing, DNS,
// policy, routing and access log) only when a cached one expires, so policy,
// DNS and route changes still reach long-lived associations within the TTL.
const (
	udpDecisionTTL   = 30 * time.Second
	udpDecisionLimit = 256
)

type udpDecision struct {
	dst     M.Socksaddr
	expires time.Time
	// inspect mirrors when the uncached path hands a packet to payload rules:
	// only while the destination has no sniffed domain.
	inspect bool
	check   func([]byte) error
}

// route maps a client destination to the checked target for one packet.
func (c *meterPacketConn) route(dst M.Socksaddr, payload []byte) (M.Socksaddr, error) {
	now := time.Now()
	c.mu.Lock()
	decision, cached := c.decisions[dst]
	c.mu.Unlock()
	if cached && now.Before(decision.expires) {
		if decision.inspect && decision.check != nil && c.router.inspection.maxPacket > 0 {
			if err := decision.check(payload[:min(len(payload), c.router.inspection.maxPacket)]); err != nil {
				return dst, err
			}
		}
		return decision.dst, nil
	}
	metadata := c.metadata
	if dst != metadata.Destination {
		metadata.Domain, metadata.SniffContext = "", nil
	}
	metadata.Destination = dst
	first := c.router.inspection.packet(c.ctx, &metadata, payload)
	if dst == c.metadata.Destination {
		c.metadata.Domain, c.metadata.SniffContext = metadata.Domain, metadata.SniffContext
	}
	req, err := c.router.request(c.ctx, metadata, "udp", first)
	if err == nil && req.Outbound != c.req.Outbound {
		err = errors.New("proxy: changing outbound inside one UDP association is not supported")
	}
	if err != nil {
		return dst, err
	}
	newDst := M.ParseSocksaddr(req.Destination)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.originalDestinations[newDst] = dst
	// A QUIC handshake that is still being sniffed may yet reveal a domain
	// that changes the decision, so only settled decisions are reused.
	if metadata.Domain == "" && metadata.SniffContext != nil {
		return newDst, nil
	}
	if len(c.decisions) >= udpDecisionLimit {
		for key, old := range c.decisions {
			if !now.Before(old.expires) {
				delete(c.decisions, key)
			}
		}
		for key := range c.decisions {
			if len(c.decisions) < udpDecisionLimit {
				break
			}
			delete(c.decisions, key)
		}
	}
	c.decisions[dst] = udpDecision{dst: newDst, expires: now.Add(udpDecisionTTL),
		inspect: dst != c.metadata.Destination || c.metadata.Domain == "", check: req.PacketCheck}
	return newDst, nil
}

func (c *meterPacketConn) WritePacket(b *buf.Buffer, dst M.Socksaddr) error {
	if err := c.router.limiter.wait(c.ctx, requestMeterID(c.req), b.Len()); err != nil {
		b.Release()
		return err
	}
	c.mu.Lock()
	if original, found := c.originalDestinations[dst]; found {
		dst = original
	}
	c.mu.Unlock()
	n := b.Len()
	err := c.PacketConn.WritePacket(b, dst)
	if err == nil {
		c.meter.add(requestMeterID(c.req), 0, n)
	}
	return err
}

// Preserve the protocol writer's required packet head/tail room. Without these
// interfaces, sing's packet copier can allocate an undersized framing buffer.
func (c *meterPacketConn) FrontHeadroom() int  { return N.CalculateFrontHeadroom(c.PacketConn) }
func (c *meterPacketConn) RearHeadroom() int   { return N.CalculateRearHeadroom(c.PacketConn) }
func (c *meterPacketConn) ReaderMTU() int      { return N.CalculateMTU(c.PacketConn, nil) }
func (c *meterPacketConn) WriterMTU() int      { return N.CalculateMTU(nil, c.PacketConn) }
func (c *meterPacketConn) ReaderOverhead() int { return N.CalculateReaderOverhead(c.PacketConn) }
func (c *meterPacketConn) Close() error {
	c.done()
	return c.PacketConn.Close()
}
