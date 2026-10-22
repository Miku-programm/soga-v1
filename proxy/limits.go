package proxy

import (
	"context"
	"errors"
	"math"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"
)

const rateBurstBytes = 64 * 1024

// Limiter can be shared by listeners belonging to one node. TCP admissions count
// distinct authenticated physical source peers, including multiplexed streams.
// Speed is aggregate upload+download, decimal Mbps, with a 64 KiB burst. These are
// explicit reconstruction policies; the original algorithm is unknown.
type Limiter struct {
	mu      sync.Mutex
	users   map[int64]*userLimit
	node    atomic.Pointer[rate.Limiter]
	prefix4 int
	prefix6 int
}

// userLimit entries are never removed, so a connection may keep the pointer
// for its lifetime; speed changes reach it through the atomic pointer.
type userLimit struct {
	spec    User
	speed   atomic.Pointer[rate.Limiter]
	ips     map[string]int
	devices map[string]int
	tcp     map[string]int
}

func NewLimiter() *Limiter {
	return &Limiter{users: make(map[int64]*userLimit), prefix4: 32, prefix6: 128}
}

func normalizedPrefixes(p4, p6 *int) (int, int, error) {
	v4, v6 := 32, 128
	if p4 != nil {
		v4 = *p4
	}
	if p6 != nil {
		v6 = *p6
	}
	if v4 < 0 || v4 > 32 || v6 < 0 || v6 > 128 {
		return 0, 0, errors.New("proxy: invalid IP prefix length")
	}
	return v4, v6, nil
}

func maskIP(ip string, v4, v6 int) string {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return ip
	}
	addr = addr.Unmap()
	bits := v6
	if addr.Is4() {
		bits = v4
	}
	return netip.PrefixFrom(addr, bits).Masked().Addr().String()
}

func (l *Limiter) SetIPPrefixes(v4, v6 int) error {
	v4, v6, err := normalizedPrefixes(&v4, &v6)
	if err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if v4 != l.prefix4 || v6 != l.prefix6 {
		for _, user := range l.users {
			if len(user.ips) > 0 {
				return errors.New("proxy: cannot change IP prefixes while peers are active")
			}
		}
	}
	l.prefix4, l.prefix6 = v4, v6
	return nil
}

func speedLimiter(mbps float64) *rate.Limiter {
	if mbps <= 0 {
		return nil
	}
	return rate.NewLimiter(rate.Limit(mbps*1_000_000/8), rateBurstBytes)
}

func validSpeed(mbps float64) bool { return mbps >= 0 && !math.IsNaN(mbps) && !math.IsInf(mbps, 0) }

// SetUserLimits affects new admissions and subsequent payload pacing.
// Existing peers are closed by Server.UpdateUsers, not by changing limits alone.
func (l *Limiter) SetUserLimits(user User) error {
	if user.ID <= 0 || !validSpeed(user.SpeedLimit) || user.DeviceLimit < 0 || user.IPLimit < 0 || user.TCPLimit < 0 {
		return errors.New("proxy: invalid user limits")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	u := l.users[user.ID]
	if u == nil {
		u = &userLimit{ips: make(map[string]int), devices: make(map[string]int), tcp: make(map[string]int)}
		l.users[user.ID] = u
	}
	if user.SpeedLimit != u.spec.SpeedLimit {
		u.speed.Store(speedLimiter(user.SpeedLimit))
	}
	u.spec = user
	return nil
}

func (l *Limiter) SetNodeSpeedLimit(mbps float64) error {
	if !validSpeed(mbps) {
		return errors.New("proxy: invalid node speed")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if mbps == 0 {
		l.node.Store(nil)
	} else if node := l.node.Load(); node == nil {
		l.node.Store(speedLimiter(mbps))
	} else {
		node.SetLimit(rate.Limit(mbps * 1_000_000 / 8))
	}
	return nil
}

func (l *Limiter) acquire(req Request, physicalTCP bool) (func(), error) {
	ip, _, err := net.SplitHostPort(req.Source)
	if err != nil {
		return nil, errors.New("proxy: cannot enforce limits without source IP")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	ip = maskIP(ip, l.prefix4, l.prefix6)
	u := l.users[req.UserID]
	if u == nil {
		return nil, errors.New("proxy: missing authenticated user limits")
	}
	device := "ip:" + ip
	if req.DeviceID != "" {
		device = "cid:" + req.DeviceID
	} else if req.deviceLimitByCID {
		device = "" // SSR UDP carries no authenticated CID. IP limits still apply.
	}
	if u.spec.IPLimit > 0 && u.ips[ip] == 0 && len(u.ips) >= u.spec.IPLimit {
		return nil, errors.New("proxy: user IP limit reached")
	}
	if device != "" && u.spec.DeviceLimit > 0 && u.devices[device] == 0 && len(u.devices) >= u.spec.DeviceLimit {
		return nil, errors.New("proxy: user device limit reached")
	}
	if physicalTCP && u.spec.TCPLimit > 0 && u.tcp[req.Source] == 0 && len(u.tcp) >= u.spec.TCPLimit {
		return nil, errors.New("proxy: user TCP limit reached")
	}
	u.ips[ip]++
	if device != "" {
		u.devices[device]++
	}
	if physicalTCP {
		u.tcp[req.Source]++
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			l.mu.Lock()
			defer l.mu.Unlock()
			u.ips[ip]--
			if device != "" {
				u.devices[device]--
				if u.devices[device] == 0 {
					delete(u.devices, device)
				}
			}
			if u.ips[ip] == 0 {
				delete(u.ips, ip)
			}
			if physicalTCP {
				u.tcp[req.Source]--
				if u.tcp[req.Source] == 0 {
					delete(u.tcp, req.Source)
				}
			}
		})
	}, nil
}

func (l *Limiter) admissionRequest(req Request) AdmissionRequest {
	ip, _, _ := net.SplitHostPort(req.Source)
	l.mu.Lock()
	defer l.mu.Unlock()
	ip = maskIP(ip, l.prefix4, l.prefix6)
	result := AdmissionRequest{UserID: req.UserID, IP: ip, DeviceID: "ip:" + ip}
	if req.deviceLimitByCID {
		result.DeviceID = ""
		if req.DeviceID != "" {
			result.DeviceID = "cid:" + req.DeviceID
		}
	}
	if u := l.users[req.UserID]; u != nil {
		result.IPLimit, result.DeviceLimit = u.spec.IPLimit, u.spec.DeviceLimit
	}
	return result
}

// pacer is resolved once per connection, so the payload path takes no lock:
// an unlimited node and user cost two atomic loads per read or write.
type pacer struct {
	l    *Limiter
	user *userLimit // nil for unattributed traffic
}

func (l *Limiter) pacer(id int64) *pacer {
	p := &pacer{l: l}
	if id > 0 {
		l.mu.Lock()
		p.user = l.users[id]
		l.mu.Unlock()
	}
	return p
}

func (p *pacer) pace(ctx context.Context, n int) error {
	var speed *rate.Limiter
	if p.user != nil {
		speed = p.user.speed.Load()
	}
	node := p.l.node.Load()
	if speed == nil && node == nil {
		return nil
	}
	for n > 0 {
		chunk := min(n, rateBurstBytes)
		now := time.Now()
		var delay time.Duration
		var reservations [2]*rate.Reservation
		for i, limiter := range [2]*rate.Limiter{speed, node} {
			if limiter == nil {
				continue
			}
			r := limiter.ReserveN(now, chunk)
			if !r.OK() {
				return errors.New("proxy: rate chunk exceeds burst")
			}
			reservations[i] = r
			delay = max(delay, r.DelayFrom(now))
		}
		if delay > 0 {
			timer := time.NewTimer(delay)
			select {
			case <-timer.C:
			case <-ctx.Done():
				timer.Stop()
				for _, r := range reservations {
					if r != nil {
						r.CancelAt(now)
					}
				}
				return ctx.Err()
			}
		}
		n -= chunk
	}
	return nil
}

func (l *Limiter) wait(ctx context.Context, id int64, n int) error { return l.pacer(id).pace(ctx, n) }
