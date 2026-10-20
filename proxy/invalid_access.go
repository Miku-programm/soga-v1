package proxy

import (
	"errors"
	"sync"
	"time"
)

type InvalidAccessConfig struct{ Count, WindowSeconds, ForbiddenSeconds int }

func (c *InvalidAccessConfig) validate() error {
	if c != nil && (c.Count <= 0 || c.WindowSeconds <= 0 || c.ForbiddenSeconds <= 0) {
		return errors.New("proxy: invalid access limits must be positive")
	}
	return nil
}

type invalidPeer struct {
	failures []time.Time
	until    time.Time
}
type invalidAccessGuard struct {
	mu    sync.Mutex
	spec  *InvalidAccessConfig
	peers map[string]*invalidPeer
}

func newInvalidAccessGuard(spec *InvalidAccessConfig) *invalidAccessGuard {
	return &invalidAccessGuard{spec: spec, peers: make(map[string]*invalidPeer)}
}
func (g *invalidAccessGuard) blocked(ip string) bool {
	if g.spec == nil {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	p := g.peers[ip]
	return p != nil && time.Now().Before(p.until)
}
func (g *invalidAccessGuard) failure(ip string) {
	if g.spec == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	now := time.Now()
	cutoff := now.Add(-time.Duration(g.spec.WindowSeconds) * time.Second)
	p := g.peers[ip]
	if p == nil {
		if len(g.peers) >= 65536 {
			for key, old := range g.peers {
				if old.until.Before(now) && (len(old.failures) == 0 || old.failures[len(old.failures)-1].Before(cutoff)) {
					delete(g.peers, key)
				}
			}
			// Bound memory under unauthenticated source churn.
			if len(g.peers) >= 65536 {
				for key := range g.peers {
					delete(g.peers, key)
					break
				}
			}
		}
		p = &invalidPeer{}
		g.peers[ip] = p
	}
	if now.Before(p.until) {
		return
	}
	keep := p.failures[:0]
	for _, at := range p.failures {
		if at.After(cutoff) {
			keep = append(keep, at)
		}
	}
	p.failures = append(keep, now)
	if len(p.failures) >= g.spec.Count {
		p.until = now.Add(time.Duration(g.spec.ForbiddenSeconds) * time.Second)
		p.failures = nil
	}
}
