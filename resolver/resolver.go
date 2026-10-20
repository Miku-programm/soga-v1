// Package resolver implements the supplied DNS configuration contract.
package resolver

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"gopkg.in/yaml.v3"
	"reconstructed.local/soga/policy"
)

type Options struct {
	Defaults     []string
	Strategy     string
	CacheTime    time.Duration
	Geo          policy.GeoSource
	HTTPClient   *http.Client
	TLSConfig    *tls.Config
	SystemLookup func(context.Context, string, string) ([]netip.Addr, error)
	PanelRules   []RuleGroup
}

// RuleGroup appends a panel-provided DNS rule after explicit local DNS rules.
type RuleGroup struct {
	Domains []string
	Servers []string
}
type group struct {
	servers  []string
	strategy string
	rules    []policy.Rule
}
type cached struct {
	ips   []netip.Addr
	until time.Time
}
type Resolver struct {
	opts   Options
	groups []group
	mu     sync.Mutex
	cache  map[string]cached
}

// New preserves the order of YAML mappings, including the legacy sequence form.
func New(data []byte, opts Options) (*Resolver, error) {
	if opts.Strategy == "" {
		opts.Strategy = "ipv4_first"
	}
	if !validStrategy(opts.Strategy) || opts.CacheTime < 0 {
		return nil, errors.New("invalid DNS strategy or cache time")
	}
	if opts.HTTPClient == nil {
		opts.HTTPClient = &http.Client{Timeout: 8 * time.Second}
	}
	if opts.SystemLookup == nil {
		opts.SystemLookup = net.DefaultResolver.LookupNetIP
	}
	r := &Resolver{opts: opts, cache: map[string]cached{}}
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	if len(doc.Content) == 0 {
		return r.finish()
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return nil, errors.New("DNS YAML must be a mapping")
	}
	keys := map[string]bool{}
	for i := 0; i < len(root.Content); i += 2 {
		key, value := root.Content[i].Value, root.Content[i+1]
		if keys[key] {
			return nil, fmt.Errorf("duplicate DNS key %q", key)
		}
		keys[key] = true
		g := group{servers: split(key), strategy: opts.Strategy}
		var rules []string
		switch value.Kind {
		case yaml.SequenceNode:
			if err := value.Decode(&rules); err != nil {
				return nil, err
			}
		case yaml.MappingNode:
			seen := map[string]bool{}
			for j := 0; j < len(value.Content); j += 2 {
				k, v := value.Content[j].Value, value.Content[j+1]
				if seen[k] {
					return nil, fmt.Errorf("duplicate DNS field %q", k)
				}
				seen[k] = true
				switch k {
				case "strategy":
					if err := v.Decode(&g.strategy); err != nil {
						return nil, err
					}
				case "rules":
					if err := v.Decode(&rules); err != nil {
						return nil, err
					}
				default:
					return nil, fmt.Errorf("unknown DNS field %q", k)
				}
			}
		case yaml.ScalarNode:
			if value.Tag != "!!null" {
				return nil, errors.New("invalid DNS rule group")
			}
		default:
			return nil, errors.New("invalid DNS rule group")
		}
		if !validStrategy(g.strategy) {
			return nil, fmt.Errorf("invalid DNS strategy %q", g.strategy)
		}
		var err error
		g.rules, err = policy.CompileAll(rules, opts.Geo)
		if err != nil {
			return nil, err
		}
		r.groups = append(r.groups, g)
	}
	return r, r.finishError()
}

func (r *Resolver) finish() (*Resolver, error) { return r, r.finishError() }
func (r *Resolver) finishError() error {
	for _, item := range r.opts.PanelRules {
		if len(item.Servers) == 0 {
			return errors.New("panel DNS rule requires a server")
		}
		rules, err := policy.CompileAll(item.Domains, r.opts.Geo)
		if err != nil {
			return err
		}
		r.groups = append(r.groups, group{servers: slices.Clone(item.Servers), strategy: r.opts.Strategy, rules: rules})
	}
	return r.validateServers()
}
func split(s string) []string {
	var out []string
	for _, v := range strings.Split(s, ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}
func validStrategy(s string) bool {
	return s == "ipv4_first" || s == "ipv4_only" || s == "ipv6_first" || s == "ipv6_only"
}
func (r *Resolver) validateServers() error {
	servers := slices.Clone(r.opts.Defaults)
	for _, g := range r.groups {
		if len(g.servers) == 0 {
			return errors.New("empty DNS server")
		}
		servers = append(servers, g.servers...)
	}
	for _, s := range servers {
		if _, _, err := endpoint(s); err != nil {
			return err
		}
	}
	return nil
}
func endpoint(text string) (string, string, error) {
	scheme, addr, ok := strings.Cut(text, "://")
	if !ok {
		scheme, addr = "udp", text
	}
	if scheme == "https" {
		u, err := url.Parse(text)
		if err != nil || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
			return "", "", errors.New("invalid DNS HTTPS URL")
		}
		return scheme, text, nil
	}
	if scheme != "udp" && scheme != "tcp" && scheme != "tcp-tls" {
		return "", "", fmt.Errorf("unsupported DNS scheme %q", scheme)
	}
	if strings.ContainsAny(addr, "/?#@") {
		return "", "", errors.New("invalid DNS server address")
	}
	if _, _, err := net.SplitHostPort(addr); err != nil {
		p := "53"
		if scheme == "tcp-tls" {
			p = "853"
		}
		// Bracket-only IPv6 and bare IPv6 are both accepted.
		addr = net.JoinHostPort(strings.Trim(addr, "[]"), p)
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil || host == "" || port == "" {
		return "", "", errors.New("invalid DNS endpoint")
	}
	return scheme, addr, nil
}

func (r *Resolver) Lookup(ctx context.Context, host string) ([]netip.Addr, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{ip.Unmap()}, nil
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == "" {
		return nil, errors.New("empty DNS name")
	}
	r.mu.Lock()
	hit, ok := r.cache[host]
	r.mu.Unlock()
	if ok && time.Now().Before(hit.until) {
		return slices.Clone(hit.ips), nil
	}
	strategy := r.opts.Strategy
	var servers []string
	for _, g := range r.groups {
		if policy.MatchAny(g.rules, policy.Target{Host: host}) {
			servers = g.servers
			strategy = g.strategy
			break
		}
	}
	servers = append(slices.Clone(servers), r.opts.Defaults...)
	var ips []netip.Addr
	ttl := r.opts.CacheTime
	for _, server := range servers {
		found, minimum, err := r.query(ctx, server, host, strategy)
		if err == nil && len(found) > 0 {
			ips = found
			if minimum < ttl {
				ttl = minimum
			}
			break
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	if len(ips) == 0 {
		network := "ip"
		if strategy == "ipv4_only" {
			network = "ip4"
		} else if strategy == "ipv6_only" {
			network = "ip6"
		}
		var err error
		ips, err = r.opts.SystemLookup(ctx, network, host)
		if err != nil {
			return nil, err
		}
		ips = ordered(ips, strategy)
	}
	if len(ips) == 0 {
		return nil, errors.New("DNS returned no addresses")
	}
	if ttl > 0 {
		r.mu.Lock()
		if len(r.cache) >= 65536 {
			for k, v := range r.cache {
				if time.Now().After(v.until) {
					delete(r.cache, k)
				}
			}
			if len(r.cache) >= 65536 {
				clear(r.cache)
			}
		}
		r.cache[host] = cached{slices.Clone(ips), time.Now().Add(ttl)}
		r.mu.Unlock()
	}
	return slices.Clone(ips), nil
}
func ordered(ips []netip.Addr, strategy string) []netip.Addr {
	var first, second []netip.Addr
	seen := map[netip.Addr]bool{}
	for _, ip := range ips {
		ip = ip.Unmap()
		if !ip.IsValid() || seen[ip] || strategy == "ipv4_only" && !ip.Is4() || strategy == "ipv6_only" && ip.Is4() {
			continue
		}
		seen[ip] = true
		if ip.Is4() && strings.HasPrefix(strategy, "ipv4") || ip.Is6() && strings.HasPrefix(strategy, "ipv6") {
			first = append(first, ip)
		} else {
			second = append(second, ip)
		}
	}
	return append(first, second...)
}
func (r *Resolver) query(ctx context.Context, server, host, strategy string) ([]netip.Addr, time.Duration, error) {
	types := []uint16{dns.TypeA, dns.TypeAAAA}
	switch strategy {
	case "ipv4_only":
		types = types[:1]
	case "ipv6_only":
		types = types[1:]
	case "ipv6_first":
		types = []uint16{dns.TypeAAAA, dns.TypeA}
	}
	var ips []netip.Addr
	ttl := r.opts.CacheTime
	var last error
	for _, kind := range types {
		q := new(dns.Msg)
		q.SetQuestion(dns.Fqdn(host), kind)
		answer, err := r.exchange(ctx, server, q)
		if err != nil {
			last = err
			continue
		}
		if answer.Rcode != dns.RcodeSuccess {
			last = fmt.Errorf("DNS response code %d", answer.Rcode)
			continue
		}
		allowed := map[string]bool{strings.ToLower(dns.Fqdn(host)): true}
		for range 16 {
			changed := false
			for _, rr := range answer.Answer {
				if c, ok := rr.(*dns.CNAME); ok && allowed[strings.ToLower(c.Hdr.Name)] && !allowed[strings.ToLower(c.Target)] {
					allowed[strings.ToLower(c.Target)] = true
					changed = true
				}
			}
			if !changed {
				break
			}
		}
		for _, rr := range answer.Answer {
			if !allowed[strings.ToLower(rr.Header().Name)] {
				continue
			}
			var ip net.IP
			switch v := rr.(type) {
			case *dns.A:
				if kind == dns.TypeA {
					ip = v.A
				}
			case *dns.AAAA:
				if kind == dns.TypeAAAA {
					ip = v.AAAA
				}
			}
			if a, ok := netip.AddrFromSlice(ip); ok {
				ips = append(ips, a.Unmap())
				ttl = min(ttl, time.Duration(rr.Header().Ttl)*time.Second)
			}
		}
	}
	if len(ips) > 0 {
		return ordered(ips, strategy), ttl, nil
	}
	if last == nil {
		last = errors.New("DNS response has no matching addresses")
	}
	return nil, 0, last
}
func (r *Resolver) exchange(ctx context.Context, server string, q *dns.Msg) (*dns.Msg, error) {
	scheme, addr, err := endpoint(server)
	if err != nil {
		return nil, err
	}
	if scheme == "https" {
		data, err := q.Pack()
		if err != nil {
			return nil, err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, addr, bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/dns-message")
		req.Header.Set("Accept", "application/dns-message")
		resp, err := r.opts.HTTPClient.Do(req)
		if err != nil {
			return nil, errors.New("DNS HTTPS request failed")
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			return nil, fmt.Errorf("DNS HTTPS status %d", resp.StatusCode)
		}
		data, err = io.ReadAll(io.LimitReader(resp.Body, 65537))
		if err != nil {
			return nil, err
		}
		if len(data) > 65536 {
			return nil, errors.New("DNS HTTPS response too large")
		}
		answer := new(dns.Msg)
		if err = answer.Unpack(data); err != nil {
			return nil, err
		}
		if !answer.Response || answer.Id != q.Id {
			return nil, errors.New("mismatched DNS response")
		}
		return answer, nil
	}
	client := dns.Client{Net: scheme, Timeout: 5 * time.Second, TLSConfig: r.opts.TLSConfig}
	answer, _, err := client.ExchangeContext(ctx, q, addr)
	if err == nil && answer.Truncated && scheme == "udp" {
		client.Net = "tcp"
		answer, _, err = client.ExchangeContext(ctx, q, addr)
	}
	return answer, err
}
