package engine

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"path/filepath"
	"reconstructed.local/soga/geodata"
	"reconstructed.local/soga/panel"
	"reconstructed.local/soga/resolver"
	"reconstructed.local/soga/routing"
)

type remoteDocument struct {
	url     string
	data    []byte
	fetched time.Time
}

func (n *Node) updateGeo(ctx context.Context) error {
	c := n.opts.Config
	if n.opts.Paths.GeoSite != "" || n.opts.Paths.GeoIP != "" {
		return nil
	}
	candidate, err := geodata.Prepare(ctx, c.GeoSiteUrl, c.GeoIpUrl)
	if err != nil {
		return err
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed {
		return nil
	}
	old, dk, rk := n.geo, n.dnsKey, n.routeKey
	n.geo = candidate.Data
	// Force compiled DNS/route categories to bind to the new immutable data.
	n.dnsKey, n.routeKey = [32]byte{}, [32]byte{}
	accepted := false
	defer func() {
		if accepted {
			return
		}
		n.geo, n.dnsKey, n.routeKey = old, dk, rk
	}()
	p, err := n.loadPolicy(ctx, n.node)
	if err != nil {
		return err
	}
	dns, dnsKey, err := n.prepareDNS(ctx, n.node)
	if err != nil {
		return err
	}
	routes, routeKey, err := n.prepareRoutes(ctx)
	if err != nil {
		return err
	}
	// Outbound definitions need their normal listener rebuild. A geo refresh
	// only recompiles categories in the last successfully installed config.
	if routeKey != rk {
		return errors.New("routing document changed during geodata refresh; synchronize it first")
	}
	if err = candidate.Publish(n.geoStateDir()); err != nil {
		return err
	}
	n.policy.Store(p)
	n.dns.Store(dns)
	n.routes.Store(routes)
	n.dnsKey, n.routeKey = dnsKey, routeKey
	accepted = true
	return nil
}

func (n *Node) geoStateDir() string {
	return filepath.Join(n.opts.Paths.StateDir, "node-"+n.opts.NodeID+"-geodata")
}

// readDocument keeps a bounded, successful response for at most one minute.
// Parse failures never replace the node's active DNS/routing objects.
func readDocument(ctx context.Context, path, remote string, cached *remoteDocument) ([]byte, error) {
	if remote != "" {
		if cached.url == remote && time.Since(cached.fetched) < time.Minute {
			return cached.data, nil
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, remote, nil)
		if err != nil {
			return nil, errors.New("invalid remote configuration URL")
		}
		client := http.Client{Timeout: 10 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			return nil, errors.New("remote configuration request failed")
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("remote configuration HTTP status %d", resp.StatusCode)
		}
		data, err := io.ReadAll(io.LimitReader(resp.Body, 8*1024*1024+1))
		if err != nil {
			return nil, err
		}
		if len(data) > 8*1024*1024 {
			return nil, errors.New("remote configuration exceeds 8 MiB")
		}
		*cached = remoteDocument{remote, data, time.Now()}
		return data, nil
	}
	if path == "" {
		return nil, nil
	}
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 8*1024*1024+1))
	if len(data) > 8*1024*1024 {
		return nil, errors.New("configuration exceeds 8 MiB")
	}
	return data, err
}

func (n *Node) prepareDNS(ctx context.Context, node panel.Node) (*resolver.Resolver, [32]byte, error) {
	data, err := readDocument(ctx, n.opts.Paths.DNS, n.opts.Config.DnsConfigUrl, &n.dnsDocument)
	if err != nil {
		return nil, [32]byte{}, fmt.Errorf("DNS configuration: %w", err)
	}
	ruleData, err := json.Marshal(node.DNSRules)
	if err != nil {
		return nil, [32]byte{}, err
	}
	digest := sha256.New()
	digest.Write(data)
	digest.Write([]byte{0})
	digest.Write(ruleData)
	key := [32]byte(digest.Sum(nil))
	if n.dns.Load() != nil && key == n.dnsKey {
		return n.dns.Load(), key, nil
	}
	c := n.opts.Config
	var panelRules []resolver.RuleGroup
	for _, rule := range node.DNSRules {
		panelRules = append(panelRules, resolver.RuleGroup{Domains: rule.Domains, Servers: rule.Servers})
	}
	r, err := resolver.New(data, resolver.Options{Defaults: c.DefaultDns, Strategy: c.DnsStrategy,
		CacheTime: time.Duration(c.DnsCacheTime) * time.Minute, Geo: n.geo, PanelRules: panelRules})
	return r, key, err
}

func (n *Node) refreshRemote(ctx context.Context) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed {
		return nil
	}
	if n.opts.Config.DnsConfigUrl != "" {
		r, key, err := n.prepareDNS(ctx, n.node)
		if err != nil {
			return err
		}
		n.dns.Store(r)
		n.dnsKey = key
	}
	if n.opts.Config.RoutesUrl != "" {
		_, key, err := n.prepareRoutes(ctx)
		if err != nil {
			return err
		}
		if key != n.routeKey {
			return n.applyConfiguration(ctx, n.node, n.users)
		}
	}
	return nil
}

func (n *Node) prepareRoutes(ctx context.Context) (*routing.Router, [32]byte, error) {
	data, err := readDocument(ctx, n.opts.Paths.Routes, n.opts.Config.RoutesUrl, &n.routeDocument)
	if err != nil {
		return nil, [32]byte{}, fmt.Errorf("routes configuration: %w", err)
	}
	key := sha256.Sum256(data)
	if n.routes.Load() != nil && key == n.routeKey {
		return n.routes.Load(), key, nil
	}
	r, err := routing.New(data, n.geo)
	return r, key, err
}
