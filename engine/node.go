package engine

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"math/rand/v2"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"reconstructed.local/soga/accounting"
	"reconstructed.local/soga/config"
	"reconstructed.local/soga/dynamic"
	"reconstructed.local/soga/geodata"
	"reconstructed.local/soga/hoststats"
	"reconstructed.local/soga/logging"
	"reconstructed.local/soga/panel"
	"reconstructed.local/soga/policy"
	"reconstructed.local/soga/proxy"
	"reconstructed.local/soga/redislimit"
	"reconstructed.local/soga/resolver"
	"reconstructed.local/soga/routing"
	"reconstructed.local/soga/rulelist"
)

type Options struct {
	Config   config.Config
	Values   map[string]string
	Explicit map[string]bool
	NodeID   string
	Paths    Paths
	API      panel.API
	Logger   *slog.Logger
}

const maxIntervalSeconds = 365 * 24 * 60 * 60

type Node struct {
	mu                           sync.Mutex
	opts                         Options
	api                          panel.API
	closeAPI                     func() error
	caps                         panel.Capabilities
	ctx                          context.Context
	cancel                       context.CancelFunc
	done                         chan struct{}
	servers                      []*proxy.Server
	configs                      []proxy.Config
	node                         panel.Node
	users                        []panel.User
	key                          string
	started                      bool
	ready                        atomic.Bool
	closed                       bool
	ledger                       *accounting.Ledger
	limiter                      *proxy.Limiter
	stats                        *hoststats.Sampler
	dynamic                      *dynamic.Controller
	authCache                    *proxy.AuthenticationCache
	redis                        *redislimit.Manager
	redisWarn                    atomic.Int64
	lastOnline                   map[int64]accounting.Counters
	access                       *logging.Access
	policy                       atomic.Pointer[policy.Policy]
	dns                          atomic.Pointer[resolver.Resolver]
	dnsDocument                  remoteDocument
	dnsKey                       [32]byte
	routes                       atomic.Pointer[routing.Router]
	routeDocument                remoteDocument
	routeKey                     [32]byte
	block, white                 rulelist.Store
	blockDocument, whiteDocument remoteDocument
	geo                          *policy.GeoData
	auditMu                      sync.Mutex
	audits                       map[panel.AuditLog]bool
	denials                      map[[2]int64]panel.PolicyDenial
}

// StartNode performs the initial complete fetch before opening a listener.
// Later failed pulls keep the last working configuration and users.
func StartNode(parent context.Context, opts Options) (*Node, error) {
	if parent == nil {
		return nil, errors.New("nil runtime context")
	}
	if err := validatePanelConfigService(opts.Config); err != nil {
		return nil, err
	}
	id, err := strconv.ParseInt(opts.NodeID, 10, 64)
	if err != nil || id <= 0 {
		return nil, fmt.Errorf("invalid node_id %q", opts.NodeID)
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if (opts.Config.ProxyProtocol || opts.Config.UdpProxyProtocol) && opts.Values[proxyProtocolTrustedKey] == "" {
		opts.Logger.Warn("PROXY headers are accepted from any client, which can forge its source IP; set " +
			proxyProtocolTrustedKey + " to the relay addresses")
	}
	if opts.Config.CheckInterval <= 0 || opts.Config.CheckInterval > maxIntervalSeconds ||
		opts.Config.SubmitInterval <= 0 || opts.Config.SubmitInterval > maxIntervalSeconds ||
		opts.Config.RandomIntervalRange < 0 || opts.Config.RandomIntervalRange > maxIntervalSeconds {
		return nil, errors.New("check_interval/submit_interval must be 1..31536000 seconds; random_interval_range must be 0..31536000")
	}
	if opts.Paths.StateDir == "" {
		return nil, errors.New("runtime state directory is required")
	}
	if opts.Config.GeoUpdateEnable && (opts.Config.GeoUpdateInterval < 1 || opts.Config.GeoUpdateInterval > 24*365) {
		return nil, errors.New("geo_update_interval must be 1..8760 hours")
	}
	for _, v := range []float64{opts.Config.SubmitTrafficMinTraffic, opts.Config.SubmitAliveIpMinTraffic} {
		if v < 0 || math.IsNaN(v) || math.IsInf(v, 0) || v > float64(math.MaxInt64/1024) {
			return nil, errors.New("invalid traffic reporting threshold")
		}
	}
	api := opts.API
	var closeAPI func() error
	opened := false
	defer func() {
		if !opened && closeAPI != nil {
			_ = closeAPI()
		}
	}()
	if api == nil {
		api, closeAPI, err = openPanel(opts.Config, opts.NodeID)
		if err != nil {
			return nil, err
		}
	}
	geo, err := geodata.Load(opts.Paths.GeoSite, opts.Paths.GeoIP, filepath.Join(opts.Paths.StateDir, "node-"+opts.NodeID+"-geodata"))
	if err != nil {
		return nil, err
	}
	ledger, err := accounting.Open(filepath.Join(opts.Paths.StateDir, "node-"+opts.NodeID+"-traffic.json"))
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(parent)
	n := &Node{opts: opts, api: api, closeAPI: closeAPI, ctx: ctx, cancel: cancel, done: make(chan struct{}),
		ledger: ledger, limiter: proxy.NewLimiter(), stats: hoststats.New(), lastOnline: map[int64]accounting.Counters{},
		geo: geo, audits: map[panel.AuditLog]bool{},
		caps: panel.Capabilities{AuditRules: true, WhiteList: true, AliveIPs: true, AuditLogs: true, Status: true}}
	n.dynamic, err = dynamic.New(opts.Config, n.limiter)
	if err != nil {
		cancel()
		return nil, err
	}
	if kind := opts.Config.NormalizedServerType(); kind == "v2ray" || kind == "ss" {
		if opts.Config.IpUserCacheTime < 1 || opts.Config.IpUserCacheTime > 8760 {
			cancel()
			return nil, errors.New("ip_user_cache_time must be 1..8760 hours")
		}
		cachePath := filepath.Join(opts.Config.IpUserCacheSaveDir, "reconstructed-node-"+opts.NodeID+"-"+kind+"-auth-cache.json")
		n.authCache, err = proxy.NewAuthenticationCache(proxy.AuthenticationCacheConfig{
			TTL: time.Duration(opts.Config.IpUserCacheTime) * time.Hour, Path: cachePath, Persist: opts.Config.IpUserCacheSaveEnable,
			OnError: func(err error) { opts.Logger.Warn("authentication cache persistence failed", "error", err) }})
		if err != nil {
			cancel()
			return nil, err
		}
		defer func() {
			if !opened {
				_ = n.authCache.Close()
			}
		}()
	}
	redisSettings, redisEnabled, legacyRedis, err := redisOptions(opts.Config, opts.Explicit)
	if err != nil {
		cancel()
		return nil, err
	}
	if legacyRedis {
		opts.Logger.Warn("redis_* is deprecated; migrate to redis_ip_limit_*")
	}
	if redisEnabled {
		n.redis, err = redislimit.New(redisSettings)
		if err != nil {
			cancel()
			return nil, err
		}
		defer func() {
			if !opened {
				_ = n.redis.Close()
			}
		}()
	}
	if api, ok := api.(panel.CapableAPI); ok {
		n.caps = api.Capabilities()
	}
	n.access, err = logging.NewAccess(ctx, opts.Config, func(err error) { opts.Logger.Warn("access log write failed", "error", err) })
	if err != nil {
		cancel()
		return nil, err
	}
	if err = n.Sync(ctx); err != nil {
		cancel()
		for _, server := range n.servers {
			_ = server.Close()
		}
		closeCtx, stop := context.WithTimeout(context.Background(), 10*time.Second)
		_ = n.access.Close(closeCtx)
		stop()
		return nil, err
	}
	go n.loop()
	opened = true
	return n, nil
}

func (n *Node) Sync(ctx context.Context) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed {
		return net.ErrClosed
	}
	node, err := n.api.FetchNode(ctx)
	if err != nil {
		return fmt.Errorf("fetch node: %w", err)
	}
	users, err := n.api.FetchUsers(ctx)
	if err != nil {
		return fmt.Errorf("fetch users: %w", err)
	}
	// Panel order is significant: the last SSR carrier for an effective
	// listening port replaces the earlier carrier's settings.
	return n.applyConfiguration(ctx, node, users)
}

// Caller holds n.mu. Validation completes before any listener is changed.
func (n *Node) applyConfiguration(ctx context.Context, node panel.Node, users []panel.User) error {
	if node.Basic.PullInterval < 0 || node.Basic.PullInterval > maxIntervalSeconds ||
		node.Basic.PushInterval < 0 || node.Basic.PushInterval > maxIntervalSeconds {
		return errors.New("panel pull/push interval must be 0..31536000 seconds")
	}
	nextPolicy, err := n.loadPolicy(ctx, node)
	if err != nil {
		return err
	}
	nextRoutes, routeKey, err := n.prepareRoutes(ctx)
	if err != nil {
		return err
	}
	nextDNS, dnsKey, err := n.prepareDNS(ctx, node)
	if err != nil {
		return err
	}
	addresses, err := listenAddresses(n.opts.Config.Listen)
	if err != nil {
		return err
	}
	var configs []proxy.Config
	var certificateHashes [][32]byte
	plans, err := planListeners(node, users, addresses)
	if err != nil {
		return err
	}
	var identities []struct {
		Config  panel.NodeConfig
		Owner   int64
		Address string
	}
	userMap := map[int64]proxy.User{}
	for _, plan := range plans {
		cfg, err := buildProxy(ctx, n.opts.Config, n.opts.Values, n.opts.Paths, plan.node, plan.users, plan.address, plan.carrier)
		if err != nil {
			return err
		}
		cfg.Transform = n.transform
		cfg.SSRCarrierID = plan.carrier
		cfg.Limiter = n.limiter
		cfg.AuthCache = n.authCache
		if n.redis != nil {
			cfg.GlobalAdmission = n.globalAdmission
		}
		cfg.Outbounds = nextRoutes.Outbounds()
		if cfg.TLS != nil && cfg.TLS.Enabled && cfg.TLS.CertificatePath != "" {
			for _, path := range []string{cfg.TLS.CertificatePath, cfg.TLS.KeyPath} {
				data, err := os.ReadFile(path)
				if err != nil {
					return err
				}
				certificateHashes = append(certificateHashes, sha256.Sum256(data))
			}
		}
		if cfg.Tunnel != nil && cfg.Tunnel.TLSConfig != nil {
			for _, pair := range cfg.Tunnel.TLSConfig.Certificates {
				for _, der := range pair.Certificate {
					certificateHashes = append(certificateHashes, sha256.Sum256(der))
				}
			}
		}
		configs = append(configs, cfg)
		for _, user := range cfg.Users {
			userMap[user.ID] = user
		}
		identities = append(identities, struct {
			Config  panel.NodeConfig
			Owner   int64
			Address string
		}{plan.node.Config, plan.owner, plan.address})
	}
	// Scheduling-only changes do not disconnect users. Certificate renewals
	// and outbound changes do need to rebuild the listener's protocol core.
	encoded, err := json.Marshal(struct {
		Listeners    any
		Routes       [32]byte
		Certificates [][32]byte
	}{identities, routeKey, certificateHashes})
	if err != nil {
		return err
	}
	key := string(encoded)
	var preparedUsers []proxy.User
	for _, user := range userMap {
		preparedUsers = append(preparedUsers, user)
	}
	if len(configs) > 0 {
		if err := n.limiter.SetNodeSpeedLimit(configs[0].NodeSpeedLimit); err != nil {
			return err
		}
		for _, user := range preparedUsers {
			if err := n.limiter.SetUserLimits(user); err != nil {
				return err
			}
		}
	}
	if !n.started || key != n.key {
		n.ready.Store(false)
		if err := n.rebind(configs); err != nil {
			if len(n.configs) > 0 {
				return errors.Join(err, n.restoreConfiguration())
			}
			return err
		}
		n.key, n.started = key, true
	} else if !reflect.DeepEqual(n.users, users) {
		for i, server := range n.servers {
			if err := server.UpdateUsers(configs[i].Users); err != nil {
				n.ready.Store(false)
				return errors.Join(err, n.restoreConfiguration())
			}
		}
	}
	n.policy.Store(nextPolicy)
	n.dns.Store(nextDNS)
	n.dnsKey = dnsKey
	n.routes.Store(nextRoutes)
	n.routeKey = routeKey
	if err := n.dynamic.ReplaceUsers(preparedUsers, time.Now()); err != nil {
		return err
	}
	n.node, n.users = node, slices.Clone(users)
	n.configs = configs
	n.ready.Store(true)
	n.opts.Logger.Info("node synchronized", "node_id", n.opts.NodeID, "users", len(users), "listeners", n.AddressesLocked())
	return nil
}

// Reopening the old cores installs their base user limits. Restore the active
// temporary restrictions too, before requests can use the recovered listeners.
// Caller holds n.mu and has already set ready=false.
func (n *Node) restoreConfiguration() error {
	if err := n.rebind(n.configs); err != nil {
		return err
	}
	users := map[int64]proxy.User{}
	for _, cfg := range n.configs {
		for _, user := range cfg.Users {
			users[user.ID] = user
		}
	}
	previous := make([]proxy.User, 0, len(users))
	for _, user := range users {
		previous = append(previous, user)
	}
	if err := n.dynamic.ReplaceUsers(previous, time.Now()); err != nil {
		return err
	}
	n.ready.Store(true)
	return nil
}

// rebind retains final counters even when a new listener fails to bind. Its
// caller can invoke it again with the last working configuration to roll back.
func (n *Node) rebind(configs []proxy.Config) error {
	n.started = false
	for _, server := range n.servers {
		_ = server.Close()
	}
	if err := n.observe(); err != nil {
		return err
	}
	n.servers = nil
	n.ledger.ResetSource()
	n.lastOnline = map[int64]accounting.Counters{}
	for _, cfg := range configs {
		server, err := proxy.Start(n.ctx, cfg)
		if err != nil {
			for _, previous := range n.servers {
				_ = previous.Close()
			}
			return err
		}
		n.servers = append(n.servers, server)
	}
	n.started = true
	return nil
}

func (n *Node) loadPolicy(ctx context.Context, node panel.Node) (*policy.Policy, error) {
	c := n.opts.Config
	load := func(store *rulelist.Store, path, remote string, cached *remoteDocument) ([]string, error) {
		if remote != "" {
			data, err := readDocument(ctx, "", remote, cached)
			if err != nil {
				return nil, err
			}
			return rulelist.ParseRemote(string(data)), nil
		}
		if path != "" {
			_, err := store.LoadLocal(path, "", nil)
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				return nil, err
			}
		}
		return store.Snapshot(), nil
	}
	black, err := load(&n.block, n.opts.Paths.BlockList, c.BlockListUrl, &n.blockDocument)
	if err != nil {
		return nil, fmt.Errorf("block list: %w", err)
	}
	// Enforce the documented setting even with no blockList file or with
	// a remote list. The original standalone rulelist loader remains intact.
	for _, port := range c.ForbiddenPorts {
		black = append(black, "port:"+port)
	}
	white, err := load(&n.white, n.opts.Paths.WhiteList, c.WhiteListUrl, &n.whiteDocument)
	if err != nil {
		return nil, fmt.Errorf("white list: %w", err)
	}
	if n.caps.WhiteList {
		panelWhite, err := n.api.FetchWhiteList(ctx)
		if err != nil {
			return nil, fmt.Errorf("panel white list: %w", err)
		}
		white = append(white, panelWhite...)
	}
	p := &policy.Policy{BanPrivate: c.BanPrivateIp, DetectPacket: c.DetectPacket,
		ForbidBitTorrent: c.ForbiddenBitTorrent, ExemptUsers: map[int64]bool{}}
	p.Block, err = policy.CompileAll(black, n.geo)
	if err != nil {
		return nil, err
	}
	p.White, err = policy.CompileAll(white, n.geo)
	if err != nil {
		return nil, err
	}
	if node.Policy != nil && node.Policy.Mode != "all" {
		switch node.Policy.Mode {
		case "", "reject":
		case "allow":
			p.AllowOnly = true
		default:
			return nil, fmt.Errorf("invalid panel policy mode %q", node.Policy.Mode)
		}
		for _, item := range node.Policy.Rules {
			r, err := policy.Compile(item.Rule, n.geo)
			if err != nil {
				return nil, err
			}
			r.AuditID = item.ID
			if p.AllowOnly {
				p.Allowed = append(p.Allowed, r)
			} else {
				p.Block = append(p.Block, r)
			}
		}
	}
	if n.caps.AuditRules {
		audit, err := n.api.FetchAuditRules(ctx)
		if err != nil {
			return nil, fmt.Errorf("panel audit rules: %w", err)
		}
		for _, item := range audit {
			r, err := policy.Compile(item.Rule, n.geo)
			if err != nil {
				return nil, err
			}
			r.AuditID = int64(item.ID)
			p.Block = append(p.Block, r)
		}
	}
	for _, item := range c.BlockListWhiteUserId {
		id, err := strconv.ParseInt(item, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("block_list_white_user_id: %w", err)
		}
		p.ExemptUsers[id] = true
	}
	return p, nil
}

func (n *Node) transform(ctx context.Context, req proxy.Request) (proxy.Request, error) {
	if !n.ready.Load() {
		return req, errors.New("node configuration is being installed")
	}
	host, portText, err := net.SplitHostPort(req.Destination)
	if err != nil {
		return req, err
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		return req, err
	}
	nodeID, _ := strconv.ParseInt(n.opts.NodeID, 10, 64)
	target := policy.Target{Host: host, Port: uint16(port), UserID: req.UserID, NodeID: nodeID, Network: req.Network, Unattributed: req.Unattributed}
	if ip, err := netip.ParseAddr(host); err == nil {
		target.Addresses = []netip.Addr{ip}
	} else {
		resolver := n.dns.Load()
		if resolver == nil {
			return req, errors.New("node DNS is not ready")
		}
		ips, err := resolver.Lookup(ctx, host)
		if err != nil {
			return req, err
		}
		if len(ips) == 0 {
			return req, errors.New("DNS returned no addresses")
		}
		target.Addresses = ips
	}
	// The sniffed name is client-supplied; policy checks keep the real
	// destination too, so a spoofed SNI/Host cannot relax the rules.
	actual := target
	if req.SniffedDomain != "" {
		target.Host = req.SniffedDomain
	}
	active := n.policy.Load()
	// No accepted policy is available during the short initial bind window.
	if active == nil {
		return req, errors.New("node policy is not ready")
	}
	checkErr := active.CheckSniffed(actual, req.SniffedDomain)
	if checkErr == nil {
		checkErr = active.CheckPacket(actual, req.FirstPacket)
	}
	if err := checkErr; err != nil {
		if !req.Unattributed {
			n.recordDenial(req.UserID, req.Destination, err)
		}
		return req, err
	}
	// Pin the checked IP, so the core cannot perform a second unchecked lookup.
	selection, err := n.routes.Load().Select(target, req.Source)
	if err != nil {
		return req, err
	}
	if selection.RedirectHost != "" {
		target.Host = selection.RedirectHost
		ips, err := n.dns.Load().Lookup(ctx, target.Host)
		if err != nil {
			return req, err
		}
		target.Addresses = ips
		if selection.RedirectPort != 0 {
			target.Port = selection.RedirectPort
			portText = strconv.Itoa(int(target.Port))
		}
		if err := active.Check(target); err != nil {
			if !req.Unattributed {
				n.recordDenial(req.UserID, net.JoinHostPort(target.Host, portText), err)
			}
			return req, err
		}
	}
	ip := target.Addresses[0].Unmap()
	if selection.Family != "" {
		found := false
		prefer4 := selection.Family == "ipv4_first" || selection.Family == "ipv4_only"
		for _, candidate := range target.Addresses {
			if candidate.Unmap().Is4() == prefer4 {
				ip = candidate.Unmap()
				found = true
				break
			}
		}
		if !found && (selection.Family == "ipv4_only" || selection.Family == "ipv6_only") {
			return req, errors.New("no resolved address matches outbound bind family")
		}
	}
	req.Destination = net.JoinHostPort(ip.String(), portText)
	req.Outbound = selection.Tag
	n.access.Write(logging.FormatRecord(req.Network, nodeID, req.UserID, req.Source, target.Host, req.Destination))
	return req, nil
}

func (n *Node) recordDenial(user int64, target string, err error) {
	var denied *policy.Denied
	if !errors.As(err, &denied) {
		return
	}
	n.auditMu.Lock()
	defer n.auditMu.Unlock()
	if _, ok := n.api.(panel.PolicyReporter); ok {
		if n.denials == nil {
			n.denials = map[[2]int64]panel.PolicyDenial{}
		}
		key := [2]int64{user, denied.AuditID}
		if len(n.denials) < 16384 {
			if _, exists := n.denials[key]; !exists {
				n.denials[key] = panel.PolicyDenial{UserID: user, RuleID: denied.AuditID, Rule: denied.Rule, Target: target}
			}
		}
	} else if n.caps.AuditLogs && denied.AuditID != 0 && len(n.audits) < 16384 {
		n.audits[panel.AuditLog{UserID: user, AuditID: int(denied.AuditID)}] = true
	}
}

func (n *Node) observe() error {
	totals, err := n.counters()
	if err != nil {
		return err
	}
	return n.ledger.Observe(totals)
}

func (n *Node) counters() (map[int64]accounting.Counters, error) {
	totals := map[int64]accounting.Counters{}
	for _, server := range n.servers {
		for id, value := range server.TrafficSnapshot() {
			total := totals[id]
			if math.MaxUint64-total.Upload < value.Upload || math.MaxUint64-total.Download < value.Download {
				return nil, errors.New("traffic counter sum overflow")
			}
			total.Upload += value.Upload
			total.Download += value.Download
			totals[id] = total
		}
	}
	return totals, nil
}

// Push retries pending traffic until an explicit panel acknowledgement arrives.
func (n *Node) Push(ctx context.Context) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.pushLocked(ctx)
}

func (n *Node) pushLocked(ctx context.Context) error {
	if err := n.observe(); err != nil {
		return err
	}
	batch := n.ledger.Batch()
	if !n.closed && n.opts.Config.SubmitTrafficMinTraffic > 0 {
		threshold := uint64(n.opts.Config.SubmitTrafficMinTraffic * 1024)
		batch = slices.DeleteFunc(batch, func(item panel.Traffic) bool {
			return uint64(item.Upload)+uint64(item.Download) < threshold
		})
	}
	if len(batch) != 0 {
		if err := n.api.ReportTraffic(ctx, batch); err != nil {
			return err
		}
		if err := n.ledger.Acknowledge(batch); err != nil {
			return err
		}
	}
	current, err := n.counters()
	if err != nil {
		return err
	}
	if n.caps.AliveIPs {
		online := map[int64]map[string]bool{}
		for _, server := range n.servers {
			for id, ips := range server.OnlineSnapshot() {
				if online[id] == nil {
					online[id] = map[string]bool{}
				}
				for _, ip := range ips {
					online[id][ip] = true
				}
			}
		}
		items := make([]panel.AliveIP, 0, len(online))
		for id, ips := range online {
			before, after := n.lastOnline[id], current[id]
			period := uint64(0)
			if after.Upload >= before.Upload && after.Download >= before.Download {
				u, d := after.Upload-before.Upload, after.Download-before.Download
				if math.MaxUint64-u < d {
					period = math.MaxUint64
				} else {
					period = u + d
				}
			}
			if period < uint64(n.opts.Config.SubmitAliveIpMinTraffic*1024) {
				continue
			}
			item := panel.AliveIP{ID: id}
			for ip := range ips {
				item.IPs = append(item.IPs, ip)
			}
			slices.Sort(item.IPs)
			items = append(items, item)
		}
		slices.SortFunc(items, func(a, b panel.AliveIP) int {
			if a.ID < b.ID {
				return -1
			}
			if a.ID > b.ID {
				return 1
			}
			return 0
		})
		if err := n.api.ReportAliveIPs(ctx, items); err != nil {
			return err
		}
	}
	if reporter, ok := n.api.(panel.PolicyReporter); ok {
		n.auditMu.Lock()
		items := make([]panel.PolicyDenial, 0, len(n.denials))
		for _, item := range n.denials {
			items = append(items, item)
		}
		n.auditMu.Unlock()
		if len(items) > 0 {
			if err := reporter.ReportPolicyDenials(ctx, items); err != nil {
				return err
			}
			n.auditMu.Lock()
			for _, item := range items {
				delete(n.denials, [2]int64{item.UserID, item.RuleID})
			}
			n.auditMu.Unlock()
		}
	} else if n.caps.AuditLogs {
		n.auditMu.Lock()
		items := make([]panel.AuditLog, 0, len(n.audits))
		for item := range n.audits {
			items = append(items, item)
		}
		n.auditMu.Unlock()
		if len(items) != 0 {
			if err := n.api.ReportAuditLogs(ctx, items); err != nil {
				return err
			}
			n.auditMu.Lock()
			for _, item := range items {
				delete(n.audits, item)
			}
			n.auditMu.Unlock()
		}
	}
	if n.caps.Status {
		status, err := n.stats.Read("/")
		if err != nil {
			return err
		}
		if reporter, ok := n.api.(interface {
			ReportDJStatus(context.Context, panel.Status, map[string]json.RawMessage) error
		}); ok {
			extra, extraErr := n.stats.ReadDJExtras(status.Loads)
			if extraErr != nil {
				return extraErr
			}
			err = reporter.ReportDJStatus(ctx, status, extra)
		} else {
			err = n.api.ReportStatus(ctx, status)
		}
		if err != nil {
			return err
		}
	}
	n.lastOnline = current
	return nil
}

func (n *Node) AddressesLocked() []string {
	items := make([]string, 0, len(n.servers))
	for _, server := range n.servers {
		items = append(items, server.Addr())
	}
	return items
}

func (n *Node) Addresses() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.AddressesLocked()
}

func (n *Node) interval(pull bool) time.Duration {
	n.mu.Lock()
	defer n.mu.Unlock()
	seconds := n.opts.Config.SubmitInterval
	override := n.node.Basic.PushInterval
	if pull {
		seconds, override = n.opts.Config.CheckInterval, n.node.Basic.PullInterval
	}
	if override > 0 {
		seconds = int64(override)
	}
	jitter := min(n.opts.Config.RandomIntervalRange, seconds-1)
	if jitter > 0 {
		seconds += rand.Int64N(2*jitter+1) - jitter
	}
	return time.Duration(seconds) * time.Second
}

func (n *Node) loop() {
	defer close(n.done)
	pull, push := time.NewTimer(n.interval(true)), time.NewTimer(n.interval(false))
	remote := time.NewTicker(time.Minute)
	health := time.NewTicker(30 * time.Second)
	speed := time.NewTicker(time.Second)
	var geoTimer *time.Ticker
	var geoTick <-chan time.Time
	if n.opts.Config.GeoUpdateEnable {
		geoTimer = time.NewTicker(time.Duration(n.opts.Config.GeoUpdateInterval) * time.Hour)
		geoTick = geoTimer.C
		defer geoTimer.Stop()
	}
	defer pull.Stop()
	defer push.Stop()
	defer remote.Stop()
	defer health.Stop()
	defer speed.Stop()
	for {
		select {
		case <-n.ctx.Done():
			return
		case <-pull.C:
			if err := n.Sync(n.ctx); err != nil && n.ctx.Err() == nil {
				n.opts.Logger.Error("node synchronization failed", "node_id", n.opts.NodeID, "error", err)
			}
			pull.Reset(n.interval(true))
		case <-push.C:
			if err := n.Push(n.ctx); err != nil && n.ctx.Err() == nil {
				n.opts.Logger.Error("node report failed; pending traffic retained", "node_id", n.opts.NodeID, "error", err)
			}
			push.Reset(n.interval(false))
		case <-remote.C:
			if err := n.refreshRemote(n.ctx); err != nil && n.ctx.Err() == nil {
				n.opts.Logger.Error("remote configuration refresh failed", "node_id", n.opts.NodeID, "error", err)
			}
		case <-health.C:
			probeCtx, stop := context.WithTimeout(n.ctx, 15*time.Second)
			n.routes.Load().Probe(probeCtx)
			stop()
		case now := <-speed.C:
			if n.opts.Config.DyLimitEnable {
				n.mu.Lock()
				counters, err := n.counters()
				if err == nil {
					totals := make(map[int64]proxy.Traffic, len(counters))
					for id, value := range counters {
						totals[id] = proxy.Traffic{Upload: value.Upload, Download: value.Download}
					}
					err = n.dynamic.Observe(now, totals)
				}
				n.mu.Unlock()
				if err != nil {
					n.opts.Logger.Error("dynamic speed limit update failed", "error", err)
				}
			}
		case <-geoTick:
			if err := n.updateGeo(n.ctx); err != nil && n.ctx.Err() == nil {
				n.opts.Logger.Error("geodata update failed; active rules retained", "error", err)
			}
		}
	}
}

// Close stops listeners, captures final counters, and attempts one final report
// with the caller's separate timeout. Pending data survives report failures.
func (n *Node) Close(ctx context.Context) error {
	n.cancel()
	<-n.done
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed {
		return nil
	}
	n.closed = true
	var result error
	for _, server := range n.servers {
		result = errors.Join(result, server.Close())
	}
	result = errors.Join(result, n.pushLocked(ctx), n.access.Close(ctx))
	result = errors.Join(result, n.authCache.Close())
	if n.redis != nil {
		result = errors.Join(result, n.redis.Close())
	}
	if n.closeAPI != nil {
		result = errors.Join(result, n.closeAPI())
	}
	return result
}
