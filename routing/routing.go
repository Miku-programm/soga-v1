// Package routing implements ordered document routes and outbound selection.
package routing

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash/fnv"
	"math/rand/v2"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/pelletier/go-toml/v2"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	"reconstructed.local/soga/policy"
	"reconstructed.local/soga/proxy/ssrcore"
)

type Document struct {
	Enable bool    `toml:"enable"`
	Routes []Route `toml:"routes"`
}
type Route struct {
	Rules       []string `toml:"rules"`
	Protocol    string   `toml:"protocol"`
	Balance     string   `toml:"balance"`
	HealthCheck *bool    `toml:"health_check"`
	Outs        []Out    `toml:"Outs"`
}
type Out struct {
	Listen         string `toml:"listen"`
	ListenIPv4     string `toml:"listen_ipv4"`
	ListenIPv6     string `toml:"listen_ipv6"`
	ListenStrategy string `toml:"listen_strategy"`
	Type           string `toml:"type"`
	Server         string `toml:"server"`
	Port           int    `toml:"port"`
	Username       string `toml:"username"`
	Password       string `toml:"password"`
	UUID           string `toml:"uuid"`
	AlterID        int    `toml:"alter_id"`
	Network        string `toml:"network"`
	WSPath         string `toml:"ws_path"`
	TLS            bool   `toml:"tls"`
	SNI            string `toml:"sni"`
	SkipCertVerify bool   `toml:"skip_cert_verify"`
	Cipher         string `toml:"cipher"`
	Obfs           string `toml:"obfs"`
	ObfsParam      string `toml:"obfs_param"`
	Protocol       string `toml:"protocol"`
	ProtocolParam  string `toml:"protocol_param"`
}
type compiledRoute struct {
	rules    []policy.Rule
	tcp, udp bool
	balance  string
	health   bool
	next     atomic.Uint64
	outs     []*outbound
}
type outbound struct {
	tag    string
	config Out
	alive  atomic.Bool
}
type Router struct {
	enabled   bool
	routes    []*compiledRoute
	outbounds []option.Outbound
}
type Selection struct {
	Tag          string
	RedirectHost string
	RedirectPort uint16
	Family       string
}

func New(data []byte, geo policy.GeoSource) (*Router, error) {
	var doc Document
	if err := toml.NewDecoder(bytes.NewReader(data)).DisallowUnknownFields().Decode(&doc); err != nil {
		return nil, err
	}
	r := &Router{enabled: doc.Enable}
	if !doc.Enable {
		return r, nil
	}
	if len(doc.Routes) == 0 {
		return nil, errors.New("enabled routing requires at least one route")
	}
	digest := sha256.Sum256(data)
	for i, raw := range doc.Routes {
		c := &compiledRoute{balance: raw.Balance, health: raw.HealthCheck == nil || *raw.HealthCheck}
		if c.balance == "" {
			c.balance = "random"
		}
		switch c.balance {
		case "random", "round_robin", "ip_hash", "user_id_hash":
		default:
			return nil, fmt.Errorf("unknown balance %q", c.balance)
		}
		if raw.Protocol == "" {
			c.tcp, c.udp = true, true
		} else {
			for _, p := range strings.Split(raw.Protocol, ",") {
				switch strings.TrimSpace(p) {
				case "tcp":
					c.tcp = true
				case "udp":
					c.udp = true
				default:
					return nil, fmt.Errorf("invalid route protocol %q", p)
				}
			}
		}
		if len(raw.Rules) == 0 && raw.Protocol != "" {
			raw.Rules = []string{"*"}
		}
		var err error
		c.rules, err = policy.CompileAll(raw.Rules, geo)
		if err != nil {
			return nil, err
		}
		if len(raw.Outs) == 0 {
			return nil, fmt.Errorf("route %d has no outbounds", i+1)
		}
		for j, o := range raw.Outs {
			tag := fmt.Sprintf("route-%x-%d-%d", digest[:6], i, j)
			opts, err := makeOutbound(tag, o)
			if err != nil {
				return nil, fmt.Errorf("route %d outbound %d: %w", i+1, j+1, err)
			}
			item := &outbound{tag: tag, config: o}
			item.alive.Store(true)
			c.outs = append(c.outs, item)
			r.outbounds = append(r.outbounds, opts)
		}
		r.routes = append(r.routes, c)
	}
	return r, nil
}
func (r *Router) Outbounds() []option.Outbound { return append([]option.Outbound(nil), r.outbounds...) }

func (r *Router) Select(target policy.Target, source string) (Selection, error) {
	if r == nil || !r.enabled {
		return Selection{}, nil
	}
	for _, route := range r.routes {
		if target.Network == "tcp" && !route.tcp || target.Network == "udp" && !route.udp {
			continue
		}
		if !policy.MatchAny(route.rules, target) {
			continue
		}
		var available []*outbound
		for _, o := range route.outs {
			if !route.health || o.alive.Load() {
				available = append(available, o)
			}
		}
		if len(available) == 0 {
			return Selection{}, errors.New("matched route has no healthy outbounds")
		}
		var index uint64
		switch route.balance {
		case "random":
			index = rand.Uint64N(uint64(len(available)))
		case "round_robin":
			index = route.next.Add(1) - 1
		case "user_id_hash":
			h := fnv.New64a()
			_, _ = h.Write([]byte(strconv.FormatInt(target.UserID, 10)))
			index = h.Sum64()
		case "ip_hash":
			ip, _, err := net.SplitHostPort(source)
			if err != nil {
				ip = source
			}
			h := fnv.New64a()
			_, _ = h.Write([]byte(ip))
			index = h.Sum64()
		}
		o := available[index%uint64(len(available))]
		if target.Network == "udp" && o.config.Type == "http" {
			return Selection{}, errors.New("HTTP CONNECT outbound does not support UDP")
		}
		s := Selection{Tag: o.tag, Family: o.config.ListenStrategy}
		v4, v6 := o.config.ListenIPv4, o.config.ListenIPv6
		if o.config.Listen != "" {
			ip, _ := netip.ParseAddr(o.config.Listen)
			if ip.Is4() && v4 == "" {
				v4 = ip.String()
			} else if ip.Is6() && v6 == "" {
				v6 = ip.String()
			}
		}
		if v4 != "" && v6 == "" {
			s.Family = "ipv4_only"
		} else if v6 != "" && v4 == "" {
			s.Family = "ipv6_only"
		}
		if o.config.Type == "redirect" {
			s.RedirectHost = o.config.Server
			s.RedirectPort = uint16(o.config.Port)
		}
		return s, nil
	}
	return Selection{}, errors.New("no route matches destination")
}

// Probe refreshes upstream socket reachability; it is not a credential or
// destination-service check. Calls are bounded and do not send user traffic.
func (r *Router) Probe(ctx context.Context) {
	if r == nil {
		return
	}
	for _, route := range r.routes {
		if !route.health {
			continue
		}
		for _, o := range route.outs {
			if o.config.Type == "direct" || o.config.Type == "redirect" {
				continue
			}
			dialer := net.Dialer{Timeout: 2 * time.Second}
			c, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(o.config.Server, strconv.Itoa(o.config.Port)))
			o.alive.Store(err == nil)
			if c != nil {
				_ = c.Close()
			}
			if ctx.Err() != nil {
				return
			}
		}
	}
}

func makeOutbound(tag string, o Out) (option.Outbound, error) {
	bind, err := dialer(o)
	if err != nil {
		return option.Outbound{}, err
	}
	kind := o.Type
	if kind == "ss" {
		kind = "shadowsocks"
	}
	if kind != "direct" {
		if o.Server == "" || o.Port < 0 || o.Port > 65535 || o.Port == 0 && kind != "redirect" {
			return option.Outbound{}, errors.New("outbound requires a valid server and port")
		}
	}
	server := option.ServerOptions{Server: o.Server, ServerPort: uint16(o.Port)}
	tls := option.OutboundTLSOptionsContainer{}
	if o.TLS || kind == "trojan" {
		tls.TLS = &option.OutboundTLSOptions{Enabled: true, ServerName: o.SNI, Insecure: o.SkipCertVerify}
	}
	var opts any
	switch kind {
	case "direct", "redirect":
		kind = "direct"
		opts = &option.DirectOutboundOptions{DialerOptions: bind}
	case "socks":
		opts = &option.SOCKSOutboundOptions{DialerOptions: bind, ServerOptions: server, Version: "5", Username: o.Username, Password: o.Password}
	case "http":
		opts = &option.HTTPOutboundOptions{DialerOptions: bind, ServerOptions: server, Username: o.Username, Password: o.Password, OutboundTLSOptionsContainer: tls}
	case "trojan":
		opts = &option.TrojanOutboundOptions{DialerOptions: bind, ServerOptions: server, Password: o.Password, OutboundTLSOptionsContainer: tls}
	case "shadowsocks":
		if o.Obfs != "" && o.Obfs != "plain" {
			return option.Outbound{}, errors.New("Shadowsocks outbound plugins are not in the supplied route contract")
		}
		opts = &option.ShadowsocksOutboundOptions{DialerOptions: bind, ServerOptions: server, Method: o.Cipher, Password: o.Password}
	case "vmess":
		v := &option.VMessOutboundOptions{DialerOptions: bind, ServerOptions: server, UUID: o.UUID, AlterId: o.AlterID, Security: "auto", OutboundTLSOptionsContainer: tls}
		switch o.Network {
		case "", "tcp":
		case "ws":
			v.Transport = &option.V2RayTransportOptions{Type: "ws", WebsocketOptions: option.V2RayWebsocketOptions{Path: o.WSPath}}
		case "http", "h2":
			v.Transport = &option.V2RayTransportOptions{Type: "http", HTTPOptions: option.V2RayHTTPOptions{Path: o.WSPath}}
		case "grpc":
			v.Transport = &option.V2RayTransportOptions{Type: "grpc", GRPCOptions: option.V2RayGRPCOptions{ServiceName: o.WSPath}}
		default:
			return option.Outbound{}, fmt.Errorf("unsupported VMess outbound transport %q", o.Network)
		}
		opts = v
	case "ssr":
		opts = &ssrcore.OutboundOptions{DialerOptions: bind, Server: o.Server, ServerPort: uint16(o.Port),
			Method: o.Cipher, Password: o.Password, Protocol: o.Protocol, Obfs: o.Obfs,
			ProtocolParam: o.ProtocolParam, ObfsParam: o.ObfsParam}
	default:
		return option.Outbound{}, fmt.Errorf("unsupported outbound %q", kind)
	}
	return option.Outbound{Type: kind, Tag: tag, Options: opts}, nil
}
func dialer(o Out) (option.DialerOptions, error) {
	if o.ListenStrategy != "" && o.ListenStrategy != "ipv4_first" && o.ListenStrategy != "ipv6_first" {
		return option.DialerOptions{}, errors.New("invalid listen_strategy")
	}
	v4, v6 := o.ListenIPv4, o.ListenIPv6
	if o.Listen != "" {
		ip, err := netip.ParseAddr(o.Listen)
		if err != nil {
			return option.DialerOptions{}, err
		}
		if ip.Is4() && v4 == "" {
			v4 = ip.String()
		} else if ip.Is6() && v6 == "" {
			v6 = ip.String()
		}
	}
	var result option.DialerOptions
	for _, item := range []struct {
		value string
		four  bool
	}{{v4, true}, {v6, false}} {
		if item.value == "" {
			continue
		}
		ip, err := netip.ParseAddr(item.value)
		if err != nil || ip.Is4() != item.four {
			return result, errors.New("outbound bind address has wrong family")
		}
		b := badoption.Addr(ip)
		if item.four {
			result.Inet4BindAddress = &b
		} else {
			result.Inet6BindAddress = &b
		}
	}
	return result, nil
}
