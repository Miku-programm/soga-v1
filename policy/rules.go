// Package policy implements the supplied documentation's destination rule grammar.
// This is a compatibility implementation, not recovered original source.
package policy

import (
	"bytes"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

type Target struct {
	Host         string
	Addresses    []netip.Addr
	Port         uint16
	Network      string
	NodeID       int64
	UserID       int64
	Unattributed bool
}

type Domain struct {
	Kind       uint64
	Value      string
	Attributes map[string]bool
}

// GeoSource must distinguish a missing category from an empty category.
type GeoSource interface {
	Domains(category string) ([]Domain, bool)
	Prefixes(category string) ([]netip.Prefix, bool, bool) // prefixes, inverse, found
}

type Rule struct {
	Text    string
	AuditID int64
	match   func(Target) bool
	packet  *regexp.Regexp
}

func (r Rule) Match(t Target) bool { return r.match(t) }

func Compile(text string, geo GeoSource) (Rule, error) {
	r := Rule{Text: text}
	arg := text
	kind := ""
	if i := strings.IndexByte(text, ':'); i >= 0 {
		switch text[:i] {
		case "regexp", "domain", "full", "keyword", "geosite", "ip", "geoip", "port", "node_id":
			kind, arg = text[:i], text[i+1:]
		}
	}
	if text == "*" {
		r.match = func(Target) bool { return true }
		return r, nil
	}
	if arg == "" {
		return Rule{}, fmt.Errorf("empty rule operand: %q", text)
	}
	switch kind {
	case "regexp":
		re, err := regexp.Compile(arg)
		if err != nil {
			return Rule{}, fmt.Errorf("rule %q: %w", text, err)
		}
		r.match = func(t Target) bool { return re.MatchString(domain(t.Host)) }
		r.packet = re
	case "domain", "full":
		arg = domain(arg)
		r.match = func(t Target) bool {
			host := domain(t.Host)
			return host == arg || (kind == "domain" && strings.HasSuffix(host, "."+arg))
		}
	case "ip":
		prefix, err := parsePrefix(arg)
		if err != nil {
			return Rule{}, fmt.Errorf("rule %q: %w", text, err)
		}
		r.match = func(t Target) bool {
			for _, ip := range addresses(t) {
				if prefix.Contains(ip.Unmap()) {
					return true
				}
			}
			return false
		}
	case "port":
		var ranges [][2]uint64
		for _, item := range strings.Split(arg, ",") {
			a, b, split := strings.Cut(strings.TrimSpace(item), "-")
			low, err := strconv.ParseUint(a, 10, 16)
			if err != nil || low == 0 {
				return Rule{}, fmt.Errorf("invalid port rule %q", text)
			}
			high := low
			if split {
				high, err = strconv.ParseUint(b, 10, 16)
				if err != nil || high < low {
					return Rule{}, fmt.Errorf("invalid port range %q", text)
				}
			}
			ranges = append(ranges, [2]uint64{low, high})
		}
		r.match = func(t Target) bool {
			for _, item := range ranges {
				if uint64(t.Port) >= item[0] && uint64(t.Port) <= item[1] {
					return true
				}
			}
			return false
		}
	case "node_id":
		ids := map[int64]bool{}
		for _, item := range strings.Split(arg, ",") {
			id, err := strconv.ParseInt(strings.TrimSpace(item), 10, 64)
			if err != nil {
				return Rule{}, fmt.Errorf("invalid node rule %q", text)
			}
			ids[id] = true
		}
		r.match = func(t Target) bool { return ids[t.NodeID] }
	case "geosite":
		category, attribute, _ := strings.Cut(strings.ToLower(arg), "@")
		if geo == nil {
			return Rule{}, fmt.Errorf("rule %q requires geosite data", text)
		}
		entries, found := geo.Domains(category)
		if !found {
			return Rule{}, fmt.Errorf("geosite category %q not found", category)
		}
		var sub []Rule
		for _, entry := range entries {
			if attribute != "" && !entry.Attributes[attribute] {
				continue
			}
			prefixes := []string{"", "regexp:", "domain:", "full:"}
			if entry.Kind > 3 {
				return Rule{}, fmt.Errorf("unknown geosite domain type %d", entry.Kind)
			}
			child, err := Compile(prefixes[entry.Kind]+entry.Value, nil)
			if err != nil {
				return Rule{}, err
			}
			sub = append(sub, child)
		}
		r.match = func(t Target) bool { return MatchAny(sub, t) }
	case "geoip":
		if geo == nil {
			return Rule{}, fmt.Errorf("rule %q requires geoip data", text)
		}
		prefixes, inverse, found := geo.Prefixes(strings.ToLower(arg))
		if !found {
			return Rule{}, fmt.Errorf("geoip category %q not found", arg)
		}
		r.match = func(t Target) bool {
			ips := addresses(t)
			for _, ip := range ips {
				found := false
				for _, prefix := range prefixes {
					if prefix.Contains(ip.Unmap()) {
						found = true
						break
					}
				}
				if found != inverse {
					return true
				}
			}
			return false
		}
	default:
		arg = strings.ToLower(arg)
		r.match = func(t Target) bool { return strings.Contains(domain(t.Host), arg) }
	}
	return r, nil
}

func CompileAll(texts []string, geo GeoSource) ([]Rule, error) {
	result := make([]Rule, 0, len(texts))
	for _, text := range texts {
		r, err := Compile(text, geo)
		if err != nil {
			return nil, err
		}
		result = append(result, r)
	}
	return result, nil
}

func MatchAny(rules []Rule, t Target) bool {
	for _, r := range rules {
		if r.Match(t) {
			return true
		}
	}
	return false
}

func domain(s string) string { return strings.ToLower(strings.TrimSuffix(s, ".")) }
func addresses(t Target) []netip.Addr {
	if ip, err := netip.ParseAddr(t.Host); err == nil {
		return append([]netip.Addr{ip}, t.Addresses...)
	}
	return t.Addresses
}
func parsePrefix(text string) (netip.Prefix, error) {
	if ip, err := netip.ParseAddr(text); err == nil {
		ip = ip.Unmap()
		return netip.PrefixFrom(ip, ip.BitLen()), nil
	}
	p, err := netip.ParsePrefix(text)
	if err != nil {
		return netip.Prefix{}, err
	}
	return p.Masked(), nil
}

type Denied struct {
	Rule    string
	AuditID int64
}

func (e *Denied) Error() string { return "destination denied by rule " + e.Rule }

type Policy struct {
	White, Block     []Rule
	Allowed          []Rule
	AllowOnly        bool
	ExemptUsers      map[int64]bool
	BanPrivate       bool
	DetectPacket     bool
	ForbidBitTorrent bool
}

func (p *Policy) CheckPacket(t Target, data []byte) error {
	if p == nil || len(data) == 0 || (!t.Unattributed && p.ExemptUsers[t.UserID]) || MatchAny(p.White, t) {
		return nil
	}
	if p.ForbidBitTorrent && bytes.Contains(data, []byte("\x13BitTorrent protocol")) {
		return &Denied{Rule: "forbidden_bit_torrent"}
	}
	if p.DetectPacket {
		for _, rule := range p.Block {
			if rule.packet != nil && rule.packet.Match(data) {
				return &Denied{rule.Text, rule.AuditID}
			}
		}
	}
	return nil
}

func (p *Policy) Check(t Target) error {
	if p == nil || (!t.Unattributed && p.ExemptUsers[t.UserID]) || MatchAny(p.White, t) {
		return nil
	}
	for _, rule := range p.Block {
		if rule.Match(t) {
			return &Denied{rule.Text, rule.AuditID}
		}
	}
	if p.AllowOnly && !MatchAny(p.Allowed, t) {
		return &Denied{Rule: "panel_allow_list"}
	}
	return p.checkPrivate(t)
}

// CheckSniffed checks a destination whose name was also sniffed from the
// client's TLS SNI, HTTP Host or QUIC handshake. The sniffed name is chosen by
// the client and need not belong to the address actually dialled, so it can
// only add denials: block rules apply to both the real destination and the
// sniffed name, and a whitelist entry matching only the sniffed name exempts
// neither the real destination's block rules nor ban_private_ip. The panel
// allow list accepts either name, because an IP destination can only be
// associated with a domain through sniffing.
func (p *Policy) CheckSniffed(actual Target, sniffed string) error {
	if sniffed == "" || domain(sniffed) == domain(actual.Host) {
		return p.Check(actual)
	}
	if p == nil || (!actual.Unattributed && p.ExemptUsers[actual.UserID]) || MatchAny(p.White, actual) {
		return nil
	}
	view := actual
	view.Host = sniffed
	sniffedWhite := MatchAny(p.White, view)
	for _, rule := range p.Block {
		if rule.Match(actual) || (!sniffedWhite && rule.Match(view)) {
			return &Denied{rule.Text, rule.AuditID}
		}
	}
	if p.AllowOnly && !MatchAny(p.Allowed, actual) && !MatchAny(p.Allowed, view) {
		return &Denied{Rule: "panel_allow_list"}
	}
	return p.checkPrivate(actual)
}

func (p *Policy) checkPrivate(t Target) error {
	if !p.BanPrivate {
		return nil
	}
	for _, ip := range addresses(t) {
		if privateAddress(ip) {
			return &Denied{Rule: "ban_private_ip"}
		}
	}
	return nil
}

// Ranges that are not publicly routable but are missed by netip's predicates.
// 100.64.0.0/10 also hosts cloud metadata services such as 100.100.100.200.
var reservedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
}

var nat64Prefix = netip.MustParsePrefix("64:ff9b::/96")

func privateAddress(ip netip.Addr) bool {
	ip = ip.Unmap()
	if nat64Prefix.Contains(ip) {
		// Well-known NAT64 translates the embedded IPv4 address.
		b := ip.As16()
		ip = netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]})
	}
	if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() ||
		ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	for _, prefix := range reservedPrefixes {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}
