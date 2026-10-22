package policy

import (
	"cmp"
	"encoding/binary"
	"fmt"
	"math"
	"net/netip"
	"regexp"
	"slices"
	"strings"
)

// geositeKinds maps a V2Ray Domain.Type (Plain, Regex, RootDomain, Full) to
// the rule kind of the "kind:value" text a geosite entry once compiled to.
var geositeKinds = [...]string{"", "regexp", "domain", "full"}

// Flags of a name in siteMatcher.names.
const (
	nameFull   uint8 = 1
	nameSuffix uint8 = 2
)

// siteMatcher is a compiled geosite: rule. It matches exactly the targets
// that MatchAny matched over the former per-entry sub-rules, each compiled
// from geositeKinds[Kind]+":"+Value (Plain: Value alone).
//
// names maps a normalised value to nameFull (host == value) and/or
// nameSuffix (host == value or host ends with "."+value). keywords holds the
// lower-cased operands of plain entries, tested with strings.Contains, and
// regexps the compiled regex entries. all is set by a plain "*" entry;
// others holds plain entries whose value reads as an ip:, port: or node_id:
// rule, which match target fields other than the host.
type siteMatcher struct {
	all      bool
	names    map[string]uint8
	keywords []string
	regexps  []*regexp.Regexp
	others   []Rule
}

func (m *siteMatcher) match(t Target) bool {
	if m.all || len(m.others) != 0 && MatchAny(m.others, t) {
		return true
	}
	host := domain(t.Host)
	if len(m.names) != 0 {
		if m.names[host] != 0 {
			return true
		}
		// host ends with "."+v exactly when v follows one of its dots.
		for i := 0; i < len(host); i++ {
			if host[i] == '.' && m.names[host[i+1:]]&nameSuffix != 0 {
				return true
			}
		}
	}
	for _, keyword := range m.keywords {
		if strings.Contains(host, keyword) {
			return true
		}
	}
	for _, re := range m.regexps {
		if re.MatchString(host) {
			return true
		}
	}
	return false
}

type siteMatcherBuilder struct {
	matcher      siteMatcher
	seenKeywords map[string]bool
	seenRegexps  map[string]bool
}

func newSiteMatcher(entries []Domain, attribute string) (*siteMatcher, error) {
	var b siteMatcherBuilder
	for _, entry := range entries {
		if err := b.add(entry, attribute); err != nil {
			return nil, err
		}
	}
	return b.finish(), nil
}

// add classifies entry exactly as Compile classified its former sub-rule
// text and returns the error that compiling that text returned.
func (b *siteMatcherBuilder) add(entry Domain, attribute string) error {
	if attribute != "" && !entry.Attributes[attribute] {
		return nil
	}
	if entry.Kind >= uint64(len(geositeKinds)) {
		return fmt.Errorf("unknown geosite domain type %d", entry.Kind)
	}
	kind, arg := geositeKinds[entry.Kind], entry.Value
	if entry.Kind == 0 {
		// Plain: the text is the value itself, which may be "*" or carry a
		// recognised "kind:" prefix of its own.
		if entry.Value == "*" {
			b.matcher.all = true
			return nil
		}
		kind, arg = splitRule(entry.Value)
	}
	if arg == "" {
		return fmt.Errorf("empty rule operand: %q", geositeRuleText(entry))
	}
	switch kind {
	case "regexp":
		if b.seenRegexps[arg] {
			return nil
		}
		re, err := regexp.Compile(arg)
		if err != nil {
			return fmt.Errorf("rule %q: %w", geositeRuleText(entry), err)
		}
		if b.seenRegexps == nil {
			b.seenRegexps = map[string]bool{}
		}
		b.seenRegexps[arg] = true
		b.matcher.regexps = append(b.matcher.regexps, re)
	case "domain", "full":
		flag := nameFull
		if kind == "domain" {
			flag = nameSuffix
		}
		if b.matcher.names == nil {
			b.matcher.names = map[string]uint8{}
		}
		name := domain(arg)
		b.matcher.names[name] |= flag
	case "", "keyword":
		keyword := strings.ToLower(arg)
		if b.seenKeywords[keyword] {
			return nil
		}
		if b.seenKeywords == nil {
			b.seenKeywords = map[string]bool{}
		}
		b.seenKeywords[keyword] = true
		b.matcher.keywords = append(b.matcher.keywords, keyword)
	default:
		// Only a plain entry gets here (ip:, port:, node_id:, or geosite:
		// and geoip:, which fail without data): compile it as before.
		child, err := Compile(entry.Value, nil)
		if err != nil {
			return err
		}
		b.matcher.others = append(b.matcher.others, child)
	}
	return nil
}

func (b *siteMatcherBuilder) finish() *siteMatcher {
	m := b.matcher
	return &m
}

// geositeRuleText is the rule text an entry formerly compiled to.
func geositeRuleText(entry Domain) string {
	if entry.Kind == 0 {
		return entry.Value
	}
	return geositeKinds[entry.Kind] + ":" + entry.Value
}

// geoSiteMatcher returns the matcher of a lower-cased geosite category and
// attribute; found is false for a missing category. Matchers of *GeoData are
// memoised, other sources are compiled on every call.
func geoSiteMatcher(geo GeoSource, category, attribute string) (*siteMatcher, bool, error) {
	if g, ok := geo.(*GeoData); ok && g != nil {
		return g.memoSiteMatcher(category, attribute)
	}
	entries, found := geo.Domains(category)
	if !found {
		return nil, false, nil
	}
	m, err := newSiteMatcher(entries, attribute)
	return m, true, err
}

func (g *GeoData) memoSiteMatcher(category, attribute string) (*siteMatcher, bool, error) {
	key := strings.ToLower(category)
	g.mu.Lock()
	c := g.sites[key]
	var memo *siteMatcherMemo
	if c != nil {
		memo = c.matchers[attribute]
		if memo == nil {
			if c.matchers == nil {
				c.matchers = map[string]*siteMatcherMemo{}
			}
			memo = &siteMatcherMemo{}
			c.matchers[attribute] = memo
		}
	}
	g.mu.Unlock()
	if c == nil {
		return nil, false, nil
	}
	memo.once.Do(func() { memo.matcher, memo.err = c.compile(attribute) })
	return memo.matcher, true, memo.err
}

// compile builds the category's matcher straight from the raw entries, in
// the order Domains returns them, without materialising Domains.
func (c *siteCategory) compile(attribute string) (*siteMatcher, error) {
	var b siteMatcherBuilder
	for _, entry := range c.entries {
		for item, rest, ok := nextItem(entry); ok; item, rest, ok = nextItem(rest) {
			var d Domain
			if err := decodeDomain(item, &d); err != nil {
				return nil, err
			}
			if err := b.add(d, attribute); err != nil {
				return nil, err
			}
		}
	}
	return b.finish(), nil
}

// ipMatcher is a compiled geoip: rule: the category's prefixes as sorted,
// merged, disjoint address ranges per family, searched in O(log n).
type ipMatcher struct {
	v4      []v4Range
	v6      []v6Range
	inverse bool
}

type v4Range struct {
	first, last uint32
}

type u128 struct {
	hi, lo uint64
}

type v6Range struct {
	first, last u128
}

func (a u128) compare(b u128) int {
	if c := cmp.Compare(a.hi, b.hi); c != 0 {
		return c
	}
	return cmp.Compare(a.lo, b.lo)
}

func (a u128) less(b u128) bool { return a.compare(b) < 0 }

// next returns a+1, or false if a is the largest value.
func (a u128) next() (u128, bool) {
	if a.lo != math.MaxUint64 {
		a.lo++
		return a, true
	}
	if a.hi != math.MaxUint64 {
		a.hi++
		a.lo = 0
		return a, true
	}
	return u128{}, false
}

// match reports, like the former linear scan, whether some address of t
// (host literal first, then t.Addresses) is in the set, or for an inverse
// category is not.
func (m *ipMatcher) match(t Target) bool {
	if ip, ok := parseHostAddr(t.Host); ok && m.contains(ip) != m.inverse {
		return true
	}
	for _, ip := range t.Addresses {
		if m.contains(ip) != m.inverse {
			return true
		}
	}
	return false
}

// contains reports whether any prefix of the set contains ip.Unmap(), with
// netip.Prefix.Contains semantics: families never mix (IPv4-mapped IPv6
// prefixes therefore never match), and zoned or invalid addresses never
// match.
func (m *ipMatcher) contains(ip netip.Addr) bool {
	ip = ip.Unmap()
	if ip.Zone() != "" {
		return false
	}
	if ip.Is4() {
		a := ip.As4()
		return containsV4(m.v4, binary.BigEndian.Uint32(a[:]))
	}
	if ip.Is6() {
		a := ip.As16()
		x := u128{hi: binary.BigEndian.Uint64(a[:8]), lo: binary.BigEndian.Uint64(a[8:])}
		return containsV6(m.v6, x)
	}
	return false
}

func containsV4(ranges []v4Range, x uint32) bool {
	i, j := 0, len(ranges)
	for i < j {
		h := int(uint(i+j) >> 1)
		if ranges[h].last < x {
			i = h + 1
		} else {
			j = h
		}
	}
	return i < len(ranges) && ranges[i].first <= x
}

func containsV6(ranges []v6Range, x u128) bool {
	i, j := 0, len(ranges)
	for i < j {
		h := int(uint(i+j) >> 1)
		if ranges[h].last.less(x) {
			i = h + 1
		} else {
			j = h
		}
	}
	return i < len(ranges) && !x.less(ranges[i].first)
}

type ipSetBuilder struct {
	v4 []v4Range
	v6 []v6Range
}

func (b *ipSetBuilder) add(p netip.Prefix) {
	if !p.IsValid() {
		return // netip.Prefix.Contains is false for an invalid prefix
	}
	p = p.Masked()
	bits := p.Bits()
	addr := p.Addr()
	if addr.Is4() {
		a := addr.As4()
		first := binary.BigEndian.Uint32(a[:])
		mask := ^uint32(0) >> bits
		b.v4 = append(b.v4, v4Range{first: first, last: first | mask})
		return
	}
	a := addr.As16()
	first := u128{hi: binary.BigEndian.Uint64(a[:8]), lo: binary.BigEndian.Uint64(a[8:])}
	hiMask, loMask := ^uint64(0), ^uint64(0)
	if bits < 64 {
		hiMask >>= bits
	} else {
		hiMask = 0
		loMask >>= bits - 64
	}
	last := first
	last.hi |= hiMask
	last.lo |= loMask
	b.v6 = append(b.v6, v6Range{first: first, last: last})
}

func (b *ipSetBuilder) finish(inverse bool) *ipMatcher {
	return &ipMatcher{v4: mergeV4(b.v4), v6: mergeV6(b.v6), inverse: inverse}
}

// mergeV4 sorts ranges and merges overlapping or adjacent ones in place,
// returning an exactly sized copy.
func mergeV4(ranges []v4Range) []v4Range {
	if len(ranges) == 0 {
		return nil
	}
	slices.SortFunc(ranges, func(a, b v4Range) int { return cmp.Compare(a.first, b.first) })
	merged := ranges[:1]
	for _, r := range ranges[1:] {
		top := &merged[len(merged)-1]
		if top.last == math.MaxUint32 || r.first <= top.last+1 {
			top.last = max(top.last, r.last)
			continue
		}
		merged = append(merged, r)
	}
	return slices.Clone(merged)
}

func mergeV6(ranges []v6Range) []v6Range {
	if len(ranges) == 0 {
		return nil
	}
	slices.SortFunc(ranges, func(a, b v6Range) int { return a.first.compare(b.first) })
	merged := ranges[:1]
	for _, r := range ranges[1:] {
		top := &merged[len(merged)-1]
		if next, ok := top.last.next(); !ok || !next.less(r.first) {
			if top.last.less(r.last) {
				top.last = r.last
			}
			continue
		}
		merged = append(merged, r)
	}
	return slices.Clone(merged)
}

func newIPMatcher(prefixes []netip.Prefix, inverse bool) *ipMatcher {
	var b ipSetBuilder
	for _, p := range prefixes {
		b.add(p)
	}
	return b.finish(inverse)
}

// geoIPMatcher returns the matcher of a lower-cased geoip category; found is
// false for a missing category. Matchers of *GeoData are memoised, other
// sources are compiled on every call.
func geoIPMatcher(geo GeoSource, category string) (*ipMatcher, bool) {
	if g, ok := geo.(*GeoData); ok && g != nil {
		c := g.lookupIP(category)
		if c == nil {
			return nil, false
		}
		return c.compile(), true
	}
	prefixes, inverse, found := geo.Prefixes(category)
	if !found {
		return nil, false
	}
	return newIPMatcher(prefixes, inverse), true
}

// compile builds the category's matcher once, straight from the raw entry.
func (c *ipCategory) compile() *ipMatcher {
	c.matcherOnce.Do(func() {
		var b ipSetBuilder
		for item, rest, ok := nextItem(c.entry); ok; item, rest, ok = nextItem(rest) {
			if p, err := parseCIDR(item); err == nil {
				b.add(p)
			}
		}
		c.matcher = b.finish(c.inverse)
	})
	return c.matcher
}
