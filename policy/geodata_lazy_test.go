package policy

import (
	"encoding/binary"
	"errors"
	"fmt"
	"maps"
	"math/rand/v2"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
)

// Protobuf encoders for synthetic GeoSiteList / GeoIPList data.

func pbBytes(dst []byte, number uint64, payload []byte) []byte {
	dst = binary.AppendUvarint(dst, number<<3|2)
	dst = binary.AppendUvarint(dst, uint64(len(payload)))
	return append(dst, payload...)
}

func pbVarint(dst []byte, number, value uint64) []byte {
	dst = binary.AppendUvarint(dst, number<<3)
	return binary.AppendUvarint(dst, value)
}

func pbFixed32(dst []byte, number uint64) []byte {
	dst = binary.AppendUvarint(dst, number<<3|5)
	return append(dst, 1, 2, 3, 4)
}

func pbFixed64(dst []byte, number uint64) []byte {
	dst = binary.AppendUvarint(dst, number<<3|1)
	return append(dst, 1, 2, 3, 4, 5, 6, 7, 8)
}

// testAttr encodes a Domain.Attribute; field 2 is bool_value, 3 int_value.
func testAttr(key string, field, value uint64) []byte {
	return pbVarint(pbBytes(nil, 1, []byte(key)), field, value)
}

func testDomain(kind uint64, value string, attrs ...[]byte) []byte {
	b := pbVarint(nil, 1, kind)
	b = pbBytes(b, 2, []byte(value))
	for _, attr := range attrs {
		b = pbBytes(b, 3, attr)
	}
	return b
}

func testEntry(name string, items ...[]byte) []byte {
	b := pbBytes(nil, 1, []byte(name))
	for _, item := range items {
		b = pbBytes(b, 2, item)
	}
	return b
}

func testCIDR(prefix string) []byte {
	p := netip.MustParsePrefix(prefix)
	b := pbBytes(nil, 1, p.Addr().AsSlice())
	return pbVarint(b, 2, uint64(p.Bits()))
}

func testIPEntry(name string, inverse bool, prefixes ...string) []byte {
	b := pbBytes(nil, 1, []byte(name))
	for _, p := range prefixes {
		b = pbBytes(b, 2, testCIDR(p))
	}
	if inverse {
		b = pbVarint(b, 3, 1)
	}
	return b
}

func testList(entries ...[]byte) []byte {
	var b []byte
	for _, entry := range entries {
		b = pbBytes(b, 1, entry)
	}
	return b
}

func testGeoSite() []byte {
	ads := testAttr("ads", 2, 1)
	list := testList(
		testEntry("Mix",
			testDomain(2, "example.com"),
			testDomain(2, "Upper.Example.ORG."),
			testDomain(3, "full.test"),
			testDomain(3, "Exact.Example.Net"),
			testDomain(0, "keyword"),
			testDomain(0, "KeyWord2"),
			testDomain(1, `^re[0-9]+\.test$`),
			testDomain(1, `(?i)^CaSe\.test$`),
			testDomain(1, `^re[0-9]+\.test$`),
			testDomain(2, "ads.test", ads),
			testDomain(3, "cn.only.test", testAttr("CN", 3, 5), ads),
			testDomain(3, "notads.test", testAttr("ads", 2, 0)),
			testDomain(2, "both.test"),
			testDomain(3, "both.test"),
			testDomain(0, "full:PlainFull.test"),
			testDomain(0, "domain:plaindomain.test."),
			testDomain(0, "regexp:^plainre"),
			testDomain(0, "keyword:KW3"),
			testDomain(0, "Regexp:x"),
			testDomain(0, ":colon"),
			testDomain(0, "port:8443", ads),
			testDomain(0, "ip:198.51.100.0/24"),
			testDomain(0, "node_id:7"),
			testDomain(1, "^dup$", ads),
			append(testDomain(3, "v.test"), pbFixed64(nil, 7)...),
		),
		testEntry("edge", testDomain(2, "."), testDomain(3, "x..")),
		testEntry("star", testDomain(2, "never.test"), testDomain(0, "*")),
		testEntry("dup", testDomain(3, "first.test")),
		testEntry("empty"),
		testEntry("badkind", testDomain(2, "ok.test", testAttr("y", 2, 1)), testDomain(5, "weird", testAttr("x", 2, 1))),
		testEntry("badre", testDomain(1, "[")),
		testEntry("emptyop", testDomain(0, "")),
		testEntry("emptydomain", testDomain(2, "")),
		testEntry("emptykeyword", testDomain(0, "keyword:")),
		testEntry("geochild", testDomain(0, "geosite:foo")),
		testEntry("geoipchild", testDomain(0, "geoip:cn")),
		testEntry("badport", testDomain(0, "port:0")),
		append(testEntry("unknown", testDomain(3, "u.test")), pbFixed32(nil, 9)...),
		testEntry("DUP", testDomain(3, "second.test"), testDomain(2, "first.test")),
	)
	return append(list, pbVarint(nil, 2, 5)...) // unknown top-level field
}

func testGeoIP() []byte {
	return testList(
		testIPEntry("V4", false, "10.0.0.0/8", "192.0.2.0/24", "192.0.2.128/25", "198.51.100.0/25",
			"198.51.100.128/25", "203.0.113.7/32", "10.1.2.3/8", "255.255.255.255/32", "0.0.0.0/32",
			"::ffff:192.0.2.0/120"),
		testIPEntry("v6", false, "2001:db8::/32", "2001:db8:1::/48", "fe80::/10", "::/128",
			"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128", "2001:db9::/33", "2001:db9:8000::/33", "64:ff9b::/96"),
		testIPEntry("inv", true, "10.0.0.0/8", "2001:db8::/32"),
		testIPEntry("all", false, "0.0.0.0/0", "::/0"),
		testIPEntry("dup", false, "192.0.2.0/24"),
		testIPEntry("DUP", true, "198.51.100.0/24"),
		testIPEntry("none", true),
	)
}

var testHosts = []string{"", ".", "..", "example.com", "a.example.com", "EXAMPLE.COM.", "a.b.example.com",
	"badexample.com", "example.com.evil", "example.co", "upper.example.org", "x.UPPER.example.org.",
	"full.test", "a.full.test", "FULL.TEST.", "exact.example.net", "sub.exact.example.net",
	"haskeywordinside.io", "keyword2.x", "KEYWORD2.X", "keywor", "re12.test", "re.test", "re1.test.x",
	"case.test", "CASE.TEST", "xcase.test", "ads.test", "x.ads.test", "cn.only.test", "x.cn.only.test",
	"notads.test", "both.test", "x.both.test", "plainfull.test", "x.plainfull.test", "plaindomain.test",
	"y.plaindomain.test", "plainrest", "xplainre", "kw3.com", "regexp:x", "a:colon", "dup", "x.dup",
	"x..", "x.", "y.x..", "first.test", "a.first.test", "second.test", "never.test", "ok.test", "u.test",
	"v.test", "198.51.100.7", "localhost"}

var testAddrs = []string{"10.0.0.1", "10.255.255.255", "11.0.0.0", "9.255.255.255", "192.0.2.1",
	"192.0.2.200", "192.0.3.0", "198.51.100.127", "198.51.100.128", "198.51.100.255", "198.51.101.0",
	"203.0.113.7", "203.0.113.8", "203.0.113.6", "255.255.255.255", "255.255.255.254", "0.0.0.0",
	"0.0.0.1", "::ffff:10.0.0.1", "::ffff:192.0.2.5", "2001:db8::1", "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff",
	"2001:db9::1", "2001:db9:8000::1", "2001:db9:ffff::1", "2001:dba::", "2001:db7:ffff:ffff:ffff:ffff:ffff:ffff",
	"fe80::1", "fe80::1%eth0", "febf:ffff::1", "fec0::", "::", "::1", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
	"ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe", "64:ff9b::c000:201", "1.2.3.4"}

func testTargets() []Target {
	var targets []Target
	other := netip.MustParseAddr("198.51.100.9")
	for _, host := range testHosts {
		targets = append(targets, Target{Host: host}, Target{Host: host, Port: 8443}, Target{Host: host, NodeID: 7},
			Target{Host: host, Addresses: []netip.Addr{other}})
	}
	for _, a := range testAddrs {
		ip := netip.MustParseAddr(a)
		targets = append(targets, Target{Host: a}, Target{Host: "name.test", Addresses: []netip.Addr{ip}})
		for _, b := range testAddrs {
			targets = append(targets, Target{Host: a, Addresses: []netip.Addr{netip.MustParseAddr(b)}})
		}
	}
	return append(targets, Target{}, Target{Addresses: []netip.Addr{{}}}, Target{Host: "not-an-ip"})
}

// The former eager decoder, kept verbatim as the reference.

type refGeoIP struct {
	prefixes []netip.Prefix
	inverse  bool
}

type refGeoData struct {
	sites map[string][]Domain
	ips   map[string]refGeoIP
}

func refParseGeoData(site, ip []byte) (*refGeoData, error) {
	g := &refGeoData{sites: map[string][]Domain{}, ips: map[string]refGeoIP{}}
	if len(site) > 256<<20 || len(ip) > 256<<20 {
		return nil, errors.New("geodata exceeds 256 MiB")
	}
	if err := g.parse(site, true); err != nil {
		return nil, fmt.Errorf("geosite: %w", err)
	}
	if err := g.parse(ip, false); err != nil {
		return nil, fmt.Errorf("geoip: %w", err)
	}
	if len(site) > 0 && len(g.sites) == 0 || len(ip) > 0 && len(g.ips) == 0 {
		return nil, errors.New("geodata contains no categories")
	}
	return g, nil
}

func refWireFields(data []byte, consume func(wireField) error) error {
	for len(data) != 0 {
		tag, n := binary.Uvarint(data)
		if n <= 0 || tag>>3 == 0 {
			return errors.New("invalid protobuf tag")
		}
		data = data[n:]
		field := wireField{number: tag >> 3, wire: tag & 7}
		switch field.wire {
		case 0:
			field.value, n = binary.Uvarint(data)
			if n <= 0 {
				return errors.New("invalid protobuf varint")
			}
			data = data[n:]
		case 1:
			if len(data) < 8 {
				return errors.New("truncated protobuf fixed64")
			}
			data = data[8:]
		case 2:
			length, n := binary.Uvarint(data)
			if n <= 0 || length > uint64(len(data)-n) {
				return errors.New("invalid protobuf length")
			}
			field.bytes = data[n : n+int(length)]
			data = data[n+int(length):]
		case 5:
			if len(data) < 4 {
				return errors.New("truncated protobuf fixed32")
			}
			data = data[4:]
		default:
			return fmt.Errorf("unsupported protobuf wire type %d", field.wire)
		}
		if err := consume(field); err != nil {
			return err
		}
	}
	return nil
}

func (g *refGeoData) parse(data []byte, sites bool) error {
	return refWireFields(data, func(entry wireField) error {
		if entry.number != 1 {
			return nil
		}
		if entry.wire != 2 {
			return errors.New("invalid geodata entry wire type")
		}
		var category string
		var domains []Domain
		var ip refGeoIP
		err := refWireFields(entry.bytes, func(field wireField) error {
			switch field.number {
			case 1:
				if field.wire != 2 {
					return errors.New("invalid category wire type")
				}
				category = strings.ToLower(string(field.bytes))
			case 2:
				if field.wire != 2 {
					return errors.New("invalid geodata item wire type")
				}
				if sites {
					d, err := refParseDomain(field.bytes)
					if err != nil {
						return err
					}
					domains = append(domains, d)
				} else {
					p, err := refParseCIDR(field.bytes)
					if err != nil {
						return err
					}
					ip.prefixes = append(ip.prefixes, p)
				}
			case 3:
				if !sites {
					if field.wire != 0 {
						return errors.New("invalid inverse_match wire type")
					}
					ip.inverse = field.value != 0
				}
			}
			return nil
		})
		if err != nil {
			return err
		}
		if category == "" {
			return errors.New("empty geodata category")
		}
		if sites {
			g.sites[category] = append(g.sites[category], domains...)
		} else {
			g.ips[category] = ip
		}
		return nil
	})
}

func refParseDomain(data []byte) (Domain, error) {
	d := Domain{Attributes: map[string]bool{}}
	err := refWireFields(data, func(f wireField) error {
		switch f.number {
		case 1:
			if f.wire != 0 {
				return errors.New("invalid domain kind wire type")
			}
			d.Kind = f.value
		case 2:
			if f.wire != 2 {
				return errors.New("invalid domain value wire type")
			}
			d.Value = string(f.bytes)
		case 3:
			if f.wire != 2 {
				return errors.New("invalid domain attribute wire type")
			}
			var key string
			value := false
			if err := refWireFields(f.bytes, func(a wireField) error {
				if a.number == 1 {
					key = strings.ToLower(string(a.bytes))
				} else if a.number == 2 || a.number == 3 {
					value = a.value != 0
				}
				return nil
			}); err != nil {
				return err
			}
			d.Attributes[key] = value
		}
		return nil
	})
	return d, err
}

func refParseCIDR(data []byte) (netip.Prefix, error) {
	var raw []byte
	var bits uint64
	err := refWireFields(data, func(f wireField) error {
		if f.number == 1 {
			if f.wire != 2 {
				return errors.New("invalid CIDR address wire type")
			}
			raw = f.bytes
		} else if f.number == 2 {
			if f.wire != 0 {
				return errors.New("invalid CIDR prefix wire type")
			}
			bits = f.value
		}
		return nil
	})
	if err != nil {
		return netip.Prefix{}, err
	}
	ip, ok := netip.AddrFromSlice(raw)
	if !ok || bits > uint64(ip.BitLen()) {
		return netip.Prefix{}, errors.New("invalid geodata CIDR")
	}
	return netip.PrefixFrom(ip, int(bits)).Masked(), nil
}

// refCompile is the former Compile of geosite: and geoip: rules: one
// sub-rule per entry under MatchAny, and a linear prefix scan.
func refCompile(text string, ref *refGeoData) (func(Target) bool, error) {
	kind, arg, _ := strings.Cut(text, ":")
	switch kind {
	case "geosite":
		category, attribute, _ := strings.Cut(strings.ToLower(arg), "@")
		entries, found := ref.sites[strings.ToLower(category)]
		if !found {
			return nil, fmt.Errorf("geosite category %q not found", category)
		}
		var sub []Rule
		for _, entry := range entries {
			if attribute != "" && !entry.Attributes[attribute] {
				continue
			}
			prefixes := []string{"", "regexp:", "domain:", "full:"}
			if entry.Kind > 3 {
				return nil, fmt.Errorf("unknown geosite domain type %d", entry.Kind)
			}
			child, err := Compile(prefixes[entry.Kind]+entry.Value, nil)
			if err != nil {
				return nil, err
			}
			sub = append(sub, child)
		}
		return func(t Target) bool { return MatchAny(sub, t) }, nil
	case "geoip":
		value, found := ref.ips[strings.ToLower(arg)]
		if !found {
			return nil, fmt.Errorf("geoip category %q not found", arg)
		}
		return func(t Target) bool {
			ips := t.Addresses
			if ip, err := netip.ParseAddr(t.Host); err == nil {
				ips = append([]netip.Addr{ip}, t.Addresses...)
			}
			for _, ip := range ips {
				found := false
				for _, prefix := range value.prefixes {
					if prefix.Contains(ip.Unmap()) {
						found = true
						break
					}
				}
				if found != value.inverse {
					return true
				}
			}
			return false
		}, nil
	}
	return nil, fmt.Errorf("not a geo rule: %s", text)
}

// diffGeoData reports the first difference between g, fully decoded, and
// the former eager decoding.
func diffGeoData(g *GeoData, ref *refGeoData) error {
	if got, want := slices.Sorted(maps.Keys(g.sites)), slices.Sorted(maps.Keys(ref.sites)); !slices.Equal(got, want) {
		return fmt.Errorf("site categories %q, want %q", got, want)
	}
	if got, want := slices.Sorted(maps.Keys(g.ips)), slices.Sorted(maps.Keys(ref.ips)); !slices.Equal(got, want) {
		return fmt.Errorf("ip categories %q, want %q", got, want)
	}
	for name, want := range ref.sites {
		got, ok := g.Domains(name)
		if !ok || len(got) != len(want) || cap(got) != len(want) {
			return fmt.Errorf("site %q: %d domains (cap %d), want %d", name, len(got), cap(got), len(want))
		}
		for i := range want {
			if got[i].Kind != want[i].Kind || got[i].Value != want[i].Value || !maps.Equal(got[i].Attributes, want[i].Attributes) {
				return fmt.Errorf("site %q domain %d: %+v, want %+v", name, i, got[i], want[i])
			}
			if got[i].Attributes != nil && len(got[i].Attributes) == 0 {
				return fmt.Errorf("site %q domain %d: empty attribute map", name, i)
			}
		}
	}
	for name, want := range ref.ips {
		got, inverse, ok := g.Prefixes(name)
		if !ok || inverse != want.inverse || !slices.Equal(got, want.prefixes) || cap(got) != len(want.prefixes) {
			return fmt.Errorf("ip %q: %v %v, want %v %v", name, got, inverse, want.prefixes, want.inverse)
		}
	}
	return nil
}

// opaqueGeo hides *GeoData so that Compile takes the generic GeoSource path.
type opaqueGeo struct{ g *GeoData }

func (o opaqueGeo) Domains(category string) ([]Domain, bool) { return o.g.Domains(category) }

func (o opaqueGeo) Prefixes(category string) ([]netip.Prefix, bool, bool) {
	return o.g.Prefixes(category)
}

func TestGeoMatchersEquivalentToLinearRules(t *testing.T) {
	site, ip := testGeoSite(), testGeoIP()
	g, err := ParseGeoData(site, ip)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := refParseGeoData(site, ip)
	if err != nil {
		t.Fatal(err)
	}
	if err := diffGeoData(g, ref); err != nil {
		t.Fatal(err)
	}
	rules := []string{"geosite:mix", "geosite:MIX", "geosite:mix@ads", "geosite:Mix@ADS", "geosite:mix@cn",
		"geosite:mix@none", "geosite:mix@", "geosite:edge", "geosite:star", "geosite:star@ads", "geosite:dup",
		"geosite:empty", "geosite:badkind", "geosite:badkind@y", "geosite:badkind@x", "geosite:badre",
		"geosite:emptyop", "geosite:emptydomain", "geosite:emptykeyword", "geosite:geochild",
		"geosite:geoipchild", "geosite:badport", "geosite:unknown", "geosite:absent", "geoip:v4", "geoip:V4",
		"geoip:v6", "geoip:inv", "geoip:all", "geoip:dup", "geoip:none", "geoip:absent"}
	targets := testTargets()
	// Twice per source: the second *GeoData compile is served from the memo.
	sources := []GeoSource{g, opaqueGeo{g}, g}
	for _, text := range rules {
		want, wantErr := refCompile(text, ref)
		for i, source := range sources {
			got, gotErr := Compile(text, source)
			if (gotErr == nil) != (wantErr == nil) || gotErr != nil && gotErr.Error() != wantErr.Error() {
				t.Fatalf("%s (source %d): error %v, want %v", text, i, gotErr, wantErr)
			}
			if wantErr != nil {
				continue
			}
			for _, target := range targets {
				if got.Match(target) != want(target) {
					t.Fatalf("%s (source %d): %+v matched %v, want %v", text, i, target, got.Match(target), want(target))
				}
			}
		}
	}
}

func TestGeoDataRejectsWhatEagerDecodingRejected(t *testing.T) {
	check := func(site, ip []byte) {
		t.Helper()
		g, err := ParseGeoData(site, ip)
		ref, refErr := refParseGeoData(site, ip)
		if (err == nil) != (refErr == nil) || err != nil && err.Error() != refErr.Error() {
			t.Fatalf("site %x ip %x: error %v, want %v", site, ip, err, refErr)
		}
		if err == nil {
			if diff := diffGeoData(g, ref); diff != nil {
				t.Fatalf("site %x ip %x: %v", site, ip, diff)
			}
		}
	}
	for _, malformed := range [][]byte{{10, 255}, {0}, {10, 5, 1}, {15}, {8, 1}, {10, 0}, {10, 2, 18, 0},
		{11}, {12}, {9, 1, 2}, {13, 1, 2, 3}, {16, 1}, {10, 3, 8, 1, 1}, {10, 4, 10, 1, 'a', 26}} {
		if _, err := ParseGeoData(malformed, nil); err == nil {
			t.Fatalf("malformed geosite %x accepted", malformed)
		}
		if _, err := ParseGeoData(nil, malformed); err == nil {
			t.Fatalf("malformed geoip %x accepted", malformed)
		}
		check(malformed, nil)
		check(nil, malformed)
	}
	// Every truncation and many single-byte corruptions of valid data must be
	// accepted or rejected (with the same error) exactly as before.
	site, ip := testGeoSite(), testGeoIP()
	values := []byte{0x00, 0x01, 0x05, 0x08, 0x0a, 0x0d, 0x12, 0x1a, 0x7f, 0x80, 0xff}
	for _, data := range [][]byte{site, ip} {
		isSite := &data[0] == &site[0]
		for i := range data {
			mutations := [][]byte{data[:i]}
			for _, v := range values {
				mutated := slices.Clone(data)
				mutated[i] = v
				mutations = append(mutations, mutated)
			}
			for _, mutated := range mutations {
				if isSite {
					check(mutated, ip)
				} else {
					check(site, mutated)
				}
			}
		}
	}
}

func TestGeoDataDecodesCategoriesLazily(t *testing.T) {
	g, err := ParseGeoData(testGeoSite(), testGeoIP())
	if err != nil {
		t.Fatal(err)
	}
	decoded := func() (sites, ips []string) {
		for name, c := range g.sites {
			if c.domains != nil || c.matchers != nil {
				sites = append(sites, name)
			}
		}
		for name, c := range g.ips {
			if c.prefixes != nil || c.matcher != nil {
				ips = append(ips, name)
			}
		}
		slices.Sort(sites)
		slices.Sort(ips)
		return sites, ips
	}
	if sites, ips := decoded(); len(g.sites) == 0 || len(g.ips) == 0 || sites != nil || ips != nil {
		t.Fatalf("parse decoded categories: %q %q", sites, ips)
	}
	domains, ok := g.Domains("MIX")
	if !ok || len(domains) != g.sites["mix"].count || len(domains) != cap(domains) {
		t.Fatalf("mix: %d domains (cap %d), indexed %d", len(domains), cap(domains), g.sites["mix"].count)
	}
	if domains[0].Value != "example.com" || domains[0].Attributes != nil {
		t.Fatalf("attribute-less domain decoded as %+v", domains[0])
	}
	if again, _ := g.Domains("mix"); &again[0] != &domains[0] {
		t.Fatal("domains decoded twice")
	}
	if sites, ips := decoded(); !slices.Equal(sites, []string{"mix"}) || ips != nil {
		t.Fatalf("Domains(mix) decoded %q %q", sites, ips)
	}
	if prefixes, _, ok := g.Prefixes("v6"); !ok || len(prefixes) == 0 || len(prefixes) != cap(prefixes) {
		t.Fatalf("v6: %v", prefixes)
	}
	if sites, ips := decoded(); !slices.Equal(sites, []string{"mix"}) || !slices.Equal(ips, []string{"v6"}) {
		t.Fatalf("Prefixes(v6) decoded %q %q", sites, ips)
	}
	// Compiling builds and memoises a matcher without decoding the category.
	if _, err := Compile("geoip:v4", g); err != nil {
		t.Fatal(err)
	}
	if c := g.ips["v4"]; c.matcher == nil || c.prefixes != nil {
		t.Fatal("geoip:v4 did not compile from the raw entry")
	}
	if _, err := Compile("geosite:star@ads", g); err != nil {
		t.Fatal(err)
	}
	if c := g.sites["star"]; c.domains != nil || len(c.matchers) != 1 || c.matchers["ads"].matcher == nil {
		t.Fatal("geosite:star@ads did not compile from the raw entries")
	}
	if _, err := Compile("geosite:mix@ads", g); err != nil {
		t.Fatal(err)
	}
	memo := g.sites["mix"].matchers["ads"]
	if _, err := Compile("geosite:MIX@Ads", g); err != nil {
		t.Fatal(err)
	}
	if c := g.sites["mix"]; len(c.matchers) != 1 || c.matchers["ads"] != memo || memo.matcher == nil {
		t.Fatal("geosite matcher not memoised per category and attribute")
	}
	if sites, ips := decoded(); !slices.Equal(sites, []string{"mix", "star"}) || !slices.Equal(ips, []string{"v4", "v6"}) {
		t.Fatalf("compiling decoded %q %q", sites, ips)
	}
}

func TestGeoDataConcurrentFirstUse(t *testing.T) {
	g, err := ParseGeoData(testGeoSite(), testGeoIP())
	if err != nil {
		t.Fatal(err)
	}
	host := Target{Host: "a.example.com"}
	addr := Target{Host: "192.0.2.9"}
	const workers = 32
	domains := make([][]Domain, workers)
	prefixes := make([][]netip.Prefix, workers)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			d, siteFound := g.Domains("mix")
			p, _, ipFound := g.Prefixes("v4")
			site, siteErr := Compile("geosite:mix", g)
			ads, adsErr := Compile("geosite:mix@ads", g)
			ip, ipErr := Compile("geoip:V4", g)
			if !siteFound || !ipFound || siteErr != nil || adsErr != nil || ipErr != nil {
				t.Errorf("worker %d: %v %v %v %v %v", i, siteFound, ipFound, siteErr, adsErr, ipErr)
				return
			}
			if !site.Match(host) || site.Match(addr) || ads.Match(host) || !ip.Match(addr) || ip.Match(host) {
				t.Errorf("worker %d: wrong match result", i)
			}
			domains[i], prefixes[i] = d, p
		}()
	}
	close(start)
	wg.Wait()
	if t.Failed() {
		return
	}
	for i := range workers {
		if len(domains[i]) == 0 || &domains[i][0] != &domains[0][0] || len(prefixes[i]) == 0 || &prefixes[i][0] != &prefixes[0][0] {
			t.Fatalf("worker %d saw a different decoding", i)
		}
	}
	if c := g.sites["mix"]; len(c.matchers) != 2 {
		t.Fatalf("%d geosite matchers memoised, want 2", len(c.matchers))
	}
}

func TestParseHostAddrMatchesNetip(t *testing.T) {
	for _, host := range []string{"", ".", "1", "1.2.3.4", "01.2.3.4", "1.2.3", "1.2.3.4.5", "256.1.1.1",
		"1.2.3.4%eth0", "::", "::1", "fe80::1%eth0", "::ffff:1.2.3.4", "example.com", "a", "1.2.3.a", "%",
		"%eth0", "1:2", "[::1]", " 1.2.3.4", "1.2.3.4 ", "1..2.3", "localhost", "0x7f.0.0.1", "abcd::",
		"2001:db8::1", "1.2.3.4:80"} {
		want, err := netip.ParseAddr(host)
		got, ok := parseHostAddr(host)
		if ok != (err == nil) || got != want {
			t.Fatalf("%q: %v %v, want %v %v", host, got, ok, want, err)
		}
	}
}

// lastAddr is the highest address of p.
func lastAddr(p netip.Prefix) netip.Addr {
	a := p.Masked().Addr().AsSlice()
	for i := p.Bits(); i < len(a)*8; i++ {
		a[i/8] |= 0x80 >> (i % 8)
	}
	ip, _ := netip.AddrFromSlice(a)
	return ip
}

func TestIPMatcherRandomPrefixes(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	for round := 0; round < 40; round++ {
		var prefixes []netip.Prefix
		n := 1 + rng.IntN(60)
		for i := 0; i < n; i++ {
			switch rng.IntN(8) {
			case 0:
				prefixes = append(prefixes, netip.Prefix{})
			case 1:
				a := [16]byte{10: 0xff, 11: 0xff, 12: 10, 13: byte(rng.IntN(4))}
				prefixes = append(prefixes, netip.PrefixFrom(netip.AddrFrom16(a), 96+rng.IntN(33)))
			case 2, 3, 4:
				a := [4]byte{10, byte(rng.IntN(4)), byte(rng.IntN(256)), byte(rng.IntN(256))}
				prefixes = append(prefixes, netip.PrefixFrom(netip.AddrFrom4(a), 8+rng.IntN(25)))
			default:
				a := [16]byte{0: 0x20, 1: 0x01, 2: byte(rng.IntN(4)), 3: byte(rng.IntN(256)), 15: byte(rng.IntN(256))}
				prefixes = append(prefixes, netip.PrefixFrom(netip.AddrFrom16(a), 16+rng.IntN(113)))
			}
		}
		var queries []netip.Addr
		for _, p := range prefixes {
			if !p.IsValid() {
				continue
			}
			first, last := p.Masked().Addr(), lastAddr(p)
			queries = append(queries, first, first.Prev(), last, last.Next())
			if first.Is4() {
				queries = append(queries, netip.AddrFrom16(first.As16()), netip.AddrFrom16(last.Next().As16()))
			}
		}
		for i := 0; i < 200; i++ {
			a4 := [4]byte{10, byte(rng.IntN(5)), byte(rng.IntN(256)), byte(rng.IntN(256))}
			a6 := [16]byte{0: 0x20, 1: 0x01, 2: byte(rng.IntN(5)), 3: byte(rng.IntN(256)), 15: byte(rng.IntN(256))}
			queries = append(queries, netip.AddrFrom4(a4), netip.AddrFrom16(a6))
		}
		queries = append(queries, netip.Addr{}, netip.MustParseAddr("2001:100::1%eth0"))
		inverse := round%2 == 1
		m := newIPMatcher(prefixes, inverse)
		for _, q := range queries {
			want := false
			for _, p := range prefixes {
				if p.Contains(q.Unmap()) {
					want = true
					break
				}
			}
			if got := m.contains(q); got != want {
				t.Fatalf("round %d: contains(%v) = %v, want %v; prefixes %v", round, q, got, want, prefixes)
			}
			target := Target{Host: "name.test", Addresses: []netip.Addr{q}}
			if got := m.match(target); got != (want != inverse) {
				t.Fatalf("round %d: match(%v) = %v with inverse %v", round, q, got, inverse)
			}
		}
	}
}
