package geodata

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"reconstructed.local/soga/policy"
)

// The former eager decoder of policy.ParseGeoData, kept as the reference for
// the lazily decoded embedded dataset.

type eagerField struct {
	number uint64
	wire   uint64
	value  uint64
	bytes  []byte
}

type eagerGeoIP struct {
	prefixes []netip.Prefix
	inverse  bool
}

type eagerGeoData struct {
	sites map[string][]policy.Domain
	ips   map[string]eagerGeoIP
}

func eagerFields(data []byte, consume func(eagerField) error) error {
	for len(data) != 0 {
		tag, n := binary.Uvarint(data)
		if n <= 0 || tag>>3 == 0 {
			return errors.New("invalid protobuf tag")
		}
		data = data[n:]
		field := eagerField{number: tag >> 3, wire: tag & 7}
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

func eagerParse(site, ip []byte) (*eagerGeoData, error) {
	g := &eagerGeoData{sites: map[string][]policy.Domain{}, ips: map[string]eagerGeoIP{}}
	for _, source := range []struct {
		data  []byte
		sites bool
	}{{site, true}, {ip, false}} {
		if err := g.parse(source.data, source.sites); err != nil {
			return nil, err
		}
	}
	return g, nil
}

func (g *eagerGeoData) parse(data []byte, sites bool) error {
	return eagerFields(data, func(entry eagerField) error {
		if entry.number != 1 {
			return nil
		}
		if entry.wire != 2 {
			return errors.New("invalid geodata entry wire type")
		}
		var category string
		var domains []policy.Domain
		var ip eagerGeoIP
		err := eagerFields(entry.bytes, func(field eagerField) error {
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
					d, err := eagerDomain(field.bytes)
					if err != nil {
						return err
					}
					domains = append(domains, d)
				} else {
					p, err := eagerCIDR(field.bytes)
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

func eagerDomain(data []byte) (policy.Domain, error) {
	d := policy.Domain{Attributes: map[string]bool{}}
	err := eagerFields(data, func(f eagerField) error {
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
			if err := eagerFields(f.bytes, func(a eagerField) error {
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

func eagerCIDR(data []byte) (netip.Prefix, error) {
	var raw []byte
	var bits uint64
	err := eagerFields(data, func(f eagerField) error {
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

// lastAddr is the highest address of p.
func lastAddr(p netip.Prefix) netip.Addr {
	a := p.Masked().Addr().AsSlice()
	for i := p.Bits(); i < len(a)*8; i++ {
		a[i/8] |= 0x80 >> (i % 8)
	}
	ip, _ := netip.AddrFromSlice(a)
	return ip
}

func TestEmbeddedDataDecodesLikeEagerParser(t *testing.T) {
	if testing.Short() {
		t.Skip("decodes the complete embedded dataset twice")
	}
	g, err := policy.ParseGeoData(site, ip)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := eagerParse(site, ip)
	if err != nil {
		t.Fatal(err)
	}
	if len(ref.sites) == 0 || len(ref.ips) == 0 {
		t.Fatal("reference decoded no categories")
	}
	for name, want := range ref.sites {
		got, ok := g.Domains(strings.ToUpper(name))
		if !ok || len(got) != len(want) {
			t.Fatalf("geosite %q: %d domains, want %d", name, len(got), len(want))
		}
		for i := range want {
			if got[i].Kind != want[i].Kind || got[i].Value != want[i].Value || !maps.Equal(got[i].Attributes, want[i].Attributes) {
				t.Fatalf("geosite %q domain %d: %+v, want %+v", name, i, got[i], want[i])
			}
		}
	}
	for name, want := range ref.ips {
		got, inverse, ok := g.Prefixes(name)
		if !ok || inverse != want.inverse || len(got) != len(want.prefixes) {
			t.Fatalf("geoip %q: %d prefixes, want %d", name, len(got), len(want.prefixes))
		}
		for i := range want.prefixes {
			if got[i] != want.prefixes[i] {
				t.Fatalf("geoip %q prefix %d: %v, want %v", name, i, got[i], want.prefixes[i])
			}
		}
	}
	for _, absent := range []string{"", "absent-category"} {
		if _, ok := g.Domains(absent); ok {
			t.Fatalf("geosite %q found", absent)
		}
		if _, _, ok := g.Prefixes(absent); ok {
			t.Fatalf("geoip %q found", absent)
		}
	}
}

func TestEmbeddedGeoRulesMatchLinearRules(t *testing.T) {
	if testing.Short() {
		t.Skip("decodes the complete embedded dataset")
	}
	g, err := policy.ParseGeoData(site, ip)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := eagerParse(site, ip)
	if err != nil {
		t.Fatal(err)
	}
	kinds := []string{"", "regexp:", "domain:", "full:"}
	for _, rule := range []string{"geosite:google", "geosite:google@cn", "geosite:google@ads", "geosite:netflix",
		"geosite:category-porn", "geosite:geolocation-!cn@cn", "geosite:geolocation-cn"} {
		category, attribute, _ := strings.Cut(strings.TrimPrefix(rule, "geosite:"), "@")
		entries := ref.sites[category]
		if len(entries) == 0 {
			t.Fatalf("%s: category missing", rule)
		}
		// The former compilation: one sub-rule per entry under MatchAny.
		var sub []policy.Rule
		for _, entry := range entries {
			if attribute != "" && !entry.Attributes[attribute] {
				continue
			}
			if entry.Kind >= uint64(len(kinds)) {
				t.Fatalf("%s: domain type %d", rule, entry.Kind)
			}
			child, err := policy.Compile(kinds[entry.Kind]+entry.Value, nil)
			if err != nil {
				t.Fatal(err)
			}
			sub = append(sub, child)
		}
		got, err := policy.Compile(rule, g)
		if err != nil {
			t.Fatal(err)
		}
		hosts := []string{"", "www.google.com", "google.com.evil.test", "example.com", "baidu.com", "www.qq.com",
			"netflix.com", "a.b.c.d.example.org", "localhost"}
		step := max(1, len(entries)/150)
		for i := 0; i < len(entries); i += step {
			if v := entries[i].Value; entries[i].Kind != 1 {
				hosts = append(hosts, v, "sub."+v, "x"+v, strings.ToUpper(v)+".")
			}
		}
		for _, host := range hosts {
			target := policy.Target{Host: host}
			if want := policy.MatchAny(sub, target); got.Match(target) != want {
				t.Fatalf("%s: %q matched %v, want %v", rule, host, !want, want)
			}
		}
	}
	for _, category := range []string{"cn", "private", "jp"} {
		want := ref.ips[category]
		if len(want.prefixes) == 0 {
			t.Fatalf("geoip %s: category missing", category)
		}
		got, err := policy.Compile("geoip:"+strings.ToUpper(category), g)
		if err != nil {
			t.Fatal(err)
		}
		addrs := []netip.Addr{{}, netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("8.8.8.8"),
			netip.MustParseAddr("2400:3200::1"), netip.MustParseAddr("::ffff:114.114.114.114"),
			netip.MustParseAddr("fe80::1%eth0"), netip.MustParseAddr("::1")}
		step := max(1, len(want.prefixes)/150)
		for i := 0; i < len(want.prefixes); i += step {
			p := want.prefixes[i]
			first, last := p.Addr(), lastAddr(p)
			addrs = append(addrs, first, first.Prev(), last, last.Next())
			if first.Is4() {
				addrs = append(addrs, netip.AddrFrom16(first.As16()))
			}
		}
		for _, a := range addrs {
			linear := false
			for _, p := range want.prefixes {
				if p.Contains(a.Unmap()) {
					linear = true
					break
				}
			}
			targets := []policy.Target{{Host: "name.test", Addresses: []netip.Addr{a}}}
			if a.IsValid() {
				targets = append(targets, policy.Target{Host: a.String()})
			}
			for _, target := range targets {
				if got.Match(target) != (linear != want.inverse) {
					t.Fatalf("geoip:%s: %+v matched %v", category, target, got.Match(target))
				}
			}
		}
	}
}

func TestReadKeepsLittleSpareCapacity(t *testing.T) {
	want := bytes.Repeat([]byte("geodata!"), 40000)
	path := filepath.Join(t.TempDir(), "geosite.dat")
	if err := os.WriteFile(path, want, 0600); err != nil {
		t.Fatal(err)
	}
	got, err := read(path)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("read: %d bytes, %v", len(got), err)
	}
	if spare := cap(got) - len(got); spare > len(want)/16 {
		t.Fatalf("read retained %d spare bytes for %d", spare, len(got))
	}
	for _, hint := range []int64{-1, 0, 10, int64(len(want)), 1 << 40} {
		got, err := readAll(bytes.NewReader(want), hint)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("hint %d: %d bytes, %v", hint, len(got), err)
		}
	}
	if got, err := readAll(bytes.NewReader(nil), 0); err != nil || len(got) != 0 {
		t.Fatalf("empty input: %d bytes, %v", len(got), err)
	}
}
