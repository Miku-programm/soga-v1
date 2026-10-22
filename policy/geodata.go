package policy

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"sync"
)

// GeoData reads the public V2Ray GeoSiteList/GeoIPList protobuf wire format.
// Schema: github.com/v2fly/v2ray-core, app/router/routercommon/common.proto.
// Only the needed fields are decoded; unknown non-group wire fields are skipped.
//
// Loading validates the complete input but only indexes each category name
// to its raw message bytes, which GeoData retains. A category is decoded on
// its first Domains or Prefixes call and memoised; the matchers Compile
// builds for geosite: and geoip: rules are memoised per category as well.
// GeoData is safe for concurrent use.
type GeoData struct {
	mu    sync.Mutex
	sites map[string]*siteCategory
	ips   map[string]*ipCategory
}

// siteCategory indexes one geosite category. entries holds the raw GeoSite
// message bodies sharing the (lower-cased) name, in file order, because
// repeated names append their domains; count is their total domain count.
// matchers memoises compiled matchers by attribute and is guarded by
// GeoData.mu.
type siteCategory struct {
	entries [][]byte
	count   int

	once    sync.Once
	domains []Domain

	matchers map[string]*siteMatcherMemo
}

type siteMatcherMemo struct {
	once    sync.Once
	matcher *siteMatcher
	err     error
}

// ipCategory indexes one geoip category: the raw GeoIP message body (a
// repeated name replaces the earlier entry), its CIDR count and
// inverse_match flag.
type ipCategory struct {
	entry   []byte
	count   int
	inverse bool

	once     sync.Once
	prefixes []netip.Prefix

	matcherOnce sync.Once
	matcher     *ipMatcher
}

// ParseGeoData validates site and ip and indexes their categories. The
// returned GeoData keeps referencing both slices, so callers must not modify
// them afterwards.
func ParseGeoData(site, ip []byte) (*GeoData, error) {
	g := &GeoData{sites: map[string]*siteCategory{}, ips: map[string]*ipCategory{}}
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

func LoadGeoData(sitePath, ipPath string) (*GeoData, error) {
	g := &GeoData{sites: map[string]*siteCategory{}, ips: map[string]*ipCategory{}}
	for _, source := range []struct {
		path string
		site bool
	}{{sitePath, true}, {ipPath, false}} {
		if source.path == "" {
			continue
		}
		info, err := os.Stat(source.path)
		if err != nil {
			return nil, err
		}
		if info.Size() > 256<<20 {
			return nil, fmt.Errorf("geodata file exceeds 256 MiB: %s", source.path)
		}
		data, err := os.ReadFile(source.path)
		if err != nil {
			return nil, err
		}
		if err = g.parse(data, source.site); err != nil {
			return nil, fmt.Errorf("%s: %w", source.path, err)
		}
	}
	return g, nil
}

func (g *GeoData) Domains(category string) ([]Domain, bool) {
	c := g.lookupSite(category)
	if c == nil {
		return nil, false
	}
	return c.load(), true
}

func (g *GeoData) Prefixes(category string) ([]netip.Prefix, bool, bool) {
	c := g.lookupIP(category)
	if c == nil {
		return nil, false, false
	}
	return c.load(), c.inverse, true
}

func (g *GeoData) lookupSite(category string) *siteCategory {
	key := strings.ToLower(category)
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.sites[key]
}

func (g *GeoData) lookupIP(category string) *ipCategory {
	key := strings.ToLower(category)
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.ips[key]
}

// load decodes the category's domains once. The result has exactly count
// elements, or is nil for an empty category.
func (c *siteCategory) load() []Domain {
	c.once.Do(func() {
		if c.count == 0 {
			return
		}
		domains := make([]Domain, 0, c.count)
		for _, entry := range c.entries {
			for item, rest, ok := nextItem(entry); ok; item, rest, ok = nextItem(rest) {
				var d Domain
				if decodeDomain(item, &d) != nil {
					break // unreachable: the entry was validated by parse
				}
				domains = append(domains, d)
			}
		}
		c.domains = domains
	})
	return c.domains
}

// load decodes the category's prefixes once. The result has exactly count
// elements, or is nil for an empty category.
func (c *ipCategory) load() []netip.Prefix {
	c.once.Do(func() {
		if c.count == 0 {
			return
		}
		prefixes := make([]netip.Prefix, 0, c.count)
		for item, rest, ok := nextItem(c.entry); ok; item, rest, ok = nextItem(rest) {
			if p, err := parseCIDR(item); err == nil {
				prefixes = append(prefixes, p)
			}
		}
		c.prefixes = prefixes
	})
	return c.prefixes
}

type wireField struct {
	number uint64
	wire   uint64
	value  uint64
	bytes  []byte
}

// readField decodes the protobuf field at the start of data and returns it
// together with the bytes that follow it. Group wire types are rejected.
func readField(data []byte) (wireField, []byte, error) {
	tag, n := binary.Uvarint(data)
	if n <= 0 || tag>>3 == 0 {
		return wireField{}, nil, errors.New("invalid protobuf tag")
	}
	data = data[n:]
	field := wireField{number: tag >> 3, wire: tag & 7}
	switch field.wire {
	case 0:
		field.value, n = binary.Uvarint(data)
		if n <= 0 {
			return wireField{}, nil, errors.New("invalid protobuf varint")
		}
		data = data[n:]
	case 1:
		if len(data) < 8 {
			return wireField{}, nil, errors.New("truncated protobuf fixed64")
		}
		data = data[8:]
	case 2:
		length, n := binary.Uvarint(data)
		if n <= 0 || length > uint64(len(data)-n) {
			return wireField{}, nil, errors.New("invalid protobuf length")
		}
		end := n + int(length)
		field.bytes = data[n:end:end]
		data = data[end:]
	case 5:
		if len(data) < 4 {
			return wireField{}, nil, errors.New("truncated protobuf fixed32")
		}
		data = data[4:]
	default:
		return wireField{}, nil, fmt.Errorf("unsupported protobuf wire type %d", field.wire)
	}
	return field, data, nil
}

// nextItem returns the next item (field 2: a Domain or CIDR message) of a
// validated GeoSite or GeoIP body and the bytes after it; ok is false once
// no item remains.
func nextItem(rest []byte) (item, after []byte, ok bool) {
	for len(rest) != 0 {
		field, next, err := readField(rest)
		if err != nil {
			return nil, nil, false
		}
		rest = next
		if field.number == 2 && field.wire == 2 {
			return field.bytes, rest, true
		}
	}
	return nil, nil, false
}

// parse validates data completely and indexes its categories without
// decoding any domain or CIDR into memory. It rejects exactly the input the
// former eager decoder rejected, with the same errors.
func (g *GeoData) parse(data []byte, sites bool) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.sites == nil {
		g.sites = map[string]*siteCategory{}
	}
	if g.ips == nil {
		g.ips = map[string]*ipCategory{}
	}
	for rest := data; len(rest) != 0; {
		entry, next, err := readField(rest)
		if err != nil {
			return err
		}
		rest = next
		if entry.number != 1 {
			continue
		}
		if entry.wire != 2 {
			return errors.New("invalid geodata entry wire type")
		}
		category, count, inverse, err := validateEntry(entry.bytes, sites)
		if err != nil {
			return err
		}
		if !sites {
			g.ips[category] = &ipCategory{entry: entry.bytes, count: count, inverse: inverse}
			continue
		}
		if old := g.sites[category]; old != nil {
			// A new category value keeps an already decoded one intact.
			n := len(old.entries)
			entries := append(old.entries[:n:n], entry.bytes)
			g.sites[category] = &siteCategory{entries: entries, count: old.count + count}
		} else {
			g.sites[category] = &siteCategory{entries: [][]byte{entry.bytes}, count: count}
		}
	}
	return nil
}

// validateEntry checks one GeoSite (sites) or GeoIP message the way decoding
// it would, without allocating per item. It returns the lower-cased category
// name, the item count and, for GeoIP, the inverse_match flag.
func validateEntry(data []byte, sites bool) (string, int, bool, error) {
	var name []byte
	count := 0
	inverse := false
	for rest := data; len(rest) != 0; {
		field, next, err := readField(rest)
		if err != nil {
			return "", 0, false, err
		}
		rest = next
		switch field.number {
		case 1:
			if field.wire != 2 {
				return "", 0, false, errors.New("invalid category wire type")
			}
			name = field.bytes
		case 2:
			if field.wire != 2 {
				return "", 0, false, errors.New("invalid geodata item wire type")
			}
			if sites {
				err = decodeDomain(field.bytes, nil)
			} else {
				_, err = parseCIDR(field.bytes)
			}
			if err != nil {
				return "", 0, false, err
			}
			count++
		case 3:
			if !sites {
				if field.wire != 0 {
					return "", 0, false, errors.New("invalid inverse_match wire type")
				}
				inverse = field.value != 0
			}
		}
	}
	category := strings.ToLower(string(name))
	if category == "" {
		return "", 0, false, errors.New("empty geodata category")
	}
	return category, count, inverse, nil
}

// decodeDomain validates a Domain message and, when d is not nil, decodes it
// into d. d.Attributes stays nil for a domain without attributes.
func decodeDomain(data []byte, d *Domain) error {
	for rest := data; len(rest) != 0; {
		f, next, err := readField(rest)
		if err != nil {
			return err
		}
		rest = next
		switch f.number {
		case 1:
			if f.wire != 0 {
				return errors.New("invalid domain kind wire type")
			}
			if d != nil {
				d.Kind = f.value
			}
		case 2:
			if f.wire != 2 {
				return errors.New("invalid domain value wire type")
			}
			if d != nil {
				d.Value = string(f.bytes)
			}
		case 3:
			if f.wire != 2 {
				return errors.New("invalid domain attribute wire type")
			}
			var key []byte
			value := false
			for attr := f.bytes; len(attr) != 0; {
				a, after, err := readField(attr)
				if err != nil {
					return err
				}
				attr = after
				if a.number == 1 {
					key = a.bytes
				} else if a.number == 2 || a.number == 3 {
					value = a.value != 0
				}
			}
			if d != nil {
				if d.Attributes == nil {
					d.Attributes = map[string]bool{}
				}
				d.Attributes[strings.ToLower(string(key))] = value
			}
		}
	}
	return nil
}

func parseCIDR(data []byte) (netip.Prefix, error) {
	var raw []byte
	var bits uint64
	for rest := data; len(rest) != 0; {
		f, next, err := readField(rest)
		if err != nil {
			return netip.Prefix{}, err
		}
		rest = next
		if f.number == 1 {
			if f.wire != 2 {
				return netip.Prefix{}, errors.New("invalid CIDR address wire type")
			}
			raw = f.bytes
		} else if f.number == 2 {
			if f.wire != 0 {
				return netip.Prefix{}, errors.New("invalid CIDR prefix wire type")
			}
			bits = f.value
		}
	}
	ip, ok := netip.AddrFromSlice(raw)
	if !ok || bits > uint64(ip.BitLen()) {
		return netip.Prefix{}, errors.New("invalid geodata CIDR")
	}
	return netip.PrefixFrom(ip, int(bits)).Masked(), nil
}
