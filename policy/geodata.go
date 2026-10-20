package policy

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"
)

// GeoData reads the public V2Ray GeoSiteList/GeoIPList protobuf wire format.
// Schema: github.com/v2fly/v2ray-core, app/router/routercommon/common.proto.
// Only the needed fields are decoded; unknown non-group wire fields are skipped.
type GeoData struct {
	sites map[string][]Domain
	ips   map[string]geoIP
}
type geoIP struct {
	prefixes []netip.Prefix
	inverse  bool
}

func ParseGeoData(site, ip []byte) (*GeoData, error) {
	g := &GeoData{sites: map[string][]Domain{}, ips: map[string]geoIP{}}
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
	g := &GeoData{sites: map[string][]Domain{}, ips: map[string]geoIP{}}
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
	value, found := g.sites[strings.ToLower(category)]
	return value, found
}
func (g *GeoData) Prefixes(category string) ([]netip.Prefix, bool, bool) {
	value, found := g.ips[strings.ToLower(category)]
	return value.prefixes, value.inverse, found
}

type wireField struct {
	number uint64
	wire   uint64
	value  uint64
	bytes  []byte
}

func wireFields(data []byte, consume func(wireField) error) error {
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

func (g *GeoData) parse(data []byte, sites bool) error {
	return wireFields(data, func(entry wireField) error {
		if entry.number != 1 {
			return nil
		}
		if entry.wire != 2 {
			return errors.New("invalid geodata entry wire type")
		}
		var category string
		var domains []Domain
		var ip geoIP
		err := wireFields(entry.bytes, func(field wireField) error {
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
					d, err := parseDomain(field.bytes)
					if err != nil {
						return err
					}
					domains = append(domains, d)
				} else {
					p, err := parseCIDR(field.bytes)
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

func parseDomain(data []byte) (Domain, error) {
	d := Domain{Attributes: map[string]bool{}}
	err := wireFields(data, func(f wireField) error {
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
			if err := wireFields(f.bytes, func(a wireField) error {
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

func parseCIDR(data []byte) (netip.Prefix, error) {
	var raw []byte
	var bits uint64
	err := wireFields(data, func(f wireField) error {
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
