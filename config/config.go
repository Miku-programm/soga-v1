// Package config reconstructs the observed configuration-value pipeline.
// It is independent replacement code, not recovered original source.
package config

import (
	"reflect"
	"strconv"
	"strings"
	"time"
)

// Field describes a conf-tagged field recovered from runtime metadata.
// Type is the original Go kind; the target's int fields are stored as int64.
type Field struct {
	Key        string
	Name       string
	Type       string
	Default    string
	HasDefault bool
}

var fields, fieldIndices = describeFields()

func describeFields() ([]Field, map[string]int) {
	t := reflect.TypeOf(Config{})
	descriptors := make([]Field, 0, t.NumField())
	indices := make(map[string]int, t.NumField())
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		key, ok := f.Tag.Lookup("conf")
		if !ok {
			continue
		}
		value, hasDefault := f.Tag.Lookup("default")
		kind := f.Type.String()
		if kind == "int64" {
			kind = "int"
		}
		descriptors = append(descriptors, Field{Key: key, Name: f.Name, Type: kind, Default: value, HasDefault: hasDefault})
		indices[key] = i
	}
	return descriptors, indices
}

// Fields returns a copy of all 157 recovered field descriptors in key order.
func Fields() []Field { return append([]Field(nil), fields...) }

// Keys returns all registered configuration keys in key order.
func Keys() []string {
	keys := make([]string, len(fields))
	for i, field := range fields {
		keys[i] = field.Key
	}
	return keys
}

// DefaultValues reproduces the registered defaults map (0x1322f60).
// Fields without a default tag are registered with an empty string too.
func DefaultValues() map[string]string {
	values := make(map[string]string, len(fields))
	for _, field := range fields {
		values[field.Key] = field.Default
	}
	return values
}

// Defaults converts all metadata defaults using the observed assignment rules.
func Defaults() Config { return FromValues(DefaultValues()) }

// FromValues performs field assignment only, as in 0x1323420. It does not trim,
// lowercase, merge defaults, or strip comments; absent keys assign empty text.
// The Load functions implement those earlier pipeline stages separately.
func FromValues(values map[string]string) Config {
	var c Config
	for _, field := range fields {
		c.SetRaw(field.Key, values[field.Key])
	}
	return c
}

// SetRaw assigns one registered key using the branches in 0x13236c0.
// It returns false for an unknown key. No parser normalization is added here.
// Numeric errors become zero; boolean true means the exact four bytes "true".
func (c *Config) SetRaw(key, text string) bool {
	index, ok := fieldIndices[key]
	if !ok {
		return false
	}
	dst := reflect.ValueOf(c).Elem().Field(index)
	AssignValue(dst, text)
	return true
}

// AssignValue reconstructs the complete kind-dispatch boundary at 0x13236c0.
// Panic strings were statically decoded from the original callsites.
// There are deliberately no added IsValid/CanSet/overflow checks: reflect
// retains the observed behavior for invalid, immutable, and narrow values.
func AssignValue(dst reflect.Value, text string) {
	typ := dst.Type()
	if typ == reflect.TypeOf(time.Duration(0)) {
		panic("conf tag does not support time.Duration")
	}
	switch dst.Kind() {
	case reflect.String:
		dst.SetString(text)
	case reflect.Bool:
		dst.SetBool(text == "true")
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		n, err := strconv.ParseInt(text, 10, 64)
		if err != nil {
			n = 0
		}
		dst.SetInt(n)
	case reflect.Float32, reflect.Float64:
		n, err := strconv.ParseFloat(text, 64)
		if err != nil {
			n = 0
		}
		dst.SetFloat(n)
	case reflect.Slice:
		if typ.Elem().Kind() != reflect.String {
			panic("conf tag only supports []string slice, got " + typ.String())
		}
		dst.Set(reflect.ValueOf(SplitClean(text, ",", -1)))
	default:
		panic("conf tag does not support " + typ.String())
	}
}

// SplitClean reconstructs 0xb7d720: trim the whole input, split with count,
// trim each item, and discard empty results. The result is never nil.
// 0x607440 and 0x604c60 were checked as TrimSpace and genSplit semantics.
func SplitClean(text, delimiter string, count int) []string {
	parts := strings.SplitN(strings.TrimSpace(text), delimiter, count)
	result := make([]string, 0)
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			result = append(result, part)
		}
	}
	return result
}

// EffectiveWebAPIKey reproduces 0x13216c0's selected string. The original
// warning on legacy fallback is exposed through UsesLegacyWebAPIKey instead
// of introducing process-wide logging in this reusable package.
func (c Config) EffectiveWebAPIKey() string {
	if c.WebapiKey != "" {
		return c.WebapiKey
	}
	return c.WebapiMukey
}

// LegacyWebAPIKeyWarning is the decoded message at original callsite 0x1321734.
const LegacyWebAPIKeyWarning = "'webapi_mukey' is deprecated, please use 'webapi_key'"

func (c Config) UsesLegacyWebAPIKey() bool { return c.WebapiKey == "" && c.WebapiMukey != "" }

// NormalizeServerType reproduces 0x1321f40. There is no whitespace trimming.
// The three previously encrypted aliases were statically decoded separately.
func NormalizeServerType(serverType string) string {
	s := strings.ToLower(serverType)
	switch s {
	case "ss", "shadowsocks":
		return "ss"
	case "v2ray", "vmess":
		return "v2ray"
	case "trojan":
		return "trojan"
	case "ssr", "shadowsocksr":
		return "ssr"
	case "vless":
		return "vless"
	case "hysteria":
		return "hysteria"
	case "mieru":
		return "mieru"
	case "anytls":
		return "anytls"
	default:
		return s
	}
}
func (c Config) NormalizedServerType() string { return NormalizeServerType(c.ServerType) }
func (c Config) IsV2Ray() bool                { return c.NormalizedServerType() == "v2ray" }
func (c Config) IsVLess() bool                { return c.NormalizedServerType() == "vless" }

// NormalizeConfigPath and NormalizeDNSPath reproduce only the leading slash
// test and literal concatenation at 0x1323b00/0x1335660. Neither cleans a path.
func NormalizeConfigPath(path string) string {
	if len(path) == 0 || path[0] != '/' {
		return "/etc/soga/" + path
	}
	return path
}
func NormalizeDNSPath(path string) string { return NormalizeConfigPath(path) }
