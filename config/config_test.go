package config

import (
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestMetadataDefaultsAndIndependentCopies(t *testing.T) {
	if len(Fields()) != 157 || len(Keys()) != 157 || len(DefaultValues()) != 157 {
		t.Fatal("schema must preserve all 157 registered fields")
	}
	if !sort.StringsAreSorted(Keys()) {
		t.Fatal("key order must be deterministic")
	}
	defaultTags := 0
	for _, f := range Fields() {
		if f.HasDefault {
			defaultTags++
		}
	}
	if defaultTags != 111 {
		t.Fatalf("default tag count = %d", defaultTags)
	}
	c := Defaults()
	if c.Api != "webapi" || c.CertMode != "http" || c.DbMaxConn != 4 || !reflect.DeepEqual(c.NodeId, []string{"0"}) {
		t.Fatalf("metadata defaults lost: %+v", c)
	}
	if c.BlockListWhiteUserId == nil {
		t.Fatal("absent slice text must produce a nonnil empty slice")
	}
	c.NodeId[0] = "changed"
	if Defaults().NodeId[0] != "0" {
		t.Fatal("Defaults shares slice backing storage")
	}
	f := Fields()
	f[0].Key = "changed"
	if Fields()[0].Key == "changed" {
		t.Fatal("Fields shares mutable descriptors")
	}
}

func TestRawConversionBoundary(t *testing.T) {
	var c Config
	for _, tc := range []struct {
		text string
		want bool
	}{{"true", true}, {"TRUE", false}, {" true ", false}, {"1", false}, {"false", false}, {"", false}} {
		if !c.SetRaw("auto_update", tc.text) || c.AutoUpdate != tc.want {
			t.Errorf("bool %q -> %v", tc.text, c.AutoUpdate)
		}
	}
	for _, tc := range []struct {
		text string
		want int64
	}{{"42", 42}, {"+7", 7}, {"-9", -9}, {"010", 10}, {"1_000", 0}, {" 7", 0}, {"0x10", 0}, {"bad", 0}, {"9223372036854775808", 0}, {"-9223372036854775809", 0}, {"", 0}} {
		c.SetRaw("db_port", tc.text)
		if c.DbPort != tc.want {
			t.Errorf("int %q -> %d, want %d", tc.text, c.DbPort, tc.want)
		}
	}
	for _, tc := range []struct {
		text string
		want float64
	}{{"1.25", 1.25}, {"-2e2", -200}, {"bad", 0}, {" 1.25 ", 0}, {"1e9999", 0}, {"", 0}} {
		c.SetRaw("node_speed_limit", tc.text)
		if c.NodeSpeedLimit != tc.want {
			t.Errorf("float %q -> %v", tc.text, c.NodeSpeedLimit)
		}
	}
	c.SetRaw("node_speed_limit", "NaN")
	if !math.IsNaN(c.NodeSpeedLimit) {
		t.Fatal("valid NaN parsing changed")
	}
	c.SetRaw("node_speed_limit", "+Inf")
	if !math.IsInf(c.NodeSpeedLimit, 1) {
		t.Fatal("valid infinity parsing changed")
	}
	c.SetRaw("webapi_key", "  key # retained  ")
	if c.WebapiKey != "  key # retained  " {
		t.Fatal("raw assignment must not run loader cleanup")
	}
	c.SetRaw("node_id", "1,, 2,\u2003,3,")
	if !reflect.DeepEqual(c.NodeId, []string{"1", "2", "3"}) {
		t.Fatalf("slice: %#v", c.NodeId)
	}
	if c.SetRaw("NODE_ID", "4") || c.SetRaw("unknown", "x") {
		t.Fatal("raw assignment must use registered exact keys")
	}
}

func expectPanic(t *testing.T, contains string, call func()) {
	t.Helper()
	defer func() {
		recovered := recover()
		if recovered == nil {
			t.Errorf("expected panic containing %q", contains)
		} else if !strings.Contains(fmt.Sprint(recovered), contains) {
			t.Errorf("panic %q does not contain %q", recovered, contains)
		}
	}()
	call()
}

func TestAssignValueReflectionBoundaries(t *testing.T) {
	var narrow int8
	AssignValue(reflect.ValueOf(&narrow).Elem(), "128")
	if narrow != -128 {
		t.Fatal("narrow signed fields must retain reflect truncation")
	}
	AssignValue(reflect.ValueOf(&narrow).Elem(), "9223372036854775808")
	if narrow != 0 {
		t.Fatal("parser int64 overflow must become zero before assignment")
	}
	var small float32
	AssignValue(reflect.ValueOf(&small).Elem(), "1e40")
	if !math.IsInf(float64(small), 1) {
		t.Fatal("finite float64 may overflow when assigned to float32")
	}
	AssignValue(reflect.ValueOf(&small).Elem(), "1e400")
	if small != 0 {
		t.Fatal("float64 parser overflow must become zero")
	}
	var duration time.Duration
	expectPanic(t, "conf tag does not support time.Duration", func() { AssignValue(reflect.ValueOf(&duration).Elem(), "1") })
	type independentDuration time.Duration
	var other independentDuration
	AssignValue(reflect.ValueOf(&other).Elem(), "3")
	if other != 3 {
		t.Fatal("only the exact prohibited named type is rejected")
	}
	var unsigned uint64
	expectPanic(t, "conf tag does not support uint64", func() { AssignValue(reflect.ValueOf(&unsigned).Elem(), "1") })
	var numbers []int
	expectPanic(t, "conf tag only supports []string slice, got []int", func() { AssignValue(reflect.ValueOf(&numbers).Elem(), "1,2") })
	type namedString string
	var named []namedString
	expectPanic(t, "reflect", func() { AssignValue(reflect.ValueOf(&named).Elem(), "a,b") })
	type stringSlice []string
	var alias stringSlice
	AssignValue(reflect.ValueOf(&alias).Elem(), "a, b")
	if !reflect.DeepEqual(alias, stringSlice{"a", "b"}) {
		t.Fatal("assignable named slice rejected")
	}
	expectPanic(t, "reflect", func() { AssignValue(reflect.ValueOf(false), "true") })
	expectPanic(t, "reflect", func() { AssignValue(reflect.Value{}, "true") })
}

func TestSplitCleanBoundaries(t *testing.T) {
	tests := []struct {
		text, sep string
		n         int
		want      []string
	}{
		{"\u00a0a,\u2003b\u202f,,\u3000,c ", ",", -1, []string{"a", "b", "c"}},
		{" a = b = c ", "=", 2, []string{"a", "b = c"}},
		{"key=", "=", 2, []string{"key"}},
		{"=value", "=", 2, []string{"value"}},
		{" , , ", ",", -1, []string{}},
		{"a,b", ",", 0, []string{}},
		{"a,b", ",", 1, []string{"a,b"}},
		{" äβ ", "", -1, []string{"ä", "β"}},
		{"\u200bx\u200b", ",", -1, []string{"\u200bx\u200b"}},
	}
	for _, tc := range tests {
		got := SplitClean(tc.text, tc.sep, tc.n)
		if got == nil || !reflect.DeepEqual(got, tc.want) {
			t.Errorf("SplitClean(%q,%q,%d)=%#v want %#v", tc.text, tc.sep, tc.n, got, tc.want)
		}
	}
}

func TestProtocolNamesUnicodeAndPathLiterals(t *testing.T) {
	for _, tc := range []struct{ input, want string }{
		{"ShAdOwSoCkS", "ss"}, {"SHADOWSOCKSR", "ssr"}, {"VMESS", "v2ray"}, {"VLESS", "vless"},
		{"HYSTERIA", "hysteria"}, {"ANYTLS", "anytls"}, {" VMESS ", " vmess "}, {"ÉΣK", "éσk"},
		{string([]byte{'A', 0xff, 'B'}), "a\ufffdb"},
	} {
		if got := NormalizeServerType(tc.input); got != tc.want {
			t.Errorf("normalize %q -> %q want %q", tc.input, got, tc.want)
		}
	}
	for _, tc := range []struct{ input, want string }{{"", "/etc/soga/"}, {"soga.conf", "/etc/soga/soga.conf"}, {"../x", "/etc/soga/../x"}, {"/tmp//x", "/tmp//x"}, {"C:\\x", "/etc/soga/C:\\x"}} {
		if NormalizeConfigPath(tc.input) != tc.want || NormalizeDNSPath(tc.input) != tc.want {
			t.Errorf("path normalization changed %q", tc.input)
		}
	}
}

func TestAPIKeyFallback(t *testing.T) {
	c := Config{WebapiKey: "primary", WebapiMukey: "legacy"}
	if c.EffectiveWebAPIKey() != "primary" || c.UsesLegacyWebAPIKey() {
		t.Fatal("primary key must win")
	}
	c.WebapiKey = ""
	if c.EffectiveWebAPIKey() != "legacy" || !c.UsesLegacyWebAPIKey() {
		t.Fatal("nonempty legacy fallback missing")
	}
	c.WebapiMukey = ""
	if c.EffectiveWebAPIKey() != "" || c.UsesLegacyWebAPIKey() {
		t.Fatal("empty keys should not signal legacy usage")
	}
}

func TestFileGrammarAndLateCommentCleanup(t *testing.T) {
	text := "  # comment\r\nWEBAPI_KEY = first\nwebapi_key = second # note\nwebapi_url=https://example.test/a#fragment\nunknown = x=y=z\n=empty-key\nno separator\n;semi=value\nquoted=\"a # b\"\ntab=x\t#tail\nnode_id=1,,2\n"
	parsed := ParseText(text)
	if parsed["webapi_key"] != "second # note" || parsed["unknown"] != "x=y=z" || parsed[""] != "empty-key" || parsed[";semi"] != "value" {
		t.Fatalf("file grammar changed: %#v", parsed)
	}
	loaded, err := Load(strings.NewReader(text), LoadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Config.WebapiKey != "second" || loaded.Config.WebapiUrl != "https://example.test/a#fragment" {
		t.Fatal("cleanup must cut only the literal space-# sequence")
	}
	if loaded.Values["quoted"] != "\"a" || loaded.Values["tab"] != "x\t#tail" {
		t.Fatalf("quotes/tabs must not gain invented comment handling: %#v", loaded.Values)
	}
	if !reflect.DeepEqual(loaded.Config.NodeId, []string{"1", "2"}) {
		t.Fatal("slice conversion lost")
	}
}

func TestSourcePrecedenceAndEnvironmentCaseRules(t *testing.T) {
	opts := LoadOptions{Environ: []string{
		"NODE_ID=upper-ignored", "node_id=env", "webapi_key=", "webapi_url= env-url ",
		"DNS_TOKEN= token ", "DNS_EMPTY=", "dns_lower=ignored", "unknown=env-ignored", "auto_update= true ",
	}, Flags: map[string]string{"node_id": "flag", "webapi_url": ""}}
	loaded, err := Load(strings.NewReader("node_id=file\nwebapi_key=file-key\nwebapi_url=file-url\nunknown=file-value\n"), opts)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(loaded.Config.NodeId, []string{"flag"}) || loaded.Config.WebapiKey != "file-key" || loaded.Config.WebapiUrl != "" || !loaded.Config.AutoUpdate {
		t.Fatalf("source precedence failed: %+v", loaded.Config)
	}
	if loaded.Values["dns_token"] != "token" || loaded.Values["unknown"] != "file-value" {
		t.Fatal("DNS/registered-key environment policy changed")
	}
	if _, ok := loaded.Values["dns_lower"]; ok {
		t.Fatal("lowercase DNS prefix must not gain special handling")
	}
	if _, ok := loaded.Values["dns_empty"]; ok {
		t.Fatal("empty environment value must be dropped")
	}
	loaded, err = Load(nil, LoadOptions{Environ: []string{"NODE_ID=99"}})
	if err != nil || !reflect.DeepEqual(loaded.Config.NodeId, []string{"0"}) {
		t.Fatal("ordinary uppercase environment name incorrectly accepted")
	}
}

type errorReader struct{ err error }

func (r errorReader) Read([]byte) (int, error) { return 0, r.err }
func TestLoadErrorsAndExplicitCreation(t *testing.T) {
	want := errors.New("read failed")
	if got, err := Load(errorReader{want}, LoadOptions{}); got != nil || !errors.Is(err, want) {
		t.Fatal("reader error lost")
	}
	path := filepath.Join(t.TempDir(), "nested", "soga.conf")
	if _, err := LoadFile(path, FileOptions{}); !os.IsNotExist(err) {
		t.Fatalf("readonly load should return missing file: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("readonly loading created file")
	}
	if _, err := LoadFile(path, FileOptions{CreateIfMissing: true}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("webapi_key=keep\n"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := LoadFile(path, FileOptions{CreateIfMissing: true})
	if err != nil || got.Config.WebapiKey != "keep" {
		t.Fatal("existing configuration must not be truncated")
	}
}

func TestDNSVariablesSelectsOnlyCredentials(t *testing.T) {
	text := "dns_provider=dns_cf\nDNS_CF_Key=file-key\ndns_strategy=prefer_ipv4\nwebapi_key=secret\n"
	loaded, err := Load(strings.NewReader(text), LoadOptions{Environ: []string{"DNS_CF_Email=env@example.com", "DNS_CF_Token="}})
	if err != nil {
		t.Fatal(err)
	}
	got := DNSVariables(loaded.Values)
	want := map[string]string{"dns_cf_key": "file-key", "dns_cf_email": "env@example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("DNSVariables = %v, want %v", got, want)
	}
}
