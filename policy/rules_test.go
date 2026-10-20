package policy

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

func TestFirstPacketRulesAndExemption(t *testing.T) {
	rule, err := Compile(`regexp:FORBIDDEN-[0-9]+`, nil)
	if err != nil {
		t.Fatal(err)
	}
	rule.AuditID = 71
	p := Policy{Block: []Rule{rule}, DetectPacket: true, ForbidBitTorrent: true}
	target := Target{Host: "example.test", UserID: 3}
	var denied *Denied
	if err := p.CheckPacket(target, []byte("GET /FORBIDDEN-42 HTTP/1.1")); !errors.As(err, &denied) || denied.AuditID != 71 {
		t.Fatal("packet rule/audit ID missing", err)
	}
	if err := p.CheckPacket(target, []byte("GET /forbidden-42 HTTP/1.1")); err != nil {
		t.Fatal("raw packet regex lost case semantics", err)
	}
	if err := p.CheckPacket(target, []byte("\x13BitTorrent protocol")); err == nil {
		t.Fatal("plaintext BT handshake accepted")
	}
	p.ExemptUsers = map[int64]bool{3: true}
	if err := p.CheckPacket(target, []byte("FORBIDDEN-42")); err != nil {
		t.Fatal("exempt user blocked", err)
	}
}

func TestDocumentedRules(t *testing.T) {
	tests := []struct{ rule, yes, no string }{
		{"sina.com", "www.sina.com.cn", "sina.cn"},
		{"domain:google.com", "a.google.com", "evilgoogle.com"},
		{"full:google.com", "GOOGLE.COM.", "a.google.com"},
		{`regexp:^www\.google\.com$`, "www.google.com", "google.com"},
		{"ip:192.168.0.0/16", "192.168.2.1", "192.167.0.1"},
		{"ip:2001:db8::/32", "2001:db8::1", "2001:db9::1"},
	}
	for _, test := range tests {
		r, err := Compile(test.rule, nil)
		if err != nil || !r.Match(Target{Host: test.yes}) || r.Match(Target{Host: test.no}) {
			t.Fatalf("%+v: %v", test, err)
		}
	}
	r, err := Compile("port:1-1024,8443", nil)
	if err != nil || !r.Match(Target{Port: 1024}) || !r.Match(Target{Port: 8443}) || r.Match(Target{Port: 8444}) {
		t.Fatal(err)
	}
	r, err = Compile("node_id:4,6", nil)
	if err != nil || !r.Match(Target{NodeID: 6}) || r.Match(Target{NodeID: 5}) {
		t.Fatal(err)
	}
	for _, bad := range []string{"port:80-1", "port:65536", "regexp:[", "ip:broken", "domain:", "geoip:missing", "geosite:missing"} {
		if _, err := Compile(bad, nil); err == nil {
			t.Fatalf("invalid rule accepted: %s", bad)
		}
	}
}

func TestWhiteListHasPriorityAndResolvedIPIsChecked(t *testing.T) {
	white, _ := CompileAll([]string{"domain:allowed.test"}, nil)
	block, _ := CompileAll([]string{"port:1-65535"}, nil)
	p := Policy{White: white, Block: block, BanPrivate: true}
	if err := p.Check(Target{Host: "allowed.test", Port: 443, Addresses: []netip.Addr{netip.MustParseAddr("127.0.0.1")}}); err != nil {
		t.Fatal(err)
	}
	if p.Check(Target{Host: "blocked.test", Port: 443}) == nil {
		t.Fatal("block rule ignored")
	}
	p.Block = nil
	if p.Check(Target{Host: "rebinding.test", Addresses: []netip.Addr{netip.MustParseAddr("127.0.0.1")}}) == nil {
		t.Fatal("resolved private address ignored")
	}
}

func TestGeoDataWireDecodeAndMalformedInput(t *testing.T) {
	// GeoSiteList(entry={country_code:"TEST",domain={RootDomain,"example.test"}}).
	domain := append([]byte{8, 2, 18, 12}, []byte("example.test")...)
	entry := append([]byte{10, 4, 'T', 'E', 'S', 'T', 18, byte(len(domain))}, domain...)
	data := append([]byte{10, byte(len(entry))}, entry...)
	dir := t.TempDir()
	path := filepath.Join(dir, "geosite.dat")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	g, err := LoadGeoData(path, "")
	if err != nil {
		t.Fatal(err)
	}
	r, err := Compile("geosite:test", g)
	if err != nil || !r.Match(Target{Host: "sub.example.test"}) || r.Match(Target{Host: "evilexample.test"}) {
		t.Fatal(err)
	}
	if _, err := Compile("geosite:absent", g); err == nil {
		t.Fatal("missing category accepted")
	}
	// GeoIPList(entry={"TEST", CIDR{192.0.2.0,24}}).
	cidr := []byte{10, 4, 192, 0, 2, 0, 16, 24}
	ipEntry := append([]byte{10, 4, 'T', 'E', 'S', 'T', 18, byte(len(cidr))}, cidr...)
	if err := g.parse(append([]byte{10, byte(len(ipEntry))}, ipEntry...), false); err != nil {
		t.Fatal(err)
	}
	r, err = Compile("geoip:test", g)
	if err != nil || !r.Match(Target{Host: "192.0.2.30"}) || r.Match(Target{Host: "192.0.3.30"}) {
		t.Fatal(err)
	}
	for _, malformed := range [][]byte{{10, 255}, {0}, {10, 5, 1}, {15}, {8, 1}} {
		if err := g.parse(malformed, true); err == nil {
			t.Fatalf("accepted malformed data: %x", malformed)
		}
	}
}
