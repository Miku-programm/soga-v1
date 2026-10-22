package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/sniff"
	C "github.com/sagernet/sing-box/constant"
)

// captureClientHello runs a real crypto/tls client against a pipe and returns
// the raw record bytes of its ClientHello (all records until the handshake
// message is complete).
func captureClientHello(t *testing.T, cfg *tls.Config) []byte {
	t.Helper()
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	go func() { _ = tls.Client(a, cfg).Handshake() }()
	var out, hs []byte
	need := 4
	for len(hs) < need {
		header := make([]byte, 5)
		if _, err := io.ReadFull(b, header); err != nil {
			t.Fatal(err)
		}
		payload := make([]byte, int(binary.BigEndian.Uint16(header[3:])))
		if _, err := io.ReadFull(b, payload); err != nil {
			t.Fatal(err)
		}
		out = append(out, header...)
		out = append(out, payload...)
		hs = append(hs, payload...)
		if len(hs) >= 4 {
			need = 4 + (int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3]))
		}
	}
	return out
}

func tlsExt(typ uint16, body []byte) []byte {
	out := []byte{byte(typ >> 8), byte(typ), byte(len(body) >> 8), byte(len(body))}
	return append(out, body...)
}

func sniEntry(nameType byte, name string) []byte {
	out := []byte{nameType, byte(len(name) >> 8), byte(len(name))}
	return append(out, name...)
}

func sniExtension(entries ...[]byte) []byte {
	var list []byte
	for _, e := range entries {
		list = append(list, e...)
	}
	return tlsExt(0, append([]byte{byte(len(list) >> 8), byte(len(list))}, list...))
}

// wrapClientHello frames a ClientHello body as one handshake message in one
// TLS record.
func wrapClientHello(body []byte) []byte {
	msg := append([]byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	return append([]byte{22, 3, 1, byte(len(msg) >> 8), byte(len(msg))}, msg...)
}

// synthClientHelloPrefix is client_version, random and an empty session_id.
func synthClientHelloPrefix() []byte {
	return append([]byte{3, 3}, make([]byte, 33)...)
}

// synthClientHello builds a minimal single-record ClientHello. A nil exts
// omits the extensions block entirely; an empty non-nil exts emits an empty
// block.
func synthClientHello(exts [][]byte) []byte {
	body := synthClientHelloPrefix()
	body = append(body, 0, 2, 0x13, 0x01) // cipher_suites
	body = append(body, 1, 0)             // compression_methods
	if exts != nil {
		var all []byte
		for _, e := range exts {
			all = append(all, e...)
		}
		body = append(body, byte(len(all)>>8), byte(len(all)))
		body = append(body, all...)
	}
	return wrapClientHello(body)
}

// splitHelloRecord turns a single-record hello into two consecutive handshake
// records, the first carrying `at` bytes of the handshake payload.
func splitHelloRecord(t *testing.T, hello []byte, at int) []byte {
	t.Helper()
	payload := hello[5:]
	if int(binary.BigEndian.Uint16(hello[3:])) != len(payload) || at <= 0 || at >= len(payload) {
		t.Fatalf("cannot split %d-byte record at %d", len(payload), at)
	}
	var out []byte
	for _, part := range [][]byte{payload[:at], payload[at:]} {
		out = append(out, 22, 3, 3, byte(len(part)>>8), byte(len(part)))
		out = append(out, part...)
	}
	return out
}

func runStreamSniffer(fn sniff.StreamSniffer, data []byte) (domain, protocol string, err error) {
	var metadata adapter.InboundContext
	err = fn(context.Background(), &metadata, bytes.NewReader(data))
	return metadata.Domain, metadata.Protocol, err
}

// assertMatchesVendored runs the replacement and the vendored sniffer on every
// prefix of data and checks they agree: identical metadata on success, the
// same need-more-data signal on a valid truncated prefix, and never a domain
// where the vendored one fails.
func assertMatchesVendored(t *testing.T, data []byte) {
	t.Helper()
	for i := 0; i <= len(data); i++ {
		refDomain, refProtocol, refErr := runStreamSniffer(sniff.TLSClientHello, data[:i])
		gotDomain, gotProtocol, gotErr := runStreamSniffer(sniffTLSClientHello, data[:i])
		switch {
		case refErr == nil:
			if gotErr != nil || gotDomain != refDomain || gotProtocol != refProtocol {
				t.Fatalf("prefix %d/%d: vendored (%q,%q), got (%q,%q) err %v", i, len(data), refDomain, refProtocol, gotDomain, gotProtocol, gotErr)
			}
		case errors.Is(refErr, sniff.ErrNeedMoreData):
			if !errors.Is(gotErr, sniff.ErrNeedMoreData) {
				t.Fatalf("prefix %d/%d: vendored needs more data, got %v", i, len(data), gotErr)
			}
		default:
			// crypto/tls reports a bare io.EOF when the input ends exactly on
			// a record boundary mid-handshake; asking for more data there is
			// the one accepted divergence.
			if gotErr == nil {
				t.Fatalf("prefix %d/%d: vendored failed with %v, got success %q", i, len(data), refErr, gotDomain)
			}
		}
		if gotErr != nil && (gotDomain != "" || gotProtocol != "") {
			t.Fatalf("prefix %d/%d: metadata touched on error %v", i, len(data), gotErr)
		}
	}
}

func realClientHellos(t *testing.T) map[string][]byte {
	t.Helper()
	return map[string][]byte{
		"tls13-mlkem-sni": captureClientHello(t, &tls.Config{ServerName: "sniff.example.com", InsecureSkipVerify: true}),
		"tls13-no-sni":    captureClientHello(t, &tls.Config{InsecureSkipVerify: true}),
		"tls13-ip-sni":    captureClientHello(t, &tls.Config{ServerName: "192.0.2.1", InsecureSkipVerify: true}),
		"tls12-sni":       captureClientHello(t, &tls.Config{ServerName: "legacy.example.net", InsecureSkipVerify: true, MaxVersion: tls.VersionTLS12}),
	}
}

func TestSniffTLSClientHelloRealHellos(t *testing.T) {
	want := map[string]string{
		"tls13-mlkem-sni": "sniff.example.com",
		"tls13-no-sni":    "",
		"tls13-ip-sni":    "", // crypto/tls omits SNI for IP literals
		"tls12-sni":       "legacy.example.net",
	}
	for name, hello := range realClientHellos(t) {
		t.Run(name, func(t *testing.T) {
			domain, protocol, err := runStreamSniffer(sniffTLSClientHello, hello)
			if err != nil || domain != want[name] || protocol != C.ProtocolTLS {
				t.Fatalf("got (%q,%q,%v), want (%q,%q,nil)", domain, protocol, err, want[name], C.ProtocolTLS)
			}
			// The fast path, not the fallback, must handle real hellos.
			scratch := make([]byte, tlsSniffHelloCap)
			if d, err := parseClientHello(hello, scratch); err != nil || d != want[name] {
				t.Fatalf("parseClientHello: (%q,%v), want (%q,nil)", d, err, want[name])
			}
			for i := 0; i < len(hello); i++ {
				if d, err := parseClientHello(hello[:i], scratch); !errors.Is(err, sniff.ErrNeedMoreData) || d != "" {
					t.Fatalf("prefix %d: (%q,%v), want need more data", i, d, err)
				}
			}
			assertMatchesVendored(t, hello)
		})
	}
}

func TestSniffTLSClientHelloFragmentedRecords(t *testing.T) {
	hello := captureClientHello(t, &tls.Config{ServerName: "split.example.org", InsecureSkipVerify: true})
	payload := len(hello) - 5
	for _, at := range []int{1, 3, 4, 5, 40, payload / 2, payload - 1} {
		t.Run(fmt.Sprintf("at-%d", at), func(t *testing.T) {
			split := splitHelloRecord(t, hello, at)
			scratch := make([]byte, tlsSniffHelloCap)
			if d, err := parseClientHello(split, scratch); err != nil || d != "split.example.org" {
				t.Fatalf("parseClientHello: (%q,%v)", d, err)
			}
			for i := 0; i < len(split); i++ {
				if d, err := parseClientHello(split[:i], scratch); !errors.Is(err, sniff.ErrNeedMoreData) || d != "" {
					t.Fatalf("prefix %d: (%q,%v), want need more data", i, d, err)
				}
			}
			// Exactly at the record boundary crypto/tls gives up with io.EOF
			// while the parser keeps reading; both agree on everything else.
			boundary := 5 + at
			if _, _, err := runStreamSniffer(sniffTLSClientHello, split[:boundary]); !errors.Is(err, sniff.ErrNeedMoreData) {
				t.Fatalf("record boundary: %v", err)
			}
			assertMatchesVendored(t, split)
		})
	}
}

func TestSniffTLSClientHelloSyntheticAndGarbage(t *testing.T) {
	validSNI := sniExtension(sniEntry(0, "synthetic.example"))
	sniBody := append([]byte(nil), validSNI[4:]...)
	oddSuites := append(synthClientHelloPrefix(), 0, 3, 0x13, 0x01, 0x13, 1, 0)
	cases := map[string]struct {
		data   []byte
		domain string
		ok     bool
	}{
		"no-extensions":        {synthClientHello(nil), "", true},
		"empty-extensions":     {synthClientHello([][]byte{}), "", true},
		"sni":                  {synthClientHello([][]byte{validSNI}), "synthetic.example", true},
		"sni-after-other":      {synthClientHello([][]byte{tlsExt(43, []byte{2, 3, 4}), validSNI}), "synthetic.example", true},
		"sni-other-type-first": {synthClientHello([][]byte{sniExtension(sniEntry(7, "ignored"), sniEntry(0, "second.example"))}), "second.example", true},
		"trailing-dot":         {synthClientHello([][]byte{sniExtension(sniEntry(0, "dot.example."))}), "", false},
		"empty-name":           {synthClientHello([][]byte{sniExtension(sniEntry(0, ""))}), "", false},
		"two-host-names":       {synthClientHello([][]byte{sniExtension(sniEntry(0, "a.example"), sniEntry(0, "b.example"))}), "", false},
		"empty-name-list":      {synthClientHello([][]byte{tlsExt(0, []byte{0, 0})}), "", false},
		"sni-trailing-junk":    {synthClientHello([][]byte{tlsExt(0, append(sniBody, 0))}), "", false},
		"duplicate-extension":  {synthClientHello([][]byte{validSNI, validSNI}), "", false},
		"extension-overrun":    {synthClientHello([][]byte{tlsExt(43, []byte{2, 3, 4})[:5]}), "", false},
		"odd-cipher-suites":    {wrapClientHello(oddSuites), "", false},
		"server-hello":         {[]byte{22, 3, 1, 0, 6, 2, 0, 0, 2, 3, 3}, "", false},
		"application-data":     {[]byte{23, 3, 3, 0, 4, 1, 2, 3, 4}, "", false},
		"oversized-record":     {append([]byte{22, 3, 1, 0xff, 0xff}, make([]byte, 64)...), "", false},
		"http":                 {[]byte("GET / HTTP/1.1\r\nHost: plain.example\r\n\r\n"), "", false},
		"garbage":              {bytes.Repeat([]byte{0x16, 0x03, 0xde, 0xad, 0xbe, 0xef, 0x00}, 11), "", false},
		"ssh":                  {[]byte("SSH-2.0-OpenSSH_9.6\r\n"), "", false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			domain, protocol, err := runStreamSniffer(sniffTLSClientHello, tc.data)
			if tc.ok && (err != nil || domain != tc.domain || protocol != C.ProtocolTLS) {
				t.Fatalf("got (%q,%q,%v), want (%q,%q,nil)", domain, protocol, err, tc.domain, C.ProtocolTLS)
			}
			if !tc.ok && (err == nil || errors.Is(err, sniff.ErrNeedMoreData) || domain != "" || protocol != "") {
				t.Fatalf("got (%q,%q,%v), want a hard error", domain, protocol, err)
			}
			assertMatchesVendored(t, tc.data)
		})
	}
}

func TestSniffTLSClientHelloOverlongHandshake(t *testing.T) {
	// A handshake header claiming more than crypto/tls's 64 KiB cap is not a
	// ClientHello, no matter how much data follows.
	data := append([]byte{22, 3, 1, 0, 8, 1, 0x01, 0, 1, 3, 3, 0, 0}, make([]byte, 16)...)
	if d, err := parseClientHello(data, make([]byte, tlsSniffHelloCap)); err != errNotClientHello || d != "" {
		t.Fatalf("got (%q,%v)", d, err)
	}
	assertMatchesVendored(t, data)
}

func TestSniffTLSClientHelloFallbackDecidesEmptyRecord(t *testing.T) {
	// The parser rejects a zero-length handshake record and defers to the
	// vendored sniffer, so whatever crypto/tls decides is what the caller
	// sees; only agreement is asserted.
	data := append([]byte{22, 3, 1, 0, 0}, synthClientHello([][]byte{sniExtension(sniEntry(0, "empty.example"))})...)
	if _, err := parseClientHello(data, make([]byte, tlsSniffHelloCap)); err != errNotClientHello {
		t.Fatalf("parseClientHello: %v", err)
	}
	assertMatchesVendored(t, data)
}

func TestParseClientHelloDoesNotAllocate(t *testing.T) {
	hello := captureClientHello(t, &tls.Config{ServerName: "alloc.example", InsecureSkipVerify: true})
	scratch := make([]byte, tlsSniffHelloCap)
	// The only permitted allocation is the returned domain string.
	if allocs := testing.AllocsPerRun(200, func() { parseClientHello(hello, scratch) }); allocs > 1 {
		t.Fatalf("parseClientHello allocates %v times per run", allocs)
	}
}
