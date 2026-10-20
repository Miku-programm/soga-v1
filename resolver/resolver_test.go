package resolver

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestRealDNSProtocolsAndCache(t *testing.T) {
	var calls atomic.Int64
	answer := func(q *dns.Msg) *dns.Msg {
		calls.Add(1)
		r := new(dns.Msg)
		r.SetReply(q)
		if q.Question[0].Qtype == dns.TypeA {
			r.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("192.0.2.19")}}
		} else {
			r.Answer = []dns.RR{&dns.AAAA{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60}, AAAA: net.ParseIP("2001:db8::19")}}
		}
		return r
	}
	https := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		q := new(dns.Msg)
		if err := q.Unpack(data); err != nil {
			t.Error(err)
			http.Error(w, "bad query", 400)
			return
		}
		data, _ = answer(q).Pack()
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(data)
	}))
	defer https.Close()
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) { _ = w.WriteMsg(answer(q)) })
	p, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	udp := &dns.Server{PacketConn: p, Handler: handler}
	go udp.ActivateAndServe()
	defer udp.Shutdown()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tcp := &dns.Server{Listener: l, Handler: handler}
	go tcp.ActivateAndServe()
	defer tcp.Shutdown()
	tl, err := tls.Listen("tcp", "127.0.0.1:0", https.TLS.Clone())
	if err != nil {
		t.Fatal(err)
	}
	dot := &dns.Server{Listener: tl, Handler: handler}
	go dot.ActivateAndServe()
	defer dot.Shutdown()
	pool := x509.NewCertPool()
	pool.AddCert(https.Certificate())
	for _, server := range []string{p.LocalAddr().String(), "tcp://" + l.Addr().String(), "tcp-tls://" + tl.Addr().String(), https.URL + "/dns-query"} {
		t.Run(server, func(t *testing.T) {
			before := calls.Load()
			r, err := New(nil, Options{Defaults: []string{server}, Strategy: "ipv6_first", CacheTime: time.Minute,
				HTTPClient: https.Client(), TLSConfig: &tls.Config{RootCAs: pool},
				SystemLookup: func(context.Context, string, string) ([]netip.Addr, error) {
					t.Error("unexpected system fallback")
					return nil, errors.New("fallback")
				}})
			if err != nil {
				t.Fatal(err)
			}
			for range 2 {
				ips, err := r.Lookup(context.Background(), "test.invalid")
				if err != nil || len(ips) != 2 || ips[0].String() != "2001:db8::19" || ips[1].String() != "192.0.2.19" {
					t.Fatal(ips, err)
				}
				ips[0] = netip.Addr{} // A caller cannot poison the cached slice.
			}
			if calls.Load()-before != 2 {
				t.Fatal("cache missed", calls.Load()-before)
			}
		})
	}
}

func TestOrderedYAMLRulesAndFallback(t *testing.T) {
	var hits [2]atomic.Int64
	var addresses []string
	for i := range 2 {
		p, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		server := &dns.Server{PacketConn: p, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
			hits[i].Add(1)
			r := new(dns.Msg)
			r.SetReply(q)
			r.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("192.0.2." + strconv.Itoa(i+1))}}
			_ = w.WriteMsg(r)
		})}
		go server.ActivateAndServe()
		defer server.Shutdown()
		addresses = append(addresses, p.LocalAddr().String())
	}
	data := addresses[0] + ":\n  strategy: ipv4_only\n  rules: [domain:example.test]\n" + addresses[1] + ":\n  - '*'\n"
	r, err := New([]byte(data), Options{Strategy: "ipv4_only"})
	if err != nil {
		t.Fatal(err)
	}
	a, err := r.Lookup(context.Background(), "a.example.test")
	if err != nil || a[0].String() != "192.0.2.1" {
		t.Fatal(a, err)
	}
	a, err = r.Lookup(context.Background(), "else.test")
	if err != nil || a[0].String() != "192.0.2.2" {
		t.Fatal(a, err)
	}
	if hits[0].Load() != 1 || hits[1].Load() != 1 {
		t.Fatal("mapping order lost")
	}
	local := addresses[0] + ":\n  - domain:example.test\n"
	r, err = New([]byte(local), Options{Strategy: "ipv4_only",
		PanelRules: []RuleGroup{{Domains: []string{"*"}, Servers: []string{addresses[1]}}}})
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{"a.example.test": "192.0.2.1", "panel.test": "192.0.2.2"} {
		a, err = r.Lookup(context.Background(), name)
		if err != nil || len(a) != 1 || a[0].String() != want {
			t.Fatal(name, a, err)
		}
	}
	var fallback atomic.Int64
	r, err = New(nil, Options{Defaults: []string{"tcp://127.0.0.1:1"}, Strategy: "ipv6_only",
		SystemLookup: func(_ context.Context, network, host string) ([]netip.Addr, error) {
			if network != "ip6" {
				t.Error(network)
			}
			fallback.Add(1)
			return []netip.Addr{netip.MustParseAddr("2001:db8::5")}, nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = r.Lookup(context.Background(), "fallback.test"); err != nil || fallback.Load() != 1 {
		t.Fatal(err)
	}
	for _, bad := range []string{"x: {stratgy: ipv4_only}", "x: {strategy: nonsense}", "x: [domain:x]\nx: [domain:y]", "[]"} {
		if _, err := New([]byte(bad), Options{}); err == nil {
			t.Fatal("invalid YAML accepted", bad)
		}
	}
}
