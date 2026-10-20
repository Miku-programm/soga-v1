package routing

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"testing"

	"github.com/pelletier/go-toml/v2"
	"reconstructed.local/soga/policy"
)

func TestOrderingProtocolAndBalance(t *testing.T) {
	doc := `enable=true
[[routes]]
protocol="udp"
rules=["node_id:7"]
balance="round_robin"
health_check=false
[[routes.Outs]]
type="socks"
server="127.0.0.1"
port=12345
[[routes.Outs]]
type="direct"
[[routes]]
rules=["domain:example.test"]
protocol="tcp"
balance="ip_hash"
[[routes.Outs]]
type="direct"
[[routes.Outs]]
type="redirect"
server="127.0.0.1"
port=99
`
	r, err := New([]byte(doc), nil)
	if err != nil {
		t.Fatal(err)
	}
	target := policy.Target{Host: "example.test", Network: "udp", NodeID: 7, UserID: 42, Port: 443}
	first, err := r.Select(target, "127.0.0.1:123")
	if err != nil {
		t.Fatal(err)
	}
	second, err := r.Select(target, "127.0.0.1:456")
	if err != nil || first.Tag == second.Tag {
		t.Fatal(first, second, err)
	}
	third, _ := r.Select(target, "127.0.0.1:789")
	if first.Tag != third.Tag {
		t.Fatal("round robin not stable")
	}
	target.Network = "tcp"
	first, _ = r.Select(target, "192.0.2.9:123")
	second, _ = r.Select(target, "192.0.2.9:456")
	if first.Tag != second.Tag {
		t.Fatal("source port changed IP hash")
	}
	target.Host = "unmatched.test"
	if _, err := r.Select(target, "127.0.0.1:1"); err == nil {
		t.Fatal("unmatched route did not close")
	}
	for _, bad := range []string{
		"enable=true",
		"enable=true\n[[routes]]\nprotocol='icmp'\n[[routes.Outs]]\ntype='direct'",
		"enable=true\n[[routes]]\nbalance='typo'\n[[routes.Outs]]\ntype='direct'",
		"enable=true\n[[routes]]\n[[routes.Outs]]\ntype='madeup'",
		"enabel=true",
	} {
		if _, err := New([]byte(bad), nil); err == nil {
			t.Fatal("invalid config accepted", bad)
		}
	}
}

func TestHealthExclusionAndBindFamily(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	doc := Document{Enable: true, Routes: []Route{{Protocol: "tcp", Outs: []Out{
		{Type: "socks", Server: "127.0.0.1", Port: port},
		{Type: "socks", Server: "127.0.0.1", Port: 1},
	}}}}
	data, err := toml.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	r, err := New(data, nil)
	if err != nil {
		t.Fatal(err)
	}
	r.Probe(context.Background())
	target := policy.Target{Network: "tcp", Host: "x", Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.1")}}
	for range 8 {
		s, err := r.Select(target, "127.0.0.1:1")
		if err != nil || s.Tag != r.outbounds[0].Tag {
			t.Fatal(s, err)
		}
	}
	l.Close()
	r.Probe(context.Background())
	if _, err := r.Select(target, "127.0.0.1:1"); err == nil {
		t.Fatal("all unavailable still routed")
	}
	bind, err := dialer(Out{Listen: "127.0.0.2", ListenIPv4: "127.0.0.3", ListenIPv6: "::1", ListenStrategy: "ipv6_first"})
	if err != nil || netip.Addr(*bind.Inet4BindAddress).String() != "127.0.0.3" || netip.Addr(*bind.Inet6BindAddress).String() != "::1" {
		t.Fatal(bind, err)
	}
}

func TestAllDocumentedOutboundMappings(t *testing.T) {
	doc := `enable=true
[[routes]]
rules=["*"]
health_check=false
[[routes.Outs]]
type="TYPE"
server="example.test"
port=443
uuid="2d15433b-392e-4522-b9cc-4b3a0a2c714f"
password="test"
cipher="aes-128-gcm"
`
	for _, kind := range []string{"direct", "redirect", "socks", "http", "vmess", "trojan", "ss"} {
		r, err := New([]byte(strings.Replace(doc, "TYPE", kind, 1)), nil)
		if err != nil || len(r.Outbounds()) != 1 {
			t.Fatal(kind, r, err)
		}
	}
}
