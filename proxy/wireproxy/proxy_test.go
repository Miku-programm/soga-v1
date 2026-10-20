package wireproxy

import (
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/pires/go-proxyproto"
)

func tcpAddr(ip string) net.Addr { return &net.TCPAddr{IP: net.ParseIP(ip), Port: 4000} }

func TestParseTrusted(t *testing.T) {
	trusted, err := ParseTrusted(" 203.0.113.7, 198.51.100.0/24 2001:db8::/32\t::ffff:192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	for _, ip := range []string{"203.0.113.7", "198.51.100.200", "2001:db8::5", "192.0.2.1", "::ffff:203.0.113.7"} {
		if !trusted.Allows(tcpAddr(ip)) {
			t.Fatalf("%s should be trusted", ip)
		}
	}
	for _, ip := range []string{"203.0.113.8", "198.51.101.1", "2001:db9::1"} {
		if trusted.Allows(tcpAddr(ip)) {
			t.Fatalf("%s should not be trusted", ip)
		}
	}
	for _, bad := range []string{"relay.example", "10.0.0.0/33", "1.2.3.4/"} {
		if _, err := ParseTrusted(bad); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
	empty, err := ParseTrusted(" , ")
	if err != nil || len(empty) != 0 || !empty.Allows(tcpAddr("198.51.100.9")) {
		t.Fatal("an empty list must keep trusting every peer")
	}
}

func TestPolicyHonoursOnlyTrustedPeers(t *testing.T) {
	trusted, _ := ParseTrusted("203.0.113.7")
	relay, client := tcpAddr("203.0.113.7"), tcpAddr("198.51.100.9")
	for _, test := range []struct {
		peer     net.Addr
		required bool
		want     proxyproto.Policy
	}{
		{relay, false, proxyproto.USE},
		{relay, true, proxyproto.REQUIRE},
		{client, false, proxyproto.IGNORE},
	} {
		if got, err := trusted.Policy(test.peer, test.required); err != nil || got != test.want {
			t.Fatalf("Policy(%v, %v) = %v, %v; want %v", test.peer, test.required, got, err, test.want)
		}
	}
	if _, err := trusted.Policy(client, true); !errors.Is(err, proxyproto.ErrInvalidUpstream) {
		t.Fatal("untrusted peer accepted where a header is required", err)
	}
	if got, err := Trusted(nil).Policy(client, false); err != nil || got != proxyproto.USE {
		t.Fatal("empty list changed the historical policy")
	}
}

// connect sends a PROXY v1 header claiming 192.0.2.10:1234 followed by data.
func connect(t *testing.T, trusted Trusted, required bool) (net.Conn, error) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		c, err := net.Dial("tcp", l.Addr().String())
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = c.Write([]byte("PROXY TCP4 192.0.2.10 192.0.2.20 1234 443\r\nhello"))
		_, _ = io.Copy(io.Discard, c)
	}()
	raw, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { raw.Close() })
	_ = raw.SetDeadline(time.Now().Add(10 * time.Second))
	return Connection(raw, required, trusted)
}

func TestConnectionUsesHeaderOnlyFromTrustedPeer(t *testing.T) {
	loopback, _ := ParseTrusted("127.0.0.1")
	elsewhere, _ := ParseTrusted("203.0.113.7")
	for _, test := range []struct {
		name    string
		trusted Trusted
		source  string
	}{
		{"trusted", loopback, "192.0.2.10:1234"},
		{"untrusted", elsewhere, "127.0.0.1"},
	} {
		t.Run(test.name, func(t *testing.T) {
			conn, err := connect(t, test.trusted, false)
			if err != nil {
				t.Fatal(err)
			}
			got := conn.RemoteAddr().String()
			if !strings.HasPrefix(got, test.source) {
				t.Fatalf("source = %s, want %s", got, test.source)
			}
			payload := make([]byte, 5)
			if _, err := io.ReadFull(conn, payload); err != nil || string(payload) != "hello" {
				t.Fatalf("payload = %q, %v", payload, err)
			}
		})
	}
	if _, err := connect(t, elsewhere, true); err == nil {
		t.Fatal("required header accepted from an untrusted peer")
	}
}

func TestDatagramUsesHeaderOnlyFromTrustedPeer(t *testing.T) {
	claimed := &net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 1234}
	header := &proxyproto.Header{Version: 2, Command: proxyproto.PROXY, TransportProtocol: proxyproto.UDPv4,
		SourceAddr: claimed, DestinationAddr: &net.UDPAddr{IP: net.ParseIP("192.0.2.20"), Port: 443}}
	wire, err := header.Format()
	if err != nil {
		t.Fatal(err)
	}
	wire = append(wire, "data"...)
	relay := &net.UDPAddr{IP: net.ParseIP("203.0.113.7"), Port: 5000}
	client := &net.UDPAddr{IP: net.ParseIP("198.51.100.9"), Port: 5000}
	trusted, _ := ParseTrusted("203.0.113.7")

	payload, source, err := Datagram(wire, relay, false, trusted)
	if err != nil || string(payload) != "data" || source.String() != claimed.String() {
		t.Fatalf("trusted relay: %q %v %v", payload, source, err)
	}
	payload, source, err = Datagram(wire, client, false, trusted)
	if err != nil || string(payload) != "data" || source.String() != client.String() {
		t.Fatalf("untrusted client: %q %v %v", payload, source, err)
	}
	if _, _, err = Datagram(wire, client, true, trusted); err == nil {
		t.Fatal("required header accepted from an untrusted peer")
	}
	if _, source, _ = Datagram(wire, client, false, nil); source.String() != claimed.String() {
		t.Fatal("empty list changed the historical behaviour")
	}
}
