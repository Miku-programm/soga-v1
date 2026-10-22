package ssrcore

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	simpleclient "github.com/sagernet/sing-box/transport/simple-obfs"
	M "github.com/sagernet/sing/common/metadata"
	"reconstructed.local/soga/proxy/ssrcore/internal/vnet/common/obfs"
)

func muOptions(protocol, obfuscator string) Options {
	return Options{Listen: "127.0.0.1", Method: "aes-128-cfb", Password: "shared-carrier-key",
		Protocol: protocol, Obfs: obfuscator, SinglePortType: "obfs", CarrierID: 900,
		Users: []User{
			{ID: 5000000001, Password: "ordinary-user-one", Method: "aes-256-cfb", Protocol: "auth_chain_b", Obfs: "plain"},
			{ID: 202, Password: "ordinary-user-two", Method: "chacha20", Protocol: "origin", Obfs: "http_simple"},
		}}
}

// mu clients use the carrier's key and protocol parameters; the ordinary
// user's properties only determine the Host/SNI selector.
func muClient(t *testing.T, address string, o Options, host, password string) *streamConn {
	t.Helper()
	raw, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	raw.SetDeadline(time.Now().Add(5 * time.Second))
	var transport net.Conn = raw
	if o.Obfs == "simple_obfs_http" {
		transport = simpleclient.NewHTTPObfs(raw, host, "80")
		o.Obfs = "plain"
	} else if o.Obfs == "simple_obfs_tls" {
		transport = simpleclient.NewTLSObfs(raw, host)
		o.Obfs = "plain"
	}
	o.ObfsParam, o.Password = host, password
	o.ProtocolParam = ""
	c, err := newCodec(o, obfs.NewObfsAuthChainData(o.Protocol), nil)
	if err != nil {
		raw.Close()
		t.Fatal(err)
	}
	c.client = true
	return &streamConn{Conn: transport, codec: c}
}

func TestMuCarrierCipherAndSelectedBillingUser(t *testing.T) {
	for _, protocol := range Protocols() {
		for _, obfuscator := range Obfuscators()[1:] {
			t.Run(protocol+"/"+obfuscator, func(t *testing.T) {
				o := muOptions(protocol, obfuscator)
				o.ForceProxyProtocol = true // Force alone does not enable either transport's PROXY parser.
				s, router := startTestServer(t, o)
				if s.udp != nil {
					t.Fatal("obfs single-port UDP must be disabled by default")
				}
				for _, u := range o.Users {
					host, _ := HostForUser(u, "%5m%id.%suffix", "microsoft.com")
					c := muClient(t, s.tcp.Addr().String(), o, host, o.Password)
					header, _ := appendAddress(nil, M.ParseSocksaddr("example.com:443"))
					want := bytes.Repeat([]byte("different-user-same-carrier-key"), 1000)
					if _, err := c.Write(append(header, want...)); err != nil {
						c.Close()
						t.Fatal(err)
					}
					got := make([]byte, len(want))
					_, err := io.ReadFull(c, got)
					c.Close()
					if err != nil || !bytes.Equal(got, want) {
						t.Fatalf("carrier cipher roundtrip: %v", err)
					}
				}
				router.mu.Lock()
				defer router.mu.Unlock()
				if fmt.Sprint(router.users) != "[5000000001 202]" ||
					fmt.Sprint(router.unattributed) != "[false false]" ||
					fmt.Sprint(router.clientIDs) != "[false false]" {
					t.Fatalf("mu identities or quota semantics: %v %v %v", router.users, router.unattributed, router.clientIDs)
				}
			})
		}
	}
}

func TestMuSimpleObfsLegacyOfficialClients(t *testing.T) {
	for _, obfuscator := range []string{"simple_obfs_http", "simple_obfs_tls"} {
		t.Run(obfuscator, func(t *testing.T) {
			o := muOptions("origin", obfuscator)
			s, router := startTestServer(t, o)
			for _, u := range o.Users {
				host, _ := HostForUser(u, "%5m%id.%suffix", "microsoft.com")
				c := muClient(t, s.tcp.Addr().String(), o, host, o.Password)
				header, _ := appendAddress(nil, M.ParseSocksaddr("example.com:443"))
				want := bytes.Repeat([]byte("simple-obfs-real-carrier-payload"), 3000)
				if _, err := c.Write(append(header, want...)); err != nil {
					t.Fatal(err)
				}
				got := make([]byte, len(want))
				_, err := io.ReadFull(c, got)
				c.Close()
				if err != nil || !bytes.Equal(got, want) {
					t.Fatalf("official simple-obfs roundtrip: %v", err)
				}
			}
			router.mu.Lock()
			defer router.mu.Unlock()
			if fmt.Sprint(router.users) != "[5000000001 202]" {
				t.Fatalf("billing IDs: %v", router.users)
			}
		})
	}
}

func TestMuUnknownHostAndOrdinaryPasswordDoNotRoute(t *testing.T) {
	for _, obfuscator := range append(Obfuscators()[1:], "simple_obfs_http", "simple_obfs_tls") {
		t.Run(obfuscator, func(t *testing.T) {
			protocol := "auth_chain_b"
			if obfuscator == "simple_obfs_http" || obfuscator == "simple_obfs_tls" {
				protocol = "origin"
			}
			o := muOptions(protocol, obfuscator)
			s, router := startTestServer(t, o)
			host, _ := HostForUser(o.Users[0], "%5m%id.%suffix", "microsoft.com")
			for i, wrong := range [][2]string{{"unknown.microsoft.com", o.Password}, {host, o.Users[0].Password}} {
				c := muClient(t, s.tcp.Addr().String(), o, wrong[0], wrong[1])
				c.SetDeadline(time.Now().Add(time.Second))
				header, _ := appendAddress(nil, M.ParseSocksaddr("example.com:443"))
				c.Write(append(header, bytes.Repeat([]byte("bad"), 500)...))
				_, err := c.Read(make([]byte, 100))
				c.Close()
				// The origin protocol carries no authentication: a wrong key is
				// only noticed because the address decrypts to garbage, and about
				// 3 in 256 garbage headers still parse. Such a stream must never
				// reach the requested target; authenticated cases must be refused.
				if err == nil && (i == 0 || protocol != "origin") {
					t.Fatal("invalid host or wrong carrier key accepted")
				}
			}
			router.mu.Lock()
			defer router.mu.Unlock()
			if protocol != "origin" && len(router.users) != 0 {
				t.Fatalf("invalid carrier credentials routed: %v", router.users)
			}
			for _, target := range router.targets {
				if target == "example.com:443" {
					t.Fatalf("invalid carrier credentials reached the requested target: %v", router.targets)
				}
			}
		})
	}
}

func TestMuOptInUDPIsUnattributedCarrierTraffic(t *testing.T) {
	for _, protocol := range Protocols() {
		t.Run(protocol, func(t *testing.T) {
			o := muOptions(protocol, "http_simple")
			o.ObfsUDP = true
			if protocol == "origin" {
				o.CarrierID = 0 // SSPanel synthetic mu carrier has no billing account.
			}
			o.ProxyProtocol, o.ForceProxyProtocol = true, true // A TCP-only PROXY setting must not force UDP headers.
			s, router := startTestServer(t, o)
			raw, err := net.Dial("udp", s.udp.LocalAddr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer raw.Close()
			raw.SetDeadline(time.Now().Add(3 * time.Second))
			c, err := newCodec(o, obfs.NewObfsAuthChainData(o.Protocol), nil)
			if err != nil {
				t.Fatal(err)
			}
			header, _ := appendAddress(nil, M.ParseSocksaddr("8.8.8.8:53"))
			want := append(header, bytes.Repeat([]byte("carrier-udp"), 200)...)
			wire, err := c.protocol.ClientUDPPreEncrypt(want)
			if err == nil {
				wire, err = c.enc.EncryptAll(wire, c.enc.MustNewIV())
			}
			if err != nil {
				t.Fatal(err)
			}
			raw.Write(wire)
			b := make([]byte, 65535)
			n, err := raw.Read(b)
			if err != nil {
				t.Fatal(err)
			}
			clear, _, err := c.enc.DecryptAll(b[:n])
			if err == nil {
				clear, err = c.protocol.ClientUDPPostDecrypt(clear)
			}
			if err != nil || !bytes.Equal(clear, want) {
				t.Fatalf("carrier UDP roundtrip: %v", err)
			}
			router.mu.Lock()
			defer router.mu.Unlock()
			if fmt.Sprint(router.users) != fmt.Sprintf("[%d]", o.CarrierID) || fmt.Sprint(router.unattributed) != "[true]" ||
				fmt.Sprint(router.clientIDs) != "[false]" {
				t.Fatalf("carrier UDP attribution: %v %v %v", router.users, router.unattributed, router.clientIDs)
			}
		})
	}
}
