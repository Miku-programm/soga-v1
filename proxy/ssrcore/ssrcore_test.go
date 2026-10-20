package ssrcore

import (
	"bytes"
	"context"
	"fmt"
	"github.com/sirupsen/logrus"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"reconstructed.local/soga/proxy/ssrcore/internal/vnet/common/obfs"
)

func TestMain(m *testing.M) {
	logrus.SetOutput(io.Discard)
	os.Exit(m.Run())
}

type testRouter struct {
	adapter.Router
	mu           sync.Mutex
	users        []string
	targets      []string
	sources      []string
	unattributed []bool
	clientIDs    []bool
}

func (r *testRouter) record(ctx context.Context, m adapter.InboundContext) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.users = append(r.users, m.User)
	r.targets = append(r.targets, m.Destination.String())
	r.sources = append(r.sources, m.Source.String())
	r.unattributed = append(r.unattributed, UnattributedTraffic(ctx))
	_, cid := AuthenticatedClientID(ctx)
	r.clientIDs = append(r.clientIDs, cid)
}
func (r *testRouter) RouteConnectionEx(ctx context.Context, c net.Conn, m adapter.InboundContext, done N.CloseHandlerFunc) {
	r.record(ctx, m)
	go func() {
		_, err := io.Copy(c, c)
		done(err)
	}()
}
func (r *testRouter) RoutePacketConnectionEx(ctx context.Context, c N.PacketConn, m adapter.InboundContext, done N.CloseHandlerFunc) {
	r.record(ctx, m)
	defer done(nil)
	for {
		b := buf.NewPacket()
		d, err := c.ReadPacket(b)
		if err != nil {
			b.Release()
			return
		}
		if c.WritePacket(b, d) != nil {
			return
		}
	}
}

func startTestServer(t *testing.T, o Options) (*server, *testRouter) {
	t.Helper()
	r := &testRouter{}
	in, err := NewInbound(context.Background(), r, nil, "test", o)
	if err != nil {
		t.Fatal(err)
	}
	s := in.(*server)
	scope := adapter.NewScope(context.Background(), nil)
	if err = s.Start(adapter.StartStateStart, scope); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { scope.Close() })
	return s, r
}

func clientCodec(t *testing.T, o Options, id int64, password string) *codec {
	t.Helper()
	// A separate client-side state and replay counter, matching SSR subscription
	// protocol_param "uid:password", while outer Password is the node password.
	o.ProtocolParam = strconv.FormatInt(id, 10) + ":" + password
	c, err := newCodec(o, obfs.NewObfsAuthChainData(o.Protocol), nil)
	if err != nil {
		t.Fatal(err)
	}
	c.client = true
	return c
}

func TestTCPAuthenticatedUsersAndObfuscators(t *testing.T) {
	for _, protocol := range Protocols()[2:] {
		for _, obfuscator := range Obfuscators() {
			t.Run(protocol+"/"+obfuscator, func(t *testing.T) {
				o := Options{Listen: "127.0.0.1", Method: "aes-128-cfb", Password: "outer-secret",
					Protocol: protocol, Obfs: obfuscator, SinglePortType: "protocol",
					Users: []User{{ID: 101, Password: "user-one"}, {ID: 202, Password: "user-two"}}}
				s, r := startTestServer(t, o)
				for _, user := range o.Users {
					raw, err := net.Dial("tcp", s.tcp.Addr().String())
					if err != nil {
						t.Fatal(err)
					}
					raw.SetDeadline(time.Now().Add(3 * time.Second))
					c := &streamConn{Conn: raw, codec: clientCodec(t, o, user.ID, user.Password)}
					header, _ := appendAddress(nil, M.ParseSocksaddr("example.com:443"))
					payload := bytes.Repeat([]byte("SSR application payload"), 1200)
					if _, err := c.Write(append(header, payload...)); err != nil {
						t.Fatal(err)
					}
					got := make([]byte, len(payload))
					_, err = io.ReadFull(c, got)
					c.Close()
					if err != nil || !bytes.Equal(got, payload) {
						t.Fatalf("SSR roundtrip: %v equal=%v", err, bytes.Equal(got, payload))
					}
				}
				r.mu.Lock()
				defer r.mu.Unlock()
				if fmt.Sprint(r.users) != "[101 202]" || fmt.Sprint(r.targets) != "[example.com:443 example.com:443]" {
					t.Fatalf("route identities/targets: %v %v", r.users, r.targets)
				}
			})
		}
	}
}

func TestConcurrentAuthenticatedConnections(t *testing.T) {
	for _, protocol := range []string{"auth_aes128_sha1", "auth_chain_b", "auth_chain_f"} {
		t.Run(protocol, func(t *testing.T) {
			o := Options{Listen: "127.0.0.1", Method: "aes-128-cfb", Password: "outer-secret",
				Protocol: protocol, Obfs: "tls1.2_ticket_auth", SinglePortType: "protocol",
				Users: []User{{ID: 101, Password: "user-one"}, {ID: 202, Password: "user-two"}}}
			s, r := startTestServer(t, o)
			var wg sync.WaitGroup
			for i := 0; i < 20; i++ {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					u := o.Users[i%len(o.Users)]
					raw, err := net.Dial("tcp", s.tcp.Addr().String())
					if err != nil {
						t.Error(err)
						return
					}
					raw.SetDeadline(time.Now().Add(10 * time.Second))
					c := &streamConn{Conn: raw, codec: clientCodec(t, o, u.ID, u.Password)}
					defer c.Close()
					header, _ := appendAddress(nil, M.ParseSocksaddr("example.com:443"))
					want := bytes.Repeat([]byte("concurrent-payload"), 1000)
					if _, err = c.Write(append(header, want...)); err != nil {
						t.Error(err)
						return
					}
					got := make([]byte, len(want))
					if _, err = io.ReadFull(c, got); err != nil || !bytes.Equal(got, want) {
						t.Errorf("concurrent roundtrip: %v", err)
					}
				}(i)
			}
			wg.Wait()
			r.mu.Lock()
			defer r.mu.Unlock()
			if len(r.users) != 20 {
				t.Errorf("routed %d connections", len(r.users))
			}
		})
	}
}

func TestUDPAuthenticatedUsersAndRejection(t *testing.T) {
	for _, protocol := range Protocols()[2:] {
		t.Run(protocol, func(t *testing.T) {
			o := Options{Listen: "127.0.0.1", Method: "aes-128-cfb", Password: "outer-secret",
				Protocol: protocol, Obfs: "plain", SinglePortType: "protocol",
				Users: []User{{ID: 101, Password: "one"}, {ID: 202, Password: "two"}}}
			s, r := startTestServer(t, o)
			for _, user := range o.Users {
				raw, err := net.Dial("udp", s.udp.LocalAddr().String())
				if err != nil {
					t.Fatal(err)
				}
				raw.SetDeadline(time.Now().Add(3 * time.Second))
				c := clientCodec(t, o, user.ID, user.Password)
				header, _ := appendAddress(nil, M.ParseSocksaddr("8.8.8.8:53"))
				want := append(header, bytes.Repeat([]byte("udp"), 1800)...)
				wire, err := c.protocol.ClientUDPPreEncrypt(want)
				if err != nil {
					t.Fatal(err)
				}
				wire, err = c.enc.EncryptAll(wire, c.enc.MustNewIV())
				if err != nil {
					t.Fatal(err)
				}
				if _, err = raw.Write(wire); err != nil {
					t.Fatal(err)
				}
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
					t.Fatalf("UDP roundtrip err=%v equal=%v", err, bytes.Equal(clear, want))
				}
				// A UID absent from the configured table must not create a route.
				bad := clientCodec(t, o, 999, "one")
				wire, _ = bad.protocol.ClientUDPPreEncrypt(want)
				wire, _ = bad.enc.EncryptAll(wire, bad.enc.MustNewIV())
				raw.Write(wire)
				raw.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
				if _, err := raw.Read(b); err == nil {
					t.Fatal("unknown user accepted")
				}
				raw.Close()
			}
			r.mu.Lock()
			defer r.mu.Unlock()
			if fmt.Sprint(r.users) != "[101 202]" {
				t.Fatalf("UDP user attribution: %v", r.users)
			}
		})
	}
}

func TestTCPWrongPasswordAndUnknownIdentity(t *testing.T) {
	for _, protocol := range []string{"auth_aes128_md5", "auth_aes128_sha1", "auth_chain_a", "auth_chain_b"} {
		o := Options{Listen: "127.0.0.1", Method: "aes-128-cfb", Password: "outer", Protocol: protocol,
			Obfs: "plain", SinglePortType: "protocol", Users: []User{{ID: 101, Password: "good"}}}
		s, r := startTestServer(t, o)
		for _, u := range []User{{ID: 101, Password: "bad"}, {ID: 999, Password: "good"}} {
			raw, err := net.Dial("tcp", s.tcp.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			raw.SetDeadline(time.Now().Add(time.Second))
			c := &streamConn{Conn: raw, codec: clientCodec(t, o, u.ID, u.Password)}
			header, _ := appendAddress(nil, M.ParseSocksaddr("example.com:443"))
			c.Write(append(header, bytes.Repeat([]byte("X"), 8192)...))
			var b [1]byte
			if _, err := c.Read(b[:]); err == nil {
				t.Fatal("invalid credentials accepted")
			}
			c.Close()
		}
		r.mu.Lock()
		if len(r.users) != 0 {
			t.Errorf("invalid user routed: %v", r.users)
		}
		r.mu.Unlock()
	}
}

func TestReferencePythonInterop(t *testing.T) {
	script := os.Getenv("SSR_REFERENCE_CLIENT")
	if script == "" {
		t.Skip("optional pinned independent Python reference client not configured")
	}
	for _, protocol := range []string{"auth_aes128_md5", "auth_aes128_sha1", "auth_chain_a", "auth_chain_b"} {
		t.Run(protocol, func(t *testing.T) {
			o := Options{Listen: "127.0.0.1", Method: "aes-128-cfb", Password: "outer-secret",
				Protocol: protocol, Obfs: "plain", SinglePortType: "protocol", Users: []User{{ID: 101, Password: "user-one"}, {ID: 202, Password: "user-two"}}}
			s, r := startTestServer(t, o)
			cmd := exec.Command("python3", script, s.tcp.Addr().String(), protocol)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("%v: %s", err, out)
			}
			r.mu.Lock()
			defer r.mu.Unlock()
			if fmt.Sprint(r.users) != "[101 202]" {
				t.Fatal(r.users)
			}
		})
	}
}

func TestReferencePythonTLSInterop(t *testing.T) {
	script := os.Getenv("SSR_REFERENCE_CLIENT")
	if script == "" {
		t.Skip("optional pinned independent Python reference client not configured")
	}
	for _, protocol := range []string{"auth_aes128_sha1", "auth_chain_b"} {
		for _, obfuscator := range []string{"tls1.2_ticket_auth", "tls1.2_ticket_fastauth"} {
			t.Run(protocol+"/"+obfuscator, func(t *testing.T) {
				o := Options{Listen: "127.0.0.1", Method: "aes-128-cfb", Password: "outer-secret",
					Protocol: protocol, Obfs: obfuscator, SinglePortType: "protocol",
					Users: []User{{ID: 101, Password: "user-one"}, {ID: 202, Password: "user-two"}}}
				s, r := startTestServer(t, o)
				cmd := exec.Command("python3", script, s.tcp.Addr().String(), protocol, obfuscator)
				if out, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("%v: %s", err, out)
				}
				r.mu.Lock()
				defer r.mu.Unlock()
				if fmt.Sprint(r.users) != "[101 202]" {
					t.Fatal(r.users)
				}
			})
		}
	}
}

func TestFragmentedProtocolAndObfs(t *testing.T) {
	for _, protocol := range []string{"auth_aes128_sha1", "auth_chain_b", "auth_chain_f"} {
		for _, obfuscator := range Obfuscators() {
			t.Run(protocol+"/"+obfuscator, func(t *testing.T) {
				o := Options{Method: "aes-128-cfb", Password: "outer-secret", Protocol: protocol, Obfs: obfuscator,
					SinglePortType: "protocol", Users: []User{{ID: 101, Password: "user-one"}}}
				client := clientCodec(t, o, 101, "user-one")
				server, err := newCodec(o, obfs.NewObfsAuthChainData(protocol), nil)
				if err != nil {
					t.Fatal(err)
				}
				want := []byte("\x01\x08\x08\x08\x08\x00\x35fragmented-payload")
				wire, err := client.encode(want)
				if err != nil {
					t.Fatal(err)
				}
				var decoded []byte
				for rounds := 0; len(wire) > 0 && rounds < 5; rounds++ {
					var responses []byte
					for len(wire) > 0 {
						n := 3
						if len(wire) < n {
							n = len(wire)
						}
						clear, back, err := server.decode(wire[:n])
						if err != nil {
							t.Fatal(err)
						}
						decoded = append(decoded, clear...)
						responses = append(responses, back...)
						wire = wire[n:]
					}
					for len(responses) > 0 {
						n := 3
						if len(responses) < n {
							n = len(responses)
						}
						_, back, err := client.decode(responses[:n])
						if err != nil {
							t.Fatal(err)
						}
						wire = append(wire, back...)
						responses = responses[n:]
					}
				}
				if !bytes.Equal(decoded, want) {
					t.Fatalf("decoded %x want %x", decoded, want)
				}
				reply, err := server.encode(want)
				if err != nil {
					t.Fatal(err)
				}
				var got []byte
				for len(reply) > 0 {
					n := 3
					if len(reply) < n {
						n = len(reply)
					}
					clear, _, err := client.decode(reply[:n])
					if err != nil {
						t.Fatal(err)
					}
					got = append(got, clear...)
					reply = reply[n:]
				}
				if !bytes.Equal(got, want) {
					t.Fatal("fragmented response differs")
				}
			})
		}
	}
}

func TestOutboundTCPAndUDP(t *testing.T) {
	for _, protocol := range Protocols()[2:] {
		t.Run(protocol, func(t *testing.T) {
			o := Options{Listen: "127.0.0.1", Method: "aes-128-cfb", Password: "outer-secret", Protocol: protocol,
				Obfs: "tls1.2_ticket_auth", SinglePortType: "protocol", Users: []User{{ID: 5000000000, ProtocolID: 101, Password: "user-one"}}}
			s, r := startTestServer(t, o)
			o.ProtocolParam = "101:user-one"
			port := uint16(s.tcp.Addr().(*net.TCPAddr).Port)
			out, err := NewOutbound(context.Background(), nil, nil, "test-out", OutboundOptions{
				Server: "127.0.0.1", ServerPort: port, Method: o.Method, Password: o.Password,
				Protocol: o.Protocol, ProtocolParam: o.ProtocolParam, Obfs: o.Obfs})
			if err != nil {
				t.Fatal(err)
			}
			dest := M.ParseSocksaddr("example.com:443")
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			c, err := out.DialContext(ctx, "tcp", dest)
			if err != nil {
				t.Fatal(err)
			}
			c.SetDeadline(time.Now().Add(3 * time.Second))
			want := []byte("real SSR outbound")
			if _, err = c.Write(want); err != nil {
				t.Fatal(err)
			}
			got := make([]byte, len(want))
			if _, err = io.ReadFull(c, got); err != nil || !bytes.Equal(got, want) {
				t.Fatalf("TCP %v %q", err, got)
			}
			c.Close()
			p, err := out.ListenPacket(ctx, dest)
			if err != nil {
				t.Fatal(err)
			}
			p.SetDeadline(time.Now().Add(3 * time.Second))
			if _, err = p.WriteTo(want, dest); err != nil {
				t.Fatal(err)
			}
			n, addr, err := p.ReadFrom(got)
			p.Close()
			if err != nil || n != len(want) || !bytes.Equal(got, want) || addr.String() != dest.String() {
				t.Fatalf("UDP %v %q %v", err, got, addr)
			}
			r.mu.Lock()
			if fmt.Sprint(r.users) != "[5000000000 5000000000]" {
				t.Errorf("wire UID leaked into billing identity: %v", r.users)
			}
			r.mu.Unlock()
		})
	}
}

func TestForwardedTCPUDPAndTransportWrapper(t *testing.T) {
	o := Options{Listen: "127.0.0.1", Method: "aes-128-cfb", Password: "outer",
		Protocol: "auth_chain_a", Obfs: "plain", SinglePortType: "protocol",
		Users: []User{{ID: 101, Password: "one"}}, ProxyProtocol: true, UDPProxyProtocol: true, ForceProxyProtocol: true}
	o.WrapConnection = func(c net.Conn) (net.Conn, error) {
		var marker [4]byte
		if _, err := io.ReadFull(c, marker[:]); err != nil {
			return nil, err
		}
		if string(marker[:]) != "TEST" {
			return nil, fmt.Errorf("missing transport marker")
		}
		return c, nil
	}
	s, r := startTestServer(t, o)
	raw, err := net.Dial("tcp", s.tcp.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	raw.SetDeadline(time.Now().Add(2 * time.Second))
	io.WriteString(raw, "PROXY TCP4 192.0.2.9 127.0.0.1 1234 4444\r\nTEST")
	c := &streamConn{Conn: raw, codec: clientCodec(t, o, 101, "one")}
	header, _ := appendAddress(nil, M.ParseSocksaddr("example.com:443"))
	want := []byte("real proxy metadata")
	if _, err = c.Write(append(header, want...)); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(want))
	if _, err = io.ReadFull(c, got); err != nil || !bytes.Equal(got, want) {
		t.Fatalf("TCP: %v", err)
	}
	c.Close()
	udp, err := net.Dial("udp", s.udp.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	udp.SetDeadline(time.Now().Add(2 * time.Second))
	k := clientCodec(t, o, 101, "one")
	wire, err := k.protocol.ClientUDPPreEncrypt(append(header, want...))
	if err != nil {
		t.Fatal(err)
	}
	wire, err = k.enc.EncryptAll(wire, k.enc.MustNewIV())
	if err != nil {
		t.Fatal(err)
	}
	prefix := append([]byte("\r\n\r\n\x00\r\nQUIT\n"), 0x21, 0x12, 0, 12, 192, 0, 2, 10, 127, 0, 0, 1, 0x04, 0xd3, 0x11, 0x5c)
	if _, err = udp.Write(append(prefix, wire...)); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 65535)
	n, err := udp.Read(b)
	if err != nil {
		t.Fatal(err)
	}
	clear, _, err := k.enc.DecryptAll(b[:n])
	if err != nil {
		t.Fatal(err)
	}
	clear, err = k.protocol.ClientUDPPostDecrypt(clear)
	if err != nil || !bytes.Equal(clear, append(header, want...)) {
		t.Fatalf("UDP response failed: %v", err)
	}
	// Missing mandatory UDP metadata must not be accepted or routed.
	udp.Write(wire)
	udp.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	if _, err = udp.Read(b); err == nil {
		t.Fatal("required UDP metadata bypassed")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if fmt.Sprint(r.sources) != "[192.0.2.9:1234 192.0.2.10:1235]" {
		t.Fatalf("forwarded sources: %v", r.sources)
	}
}

func TestRecoveredMuHost(t *testing.T) {
	u := User{ID: 101, Password: "user-one", Method: "aes-128-cfb", Obfs: "http_simple", Protocol: "origin", ProtocolID: 999}
	for _, test := range []struct{ pattern, want string }{
		{"%5m%id.%suffix", "78494101.microsoft.com"},
		{"%100m.%id.%suffix", "78494e78d37ff04eede26ce12caf6b1b.101.microsoft.com"},
		{"%0m%id.%suffix", "101.microsoft.com"},
		{"%5m-%5m-%id-%id.%suffix", "78494-%5m-101-%id.microsoft.com"},
	} {
		got, err := HostForUser(u, test.pattern, "microsoft.com")
		if err != nil || got != test.want {
			t.Fatalf("%s = %s (%v)", test.pattern, got, err)
		}
	}
	if _, err := HostForUser(u, "%id.%suffix", "microsoft.com"); err == nil {
		t.Fatal("missing MD5 placeholder accepted")
	}
}

func TestMuPeekPreservesExactSSRWire(t *testing.T) {
	for _, obfuscator := range Obfuscators()[1:] {
		t.Run(obfuscator, func(t *testing.T) {
			o := Options{Method: "aes-128-cfb", Password: "carrier", Protocol: "origin", Obfs: obfuscator,
				ObfsParam: "78494101.microsoft.com", SinglePortType: "protocol"}
			k, err := newCodec(o, obfs.NewObfsAuthChainData(o.Protocol), nil)
			if err != nil {
				t.Fatal(err)
			}
			k.client = true
			wire, err := k.encode(bytes.Repeat([]byte("payload"), 64))
			if err != nil {
				t.Fatal(err)
			}
			left, right := net.Pipe()
			defer left.Close()
			defer right.Close()
			left.SetDeadline(time.Now().Add(2 * time.Second))
			right.SetDeadline(time.Now().Add(2 * time.Second))
			go func() {
				for _, b := range wire {
					if _, err := left.Write([]byte{b}); err != nil {
						return
					}
				}
			}()
			wrapped, host, err := peekObfsHost(right, obfuscator)
			if err != nil || host != "78494101.microsoft.com" {
				t.Fatalf("host=%q err=%v", host, err)
			}
			got := make([]byte, len(wire))
			if _, err = io.ReadFull(wrapped, got); err != nil || !bytes.Equal(got, wire) {
				t.Fatalf("wire changed: %v", err)
			}
		})
	}
}
