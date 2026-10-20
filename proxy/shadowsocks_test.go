package proxy

import (
	"bytes"
	"context"
	"encoding/base64"
	"net"
	"reconstructed.local/soga/proxy/ssrcore"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestShadowsocksObfsMultiuserCarrierKey(t *testing.T) {
	target, accepts := echoTCP(t)
	for _, method := range []string{"aes-128-gcm", "aes-192-gcm", "aes-256-gcm", "chacha20-ietf-poly1305"} {
		for _, obfs := range []string{"simple_obfs_http", "simple_obfs_tls"} {
			t.Run(method+"/"+obfs, func(t *testing.T) {
				users := []User{{ID: 42, Password: "one-password", Method: "aes-128-cfb", Protocol: "auth_chain_a", Obfs: "tls1.2_ticket_auth"}, {ID: 43, Password: "two-password", Method: "aes-256-gcm", Protocol: "origin", Obfs: "plain"}}
				cfg := Config{Protocol: "ssr", Listen: "127.0.0.1", Port: freePort(t, false), Method: method, Password: "carrier-key", Users: users, SSRProtocol: "origin", SSRObfs: obfs, SSRSinglePortType: "obfs", SSRCarrierID: 99}
				s, err := Start(context.Background(), cfg)
				if err != nil {
					t.Fatal(err)
				}
				defer s.Close()
				for _, u := range users {
					host, e := ssrcore.HostForUser(ssrcore.User{ID: u.ID, Password: u.Password, Method: u.Method, Protocol: u.Protocol, Obfs: u.Obfs}, "%5m%id.%suffix", "microsoft.com")
					if e != nil {
						t.Fatal(e)
					}
					cc := Config{Protocol: "shadowsocks", Listen: cfg.Listen, Port: cfg.Port, Method: method, SSObfs: obfs, SSHost: host}
					if err = roundTripTCP(client(t, cc, User{ID: u.ID, Password: cfg.Password}, nil), target, []byte("host identifies user, carrier key encrypts"), time.Second); err != nil {
						t.Fatal(err)
					}
					waitForDownload(t, s, u.ID, 1)
				}
				before := accepts.Load()
				bad := Config{Protocol: "shadowsocks", Listen: cfg.Listen, Port: cfg.Port, Method: method, SSObfs: obfs, SSHost: "unregistered.example"}
				if err = roundTripTCP(client(t, bad, User{ID: 42, Password: cfg.Password}, nil), target, []byte("unknown host"), time.Second); err == nil || accepts.Load() != before {
					t.Fatal("unknown mu host accepted")
				}
				if _, ok := s.TrafficSnapshot()[99]; ok {
					t.Fatal("carrier charged TCP user traffic")
				}
				probe, e := net.ListenPacket("udp", s.Addr())
				if e != nil {
					t.Fatal("mu UDP unexpectedly bound", e)
				}
				probe.Close()
			})
		}
	}
}
func TestShadowsocksMuUDPUnattributed(t *testing.T) {
	target := echoUDP(t)
	var admissions atomic.Int32
	seen := make(chan Request, 8)
	cfg := Config{Protocol: "ssr", Listen: "127.0.0.1", Port: freePort(t, false), Method: "aes-128-gcm", Password: "carrier-key", Users: []User{{ID: 42, Password: "personal", Method: "aes-128-cfb", Protocol: "origin", Obfs: "plain"}},
		SSRProtocol: "origin", SSRObfs: "simple_obfs_tls", SSRSinglePortType: "obfs", SSRCarrierID: 0, SSRObfsUDP: true, NodeSpeedLimit: 10,
		GlobalAdmission: func(context.Context, AdmissionRequest) (func(), error) { admissions.Add(1); return nil, net.ErrClosed }, Hook: func(r Request) error { seen <- r; return nil }}
	s, err := Start(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	cc := Config{Protocol: "shadowsocks", Listen: cfg.Listen, Port: cfg.Port, Method: cfg.Method}
	if err = roundTripUDP(client(t, cc, User{ID: 0, Password: cfg.Password}, nil), target, []byte("unattributed UDP uses carrier cipher")); err != nil {
		t.Fatal(err)
	}
	if admissions.Load() != 0 {
		t.Fatal("unattributed UDP consumed user quota")
	}
	if len(s.TrafficSnapshot()) != 0 || len(s.OnlineSnapshot()) != 0 {
		t.Fatal("unattributed UDP billed/reported as ordinary user")
	}
	select {
	case req := <-seen:
		if !req.Unattributed || req.UserID != 0 {
			t.Fatalf("lost attribution marker %+v", req)
		}
	case <-time.After(time.Second):
		t.Fatal("no UDP route request")
	}
}

func TestSSRRepeatedPasswordsRemainDistinctUsers(t *testing.T) {
	target, _ := echoTCP(t)
	users := []User{{ID: 42, Password: "shared-user-password"}, {ID: 43, Password: "shared-user-password"}}
	cfg := Config{Protocol: "ssr", Listen: "127.0.0.1", Port: freePort(t, false), Method: "aes-128-cfb", Password: "carrier-key", Users: users, SSRProtocol: "auth_aes128_sha1", SSRSinglePortType: "protocol"}
	s, err := Start(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for _, u := range users {
		if err = roundTripTCP(client(t, cfg, u, nil), target, []byte("distinct UID"), time.Second); err != nil {
			t.Fatal(err)
		}
	}
	for _, u := range users {
		waitForDownload(t, s, u.ID, 1)
	}
}

func TestShadowsocksCipherObfsMatrix(t *testing.T) {
	target, _ := echoTCP(t)
	udpTarget := echoUDP(t)
	for _, method := range []string{"aes-128-gcm", "aes-192-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "aes-128-cfb", "aes-256-ctr", "rc4-md5", "chacha20-ietf"} {
		for _, obfs := range []string{"plain", "simple_obfs_http", "simple_obfs_tls"} {
			t.Run(method+"/"+obfs, func(t *testing.T) {
				u := User{ID: 42, Password: "secret-password"}
				cfg := Config{Protocol: "shadowsocks", Listen: "127.0.0.1", Port: freePort(t, false), Method: method, Users: []User{u}, SSObfs: obfs, SSObfsMode: "strict", SSHost: "cdn.example", SSPath: "/"}
				if method == "2022-blake3-aes-128-gcm" || method == "2022-blake3-aes-256-gcm" {
					size := 16
					if method == "2022-blake3-aes-256-gcm" {
						size = 32
					}
					cfg.Password = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, size))
					u.Password = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, size))
					cfg.Users = []User{u}
				}
				s, err := Start(context.Background(), cfg)
				if err != nil {
					t.Fatal(err)
				}
				defer s.Close()
				out := client(t, cfg, u, nil)
				payload := bytes.Repeat([]byte("actual-SS-crypto\x00\xff"), 12000)
				if err = roundTripTCP(out, target, payload, 5*time.Second); err != nil {
					t.Fatal("TCP", err)
				}
				if err = roundTripUDP(out, udpTarget, []byte("udp-payload")); err != nil {
					t.Fatal("UDP", err)
				}
				waitForDownload(t, s, 42, uint64(len(payload)))
			})
		}
	}
}

// The client can finish reading before the server Write returns and adds its
// successful byte count. Wait for that asynchronous completion, not a delay.
func waitForDownload(t *testing.T, s *Server, id int64, minimum uint64) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if s.TrafficSnapshot()[id].Download >= minimum {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("billing identity %d missing: %+v", id, s.TrafficSnapshot())
}

func TestShadowsocksCacheAndInvalidAccess(t *testing.T) {
	target, accepts := echoTCP(t)
	cache, _ := NewAuthenticationCache(AuthenticationCacheConfig{})
	defer cache.Close()
	cache.Remember("127.0.0.1", "43")
	u := User{ID: 42, Password: "right"}
	cfg := Config{Protocol: "shadowsocks", Listen: "127.0.0.1", Port: freePort(t, false), Method: "aes-128-gcm", Users: []User{u, {ID: 43, Password: "second"}}, AuthCache: cache, InvalidAccess: &InvalidAccessConfig{Count: 2, WindowSeconds: 10, ForbiddenSeconds: 1}}
	s, err := Start(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err = roundTripTCP(client(t, cfg, u, nil), target, []byte("wrong hint still authenticates"), time.Second); err != nil {
		t.Fatal(err)
	}
	if cache.Candidate("127.0.0.1") != "42" {
		t.Fatal("hint not corrected")
	}
	before := accepts.Load()
	for i := 0; i < 2; i++ {
		if err = roundTripTCP(client(t, cfg, User{ID: 42, Password: "wrong"}, nil), target, []byte("not allowed"), time.Second); err == nil {
			t.Fatal("bad password worked")
		}
	}
	if err = roundTripTCP(client(t, cfg, u, nil), target, []byte("blocked"), time.Second); err == nil || accepts.Load() != before {
		t.Fatal("block not enforced")
	}
	time.Sleep(1100 * time.Millisecond)
	if err = roundTripTCP(client(t, cfg, u, nil), target, []byte("recovered"), time.Second); err != nil {
		t.Fatal(err)
	}
}

func TestShadowsocksUDPProxySourceAndResponse(t *testing.T) {
	for _, method := range []string{"aes-128-gcm", "aes-128-cfb"} {
		t.Run(method, func(t *testing.T) {
			target := echoUDP(t)
			seen := make(chan Request, 4)
			u := User{ID: 42, Password: "secret"}
			cfg := Config{Protocol: "shadowsocks", Listen: "127.0.0.1", Port: freePort(t, false), Method: method, Users: []User{u}, UDPProxyProtocol: true, ForceProxyProtocol: true, Hook: func(r Request) error { seen <- r; return nil }}
			s, err := Start(context.Background(), cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			relay, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer relay.Close()
			upstream, err := net.Dial("udp", s.Addr())
			if err != nil {
				t.Fatal(err)
			}
			defer upstream.Close()
			var mu sync.Mutex
			var peer net.Addr
			go func() {
				b := make([]byte, 65535)
				for {
					n, source, e := relay.ReadFrom(b)
					if e != nil {
						return
					}
					mu.Lock()
					peer = source
					mu.Unlock()
					prefix := append([]byte("\r\n\r\n\x00\r\nQUIT\n"), 0x21, 0x12, 0, 12, 192, 0, 2, 10, 127, 0, 0, 1, 0x04, 0xd3, 0x11, 0x5c)
					upstream.Write(append(prefix, b[:n]...))
				}
			}()
			go func() {
				b := make([]byte, 65535)
				for {
					n, e := upstream.Read(b)
					if e != nil {
						return
					}
					mu.Lock()
					p := peer
					mu.Unlock()
					if p != nil {
						relay.WriteTo(b[:n], p)
					}
				}
			}()
			cc := cfg
			cc.Port = uint16(relay.LocalAddr().(*net.UDPAddr).Port)
			if err = roundTripUDP(client(t, cc, u, nil), target, []byte("forwarded actual UDP")); err != nil {
				t.Fatal(err)
			}
			select {
			case req := <-seen:
				if req.Source != "192.0.2.10:1235" {
					t.Fatalf("wrong source %+v", req)
				}
			case <-time.After(time.Second):
				t.Fatal("missing request")
			}
		})
	}
}
