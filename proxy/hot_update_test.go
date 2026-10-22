package proxy

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

// Live user updates must keep the listener and unaffected sessions, revoke
// removed users immediately and admit new ones.
func TestLiveUserUpdateKeepsSessionsOfUnchangedUsers(t *testing.T) {
	destination, _ := echoTCP(t)
	for _, protocol := range []string{"vmess", "shadowsocks"} {
		t.Run(protocol, func(t *testing.T) {
			keep := User{ID: 42, UUID: testUUID, Username: "keep", Password: "keep-password-key"}
			gone := User{ID: 43, UUID: "91c43637-0cdc-46c7-bb6c-cf1b09f52c2c", Username: "gone", Password: "gone-password-key"}
			cfg := Config{Protocol: protocol, Listen: "127.0.0.1", Port: freePort(t, false), Users: []User{keep, gone}, Method: "aes-128-gcm"}
			s, err := Start(context.Background(), cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			before := s.box
			open := func(u User) net.Conn {
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				c, err := client(t, cfg, u, nil).DialContext(ctx, "tcp", M.ParseSocksaddr(destination))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { c.Close() })
				return c
			}
			echo := func(c net.Conn, payload string) error {
				_ = c.SetDeadline(time.Now().Add(3 * time.Second))
				if _, err := c.Write([]byte(payload)); err != nil {
					return err
				}
				got := make([]byte, len(payload))
				_, err := io.ReadFull(c, got)
				return err
			}
			kept, dropped := open(keep), open(gone)
			if err := echo(kept, "kept-1"); err != nil {
				t.Fatal(err)
			}
			if err := echo(dropped, "gone-1"); err != nil {
				t.Fatal(err)
			}
			added := User{ID: 44, UUID: "0f0e0d0c-0b0a-4908-8706-050403020100", Username: "added", Password: "added-password-key"}
			limited := keep
			limited.SpeedLimit = 50
			if err := s.UpdateUsers([]User{limited, added}); err != nil {
				t.Fatal(err)
			}
			if s.box != before {
				t.Fatal("user update rebuilt the listener instead of updating in place")
			}
			if err := echo(kept, "kept-2"); err != nil {
				t.Fatal("unchanged user lost its session:", err)
			}
			_ = dropped.SetDeadline(time.Now().Add(2 * time.Second))
			if _, err := dropped.Write([]byte("gone-2")); err == nil {
				if _, err = io.ReadFull(dropped, make([]byte, 6)); err == nil {
					t.Fatal("removed user's session survived the update")
				}
			}
			if err := roundTripTCP(client(t, cfg, gone, nil), destination, []byte("revoked"), time.Second); err == nil {
				t.Fatal("removed user can still authenticate")
			}
			if err := roundTripTCP(client(t, cfg, added, nil), destination, []byte("welcome"), 3*time.Second); err != nil {
				t.Fatal("added user rejected:", err)
			}
			rekeyed := added
			rekeyed.UUID, rekeyed.Password = "6ba7b810-9dad-11d1-80b4-00c04fd430c8", "rotated-password-key"
			if err := s.UpdateUsers([]User{limited, rekeyed}); err != nil {
				t.Fatal(err)
			}
			if err := roundTripTCP(client(t, cfg, added, nil), destination, []byte("stale"), time.Second); err == nil {
				t.Fatal("old credential still accepted after rotation")
			}
			if err := roundTripTCP(client(t, cfg, rekeyed, nil), destination, []byte("fresh"), 3*time.Second); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// A connection that never sends its first protocol frame must be dropped
// after the handshake timeout instead of holding a goroutine forever.
func TestSilentConnectionIsDroppedAfterHandshakeTimeout(t *testing.T) {
	previous := handshakeTimeout
	handshakeTimeout = 300 * time.Millisecond
	defer func() { handshakeTimeout = previous }()
	for _, protocol := range []string{"vmess", "shadowsocks"} {
		t.Run(protocol, func(t *testing.T) {
			u := User{ID: 42, UUID: testUUID, Username: "silent", Password: "silent-password-key"}
			cfg := Config{Protocol: protocol, Listen: "127.0.0.1", Port: freePort(t, false), Users: []User{u}, Method: "aes-128-gcm"}
			s, err := Start(context.Background(), cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			c, err := net.DialTimeout("tcp", s.Addr(), time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
			if _, err := c.Read(make([]byte, 1)); err == nil {
				t.Fatal("server wrote to an unauthenticated silent connection")
			} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
				t.Fatal("silent connection was not closed within the handshake timeout")
			}
			// Authenticated traffic is unaffected by the short timeout.
			destination, _ := echoTCP(t)
			out := client(t, cfg, u, nil)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			conn, err := out.DialContext(ctx, "tcp", M.ParseSocksaddr(destination))
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if _, err := conn.Write([]byte("first")); err != nil {
				t.Fatal(err)
			}
			if _, err := io.ReadFull(conn, make([]byte, 5)); err != nil {
				t.Fatal(err)
			}
			time.Sleep(2 * handshakeTimeout)
			_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
			if _, err := conn.Write([]byte("later")); err != nil {
				t.Fatal(err)
			}
			if _, err := io.ReadFull(conn, make([]byte, 5)); err != nil {
				t.Fatal("authenticated session hit the handshake deadline:", err)
			}
		})
	}
}
