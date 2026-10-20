package proxy

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAuthenticationHintsPersistExpireAndStillVerify(t *testing.T) {
	path := filepath.Join(t.TempDir(), "node-auth.json")
	cache, err := NewAuthenticationCache(AuthenticationCacheConfig{TTL: time.Hour, Path: path, Persist: true})
	if err != nil {
		t.Fatal(err)
	}
	defer cache.Close()
	cache.Remember("127.0.0.1", "999")
	target, accepts := echoTCP(t)
	user := User{ID: 42, UUID: testUUID}
	cfg := Config{Protocol: "vmess", Listen: "127.0.0.1", Port: freePort(t, false), Users: []User{user}, AuthCache: cache}
	s, err := Start(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err = roundTripTCP(client(t, cfg, user, nil), target, []byte("verify cache hint"), time.Second); err != nil {
		t.Fatal(err)
	}
	if cache.Candidate("127.0.0.1") != "42" {
		t.Fatal("successful user not remembered")
	}
	before := accepts.Load()
	bad := user
	bad.UUID = "91c43637-0cdc-46c7-bb6c-cf1b09f52c2c"
	if err = roundTripTCP(client(t, cfg, bad, nil), target, []byte("must not trust hint"), time.Second); err == nil || accepts.Load() != before {
		t.Fatal("hint bypassed authentication")
	}
	if err = cache.Flush(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) == "" {
		t.Fatal("cache not written")
	}
	reloaded, err := NewAuthenticationCache(AuthenticationCacheConfig{TTL: time.Hour, Path: path, Persist: true})
	if err != nil {
		t.Fatal(err)
	}
	defer reloaded.Close()
	if reloaded.Candidate("127.0.0.1") != "42" {
		t.Fatal("cache did not reload")
	}
	expiring, _ := NewAuthenticationCache(AuthenticationCacheConfig{TTL: time.Millisecond})
	defer expiring.Close()
	expiring.Remember("127.0.0.1", "42")
	time.Sleep(3 * time.Millisecond)
	if expiring.Candidate("127.0.0.1") != "" {
		t.Fatal("expired hint retained")
	}
}

func TestVMessInvalidAccessBlockPreservesMD5AndExpires(t *testing.T) {
	target, accepts := echoTCP(t)
	user := User{ID: 42, UUID: testUUID}
	cfg := Config{Protocol: "vmess", Listen: "127.0.0.1", Port: freePort(t, false), Users: []User{user}, VMessAuthMode: "auto",
		InvalidAccess: &InvalidAccessConfig{Count: 2, WindowSeconds: 10, ForbiddenSeconds: 1}}
	s, err := Start(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	bad := user
	bad.UUID = "91c43637-0cdc-46c7-bb6c-cf1b09f52c2c"
	for i := 0; i < 2; i++ {
		if err = roundTripTCP(client(t, cfg, bad, nil), target, []byte("wrong"), time.Second); err == nil {
			t.Fatal("wrong UUID worked")
		}
	}
	before := accepts.Load()
	if err = roundTripTCP(client(t, cfg, user, nil), target, []byte("temporarily denied"), time.Second); err == nil || accepts.Load() != before {
		t.Fatal("IP was not blocked")
	}
	if err = legacyZeroRoundTrip(cfg, target); err != nil {
		t.Fatal("valid MD5 incorrectly affected by AEAD block", err)
	}
	time.Sleep(1100 * time.Millisecond)
	if err = roundTripTCP(client(t, cfg, user, nil), target, []byte("after expiry"), time.Second); err != nil {
		t.Fatal(err)
	}
}
