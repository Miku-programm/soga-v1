package proxy

import (
	"context"
	M "github.com/sagernet/sing/common/metadata"
	"io"
	"net"
	vmess "reconstructed.local/soga/proxy/internal/vmesscompat"
	"strconv"
	"testing"
	"time"
)

func TestVMessAuthenticationModesAndLegacyIdentity(t *testing.T) {
	target, accepts := echoTCP(t)
	for _, mode := range []string{"auto", "md5", "aead"} {
		for _, alter := range []int{0, 2} {
			user := User{ID: 42, UUID: testUUID, AlterID: alter}
			cfg := Config{Protocol: "vmess", Listen: "127.0.0.1", Port: freePort(t, false), Users: []User{user}, VMessAuthMode: mode}
			s, err := Start(context.Background(), cfg)
			if err != nil {
				t.Fatal(err)
			}
			for _, kind := range []string{"aead", "md5"} {
				t.Run(mode+"/"+kind+map[int]string{0: "/zero", 2: "/alter2"}[alter], func(t *testing.T) {
					want := mode == "aead" && kind == "aead" || mode == "md5" && kind == "md5" || mode == "auto" && (alter == 0 || kind == "md5")
					before := accepts.Load()
					var err error
					if kind == "aead" {
						u := user
						u.AlterID = 0
						err = roundTripTCP(client(t, cfg, u, nil), target, []byte("mode-check"), time.Second)
					} else if alter > 0 {
						err = roundTripTCP(client(t, cfg, user, nil), target, []byte("mode-check"), time.Second)
					} else {
						err = legacyZeroRoundTrip(cfg, target)
					}
					if want && err != nil {
						t.Fatal(err)
					}
					if !want && (err == nil || accepts.Load() != before) {
						t.Fatal("disabled authentication method passed")
					}
				})
			}
			s.Close()
		}
	}
}

func legacyZeroRoundTrip(cfg Config, target string) error {
	return legacyZeroRoundTripWithOffset(cfg, target, 0)
}
func legacyZeroRoundTripWithOffset(cfg Config, target string, offset time.Duration) error {
	c, err := net.Dial("tcp", net.JoinHostPort(cfg.Listen, strconv.Itoa(int(cfg.Port))))
	if err != nil {
		return err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(time.Second))
	v, err := vmess.NewClient(testUUID, "aes-128-gcm", 0, vmess.ClientWithLegacyUUID(testUUID), vmess.ClientWithTimeFunc(func() time.Time { return time.Now().Add(offset) }))
	if err != nil {
		return err
	}
	plain, err := v.DialConn(c, M.ParseSocksaddr(target))
	if err != nil {
		return err
	}
	if _, err = plain.Write([]byte("legacy-zero")); err != nil {
		return err
	}
	_, err = io.ReadFull(plain, make([]byte, len("legacy-zero")))
	return err
}

func TestVMessReducedMemoryClockWindow(t *testing.T) {
	target, accepts := echoTCP(t)
	for _, reduced := range []bool{false, true} {
		cfg := Config{Protocol: "vmess", Listen: "127.0.0.1", Port: freePort(t, false), Users: []User{{ID: 42, UUID: testUUID}}, VMessAuthMode: "auto", VMessReduceMemory: reduced}
		s, err := Start(context.Background(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		for _, offset := range []time.Duration{-30 * time.Second, -15 * time.Second, 15 * time.Second, 30 * time.Second} {
			before := accepts.Load()
			err = legacyZeroRoundTripWithOffset(cfg, target, offset)
			want := !reduced || offset >= -25*time.Second && offset <= 25*time.Second
			if want && err != nil {
				t.Fatalf("reduce=%v offset=%v: %v", reduced, offset, err)
			}
			if !want && (err == nil || accepts.Load() != before) {
				t.Fatalf("reduce=%v offset=%v accepted", reduced, offset)
			}
		}
		s.Close()
	}
}
