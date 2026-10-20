package dynamic

import (
	"reconstructed.local/soga/config"
	"reconstructed.local/soga/proxy"
	"testing"
	"time"
)

func TestWindowTriggerExpiryAndWhitelist(t *testing.T) {
	c := config.Defaults()
	c.DyLimitEnable = true
	c.DyLimitTriggerTime = 60
	c.DyLimitTime = 600
	c.DyLimitTriggerSpeed = 1
	c.DyLimitSpeed = 0.5
	c.DyLimitDuration = "20:00-24:00,00:00-02:00"
	c.DyLimitWhiteUserId = []string{"2"}
	d, err := New(c, proxy.NewLimiter())
	if err != nil {
		t.Fatal(err)
	}
	start := time.Date(2026, 10, 20, 20, 0, 0, 0, zone)
	if err := d.ReplaceUsers([]proxy.User{{ID: 1, SpeedLimit: 20}, {ID: 2, SpeedLimit: 20}}, start); err != nil {
		t.Fatal(err)
	}
	for i := 0; i <= 60; i++ {
		// 2 Mbps aggregate, above a 1 Mbps trigger for the full 60 seconds.
		total := proxy.Traffic{Upload: uint64(i) * 250000}
		if err := d.Observe(start.Add(time.Duration(i)*time.Second), map[int64]proxy.Traffic{1: total, 2: total}); err != nil {
			t.Fatal(err)
		}
		if i < 60 && !d.RestrictedUntil(1).IsZero() {
			t.Fatal("triggered before full window")
		}
	}
	want := start.Add(660 * time.Second)
	if !d.RestrictedUntil(1).Equal(want) || !d.RestrictedUntil(2).IsZero() {
		t.Fatal("restriction/whitelist incorrect")
	}
	if err := d.ReplaceUsers([]proxy.User{{ID: 1, SpeedLimit: 10}, {ID: 2, SpeedLimit: 10}}, start.Add(61*time.Second)); err != nil {
		t.Fatal(err)
	}
	if !d.RestrictedUntil(1).Equal(want) {
		t.Fatal("panel update cleared restriction")
	}
	if err := d.Observe(want, map[int64]proxy.Traffic{1: {Upload: 16000000}}); err != nil {
		t.Fatal(err)
	}
	if !d.RestrictedUntil(1).IsZero() {
		t.Fatal("restriction did not expire")
	}
	// The period uses UTC+8 even if the host time zone differs.
	if !d.active(start.UTC()) || d.active(start.Add(7*time.Hour)) {
		t.Fatal("period timezone wrong")
	}
	c.DyLimitDuration = "20:00-02:00"
	if _, err := New(c, proxy.NewLimiter()); err == nil {
		t.Fatal("cross-midnight interval accepted")
	}
}
