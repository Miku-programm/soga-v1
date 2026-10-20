package engine

import (
	"context"
	"errors"
	"strings"
	"time"

	"reconstructed.local/soga/config"
	"reconstructed.local/soga/proxy"
	"reconstructed.local/soga/redislimit"
)

func redisOptions(c config.Config, explicit map[string]bool) (redislimit.Options, bool, bool, error) {
	newSpecified := c.RedisIpLimitEnable || c.RedisIpLimitAddr != "" || c.RedisIpLimitPassword != "" ||
		c.RedisIpLimitDb != 0 || c.RedisIpLimitTls || c.RedisIpLimitExpiry != 60
	for key, set := range explicit {
		if set && strings.HasPrefix(key, "redis_ip_limit_") {
			newSpecified = true
		}
	}
	enabled, addr, password, db, secure, expiry := c.RedisIpLimitEnable, c.RedisIpLimitAddr, c.RedisIpLimitPassword, c.RedisIpLimitDb, c.RedisIpLimitTls, c.RedisIpLimitExpiry
	legacy := c.RedisEnable && !newSpecified
	if legacy {
		enabled, addr, password, db, secure, expiry = c.RedisEnable, c.RedisAddr, c.RedisPassword, c.RedisDb, c.RedisTls, c.ConnLimitExpiry
	}
	if !enabled {
		return redislimit.Options{}, false, legacy, nil
	}
	if db < 0 || db > 65535 || expiry < 1 || expiry > 365*24*3600 {
		return redislimit.Options{}, false, legacy, errors.New("invalid Redis database or expiry")
	}
	return redislimit.Options{Addr: addr, Password: password, DB: int(db), TLS: secure, Expiry: time.Duration(expiry) * time.Second}, true, legacy, nil
}

func (n *Node) globalAdmission(ctx context.Context, r proxy.AdmissionRequest) (func(), error) {
	if n.redis == nil {
		return func() {}, nil
	}
	release, err := n.redis.Acquire(ctx, redislimit.Request{UserID: r.UserID, IP: r.IP, DeviceID: r.DeviceID, IPLimit: r.IPLimit, DeviceLimit: r.DeviceLimit})
	if ctx.Err() != nil {
		return release, ctx.Err()
	}
	if errors.Is(err, redislimit.ErrQuotaExceeded) {
		return release, err
	}
	if err != nil {
		// Availability failures fall back to the local limiter. Keep release so
		// the manager can renew this live connection after Redis recovers.
		now := time.Now().Unix()
		previous := n.redisWarn.Load()
		if now-previous >= 60 && n.redisWarn.CompareAndSwap(previous, now) {
			n.opts.Logger.Warn("Redis unavailable; local IP/device limits remain active", "error", err)
		}
	}
	return release, nil
}
