// Package dynamic implements documented time-window based user speed limits.
package dynamic

import (
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"reconstructed.local/soga/config"
	"reconstructed.local/soga/proxy"
)

type point struct {
	at       time.Time
	up, down uint64
}
type state struct {
	samples []point
	until   time.Time
}
type Controller struct {
	config  config.Config
	limiter *proxy.Limiter
	users   map[int64]proxy.User
	states  map[int64]*state
	exempt  map[int64]bool
	periods [][2]int
}

var zone = time.FixedZone("UTC+8", 8*60*60)

func New(c config.Config, l *proxy.Limiter) (*Controller, error) {
	d := &Controller{config: c, limiter: l, users: map[int64]proxy.User{}, states: map[int64]*state{}, exempt: map[int64]bool{}}
	if !c.DyLimitEnable {
		return d, nil
	}
	if l == nil || c.DyLimitTriggerTime <= 0 || c.DyLimitTime <= 0 || c.DyLimitSpeed <= 0 || c.DyLimitTriggerSpeed <= 0 ||
		math.IsNaN(c.DyLimitSpeed) || math.IsNaN(c.DyLimitTriggerSpeed) || math.IsInf(c.DyLimitSpeed, 0) || math.IsInf(c.DyLimitTriggerSpeed, 0) {
		return nil, errors.New("invalid dynamic speed limit configuration")
	}
	for _, id := range c.DyLimitWhiteUserId {
		n, err := strconv.ParseInt(id, 10, 64)
		if err != nil || n <= 0 {
			return nil, errors.New("invalid dynamic limit exempt user")
		}
		d.exempt[n] = true
	}
	for _, period := range config.SplitClean(c.DyLimitDuration, ",", -1) {
		start, end, ok := strings.Cut(period, "-")
		if !ok {
			return nil, fmt.Errorf("invalid dynamic period %q", period)
		}
		a, err := minute(start)
		if err != nil {
			return nil, err
		}
		b, err := minute(end)
		if err != nil {
			return nil, err
		}
		if a >= b || a >= 24*60 {
			return nil, errors.New("dynamic period must not cross midnight")
		}
		d.periods = append(d.periods, [2]int{a, b})
	}
	return d, nil
}
func minute(s string) (int, error) {
	h, m, ok := strings.Cut(s, ":")
	if !ok {
		return 0, errors.New("time must have HH:MM format")
	}
	hour, e1 := strconv.Atoi(h)
	mins, e2 := strconv.Atoi(m)
	if e1 != nil || e2 != nil || hour < 0 || hour > 24 || mins < 0 || mins > 59 || hour == 24 && mins != 0 {
		return 0, errors.New("invalid dynamic time")
	}
	return hour*60 + mins, nil
}
func (d *Controller) active(at time.Time) bool {
	if len(d.periods) == 0 {
		return true
	}
	now := at.In(zone)
	m := now.Hour()*60 + now.Minute()
	for _, p := range d.periods {
		if m >= p[0] && m < p[1] {
			return true
		}
	}
	return false
}

// ReplaceUsers preserves an active temporary restriction across panel updates.
// The caller serializes this controller with Observe.
func (d *Controller) ReplaceUsers(users []proxy.User, now time.Time) error {
	next := make(map[int64]proxy.User, len(users))
	for _, u := range users {
		next[u.ID] = u
		if st := d.states[u.ID]; st != nil && now.Before(st.until) && d.config.DyLimitEnable && !d.exempt[u.ID] {
			if u.SpeedLimit == 0 || u.SpeedLimit > d.config.DyLimitSpeed {
				u.SpeedLimit = d.config.DyLimitSpeed
			}
		}
		if err := d.limiter.SetUserLimits(u); err != nil {
			return err
		}
	}
	for id := range d.states {
		if _, ok := next[id]; !ok {
			delete(d.states, id)
		}
	}
	d.users = next
	return nil
}

func (d *Controller) Observe(now time.Time, totals map[int64]proxy.Traffic) error {
	if !d.config.DyLimitEnable {
		return nil
	}
	window := time.Duration(d.config.DyLimitTriggerTime) * time.Second
	active := d.active(now)
	for id, u := range d.users {
		st := d.states[id]
		if st == nil {
			st = &state{}
			d.states[id] = st
		}
		if !active || d.exempt[id] {
			st.samples = nil
			if !st.until.IsZero() {
				st.until = time.Time{}
				if err := d.limiter.SetUserLimits(u); err != nil {
					return err
				}
			}
			continue
		}
		if !st.until.IsZero() {
			if now.Before(st.until) {
				continue
			}
			st.until = time.Time{}
			st.samples = nil
			if err := d.limiter.SetUserLimits(u); err != nil {
				return err
			}
		}
		total := totals[id]
		if len(st.samples) > 0 {
			last := st.samples[len(st.samples)-1]
			if !now.After(last.at) {
				continue
			}
			if total.Upload < last.up || total.Download < last.down {
				st.samples = nil
			}
		}
		st.samples = append(st.samples, point{now, total.Upload, total.Download})
		// Keep the last sample at/before the window boundary. Intervals use
		// actual elapsed time, including any delay in panel synchronization.
		cutoff := now.Add(-window)
		for len(st.samples) > 1 && !st.samples[1].at.After(cutoff) {
			st.samples = st.samples[1:]
		}
		first := st.samples[0]
		elapsed := now.Sub(first.at)
		if elapsed < window {
			continue
		}
		bytes := float64(total.Upload-first.up) + float64(total.Download-first.down)
		if bytes*8/elapsed.Seconds()/1_000_000 > d.config.DyLimitTriggerSpeed {
			st.until = now.Add(time.Duration(d.config.DyLimitTime) * time.Second)
			st.samples = nil
			if u.SpeedLimit == 0 || u.SpeedLimit > d.config.DyLimitSpeed {
				u.SpeedLimit = d.config.DyLimitSpeed
			}
			if err := d.limiter.SetUserLimits(u); err != nil {
				return err
			}
		}
	}
	return nil
}

func (d *Controller) RestrictedUntil(id int64) time.Time {
	if st := d.states[id]; st != nil {
		return st.until
	}
	return time.Time{}
}
