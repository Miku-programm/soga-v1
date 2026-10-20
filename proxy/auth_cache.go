package proxy

import (
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

type AuthenticationCacheConfig struct {
	TTL     time.Duration
	Path    string
	Persist bool
	// OnError receives at most one background flush error per minute.
	OnError func(error)
}
type authenticationHint struct {
	UserID  string    `json:"user_id"`
	Expires time.Time `json:"expires"`
}
type AuthenticationCache struct {
	mu         sync.Mutex
	writeMu    sync.Mutex
	cfg        AuthenticationCacheConfig
	entries    map[string]authenticationHint
	done       chan struct{}
	closeOnce  sync.Once
	workerDone chan struct{}
	closeErr   error
}

func NewAuthenticationCache(cfg AuthenticationCacheConfig) (*AuthenticationCache, error) {
	if cfg.TTL <= 0 {
		cfg.TTL = 24 * time.Hour
	}
	if cfg.Persist && cfg.Path == "" {
		return nil, errors.New("proxy: persistent authentication cache needs a path")
	}
	c := &AuthenticationCache{cfg: cfg, entries: make(map[string]authenticationHint), done: make(chan struct{}), workerDone: make(chan struct{})}
	if cfg.Persist {
		data, err := readAuthenticationCache(cfg.Path)
		if err != nil && !os.IsNotExist(err) {
			return nil, err
		}
		if err == nil {
			var stored struct {
				Version int                           `json:"version"`
				Entries map[string]authenticationHint `json:"entries"`
			}
			if err = json.Unmarshal(data, &stored); err != nil {
				return nil, err
			}
			if stored.Version != 1 {
				return nil, errors.New("proxy: unknown authentication cache version")
			}
			now := time.Now()
			for ip, hint := range stored.Entries {
				if len(c.entries) >= 65536 {
					break
				}
				addr, e := netip.ParseAddr(ip)
				id, ie := strconv.ParseInt(hint.UserID, 10, 64)
				if e == nil && ie == nil && id > 0 && hint.Expires.After(now) {
					if hint.Expires.After(now.Add(cfg.TTL)) {
						hint.Expires = now.Add(cfg.TTL)
					}
					c.entries[addr.Unmap().String()] = hint
				}
			}
		}
		go func() {
			defer close(c.workerDone)
			ticker := time.NewTicker(time.Minute)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					if err := c.Flush(); err != nil && c.cfg.OnError != nil {
						c.cfg.OnError(err)
					}
				case <-c.done:
					return
				}
			}
		}()
	} else {
		close(c.workerDone)
	}
	return c, nil
}
func readAuthenticationCache(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	const maxSize = 16 << 20
	data, err := io.ReadAll(io.LimitReader(f, maxSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxSize {
		return nil, errors.New("proxy: authentication cache exceeds 16 MiB")
	}
	return data, nil
}
func (c *AuthenticationCache) Candidate(ip string) string {
	if c == nil {
		return ""
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return ""
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	hint, ok := c.entries[addr.Unmap().String()]
	if !ok {
		return ""
	}
	if time.Now().After(hint.Expires) {
		delete(c.entries, addr.Unmap().String())
		return ""
	}
	return hint.UserID
}
func (c *AuthenticationCache) Remember(ip, userID string) {
	if c == nil {
		return
	}
	addr, err := netip.ParseAddr(ip)
	id, idErr := strconv.ParseInt(userID, 10, 64)
	if err != nil || idErr != nil || id <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) >= 65536 {
		now := time.Now()
		for key, hint := range c.entries {
			if now.After(hint.Expires) {
				delete(c.entries, key)
			}
		}
		if len(c.entries) >= 65536 {
			for key := range c.entries {
				delete(c.entries, key)
				break
			}
		}
	}
	c.entries[addr.Unmap().String()] = authenticationHint{userID, time.Now().Add(c.cfg.TTL)}
}
func (c *AuthenticationCache) Flush() error {
	if c == nil || !c.cfg.Persist {
		return nil
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	c.mu.Lock()
	stored := struct {
		Version int                           `json:"version"`
		Entries map[string]authenticationHint `json:"entries"`
	}{1, make(map[string]authenticationHint)}
	now := time.Now()
	for ip, hint := range c.entries {
		if hint.Expires.After(now) {
			stored.Entries[ip] = hint
		} else {
			delete(c.entries, ip)
		}
	}
	c.mu.Unlock()
	data, err := json.Marshal(stored)
	if err != nil {
		return err
	}
	dir := filepath.Dir(c.cfg.Path)
	if err = os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".auth-cache-*")
	if err != nil {
		return err
	}
	temp := f.Name()
	defer os.Remove(temp)
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(temp, c.cfg.Path)
}
func (c *AuthenticationCache) Close() error {
	if c == nil {
		return nil
	}
	c.closeOnce.Do(func() {
		close(c.done)
		<-c.workerDone
		c.closeErr = c.Flush()
	})
	return c.closeErr
}
