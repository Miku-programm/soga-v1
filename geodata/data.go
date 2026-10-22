// Package geodata ships a pinned public dataset and atomically updates pairs.
package geodata

import (
	"bytes"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"reconstructed.local/soga/policy"
)

// Source, release URLs, SHA-256 hashes and licenses are retained in bundled/.
// policy.ParseGeoData only validates and indexes the data and keeps
// referencing these bytes (and any file or download it is given); categories
// are decoded on first use.
//
//go:embed bundled/geosite.dat
var site []byte

//go:embed bundled/geoip.dat
var ip []byte
var builtIn = sync.OnceValues(func() (*policy.GeoData, error) { return policy.ParseGeoData(site, ip) })

type manifest struct{ Site, IP string }

// Candidate is a parsed pair that has not yet changed the active on-disk data.
// The caller must validate its configured categories before Publish.
type Candidate struct {
	Data     *policy.GeoData
	site, ip []byte
}

func Load(sitePath, ipPath, stateDir string) (*policy.GeoData, error) {
	if sitePath == "" && ipPath == "" && stateDir != "" {
		data, err := os.ReadFile(filepath.Join(stateDir, "active.json"))
		if err == nil {
			var m manifest
			if err = json.Unmarshal(data, &m); err != nil {
				return nil, err
			}
			for _, s := range []string{m.Site, m.IP} {
				if b, err := hex.DecodeString(s); err != nil || len(b) != 32 {
					return nil, errors.New("invalid geodata manifest")
				}
			}
			sitePath = filepath.Join(stateDir, m.Site+".dat")
			ipPath = filepath.Join(stateDir, m.IP+".dat")
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	}
	if sitePath == "" && ipPath == "" {
		return builtIn()
	}
	s, i := site, ip
	var err error
	if sitePath != "" {
		s, err = read(sitePath)
		if err != nil {
			return nil, err
		}
	}
	if ipPath != "" {
		i, err = read(ipPath)
		if err != nil {
			return nil, err
		}
	}
	return policy.ParseGeoData(s, i)
}

func read(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var size int64
	if info, statErr := f.Stat(); statErr == nil {
		size = info.Size()
	}
	data, err := readAll(f, size)
	if len(data) > 256<<20 {
		return nil, errors.New("geodata exceeds 256 MiB")
	}
	return data, err
}

// readAll reads at most 256 MiB + 1 bytes from r like io.ReadAll, but sizes
// its buffer from hint (the expected length, if known). The returned slice
// stays referenced by the lazily decoded GeoData, so it should not carry the
// spare capacity of append growth.
func readAll(r io.Reader, hint int64) ([]byte, error) {
	var buf bytes.Buffer
	if hint > 0 && hint <= 256<<20 {
		buf.Grow(int(hint) + bytes.MinRead)
	}
	_, err := buf.ReadFrom(io.LimitReader(r, 256<<20+1))
	return buf.Bytes(), err
}

// Update downloads and validates both datasets before publishing one manifest.
// Readers therefore never observe one new file paired with one old file.
func Update(ctx context.Context, siteURL, ipURL, stateDir string) (*policy.GeoData, error) {
	candidate, err := Prepare(ctx, siteURL, ipURL)
	if err != nil {
		return nil, err
	}
	if err := candidate.Publish(stateDir); err != nil {
		return nil, err
	}
	return candidate.Data, nil
}

func Prepare(ctx context.Context, siteURL, ipURL string) (*Candidate, error) {
	s, err := download(ctx, siteURL)
	if err != nil {
		return nil, fmt.Errorf("geosite update: %w", err)
	}
	i, err := download(ctx, ipURL)
	if err != nil {
		return nil, fmt.Errorf("geoip update: %w", err)
	}
	data, err := policy.ParseGeoData(s, i)
	if err != nil {
		return nil, err
	}
	if len(s) == 0 || len(i) == 0 {
		return nil, errors.New("empty geodata update")
	}
	return &Candidate{Data: data, site: s, ip: i}, nil
}

func (c *Candidate) Publish(stateDir string) error {
	if c == nil || c.Data == nil || len(c.site) == 0 || len(c.ip) == 0 {
		return errors.New("invalid geodata candidate")
	}
	if stateDir == "" {
		return errors.New("geodata state directory is required")
	}
	if err := os.MkdirAll(stateDir, 0750); err != nil {
		return err
	}
	sh, ih := sha256.Sum256(c.site), sha256.Sum256(c.ip)
	m := manifest{fmt.Sprintf("%x", sh), fmt.Sprintf("%x", ih)}
	for _, item := range []struct {
		name string
		data []byte
	}{{m.Site + ".dat", c.site}, {m.IP + ".dat", c.ip}} {
		if err := atomicWrite(stateDir, item.name, item.data); err != nil {
			return err
		}
	}
	raw, err := json.Marshal(m)
	if err != nil {
		return err
	}
	if err = atomicWrite(stateDir, "active.json", raw); err != nil {
		return err
	}
	return nil
}
func download(ctx context.Context, uri string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return nil, errors.New("invalid geodata URL")
	}
	if req.URL.Scheme != "https" && req.URL.Scheme != "http" {
		return nil, errors.New("geodata URL must use HTTP(S)")
	}
	client := http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.New("geodata HTTP request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("geodata HTTP status %d", resp.StatusCode)
	}
	data, err := readAll(resp.Body, resp.ContentLength)
	if len(data) > 256<<20 {
		return nil, errors.New("geodata exceeds 256 MiB")
	}
	return data, err
}
func atomicWrite(dir, name string, data []byte) error {
	f, err := os.CreateTemp(dir, ".geodata-")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, name))
}
