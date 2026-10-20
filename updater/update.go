// Package updater installs releases of this independent reconstruction.
// It never downloads or substitutes the original proprietary soga binary.
package updater

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

type Asset struct {
	OS     string `json:"os"`
	Arch   string `json:"arch"`
	URL    string `json:"url"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}
type Manifest struct {
	Format  string  `json:"format"`
	Version string  `json:"version"`
	Assets  []Asset `json:"assets"`
}
type Options struct{ ManifestURL, Executable, CurrentVersion string }
type Result struct {
	Updated         bool
	RestartRequired bool
	Version, Backup string
}
type installedRelease struct {
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
}

func ValidateURL(uri string) error {
	u, err := url.Parse(uri)
	if err != nil || u.Host == "" || u.User != nil {
		return errors.New("invalid update URL")
	}
	if u.Scheme == "https" {
		return nil
	}
	if u.Scheme == "http" {
		ip := net.ParseIP(u.Hostname())
		if ip != nil && ip.IsLoopback() {
			return nil
		}
	}
	return errors.New("update URL requires HTTPS (HTTP is allowed only on a literal loopback IP)")
}

func version(v string) ([3]uint64, bool, error) {
	var parts [3]uint64
	base, _, pre := strings.Cut(strings.TrimPrefix(v, "v"), "-")
	fields := strings.Split(base, ".")
	if len(fields) != 3 {
		return parts, false, errors.New("release version must have major.minor.patch")
	}
	for i, s := range fields {
		n, err := strconv.ParseUint(s, 10, 32)
		if err != nil {
			return parts, false, err
		}
		parts[i] = n
	}
	return parts, pre, nil
}
func newer(next, current string) (bool, error) {
	a, ap, err := version(next)
	if err != nil {
		return false, err
	}
	b, bp, err := version(current)
	if err != nil {
		return false, err
	}
	if ap {
		return false, errors.New("automatic updates accept stable releases only")
	}
	for i := range a {
		if a[i] != b[i] {
			return a[i] > b[i], nil
		}
	}
	return bp, nil
}
func request(ctx context.Context, uri string) (*http.Response, error) {
	if err := ValidateURL(uri); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return nil, err
	}
	client := http.Client{Timeout: 5 * time.Minute, CheckRedirect: func(r *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return errors.New("too many update redirects")
		}
		return ValidateURL(r.URL.String())
	}}
	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.New("update HTTP request failed")
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("update HTTP status %d", resp.StatusCode)
	}
	return resp, nil
}

// CheckAndInstall validates the complete download before replacing the running
// executable. The old process keeps running until its supervisor restarts it.
func CheckAndInstall(ctx context.Context, o Options) (Result, error) {
	var result Result
	resp, err := request(ctx, o.ManifestURL)
	if err != nil {
		return result, err
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20+1))
	resp.Body.Close()
	if err != nil {
		return result, err
	}
	if len(raw) > 1<<20 {
		return result, errors.New("update manifest exceeds 1 MiB")
	}
	var manifest Manifest
	if err = json.Unmarshal(raw, &manifest); err != nil {
		return result, err
	}
	if manifest.Format != "soga-reconstructed-release-v1" {
		return result, errors.New("not a reconstruction release manifest")
	}
	ok, err := newer(manifest.Version, o.CurrentVersion)
	if err != nil || !ok {
		return result, err
	}
	var selected *Asset
	for i, a := range manifest.Assets {
		if a.OS == runtime.GOOS && a.Arch == runtime.GOARCH {
			if selected != nil {
				return result, errors.New("duplicate release asset")
			}
			selected = &manifest.Assets[i]
		}
	}
	if selected == nil {
		return result, errors.New("release has no asset for this platform")
	}
	sum, err := hex.DecodeString(selected.SHA256)
	if err != nil || len(sum) != sha256.Size || selected.Size < 4 || selected.Size > 512<<20 {
		return result, errors.New("invalid release checksum or size")
	}
	target, err := filepath.EvalSymlinks(o.Executable)
	if err != nil {
		return result, err
	}
	stat, err := os.Stat(target)
	if err != nil {
		return result, err
	}
	if !stat.Mode().IsRegular() {
		return result, errors.New("update target must be a regular file")
	}
	lock, err := os.OpenFile(target+".update-lock", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return result, fmt.Errorf("another update may be active (inspect .update-lock after a crash): %w", err)
	}
	lock.Close()
	defer os.Remove(target + ".update-lock")
	// Multiple node instances share an executable but keep their old in-memory
	// version after another instance updates it. Recheck the actual file only
	// after taking the lock, preserving the original rollback backup.
	stat, err = os.Stat(target)
	if err != nil {
		return result, err
	}
	current, err := os.Open(target)
	if err != nil {
		return result, err
	}
	currentHash := sha256.New()
	_, err = io.Copy(currentHash, current)
	err = errors.Join(err, current.Close())
	if err != nil {
		return result, err
	}
	digest := hex.EncodeToString(currentHash.Sum(nil))
	desired := hex.EncodeToString(sum)
	if digest == desired {
		return Result{Version: manifest.Version, RestartRequired: true}, nil
	}
	installedVersion := o.CurrentVersion
	receiptPath := target + ".installed.json"
	receiptFile, err := os.Open(receiptPath)
	if err == nil {
		raw, readErr := io.ReadAll(io.LimitReader(receiptFile, 65537))
		receiptFile.Close()
		if readErr != nil {
			return result, readErr
		}
		var receipts []installedRelease
		if len(raw) > 65536 || json.Unmarshal(raw, &receipts) != nil {
			return result, errors.New("invalid installed-release receipt")
		}
		for _, receipt := range receipts {
			if receipt.SHA256 == digest {
				installedVersion = receipt.Version
				break
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return result, err
	}
	advance, err := newer(manifest.Version, installedVersion)
	if err != nil {
		return result, err
	}
	if !advance {
		restart, err := newer(installedVersion, o.CurrentVersion)
		if err != nil {
			return result, err
		}
		return Result{Version: installedVersion, RestartRequired: restart}, nil
	}
	download, err := request(ctx, selected.URL)
	if err != nil {
		return result, err
	}
	defer download.Body.Close()
	temp, err := os.CreateTemp(filepath.Dir(target), ".reconstruction-update-")
	if err != nil {
		return result, err
	}
	path := temp.Name()
	defer os.Remove(path)
	hash := sha256.New()
	n, copyErr := io.Copy(io.MultiWriter(temp, hash), io.LimitReader(download.Body, selected.Size+1))
	if copyErr == nil && n != selected.Size {
		copyErr = errors.New("release size mismatch")
	}
	if copyErr == nil && hex.EncodeToString(hash.Sum(nil)) != strings.ToLower(selected.SHA256) {
		copyErr = errors.New("release checksum mismatch")
	}
	if copyErr == nil {
		copyErr = temp.Chmod(stat.Mode().Perm())
	}
	if copyErr == nil {
		copyErr = temp.Sync()
	}
	copyErr = errors.Join(copyErr, temp.Close())
	if copyErr != nil {
		return result, copyErr
	}
	// A separately named backup remains available for a manual rollback.
	backup := target + ".previous"
	if err = backupFile(target, backup, stat.Mode().Perm()); err != nil {
		return result, err
	}
	// Publish both fingerprints before replacement: after a crash on either
	// side of Rename, the current file still has a matching version receipt.
	receipts, err := json.Marshal([]installedRelease{{Version: installedVersion, SHA256: digest},
		{Version: manifest.Version, SHA256: desired}})
	if err != nil {
		return result, err
	}
	if err = writeReceipt(receiptPath, receipts); err != nil {
		return result, err
	}
	if err = os.Rename(path, target); err != nil {
		return result, err
	}
	return Result{Updated: true, Version: manifest.Version, Backup: backup}, nil
}

func writeReceipt(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".reconstruction-receipt-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}

func backupFile(source, target string, mode os.FileMode) error {
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.CreateTemp(filepath.Dir(target), ".reconstruction-previous-")
	if err != nil {
		return err
	}
	defer os.Remove(out.Name())
	_, err = io.Copy(out, in)
	if err == nil {
		err = out.Chmod(mode)
	}
	if err == nil {
		err = out.Sync()
	}
	err = errors.Join(err, out.Close())
	if err != nil {
		return err
	}
	return os.Rename(out.Name(), target)
}
