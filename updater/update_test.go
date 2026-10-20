package updater

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"
)

func TestDownloadValidationAtomicReplacementAndRollbackCopy(t *testing.T) {
	old, newData := []byte("old executable"), []byte("new reconstruction executable")
	hash := sha256.Sum256(newData)
	var base string
	var bad atomic.Bool
	bad.Store(true)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/manifest" {
			_ = json.NewEncoder(w).Encode(Manifest{Format: "soga-reconstructed-release-v1", Version: "1.2.4", Assets: []Asset{{OS: runtime.GOOS, Arch: runtime.GOARCH, URL: base + "/binary", SHA256: fmt.Sprintf("%x", hash), Size: int64(len(newData))}}})
		} else if bad.Load() {
			_, _ = w.Write([]byte("bad download"))
		} else {
			_, _ = w.Write(newData)
		}
	}))
	defer server.Close()
	base = server.URL
	path := filepath.Join(t.TempDir(), "runtime")
	if err := os.WriteFile(path, old, 0750); err != nil {
		t.Fatal(err)
	}
	opts := Options{ManifestURL: base + "/manifest", Executable: path, CurrentVersion: "1.2.3"}
	if _, err := CheckAndInstall(context.Background(), opts); err == nil {
		t.Fatal("truncated update accepted")
	}
	raw, _ := os.ReadFile(path)
	if string(raw) != string(old) {
		t.Fatal("failed update altered executable")
	}
	bad.Store(false)
	result, err := CheckAndInstall(context.Background(), opts)
	if err != nil || !result.Updated {
		t.Fatal(result, err)
	}
	raw, _ = os.ReadFile(path)
	backup, _ := os.ReadFile(result.Backup)
	if string(raw) != string(newData) || string(backup) != string(old) {
		t.Fatal("installed/backup bytes differ")
	}
	// A second running instance still has the previous version in memory.
	result, err = CheckAndInstall(context.Background(), opts)
	if err != nil || result.Updated || !result.RestartRequired {
		t.Fatal("old instance did not discover the already installed release", result, err)
	}
	backup, _ = os.ReadFile(path + ".previous")
	if string(backup) != string(old) {
		t.Fatal("second instance destroyed the rollback backup")
	}
	opts.CurrentVersion = "1.2.4"
	result, err = CheckAndInstall(context.Background(), opts)
	if err != nil || result.Updated {
		t.Fatal("same release reinstalled", err)
	}
	opts.CurrentVersion = "2.0.0"
	result, err = CheckAndInstall(context.Background(), opts)
	if err != nil || result.Updated {
		t.Fatal("automatic downgrade", err)
	}
}

func TestOldProcessCannotDowngradeAlreadyUpdatedExecutable(t *testing.T) {
	old, release := []byte("original runtime"), []byte("release 1.4.0 executable")
	var manifest atomic.Value
	var downloads atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/manifest" {
			_ = json.NewEncoder(w).Encode(manifest.Load().(Manifest))
		} else {
			downloads.Add(1)
			_, _ = w.Write(release)
		}
	}))
	defer server.Close()
	setManifest := func(v string, data []byte) {
		hash := sha256.Sum256(data)
		manifest.Store(Manifest{Format: "soga-reconstructed-release-v1", Version: v,
			Assets: []Asset{{OS: runtime.GOOS, Arch: runtime.GOARCH, URL: server.URL + "/binary",
				SHA256: fmt.Sprintf("%x", hash), Size: int64(len(data))}}})
	}
	path := filepath.Join(t.TempDir(), "runtime")
	if err := os.WriteFile(path, old, 0755); err != nil {
		t.Fatal(err)
	}
	opts := Options{ManifestURL: server.URL + "/manifest", Executable: path, CurrentVersion: "1.2.0"}
	setManifest("1.4.0", release)
	if result, err := CheckAndInstall(context.Background(), opts); err != nil || !result.Updated {
		t.Fatal(result, err)
	}
	// A stale mirror offers a release newer than the running process but older
	// than the file installed by another instance.
	setManifest("1.3.0", []byte("stale release"))
	result, err := CheckAndInstall(context.Background(), opts)
	if err != nil || result.Updated || !result.RestartRequired || result.Version != "1.4.0" {
		t.Fatal("installed receipt was not honored", result, err)
	}
	raw, _ := os.ReadFile(path)
	backup, _ := os.ReadFile(path + ".previous")
	if string(raw) != string(release) || string(backup) != string(old) || downloads.Load() != 1 {
		t.Fatal("stale manifest changed files or downloaded obsolete binary")
	}
}
