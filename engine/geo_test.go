package engine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"reconstructed.local/soga/config"
	"reconstructed.local/soga/geodata"
)

func TestGeoUpdateMissingLiveCategoryKeepsMemoryAndDisk(t *testing.T) {
	original, err := geodata.Load("", "", "")
	if err != nil {
		t.Fatal(err)
	}
	// Both files are valid, but the new site set cannot satisfy the live rule.
	domain := append([]byte{8, 3, 18, 12}, []byte("example.test")...)
	entry := append([]byte{10, 4, 't', 'e', 's', 't', 18, byte(len(domain))}, domain...)
	site := append([]byte{10, byte(len(entry))}, entry...)
	ip := []byte{10, 16, 10, 4, 't', 'e', 's', 't', 18, 8, 10, 4, 192, 0, 2, 0, 16, 24}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/site" {
			_, _ = w.Write(site)
		} else {
			_, _ = w.Write(ip)
		}
	}))
	defer server.Close()
	c := config.Defaults()
	c.GeoSiteUrl, c.GeoIpUrl = server.URL+"/site", server.URL+"/ip"
	dir := t.TempDir()
	block := filepath.Join(dir, "blockList")
	if err := os.WriteFile(block, []byte("geosite:google\n"), 0600); err != nil {
		t.Fatal(err)
	}
	n := &Node{opts: Options{Config: c, NodeID: "1", Paths: Paths{StateDir: dir, BlockList: block}}, geo: original}
	if err := n.updateGeo(context.Background()); err == nil {
		t.Fatal("new data missing the active category accepted")
	}
	if n.geo != original {
		t.Fatal("failed update replaced live data")
	}
	if _, err := os.Stat(filepath.Join(n.geoStateDir(), "active.json")); !os.IsNotExist(err) {
		t.Fatal("invalid live-rule update published a cache", err)
	}
}
