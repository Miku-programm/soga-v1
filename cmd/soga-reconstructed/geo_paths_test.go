package main

import (
	"os"
	"path/filepath"
	"testing"

	"reconstructed.local/soga/geodata"
)

func TestGeoPathsDiscoverIndependentDefaults(t *testing.T) {
	for _, mode := range []string{"none", "site", "ip", "both"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			// Minimal V2Ray protobuf categories with an actual domain/prefix.
			domain := append([]byte{8, 3, 18, 18}, []byte("exact.example.test")...)
			entry := append([]byte{10, 4, 't', 'e', 's', 't', 18, byte(len(domain))}, domain...)
			siteData := append([]byte{10, byte(len(entry))}, entry...)
			ipData := []byte{10, 16, 10, 4, 't', 'e', 's', 't', 18, 8, 10, 4, 192, 0, 2, 0, 16, 24}
			wantSite, wantIP := "", ""
			if mode == "site" || mode == "both" {
				wantSite = filepath.Join(dir, "geosite.dat")
				if err := os.WriteFile(wantSite, siteData, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "ip" || mode == "both" {
				wantIP = filepath.Join(dir, "geoip.dat")
				if err := os.WriteFile(wantIP, ipData, 0600); err != nil {
					t.Fatal(err)
				}
			}
			site, ip, err := discoverGeoPaths(filepath.Join(dir, "soga.conf"), "", "")
			if err != nil || site != wantSite || ip != wantIP {
				t.Fatal(site, ip, err)
			}
			data, err := geodata.Load(site, ip, "")
			if err != nil {
				t.Fatal(err)
			}
			siteCategory, ipCategory := "google", "cn"
			if wantSite != "" {
				siteCategory = "test"
			}
			if wantIP != "" {
				ipCategory = "test"
			}
			if domains, ok := data.Domains(siteCategory); !ok || len(domains) == 0 {
				t.Fatal("selected or embedded site category missing", siteCategory)
			}
			if prefixes, _, ok := data.Prefixes(ipCategory); !ok || len(prefixes) == 0 {
				t.Fatal("selected or embedded IP category missing", ipCategory)
			}
		})
	}
}

func TestGeoPathsExplicitPrecedence(t *testing.T) {
	dir := t.TempDir()
	// Invalid automatic candidates must not override explicit file arguments.
	for _, name := range []string{"geosite.dat", "geoip.dat"} {
		if err := os.Mkdir(filepath.Join(dir, name), 0700); err != nil {
			t.Fatal(err)
		}
	}
	site, ip, err := discoverGeoPaths(filepath.Join(dir, "soga.conf"), "custom-site", "custom-ip")
	if err != nil || site != "custom-site" || ip != "custom-ip" {
		t.Fatal(site, ip, err)
	}
}

func TestGeoPathsInvalidFilesDoNotFallback(t *testing.T) {
	for _, name := range []string{"geosite.dat", "geoip.dat"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, name), []byte{255}, 0600); err != nil {
				t.Fatal(err)
			}
			site, ip, err := discoverGeoPaths(filepath.Join(dir, "soga.conf"), "", "")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := geodata.Load(site, ip, ""); err == nil {
				t.Fatal("malformed selected dataset silently fell back")
			}
		})
	}
}

func TestGeoPathsStatErrors(t *testing.T) {
	for _, name := range []string{"geosite.dat", "geoip.dat"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Mkdir(filepath.Join(dir, name), 0700); err != nil {
				t.Fatal(err)
			}
			if _, _, err := discoverGeoPaths(filepath.Join(dir, "soga.conf"), "", ""); err == nil {
				t.Fatal("directory accepted as geodata")
			}
		})
	}
	if _, _, err := discoverGeoPaths("invalid\x00directory/soga.conf", "", ""); err == nil {
		t.Fatal("stat error silently treated as missing file")
	}
}
