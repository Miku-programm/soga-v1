package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// discoverGeoPaths preserves explicit overrides and checks each default
// independently. An absent file leaves that dataset embedded; an unreadable or
// invalid selected file must surface an error when discovered or loaded.
// The independent application uses the configuration's directory, rather than
// reaching into the original program's /etc/soga installation.
func discoverGeoPaths(configPath, explicitSite, explicitIP string) (site, ip string, err error) {
	dir := filepath.Dir(configPath)
	discover := func(explicit, name string) (string, error) {
		if explicit != "" {
			return explicit, nil
		}
		path := filepath.Join(dir, name)
		info, err := os.Stat(path)
		if errors.Is(err, os.ErrNotExist) {
			return "", nil
		}
		if err != nil {
			return "", fmt.Errorf("discover %s: %w", name, err)
		}
		if !info.Mode().IsRegular() {
			return "", fmt.Errorf("geodata path is not a regular file: %s", path)
		}
		return path, nil
	}
	if site, err = discover(explicitSite, "geosite.dat"); err != nil {
		return "", "", err
	}
	if ip, err = discover(explicitIP, "geoip.dat"); err != nil {
		return "", "", err
	}
	return site, ip, nil
}
