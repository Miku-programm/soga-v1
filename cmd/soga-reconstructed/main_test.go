package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVersionDisclosesIndependentReconstruction(t *testing.T) {
	var out, err bytes.Buffer
	if exit := run([]string{"version"}, &out, &err); exit != 0 ||
		!strings.Contains(out.String(), "2.17.0") ||
		!strings.Contains(out.String(), "not original source") {
		t.Fatalf("exit output %s %s", &out, &err)
	}
}

func TestDefaultsAndInspect(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run([]string{"defaults"}, &out, &errOut); code != 0 {
		t.Fatal(code, &errOut)
	}
	var defaults map[string]string
	if err := json.Unmarshal(out.Bytes(), &defaults); err != nil || len(defaults) != 157 {
		t.Fatal(len(defaults), err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "soga.conf")
	input := "server_type=VMESS\nwebapi_mukey=fixture-secret\nnode_id=10\n"
	if err := os.WriteFile(path, []byte(input), 0600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if code := run([]string{"inspect", "-c", path, "-node_id", "12"}, &out, &errOut); code != 0 {
		t.Fatal(code, &errOut)
	}
	var result struct {
		Normalized string            `json:"normalized_server_type"`
		Legacy     bool              `json:"legacy_api_key_selected"`
		Values     map[string]string `json:"values"`
	}
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Normalized != "v2ray" || !result.Legacy || result.Values["node_id"] != "12" ||
		result.Values["webapi_mukey"] != "[REDACTED]" || result.Values["ban_private_ip"] != "false" {
		t.Fatal(result)
	}
	if strings.Contains(out.String(), "fixture-secret") {
		t.Fatal("secret exposed")
	}
	data, _ := os.ReadFile(path)
	if string(data) != input {
		t.Fatal("inspection modified input")
	}
}

func TestExplicitEmptyFlagUsesRecoveredLoaderBehavior(t *testing.T) {
	var out, errOut bytes.Buffer
	path := filepath.Join(t.TempDir(), "soga.conf")
	if err := os.WriteFile(path, []byte("server_type=vmess\n"), 0600); err != nil {
		t.Fatal(err)
	}
	// FlagSet.Visit calls 0x1346da0, which stores Value.String without an
	// empty-value check. This differs from the environment-variable path.
	if code := run([]string{"inspect", "-c", path, "-server_type", ""}, &out, &errOut); code != 0 {
		t.Fatal(code, &errOut)
	}
	var result struct {
		Normalized string `json:"normalized_server_type"`
	}
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Normalized != "" {
		t.Fatal(result)
	}
}

func TestMissingConfigurationCannotAppearToStart(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run([]string{"serve", "-c", filepath.Join(t.TempDir(), "missing.conf")}, &out, &errOut); code != 1 || strings.Contains(out.String(), "started") {
		t.Fatal(code, &out, &errOut)
	}
}
