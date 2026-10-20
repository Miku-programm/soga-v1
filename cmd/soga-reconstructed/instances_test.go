package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstanceLifecycleAndAtomicConfig(t *testing.T) {
	root := t.TempDir()
	initial := "# preserved\nwebapi_key=fake\nnode_id=1\nnode_id=2\n"
	if err := os.WriteFile(filepath.Join(root, "soga.conf"), []byte(initial), 0600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	run := func(action string, args ...string) error { return manageInstances(root, action, args, &out, &out) }
	if err := run("new", "node2", "node_id=3", "DNS_TEST=sample"); err != nil {
		t.Fatal(err)
	}
	if err := run("new", "node2"); err == nil {
		t.Fatal("existing instance overwritten")
	}
	if err := run("config", "node2", "node_id=4"); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "node2", "soga.conf")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(data), "node_id=") != 1 || !strings.Contains(string(data), "node_id=4") || !strings.Contains(string(data), "# preserved") {
		t.Fatal(string(data))
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal(info, err)
	}
	if err := run("config", "node2", "webapi_key=bad\nnode_id=666"); err == nil {
		t.Fatal("newline injection accepted")
	}
	if err := run("rename", "node2", "../escape"); err == nil {
		t.Fatal("name traversal accepted")
	}
	if err := run("rename", "node2", "node3"); err != nil {
		t.Fatal(err)
	}
	if err := run("remove", "node3", "default"); err == nil {
		t.Fatal("default deletion accepted")
	}
	if _, err = os.Stat(filepath.Join(root, "node3", "soga.conf")); err != nil {
		t.Fatal("partial delete on invalid batch", err)
	}
	if err := run("remove", "node3"); err != nil {
		t.Fatal(err)
	}
	data, _ = os.ReadFile(filepath.Join(root, "soga.conf"))
	if string(data) != initial {
		t.Fatal("default template modified")
	}
}
