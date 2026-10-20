package engine

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"reconstructed.local/soga/config"
	"reconstructed.local/soga/panel"
	"reconstructed.local/soga/policy"
)

func TestForbiddenPortsWithoutFileAndRemoteFailure(t *testing.T) {
	c := config.Defaults()
	c.ForbiddenPorts = []string{"25"}
	n := &Node{opts: Options{Config: c, Paths: Paths{BlockList: filepath.Join(t.TempDir(), "absent")}}}
	p, err := n.loadPolicy(context.Background(), panel.Node{})
	if err != nil {
		t.Fatal(err)
	}
	if err = p.Check(policy.Target{Host: "192.0.2.1", Port: 25}); err == nil {
		t.Fatal("missing file disabled forbidden_ports")
	}
	var fail atomic.Bool
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail.Load() {
			http.Error(w, "temporary error", 503)
			return
		}
		fmt.Fprintln(w, "ip:198.51.100.1")
	}))
	defer remote.Close()
	n.opts.Config.BlockListUrl = remote.URL
	p, err = n.loadPolicy(context.Background(), panel.Node{})
	if err != nil {
		t.Fatal(err)
	}
	n.policy.Store(p)
	for _, target := range []policy.Target{{Host: "192.0.2.1", Port: 25}, {Host: "198.51.100.1", Port: 443}} {
		if err = p.Check(target); err == nil {
			t.Fatal("remote list or local port was ignored", target)
		}
	}
	fail.Store(true)
	n.blockDocument.fetched = time.Time{}
	if _, err = n.loadPolicy(context.Background(), panel.Node{}); err == nil {
		t.Fatal("remote error body accepted as rules")
	}
	if n.policy.Load() != p {
		t.Fatal("failed candidate changed active policy")
	}
}
