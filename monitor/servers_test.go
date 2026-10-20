package monitor

import (
	"context"
	"io"
	"net/http"
	"reconstructed.local/soga/config"
	"strings"
	"testing"
	"time"
)

func TestDedicatedDiagnosticsListeners(t *testing.T) {
	c := config.Defaults()
	c.PrometheusEnable = true
	c.PprofEnable = true
	c.PrometheusPort = 0
	c.PprofPort = 0
	s, err := Start(c, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	defer s.Close(ctx)
	addresses := s.Addresses()
	for i, path := range []string{"/metrics", "/debug/pprof/goroutine?debug=1"} {
		resp, err := http.Get("http://" + addresses[i] + path)
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil || resp.StatusCode != 200 {
			t.Fatal(resp.StatusCode, err)
		}
		if i == 0 && !strings.Contains(string(data), "soga_reconstructed_up") {
			t.Fatal(string(data))
		}
		if i == 1 && !strings.Contains(string(data), "goroutine profile:") {
			t.Fatal(string(data))
		}
	}
	resp, err := http.Get("http://" + addresses[0] + "/debug/pprof/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Fatal("debug handlers leaked into metrics listener")
	}
}
