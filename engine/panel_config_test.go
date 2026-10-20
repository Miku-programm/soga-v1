package engine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"reconstructed.local/soga/config"
)

func TestPanelConfigServiceRejectsBeforeNetworkAndDoesNotExposeKey(t *testing.T) {
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		http.Error(w, "unexpected request", http.StatusInternalServerError)
	}))
	defer server.Close()
	for _, fields := range [][2]string{{server.URL, ""}, {"", "secret-not-for-logs"}, {server.URL, "secret-not-for-logs"}} {
		c := config.Defaults()
		c.SogaPanelUrl, c.SogaPanelKey = fields[0], fields[1]
		_, err := StartNode(context.Background(), Options{Config: c, NodeID: "1", Paths: Paths{StateDir: t.TempDir()}})
		if err == nil || !strings.Contains(err.Error(), "configuration-sync") || !strings.Contains(err.Error(), "not implemented") {
			t.Fatalf("missing explicit configuration service diagnostic: %v", err)
		}
		if strings.Contains(err.Error(), "secret-not-for-logs") || strings.Contains(err.Error(), server.URL) {
			t.Fatalf("diagnostic exposes configuration values: %v", err)
		}
	}
	if calls.Load() != 0 {
		t.Fatalf("unsupported configuration service sent %d requests", calls.Load())
	}
	c := config.Defaults()
	c.SogaKey = "separate-original-license-value"
	if err := validatePanelConfigService(c); err != nil {
		t.Fatalf("configuration sync check conflates soga_key: %v", err)
	}
}
