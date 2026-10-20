package engine

import (
	"context"
	"strings"
	"testing"

	"reconstructed.local/soga/config"
	"reconstructed.local/soga/panel"
)

func TestInvalidIntervalsRejectedBeforeStartingRuntime(t *testing.T) {
	for _, name := range []string{"check", "submit", "jitter"} {
		t.Run(name, func(t *testing.T) {
			c := config.Defaults()
			switch name {
			case "check":
				c.CheckInterval = maxIntervalSeconds + 1
			case "submit":
				c.SubmitInterval = maxIntervalSeconds + 1
			case "jitter":
				c.RandomIntervalRange = maxIntervalSeconds + 1
			}
			_, err := StartNode(context.Background(), Options{Config: c, NodeID: "1"})
			if err == nil || !strings.Contains(err.Error(), "interval") {
				t.Fatal("invalid interval not rejected before runtime setup", err)
			}
		})
	}
	for _, value := range []int{-1, maxIntervalSeconds + 1} {
		for _, push := range []bool{false, true} {
			node := panel.Node{}
			if push {
				node.Basic.PushInterval = value
			} else {
				node.Basic.PullInterval = value
			}
			// Invalid panel data must be rejected before touching a live node.
			err := (&Node{}).applyConfiguration(context.Background(), node, nil)
			if err == nil || !strings.Contains(err.Error(), "interval") {
				t.Fatalf("invalid panel interval %d accepted: %v", value, err)
			}
		}
	}
}
