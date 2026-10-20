package panel

import (
	"encoding/json"
	"fmt"
	"strings"
)

func applyUniRoutes(node *Node, raw json.RawMessage) error {
	if !meaningfulJSON(raw) {
		return nil
	}
	var routes []struct {
		ID          int64           `json:"id"`
		Match       json.RawMessage `json:"match"`
		Action      string          `json:"action"`
		ActionValue string          `json:"action_value"`
	}
	if err := json.Unmarshal(raw, &routes); err != nil {
		return fmt.Errorf("UniProxy routes: %w", err)
	}
	for _, route := range routes {
		// 0x179bee0 emits only block detectors; 0x179bc80 separately
		// emits nonempty dns actions. Other route actions are ignored
		// by these two original conversions.
		if route.Action != "block" && route.Action != "dns" {
			continue
		}
		var matches []string
		if err := json.Unmarshal(route.Match, &matches); err != nil {
			// Exact fallback at 0x179bb60: SplitClean(raw JSON, ",").
			for _, line := range strings.Split(strings.TrimSpace(string(route.Match)), ",") {
				if line = strings.TrimSpace(line); line != "" {
					matches = append(matches, line)
				}
			}
		}
		if route.Action == "block" {
			if node.Policy == nil {
				node.Policy = &Policy{Mode: "reject"}
			}
			for _, match := range matches {
				node.Policy.Rules = append(node.Policy.Rules, PolicyRule{ID: route.ID, Rule: match})
			}
		} else if len(matches) > 0 && route.ActionValue != "" {
			node.DNSRules = append(node.DNSRules, DNSRule{Domains: matches, Servers: []string{route.ActionValue}})
		}
	}
	return nil
}
