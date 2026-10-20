package panel

import (
	"context"
	"strings"
)

// PolicyDenial keeps detector identity separate from user identity, including
// rule ID zero for default-deny decisions.
type PolicyDenial struct {
	UserID       int64
	RuleID       int64
	Rule, Target string
}
type PolicyReporter interface {
	ReportPolicyDenials(context.Context, []PolicyDenial) error
}

func (c *SSPanel) ReportPolicyDenials(ctx context.Context, items []PolicyDenial) error {
	logs := make([]AuditLog, 0, len(items))
	for _, v := range items {
		logs = append(logs, AuditLog{UserID: v.UserID, AuditID: int(v.RuleID)})
	}
	return c.ReportAuditLogs(ctx, logs)
}
func (c *ProxyPanel) ReportPolicyDenials(ctx context.Context, items []PolicyDenial) error {
	for _, v := range items {
		// Original SubmitDetectLog 0x16bb5e0 uses this literal reason; target is an
		// optional official API extension useful for identifying default-deny events.
		if err := c.ReportPolicyLog(ctx, ProxyAuditLog{UserID: v.UserID, RuleID: int(v.RuleID), Reason: "无", Target: v.Target}); err != nil {
			return err
		}
	}
	return nil
}
func (c *WHMCS) ReportPolicyDenials(ctx context.Context, items []PolicyDenial) error {
	ids := make([]int64, 0, len(items))
	seen := map[int64]bool{}
	for _, v := range items {
		if !seen[v.UserID] {
			seen[v.UserID] = true
			ids = append(ids, v.UserID)
		}
	}
	return c.ReportIllegalUsers(ctx, ids)
}

// SSPanel Type is intentionally ignored by original ToDetector (0x16ecd20).
// WUWGex (0xebb7a0) checks recognized prefixes, otherwise a regexp is assumed.
func SSPanelPolicy(rules []DetectRule) *Policy {
	p := &Policy{Mode: "reject", Rules: make([]PolicyRule, 0, len(rules))}
	for _, r := range rules {
		text := r.Regex
		known := false
		for _, prefix := range []string{"regexp:", "domain:", "full:", "geosite:", "keyword:", "ip:", "geoip:", "port:"} {
			if strings.HasPrefix(text, prefix) {
				known = true
				break
			}
		}
		if !known {
			text = "regexp:" + text
		}
		p.Rules = append(p.Rules, PolicyRule{ID: int64(r.ID), Rule: text})
	}
	return p
}
