package panel

import (
	"context"
	"crypto/md5"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

// DJ implements the original _U2caaPPsm form API. Config and reports are POSTs.
// Its acknowledgement is HTTP transport success; the original has no JSON ACK.
type DJ struct {
	*Client
	mu       sync.Mutex
	snapshot *djConfiguration
	emails   map[int64]string // retain removed users until callers finish pending reports
}

type djConfiguration struct {
	Inbounds []struct {
		Port     int `json:"port"`
		Settings struct {
			Clients []struct {
				ID      string `json:"id"`
				Email   string `json:"email"`
				AlterID int    `json:"alterId"`
			} `json:"clients"`
		} `json:"settings"`
	} `json:"inbounds"`
	Routing struct {
		Rules []struct {
			Domain []string `json:"domain"`
		} `json:"rules"`
	} `json:"routing"`
}

func NewDJ(opts Options) (*DJ, error) {
	if NormalizeNodeType(opts.NodeType) != "vmess" {
		return nil, fmt.Errorf("%w: DJ supports VMess", ErrUnsupported)
	}
	c, err := NewSogaV1(opts)
	if err != nil {
		return nil, err
	}
	return &DJ{Client: c, emails: make(map[int64]string)}, nil
}
func (c *DJ) Capabilities() Capabilities { return Capabilities{Status: true} }

// DJUserID is the original 0x169eee0 mapping, not an allocated local sequence.
func DJUserID(email string) int64 {
	sum := md5.Sum([]byte(email))
	return int64(binary.BigEndian.Uint32(sum[:4]))
}

func (c *DJ) form(ctx context.Context, path string, fields url.Values) ([]byte, error) {
	if fields == nil {
		fields = make(url.Values)
	}
	fields.Set("secret", c.opts.APIKey)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint("/"+path), strings.NewReader(fields.Encode()))
	if err != nil {
		return nil, errors.New("DJ request could not be constructed")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("panel POST %s: %w", path, transportCause(err))
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, &HTTPError{Endpoint: path, Status: resp.StatusCode}
	}
	return readResponse(resp)
}

func (c *DJ) fetchConfiguration(ctx context.Context) (djConfiguration, []byte, error) {
	body, err := c.form(ctx, "sub_server/get_config", nil)
	if err != nil {
		return djConfiguration{}, nil, err
	}
	var wire djConfiguration
	if err = json.Unmarshal(body, &wire); err != nil {
		return wire, nil, err
	}
	// 0x169eac0 and 0x169eb80 explicitly select inbounds[1].
	if len(wire.Inbounds) < 2 {
		return wire, nil, errors.New("DJ config requires a second inbound")
	}
	if p := wire.Inbounds[1].Port; p < 1 || p > 65535 {
		return wire, nil, errors.New("DJ second inbound has invalid port")
	}
	seen := make(map[int64]string)
	for _, u := range wire.Inbounds[1].Settings.Clients {
		if u.Email == "" || u.ID == "" {
			return wire, nil, errors.New("DJ user requires email and UUID")
		}
		id := DJUserID(u.Email)
		if _, ok := seen[id]; ok {
			return wire, nil, errors.New("DJ user IDs collide or repeat")
		}
		seen[id] = u.Email
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for id, email := range seen {
		if old, ok := c.emails[id]; ok && old != email {
			return wire, nil, errors.New("DJ user ID collides with pending traffic identity")
		}
	}
	for id, email := range seen {
		c.emails[id] = email
	}
	return wire, body, nil
}
func (c *DJ) FetchNode(ctx context.Context) (Node, error) {
	wire, body, err := c.fetchConfiguration(ctx)
	if err != nil {
		return Node{}, err
	}
	c.mu.Lock()
	c.snapshot = &wire
	c.mu.Unlock()
	n := Node{Config: NodeConfig{Port: wire.Inbounds[1].Port, AlterID: -1, StreamType: "ws", TLSType: "tls", Path: "/ws"}, RawConfig: append(json.RawMessage(nil), body...)}
	n.Policy = &Policy{Mode: "reject"}
	for _, r := range wire.Routing.Rules {
		for _, domain := range r.Domain {
			n.Policy.Rules = append(n.Policy.Rules, PolicyRule{Rule: domain})
		}
	}
	return n, nil
}
func (c *DJ) FetchUsers(ctx context.Context) ([]User, error) {
	c.mu.Lock()
	wire := c.snapshot
	c.snapshot = nil
	c.mu.Unlock()
	if wire == nil {
		w, _, err := c.fetchConfiguration(ctx)
		if err != nil {
			return nil, err
		}
		wire = &w
	}
	users := make([]User, 0, len(wire.Inbounds[1].Settings.Clients))
	for _, u := range wire.Inbounds[1].Settings.Clients {
		users = append(users, User{ID: DJUserID(u.Email), Username: u.Email, UUID: u.ID, AlterID: u.AlterID})
	}
	return users, nil
}
func (c *DJ) RoutingDomains(n Node) ([]string, error) {
	var wire djConfiguration
	if err := json.Unmarshal(n.RawConfig, &wire); err != nil {
		return nil, err
	}
	var domains []string
	for _, rule := range wire.Routing.Rules {
		domains = append(domains, rule.Domain...)
	}
	return domains, nil
}
func (c *DJ) FetchAuditRules(context.Context) ([]AuditRule, error) { return nil, ErrUnsupported }
func (c *DJ) FetchWhiteList(context.Context) ([]string, error)     { return nil, ErrUnsupported }
func (c *DJ) ReportAliveIPs(context.Context, []AliveIP) error      { return ErrUnsupported }
func (c *DJ) ReportAuditLogs(context.Context, []AuditLog) error    { return ErrUnsupported }
func (c *DJ) ReportTraffic(ctx context.Context, rows []Traffic) error {
	totals, err := aggregateTraffic(rows)
	if err != nil {
		return err
	}
	payload := make(map[string]struct {
		Upload   int64 `json:"upload"`
		Download int64 `json:"download"`
	})
	c.mu.Lock()
	for id, t := range totals {
		email, ok := c.emails[id]
		if !ok {
			c.mu.Unlock()
			return fmt.Errorf("DJ user ID %d has no verified email mapping", id)
		}
		payload[email] = struct {
			Upload   int64 `json:"upload"`
			Download int64 `json:"download"`
		}{t[0], t[1]}
	}
	c.mu.Unlock()
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	_, err = c.form(ctx, "sub_server/submit_traffic", url.Values{"email_traffic": {string(body)}})
	return err
}

// ReportStatus sends the metrics available in the common DTO. The original
// additionally samples loads, network counters/rates and socket counts; these
// are omitted rather than invented. ReportDJStatus can supply verified extras.
func (c *DJ) ReportStatus(ctx context.Context, s Status) error { return c.ReportDJStatus(ctx, s, nil) }
func (c *DJ) ReportDJStatus(ctx context.Context, s Status, extra map[string]json.RawMessage) error {
	payload := map[string]any{"v2": map[string]int{"code": 0}, "uptime": s.Uptime, "cpu": map[string]float64{"percent": s.CPU}, "memory": s.Mem, "swap": s.Swap, "disk": s.Disk}
	for k, v := range extra {
		if _, exists := payload[k]; exists {
			return fmt.Errorf("DJ status extra cannot replace %s", k)
		}
		payload[k] = v
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	_, err = c.form(ctx, "sub_server/submit_info", url.Values{"status": {string(body)}})
	return err
}

func aggregateTraffic(rows []Traffic) (map[int64][2]int64, error) {
	out := make(map[int64][2]int64, len(rows))
	for _, r := range rows {
		if r.Upload < 0 || r.Download < 0 {
			return nil, errors.New("traffic counters cannot be negative")
		}
		v := out[r.ID]
		if r.Upload > math.MaxInt64-v[0] || r.Download > math.MaxInt64-v[1] {
			return nil, errors.New("traffic counter overflow")
		}
		out[r.ID] = [2]int64{v[0] + r.Upload, v[1] + r.Download}
	}
	return out, nil
}
