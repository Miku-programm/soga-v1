package panel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
)

type ProxyPanel struct {
	*Client
	prefix string
}

func NewProxyPanel(opts Options) (*ProxyPanel, error) {
	opts.NodeType = NormalizeNodeType(opts.NodeType)
	prefix := ""
	switch opts.NodeType {
	case "vmess":
		prefix = "v2ray"
	case "trojan":
		prefix = "trojan"
	case "shadowsocksr":
		prefix = "ssr"
	default:
		return nil, fmt.Errorf("%w: ProxyPanel %s account model", ErrUnsupported, opts.NodeType)
	}
	if n, err := strconv.ParseInt(opts.NodeID, 10, 64); err != nil || n <= 0 {
		return nil, errors.New("ProxyPanel node ID must be a positive integer")
	}
	c, err := NewSogaV1(opts)
	if err != nil {
		return nil, err
	}
	c.proxyPanel = true
	return &ProxyPanel{c, "/api/" + prefix + "/v1"}, nil
}
func (c *ProxyPanel) path(action string) string  { return c.prefix + "/" + action + "/" + c.opts.NodeID }
func (c *ProxyPanel) Capabilities() Capabilities { return Capabilities{AliveIPs: true, Status: true} }

func unwrapProxyPanel(body []byte, dst any) error {
	var envelope struct {
		Status  string          `json:"status"`
		Code    *int            `json:"code"`
		Data    json.RawMessage `json:"data"`
		Message string          `json:"message"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return err
	}
	if envelope.Status != "success" || envelope.Code == nil || *envelope.Code != 200 {
		return errors.New("ProxyPanel response is not status=success/code=200")
	}
	if len(envelope.Data) == 0 || string(envelope.Data) == "null" {
		return errors.New("ProxyPanel response lacks data")
	}
	return json.Unmarshal(envelope.Data, dst)
}

func (c *ProxyPanel) FetchNode(ctx context.Context) (node Node, err error) {
	err = c.get(ctx, c.path("node"), func(body []byte) error {
		var raw json.RawMessage
		if err := unwrapProxyPanel(body, &raw); err != nil {
			return err
		}
		var wire struct {
			V2Port        wireInteger `json:"v2_port"`
			TrojanPort    wireInteger `json:"trojan_port"`
			Network       string      `json:"v2_net"`
			HeaderType    string      `json:"v2_type"`
			Host          string      `json:"v2_host"`
			Path          string      `json:"v2_path"`
			TLS           bool        `json:"v2_tls"`
			AlterID       int         `json:"v2_alter_id"`
			SpeedLimit    float64     `json:"speed_limit"`
			ClientLimit   int         `json:"client_limit"`
			Key           string      `json:"key"`
			PEM           string      `json:"pem"`
			Port          wireInteger `json:"port"`
			Single        int         `json:"single"`
			Method        string      `json:"method"`
			Protocol      string      `json:"protocol"`
			ProtocolParam string      `json:"protocol_param"`
			Obfs          string      `json:"obfs"`
			ObfsParam     string      `json:"obfs_param"`
			Password      string      `json:"passwd"`
			UDP           *int        `json:"is_udp"`
		}
		if err := json.Unmarshal(raw, &wire); err != nil {
			return err
		}
		cfg := NodeConfig{Port: int(wire.V2Port), AlterID: wire.AlterID, StreamType: wire.Network, Host: wire.Host, Path: wire.Path, TLSType: "none"}
		if wire.TLS {
			cfg.TLSType = "tls"
		}
		if c.opts.NodeType == "trojan" {
			cfg.Port = int(wire.TrojanPort)
			cfg.StreamType = "tcp"
			cfg.TLSType = "tls"
		}
		if c.opts.NodeType == "shadowsocksr" {
			cfg = NodeConfig{Port: int(wire.Port), Method: wire.Method, Protocol: wire.Protocol,
				ProtocolParam: wire.ProtocolParam, Obfs: wire.Obfs, ObfsParam: wire.ObfsParam,
				Password: wire.Password, MultiUserPorts: wire.Single == 0}
			if wire.Single != 0 {
				cfg.SinglePortType = "protocol"
			}
		}
		if !cfg.MultiUserPorts && (cfg.Port < 1 || cfg.Port > 65535) {
			return errors.New("ProxyPanel node lacks valid port")
		}
		if wire.Host != "" {
			cfg.ServerNames = []string{wire.Host}
		}
		if wire.Key != "" || wire.PEM != "" {
			if wire.Key == "" || wire.PEM == "" {
				return errors.New("ProxyPanel certificate requires both pem and key")
			}
			cfg.Certificate, cfg.CertificateKey = wire.PEM, wire.Key
			cfg.CertMode = "remote"
		}
		node = Node{Basic: Basic{SpeedLimit: wire.SpeedLimit * 8 / 1_000_000}, Config: cfg, RawConfig: append(json.RawMessage(nil), raw...)}
		if wire.HeaderType != "" && wire.HeaderType != "none" {
			node.UnsupportedOptions = append(node.UnsupportedOptions, "v2_type:"+wire.HeaderType)
		}
		if wire.ClientLimit > 0 {
			node.UnsupportedOptions = append(node.UnsupportedOptions, "client_limit")
		}
		if c.opts.NodeType == "shadowsocksr" && wire.UDP != nil && *wire.UDP == 0 {
			node.UnsupportedOptions = append(node.UnsupportedOptions, "is_udp=0")
		}
		return nil
	})
	if err != nil {
		return node, err
	}
	policy, err := c.FetchPolicy(ctx)
	if err != nil {
		return node, err
	}
	node.Policy = &Policy{Mode: policy.Mode}
	for _, r := range policy.Rules {
		prefix := ""
		switch r.Type {
		case "reg":
			prefix = "regexp:"
		case "domain":
			prefix = "domain:"
		default:
			return node, fmt.Errorf("%w: ProxyPanel rule type %s", ErrUnsupported, r.Type)
		}
		node.Policy.Rules = append(node.Policy.Rules, PolicyRule{ID: int64(r.ID), Rule: prefix + r.Pattern})
	}
	return node, nil
}
func (c *ProxyPanel) FetchUsers(ctx context.Context) (users []User, err error) {
	err = c.get(ctx, c.path("userList"), func(body []byte) error {
		var wire []struct {
			ID        int64       `json:"uid"`
			UUID      string      `json:"vmess_uid"`
			Password  string      `json:"password"`
			Speed     float64     `json:"speed_limit"`
			Port      wireInteger `json:"port"`
			Passwd    string      `json:"passwd"`
			Method    string      `json:"method"`
			Protocol  string      `json:"protocol"`
			Obfs      string      `json:"obfs"`
			ObfsParam string      `json:"obfs_param"`
			Enable    *int        `json:"enable"`
		}
		if err := unwrapProxyPanel(body, &wire); err != nil {
			return err
		}
		if wire == nil {
			return errors.New("ProxyPanel user list must be an array")
		}
		users = make([]User, 0, len(wire))
		for _, u := range wire {
			if c.opts.NodeType == "shadowsocksr" && u.Enable != nil && *u.Enable == 0 {
				continue
			}
			user := User{ID: u.ID, UUID: u.UUID, Password: u.Password, SpeedLimit: u.Speed * 8 / 1_000_000}
			if c.opts.NodeType == "shadowsocksr" {
				if u.Port <= 0 || u.Port > 1<<32-1 {
					return errors.New("ProxyPanel SSR port is outside the protocol UID range")
				}
				user.Password, user.Port, user.Method = u.Passwd, int(u.Port), u.Method
				user.Protocol, user.Obfs, user.ObfsParam = u.Protocol, u.Obfs, u.ObfsParam
				user.ProtocolID = uint32(u.Port)
			}
			users = append(users, user)
		}
		return nil
	})
	return
}

type ProxyPolicyRule struct {
	ID      int    `json:"id"`
	Type    string `json:"type"`
	Pattern string `json:"pattern"`
}
type ProxyPolicy struct {
	Mode  string            `json:"mode"`
	Rules []ProxyPolicyRule `json:"rules"`
}

func (c *ProxyPanel) FetchPolicy(ctx context.Context) (policy ProxyPolicy, err error) {
	err = c.get(ctx, c.path("nodeRule"), func(body []byte) error {
		if err := unwrapProxyPanel(body, &policy); err != nil {
			return err
		}
		switch policy.Mode {
		case "all", "allow", "reject":
		default:
			return errors.New("unknown ProxyPanel rule mode")
		}
		return nil
	})
	return
}
func (c *ProxyPanel) FetchAuditRules(context.Context) ([]AuditRule, error) {
	return nil, ErrUnsupported
}
func (c *ProxyPanel) FetchWhiteList(context.Context) ([]string, error)  { return nil, ErrUnsupported }
func (c *ProxyPanel) ReportAuditLogs(context.Context, []AuditLog) error { return ErrUnsupported }
func (c *ProxyPanel) ReportTraffic(ctx context.Context, items []Traffic) error {
	type record struct {
		ID       int64 `json:"uid"`
		Upload   int64 `json:"upload"`
		Download int64 `json:"download"`
	}
	wire := make([]record, 0, len(items))
	for _, v := range items {
		if v.Upload < 0 || v.Download < 0 {
			return errors.New("negative traffic")
		}
		wire = append(wire, record{v.ID, v.Upload, v.Download})
	}
	return c.post(ctx, c.path("userTraffic"), wire)
}
func (c *ProxyPanel) ReportAliveIPs(ctx context.Context, items []AliveIP) error {
	type record struct {
		ID int64  `json:"uid"`
		IP string `json:"ip"`
	}
	wire := make([]record, 0, len(items))
	for _, v := range items {
		for _, ip := range v.IPs {
			wire = append(wire, record{v.ID, ip})
		}
	}
	return c.post(ctx, c.path("nodeOnline"), wire)
}
func (c *ProxyPanel) ReportStatus(ctx context.Context, s Status) error {
	percent := func(u Usage) float64 {
		if u.Total == 0 {
			return 0
		}
		return float64(u.Used) / float64(u.Total) * 100
	}
	return c.post(ctx, c.path("nodeStatus"), struct {
		CPU    float64 `json:"cpu"`
		Mem    float64 `json:"mem"`
		Disk   float64 `json:"disk"`
		Uptime uint64  `json:"uptime"`
	}{s.CPU, percent(s.Mem), percent(s.Disk), s.Uptime})
}

type ProxyAuditLog struct {
	UserID int64  `json:"uid"`
	RuleID int    `json:"rule_id"`
	Reason string `json:"reason"`
	Target string `json:"target,omitempty"`
}

func (c *ProxyPanel) ReportPolicyLog(ctx context.Context, entry ProxyAuditLog) error {
	if entry.Reason == "" {
		return errors.New("ProxyPanel audit report requires reason")
	}
	return c.post(ctx, c.path("trigger"), entry)
}
