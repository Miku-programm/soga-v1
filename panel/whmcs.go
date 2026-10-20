package panel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
)

// WHMCS implements the plugin WebAPI recovered from _ZwYXGIdVc, not the WHMCS
// billing API. Its reports have a transport acknowledgement, not a JSON ACK.
type WHMCS struct{ *Client }

func NewWHMCS(opts Options) (*WHMCS, error) {
	opts.NodeType = NormalizeNodeType(opts.NodeType)
	switch opts.NodeType {
	case "vmess", "trojan", "shadowsocks":
	default:
		return nil, fmt.Errorf("%w: WHMCS WebAPI %s", ErrUnsupported, opts.NodeType)
	}
	if id, err := strconv.ParseInt(opts.NodeID, 10, 64); err != nil || id <= 0 {
		return nil, errors.New("WHMCS node ID must be a positive integer")
	}
	c, err := NewSogaV1(opts)
	if err != nil {
		return nil, err
	}
	c.whmcs = true
	return &WHMCS{c}, nil
}

func (c *WHMCS) Capabilities() Capabilities { return Capabilities{AliveIPs: true, Status: true} }

type WHMCSRoutingRule struct {
	Domain      []string `json:"domain"`
	Protocol    []string `json:"protocol"`
	OutboundTag string   `json:"outboundTag"`
}

type whmcsConfiguration struct {
	Inbounds []struct {
		Port     int    `json:"port"`
		Protocol string `json:"protocol"`
		Settings struct {
			Method   string `json:"method"`
			Password string `json:"password"`
		} `json:"settings"`
		Streaming struct {
			Network  string `json:"network"`
			Security string `json:"security"`
			WS       struct {
				Path string `json:"path"`
			} `json:"wsSettings"`
			GRPC struct {
				ServiceName string `json:"serviceName"`
			} `json:"grpcSettings"`
		} `json:"streamingSettings"`
	} `json:"inbounds"`
	Routing struct {
		Rules []WHMCSRoutingRule `json:"rules"`
	} `json:"routing"`
}

func (c *WHMCS) FetchNode(ctx context.Context) (node Node, err error) {
	err = c.get(ctx, "config", func(body []byte) error {
		var wire whmcsConfiguration
		if err := json.Unmarshal(body, &wire); err != nil {
			return err
		}
		if len(wire.Inbounds) == 0 {
			return errors.New("WHMCS configuration has no inbound")
		}
		// Original ToPanelNode 0x17664e0 uses inbounds[0], not every inbound.
		in := wire.Inbounds[0]
		if NormalizeNodeType(in.Protocol) != c.opts.NodeType {
			return errors.New("WHMCS first inbound protocol differs from configured node type")
		}
		if in.Port < 1 || in.Port > 65535 {
			return errors.New("WHMCS inbound has invalid port")
		}
		network := in.Streaming.Network
		if network == "" {
			network = "tcp"
		}
		switch network {
		case "tcp", "ws", "h2", "grpc":
		default:
			return fmt.Errorf("%w: WHMCS network %s", ErrUnsupported, network)
		}
		tls := in.Streaming.Security
		if tls == "" {
			tls = "none"
		}
		if tls != "none" && tls != "tls" {
			return fmt.Errorf("%w: WHMCS security %s", ErrUnsupported, tls)
		}
		cfg := NodeConfig{Port: in.Port, StreamType: network, TLSType: tls,
			Path: in.Streaming.WS.Path, ServiceName: in.Streaming.GRPC.ServiceName,
			Method: in.Settings.Method, Cipher: in.Settings.Method, Password: in.Settings.Password}
		if c.opts.NodeType == "trojan" {
			// The original normalized Trojan node fixes transport to tcp.
			cfg.StreamType = "tcp"
		}
		node = Node{Config: cfg, RawConfig: append(json.RawMessage(nil), body...)}
		node.Policy = &Policy{Mode: "reject"}
		for _, rule := range wire.Routing.Rules {
			if rule.OutboundTag == "block" {
				for _, domain := range rule.Domain {
					node.Policy.Rules = append(node.Policy.Rules, PolicyRule{Rule: domain})
				}
			}
		}
		return nil
	})
	return
}

// RoutingRules exposes the original rule DTO without assuming that all outbound
// tags or protocol matchers are equivalent to soga-v1 regular expressions.
func (c *WHMCS) RoutingRules(node Node) ([]WHMCSRoutingRule, error) {
	var wire whmcsConfiguration
	if err := json.Unmarshal(node.RawConfig, &wire); err != nil {
		return nil, err
	}
	return wire.Routing.Rules, nil
}

func (c *WHMCS) FetchUsers(ctx context.Context) (users []User, err error) {
	err = c.get(ctx, "user", func(body []byte) error {
		var wire struct {
			Message string `json:"msg"`
			Data    []struct {
				ID       int64   `json:"id"`
				UUID     string  `json:"uuid"`
				Secret   string  `json:"secret"`
				Password string  `json:"password"`
				Devices  int     `json:"dt"`
				Speed    float64 `json:"st"`
			} `json:"data"`
		}
		if err := json.Unmarshal(body, &wire); err != nil {
			return err
		}
		if wire.Message != "ok" || wire.Data == nil {
			return errors.New("WHMCS users require msg=ok and a data array")
		}
		users = make([]User, 0, len(wire.Data))
		for _, row := range wire.Data {
			u := User{ID: row.ID, DeviceLimit: max(0, row.Devices), SpeedLimit: max(0, min(10000, row.Speed))}
			switch c.opts.NodeType {
			case "vmess":
				u.UUID = row.UUID
			case "trojan":
				u.Password = row.Password
			case "shadowsocks":
				u.Password = row.Secret
			}
			users = append(users, u)
		}
		return nil
	})
	return
}

func (c *WHMCS) FetchAuditRules(context.Context) ([]AuditRule, error) { return nil, ErrUnsupported }
func (c *WHMCS) FetchWhiteList(context.Context) ([]string, error)     { return nil, ErrUnsupported }
func (c *WHMCS) ReportAuditLogs(context.Context, []AuditLog) error    { return ErrUnsupported }

func (c *WHMCS) ReportTraffic(ctx context.Context, traffic []Traffic) error {
	type row struct {
		ID       int64 `json:"uid"`
		Upload   int64 `json:"u"`
		Download int64 `json:"d"`
	}
	rows := make([]row, 0, len(traffic))
	for _, t := range traffic {
		if t.Upload < 0 || t.Download < 0 {
			return errors.New("negative traffic")
		}
		rows = append(rows, row{t.ID, t.Upload, t.Download})
	}
	return c.post(ctx, "submit", rows)
}
func (c *WHMCS) ReportAliveIPs(ctx context.Context, alive []AliveIP) error {
	type row struct {
		ID int64  `json:"uid"`
		IP string `json:"ip"`
	}
	rows := make([]row, 0, len(alive))
	for _, user := range alive {
		for _, ip := range user.IPs {
			rows = append(rows, row{user.ID, ip})
		}
	}
	return c.post(ctx, "onlineusers", rows)
}
func (c *WHMCS) ReportStatus(ctx context.Context, status Status) error {
	// 0x175d3c0 uses "%.0f%%" for CPU/memory/disk and leaves net empty.
	percentage := func(u Usage) float64 {
		if u.Total == 0 {
			return 0
		}
		return float64(u.Used) / float64(u.Total) * 100
	}
	return c.post(ctx, "nodestatus", struct {
		CPU    string `json:"cpu"`
		Mem    string `json:"mem"`
		Net    string `json:"net"`
		Disk   string `json:"disk"`
		Uptime uint64 `json:"uptime"`
	}{fmt.Sprintf("%.0f%%", status.CPU), fmt.Sprintf("%.0f%%", percentage(status.Mem)), "",
		fmt.Sprintf("%.0f%%", percentage(status.Disk)), status.Uptime})
}

// ReportIllegalUsers corresponds to 0x175d9e0: the wire carries only uid, not
// a rule ID. Runtime policy decides which users meet the reporting condition.
func (c *WHMCS) ReportIllegalUsers(ctx context.Context, ids []int64) error {
	type row struct {
		ID int64 `json:"uid"`
	}
	rows := make([]row, 0, len(ids))
	for _, id := range ids {
		rows = append(rows, row{id})
	}
	return c.post(ctx, "illegal", rows)
}
