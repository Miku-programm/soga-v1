package panel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

type SSPanel struct{ *Client }

func NewSSPanel(opts Options) (*SSPanel, error) {
	opts.NodeType = NormalizeNodeType(opts.NodeType)
	switch opts.NodeType {
	case "vmess", "trojan", "shadowsocks", "shadowsocksr":
	default:
		return nil, fmt.Errorf("%w: SSPanel protocol/account model %s", ErrUnsupported, opts.NodeType)
	}
	if n, err := strconv.ParseInt(opts.NodeID, 10, 64); err != nil || n <= 0 {
		return nil, errors.New("SSPanel node ID must be a positive integer")
	}
	c, err := NewSogaV1(opts)
	if err != nil {
		return nil, err
	}
	c.sspanel = true
	return &SSPanel{c}, nil
}
func (c *SSPanel) Capabilities() Capabilities { return Capabilities{AliveIPs: true, AuditLogs: true} }
func unwrapSSPanel(body []byte, dst any) error {
	var envelope struct {
		Ret  *int            `json:"ret"`
		Data json.RawMessage `json:"data"`
		Msg  string          `json:"msg"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return err
	}
	if envelope.Ret == nil || *envelope.Ret != 1 {
		return errors.New("SSPanel response is not ret=1")
	}
	if len(envelope.Data) == 0 || string(envelope.Data) == "null" {
		return errors.New("SSPanel response lacks data")
	}
	return json.Unmarshal(envelope.Data, dst)
}
func (c *SSPanel) FetchNode(ctx context.Context) (node Node, err error) {
	err = c.get(ctx, "/mod_mu/nodes/"+c.opts.NodeID+"/info", func(body []byte) error {
		var raw json.RawMessage
		if err := unwrapSSPanel(body, &raw); err != nil {
			return err
		}
		var wire struct {
			Sort   int             `json:"sort"`
			Server string          `json:"server"`
			Speed  float64         `json:"node_speedlimit"`
			Custom json.RawMessage `json:"custom_config"`
			MuOnly int             `json:"mu_only"`
		}
		if err := json.Unmarshal(raw, &wire); err != nil {
			return err
		}
		expected := map[string]int{"vmess": 11, "trojan": 14, "shadowsocks": 1}[c.opts.NodeType]
		if wire.Sort != 0 && wire.Sort != expected && c.opts.NodeType != "shadowsocksr" {
			return fmt.Errorf("%w: SSPanel sort=%d for %s; per-user-port and carrier modes need separate listeners", ErrUnsupported, wire.Sort, c.opts.NodeType)
		}
		var cfg NodeConfig
		var unsupported []string
		if len(wire.Custom) > 0 && string(wire.Custom) != "null" && string(wire.Custom) != "{}" {
			var custom map[string]json.RawMessage
			if err := json.Unmarshal(wire.Custom, &custom); err != nil {
				return err
			}
			var fields struct {
				Port        wireInteger `json:"offset_port_node"`
				UserPort    wireInteger `json:"offset_port_user"`
				V2Port      wireInteger `json:"v2_port"`
				TrojanPort  wireInteger `json:"trojan_port"`
				AlterID     wireInteger `json:"alter_id"`
				Method      string      `json:"method"`
				ServerKey   string      `json:"server_key"`
				MuMethod    string      `json:"mu_encryption"`
				MuPassword  string      `json:"mu_password"`
				Network     string      `json:"network"`
				Security    string      `json:"security"`
				Host        string      `json:"host"`
				Path        string      `json:"path"`
				ServiceName string      `json:"service_name"`
				ServiceOld  string      `json:"servicename"`
				UDP         *bool       `json:"udp"`
				Mux         bool        `json:"mux"`
				UOT         bool        `json:"uot"`
			}
			if err := json.Unmarshal(wire.Custom, &fields); err != nil {
				return err
			}
			cfg = NodeConfig{Port: int(fields.Port), Cipher: fields.Method, Password: fields.ServerKey, StreamType: fields.Network, TLSType: fields.Security, Host: fields.Host, Path: fields.Path, ServiceName: fields.ServiceName}
			// uX0Wxx 0x16e9360 prefers a positive node offset, then user
			// offset; protocol-specific ports take precedence over both.
			if cfg.Port <= 0 {
				cfg.Port = int(fields.UserPort)
			}
			if c.opts.NodeType == "shadowsocks" && cfg.Port > 0 && cfg.Cipher == "" {
				if !ssPanelAEADMethod(fields.MuMethod) {
					return errors.New("SSPanel single-port mu_encryption is not a supported AEAD method")
				}
				cfg.Cipher, cfg.Password = fields.MuMethod, fields.MuPassword
			}
			if c.opts.NodeType == "vmess" {
				cfg.AlterID = int(fields.AlterID)
				if fields.V2Port > 0 {
					cfg.Port = int(fields.V2Port)
				}
			}
			if c.opts.NodeType == "trojan" && fields.TrojanPort > 0 {
				cfg.Port = int(fields.TrojanPort)
			}
			if cfg.ServiceName == "" {
				cfg.ServiceName = fields.ServiceOld
			}
			if fields.Host != "" {
				cfg.ServerNames = []string{fields.Host}
			}
			for _, key := range []string{"ws-opts", "ws_opts", "h2-opts", "h2_opts", "grpc-opts", "grpc_opts"} {
				value, ok := custom[key]
				if !ok {
					continue
				}
				var opt struct {
					Path    string            `json:"path"`
					Headers map[string]string `json:"headers"`
					Hosts   []string          `json:"host"`
					Service string            `json:"grpc-service-name"`
				}
				if err := json.Unmarshal(value, &opt); err != nil {
					return err
				}
				if opt.Path != "" {
					cfg.Path = opt.Path
				}
				if host := opt.Headers["Host"]; host != "" {
					cfg.Host = host
				}
				if len(opt.Hosts) > 0 {
					cfg.Host = opt.Hosts[0]
				}
				if opt.Service != "" {
					cfg.ServiceName = opt.Service
				}
			}
			if fields.UDP != nil && !*fields.UDP {
				unsupported = append(unsupported, "udp=false")
			}
			if fields.Mux {
				unsupported = append(unsupported, "mux")
			}
			if fields.UOT {
				unsupported = append(unsupported, "uot")
			}
			for _, key := range []string{"plugin", "plugin_option", "header"} {
				if meaningfulJSON(custom[key]) {
					unsupported = append(unsupported, key)
				}
			}
		} else {
			var err error
			cfg, err = parseLegacySSPanel(c.opts.NodeType, wire.Server)
			if err != nil {
				return err
			}
		}
		if cfg.StreamType == "" {
			cfg.StreamType = "tcp"
		}
		if cfg.TLSType == "" {
			cfg.TLSType = "none"
		}
		if c.opts.NodeType == "trojan" {
			cfg.TLSType = "tls"
		}
		cfg.OnlyMultiUserPorts = wire.MuOnly == 1
		if (c.opts.NodeType == "shadowsocks" && cfg.Port == 0) || c.opts.NodeType == "shadowsocksr" {
			cfg.MultiUserPorts = true
		}
		if !cfg.MultiUserPorts && (cfg.Port < 1 || cfg.Port > 65535) {
			return errors.New("SSPanel requires explicit valid offset_port_node or legacy server port")
		}
		node = Node{Basic: Basic{SpeedLimit: wire.Speed}, Config: cfg, RawConfig: append(json.RawMessage(nil), raw...), UnsupportedOptions: unsupported}
		if c.opts.NodeType == "shadowsocksr" && cfg.OnlyMultiUserPorts && len(wire.Custom) > 0 && string(wire.Custom) != "null" {
			var mu struct {
				Port     wireInteger `json:"mu_port"`
				Password string      `json:"mu_password"`
				Method   string      `json:"mu_encryption"`
				Protocol string      `json:"mu_protocol"`
				Obfs     string      `json:"mu_obfs"`
			}
			if e := json.Unmarshal(wire.Custom, &mu); e != nil {
				return e
			}
			port := int(mu.Port)
			if port <= 0 {
				port = cfg.Port
			}
			if port > 0 && mu.Password != "" {
				node.Carriers = append(node.Carriers, User{Port: port, Password: mu.Password, Method: mu.Method, Protocol: mu.Protocol, Obfs: mu.Obfs, IsMultiUser: 2})
			}
		}
		return nil
	})
	if err != nil {
		return node, err
	}
	if c.opts.NodeType == "shadowsocks" {
		if node.Config.Port < 1 {
			users, err := c.FetchUsers(ctx)
			if err != nil {
				return node, err
			}
			if err = applySSPanelPasswordCarrier(&node.Config, users); err != nil {
				return node, err
			}
		}
		node.Config.MultiUserPorts = false
	}
	rules, err := c.FetchDetectRules(ctx)
	if err != nil {
		return node, err
	}
	node.Policy = SSPanelPolicy(rules)
	return node, nil
}

// GetAPIData 0x1739a20 (web) and 0x1737700 (database) select the first
// carrier in panel order when no explicit SS port was supplied. SSR carrier
// modes and normal users are not candidates. The caller retains all users for
// authentication/accounting; the runtime excludes carrier records themselves.
func applySSPanelPasswordCarrier(cfg *NodeConfig, users []User) error {
	for _, u := range users {
		if u.IsMultiUser == 0 || !ssPanelAEADMethod(u.Method) || u.Protocol != "origin" || u.Obfs != "plain" {
			continue
		}
		if u.Port < 1 || u.Port > 65535 {
			return errors.New("SSPanel password carrier has an invalid listen port")
		}
		cfg.Port, cfg.Cipher, cfg.Method, cfg.Password = u.Port, u.Method, u.Method, u.Password
		cfg.MultiUserPorts = false
		return nil
	}
	return errors.New("SSPanel requires an AEAD origin/plain password carrier or an explicit SS port")
}

func ssPanelAEADMethod(method string) bool {
	switch method {
	case "aes-128-gcm", "aes-192-gcm", "aes-256-gcm", "chacha20-ietf-poly1305",
		"2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm":
		return true
	}
	return false
}
func parseLegacySSPanel(protocol, server string) (NodeConfig, error) {
	cfg := NodeConfig{}
	parts := strings.Split(server, ";")
	if protocol == "vmess" {
		if len(parts) < 5 {
			return cfg, errors.New("legacy VMess server requires semicolon-delimited port, alterId, network, TLS")
		}
		var err error
		cfg.Port, err = strconv.Atoi(parts[1])
		if err != nil {
			return cfg, err
		}
		cfg.AlterID, err = strconv.Atoi(parts[2])
		if err != nil {
			return cfg, err
		}
		cfg.StreamType, cfg.TLSType = parts[3], parts[4]
		if len(parts) > 5 {
			for _, param := range strings.Split(parts[5], "|") {
				key, value, ok := strings.Cut(param, "=")
				if !ok {
					continue
				}
				switch key {
				case "path":
					cfg.Path = value
				case "host":
					cfg.Host = value
					cfg.ServerNames = []string{value}
				case "inside_port":
					cfg.Port, err = strconv.Atoi(value)
					if err != nil {
						return cfg, err
					}
				case "server", "outside_port":
				default:
					return cfg, fmt.Errorf("%w: legacy VMess parameter %s", ErrUnsupported, key)
				}
			}
		}
		return cfg, nil
	}
	if protocol == "trojan" {
		cfg.Port = 443 // bmG8Nfaaa 0x16eef80 initializes 443.
		if len(parts) < 2 {
			return cfg, nil
		}
		for _, param := range strings.Split(parts[1], "|") {
			key, value, ok := strings.Cut(param, "=")
			if !ok {
				continue
			}
			switch key {
			case "port":
				ports := strings.Split(value, "#")
				if len(ports) > 1 {
					value = ports[1]
				}
				port, err := strconv.Atoi(value)
				if err != nil {
					return cfg, err
				}
				if port > 0 {
					cfg.Port = port
				}
			case "host":
				cfg.Host = value
				cfg.ServerNames = []string{value}
			default:
				return cfg, fmt.Errorf("%w: legacy Trojan parameter %s", ErrUnsupported, key)
			}
		}
		return cfg, nil
	}
	if protocol == "shadowsocks" || protocol == "shadowsocksr" {
		cfg.MultiUserPorts = true
		if protocol == "shadowsocksr" && len(parts) > 1 {
			values := legacySSPanelParams(parts[1])
			var err error
			if s := values["soga_port"]; s != "" {
				cfg.LegacySogaPort, err = strconv.Atoi(s)
				if err != nil {
					return cfg, err
				}
			}
			if s := values["port"]; s != "" {
				cfg.LegacyPort, err = strconv.Atoi(strings.Split(s, "#")[0])
				if err != nil {
					return cfg, err
				}
			}
		}
		return cfg, nil
	}
	return cfg, fmt.Errorf("%w: legacy SSPanel protocol %s", ErrUnsupported, protocol)
}
func (c *SSPanel) FetchUsers(ctx context.Context) (users []User, err error) {
	err = c.get(ctx, "/mod_mu/users", func(body []byte) error {
		var wire []struct {
			ID            int64   `json:"id"`
			UUID          string  `json:"uuid"`
			Password      string  `json:"passwd"`
			Speed         float64 `json:"node_speedlimit"`
			Devices       int     `json:"node_iplimit"`
			Connector     *int    `json:"node_connector"`
			Port          int     `json:"port"`
			Method        string  `json:"method"`
			Protocol      string  `json:"protocol"`
			ProtocolParam string  `json:"protocol_param"`
			Obfs          string  `json:"obfs"`
			ObfsParam     string  `json:"obfs_param"`
			Multi         int     `json:"is_multi_user"`
		}

		if err := unwrapSSPanel(body, &wire); err != nil {
			return err
		}
		if wire == nil {
			return errors.New("SSPanel users must be an array")
		}
		users = make([]User, 0, len(wire))
		for _, u := range wire {
			uuid := u.UUID
			if uuid == "" {
				uuid = SSPanelLegacyUUID(u.ID, u.Password)
			}
			password := u.Password
			if c.opts.NodeType == "trojan" {
				password = uuid
			}
			devices := u.Devices
			if u.Connector != nil {
				devices = *u.Connector
			}
			if u.Multi < 0 || u.Multi > 2 {
				return fmt.Errorf("%w: SSPanel is_multi_user=%d", ErrUnsupported, u.Multi)
			}
			users = append(users, User{ID: u.ID, UUID: uuid, Password: password, SpeedLimit: max(0, min(10000, u.Speed)), DeviceLimit: devices, Port: u.Port, Method: u.Method, Protocol: u.Protocol, ProtocolParam: u.ProtocolParam, Obfs: u.Obfs, ObfsParam: u.ObfsParam, IsMultiUser: u.Multi})
		}
		return nil
	})
	return
}

type DetectRule struct {
	ID    int    `json:"id"`
	Regex string `json:"regex"`
	Type  int    `json:"type"`
}

func (c *SSPanel) FetchDetectRules(ctx context.Context) (rules []DetectRule, err error) {
	err = c.get(ctx, "/mod_mu/func/detect_rules", func(body []byte) error {
		if err := unwrapSSPanel(body, &rules); err != nil {
			return err
		}
		if rules == nil {
			return errors.New("SSPanel detect rules must be an array")
		}
		return nil
	})
	return
}
func (c *SSPanel) FetchAuditRules(context.Context) ([]AuditRule, error) { return nil, ErrUnsupported }
func (c *SSPanel) FetchWhiteList(context.Context) ([]string, error)     { return nil, ErrUnsupported }
func (c *SSPanel) ReportStatus(context.Context, Status) error           { return ErrUnsupported }
func (c *SSPanel) ReportTraffic(ctx context.Context, items []Traffic) error {
	type entry struct {
		ID       int64 `json:"user_id"`
		Upload   int64 `json:"u"`
		Download int64 `json:"d"`
	}
	data := make([]entry, 0, len(items))
	for _, v := range items {
		if v.Upload < 0 || v.Download < 0 {
			return errors.New("negative traffic")
		}
		data = append(data, entry{v.ID, v.Upload, v.Download})
	}
	return c.post(ctx, "/mod_mu/users/traffic", struct {
		Data []entry `json:"data"`
	}{data})
}
func (c *SSPanel) ReportAliveIPs(ctx context.Context, items []AliveIP) error {
	type entry struct {
		ID int64  `json:"user_id"`
		IP string `json:"ip"`
	}
	data := make([]entry, 0, len(items))
	for _, v := range items {
		for _, ip := range v.IPs {
			data = append(data, entry{v.ID, ip})
		}
	}
	return c.post(ctx, "/mod_mu/users/aliveip", struct {
		Data []entry `json:"data"`
	}{data})
}
func (c *SSPanel) ReportAuditLogs(ctx context.Context, items []AuditLog) error {
	type entry struct {
		ID     int64 `json:"user_id"`
		RuleID int   `json:"list_id"`
	}
	data := make([]entry, 0, len(items))
	seen := map[AuditLog]bool{}
	for _, v := range items {
		if !seen[v] {
			data = append(data, entry{v.UserID, v.AuditID})
			seen[v] = true
		}
	}
	return c.post(ctx, "/mod_mu/users/detectlog", struct {
		Data []entry `json:"data"`
	}{data})
}

// jrW5oitRt@16e7d60 trims fields, keeps the first value of each key, and
// uses only the first two pieces when a value contains another equals sign.
func legacySSPanelParams(s string) map[string]string {
	result := map[string]string{}
	for _, piece := range strings.Split(s, "|") {
		parts := strings.Split(strings.TrimSpace(piece), "=")
		if len(parts) < 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		if _, exists := result[key]; !exists {
			result[key] = strings.TrimSpace(parts[1])
		}
	}
	return result
}
