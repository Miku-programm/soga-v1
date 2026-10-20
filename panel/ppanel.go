package panel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// PPanel implements the official legacy /v1/server JSON API. The /v2/server
// protocol-bundle API and protobuf encoding are separate capabilities.
type PPanel struct{ *UniProxy }

func NewPPanel(opts Options) (*PPanel, error) {
	opts.NodeType = NormalizeNodeType(opts.NodeType)
	switch opts.NodeType {
	case "vmess", "vless", "shadowsocks", "trojan", "hysteria", "anytls":
	default:
		return nil, fmt.Errorf("%w: PPanel protocol %s", ErrUnsupported, opts.NodeType)
	}
	if n, err := strconv.ParseInt(opts.NodeID, 10, 64); err != nil || n <= 0 {
		return nil, errors.New("PPanel server ID must be a positive integer")
	}
	c, err := NewSogaV1(opts)
	if err != nil {
		return nil, err
	}
	c.ppanel = true
	return &PPanel{UniProxy: &UniProxy{Client: c}}, nil
}

func (c *PPanel) Capabilities() Capabilities { return Capabilities{AliveIPs: true, Status: true} }

func (c *PPanel) FetchNode(ctx context.Context) (node Node, err error) {
	err = c.get(ctx, "/v1/server/config", func(body []byte) error {
		var wire struct {
			Basic    Basic           `json:"basic"`
			Protocol string          `json:"protocol"`
			Config   json.RawMessage `json:"config"`
		}
		if err := json.Unmarshal(body, &wire); err != nil {
			return err
		}
		if NormalizeNodeType(wire.Protocol) != c.opts.NodeType {
			return errors.New("PPanel response protocol differs from requested protocol")
		}
		var cfg struct {
			Port            int    `json:"port"`
			Method          string `json:"method"`
			ServerKey       string `json:"server_key"`
			Flow            string `json:"flow"`
			Transport       string `json:"transport"`
			TransportConfig struct {
				Path        string `json:"path"`
				Host        string `json:"host"`
				ServiceName string `json:"service_name"`
				DisableSNI  bool   `json:"disable_sni"`
				ReduceRTT   bool   `json:"reduce_rtt"`
			} `json:"transport_config"`
			Security       string `json:"security"`
			SecurityConfig struct {
				SNI            string `json:"sni"`
				RealityAddress string `json:"reality_server_addr"`
				RealityPort    int    `json:"reality_server_port"`
				PrivateKey     string `json:"reality_private_key"`
				ShortID        string `json:"reality_short_id"`
				MLDSA          string `json:"reality_mldsa65seed"`
				PaddingScheme  string `json:"padding_scheme"`
			} `json:"security_config"`
			ObfsPassword string `json:"obfs_password"`
			HopPorts     string `json:"hop_ports"`
		}
		if len(wire.Config) == 0 {
			return errors.New("PPanel config is missing")
		}
		if err := json.Unmarshal(wire.Config, &cfg); err != nil {
			return err
		}
		if cfg.Port < 1 || cfg.Port > 65535 {
			return errors.New("PPanel config lacks valid port")
		}
		n := NodeConfig{Port: cfg.Port, Cipher: cfg.Method, Password: cfg.ServerKey, Flow: cfg.Flow, StreamType: cfg.Transport, TLSType: cfg.Security,
			Path: cfg.TransportConfig.Path, Host: cfg.TransportConfig.Host, ServiceName: cfg.TransportConfig.ServiceName, ObfsPassword: cfg.ObfsPassword}
		if n.TLSType == "" {
			n.TLSType = "none"
		}
		if cfg.SecurityConfig.SNI != "" {
			n.ServerNames = []string{cfg.SecurityConfig.SNI}
		}
		if n.TLSType == "reality" {
			n.PrivateKey = cfg.SecurityConfig.PrivateKey
			n.ShortIDs = []string{cfg.SecurityConfig.ShortID}
			if cfg.SecurityConfig.RealityPort < 1 || cfg.SecurityConfig.RealityPort > 65535 {
				return errors.New("PPanel Reality port invalid")
			}
			n.Dest = net.JoinHostPort(cfg.SecurityConfig.RealityAddress, strconv.Itoa(cfg.SecurityConfig.RealityPort))
		}
		if c.opts.NodeType == "hysteria" {
			n.TLSType = "tls"
			if cfg.ObfsPassword != "" {
				n.Obfs = "salamander"
			}
		}
		if c.opts.NodeType == "anytls" {
			n.TLSType = "tls"
			if cfg.SecurityConfig.PaddingScheme != "" {
				n.PaddingScheme = strings.Split(cfg.SecurityConfig.PaddingScheme, "\n")
			}
		}
		node = Node{Basic: wire.Basic, Config: n, RawConfig: append(json.RawMessage(nil), wire.Config...)}
		if cfg.HopPorts != "" {
			node.UnsupportedOptions = append(node.UnsupportedOptions, "hop_ports")
		}
		if cfg.SecurityConfig.MLDSA != "" {
			node.UnsupportedOptions = append(node.UnsupportedOptions, "reality_mldsa65seed")
		}
		if cfg.TransportConfig.DisableSNI {
			node.UnsupportedOptions = append(node.UnsupportedOptions, "disable_sni")
		}
		if cfg.TransportConfig.ReduceRTT {
			node.UnsupportedOptions = append(node.UnsupportedOptions, "reduce_rtt")
		}
		return nil
	})
	if err == nil {
		c.mu.Lock()
		copy := node
		c.node = &copy
		c.mu.Unlock()
	}
	return
}

func (c *PPanel) FetchUsers(ctx context.Context) ([]User, error) {
	return c.fetchUUIDUsers(ctx, "/v1/server/user")
}
func (c *PPanel) ReportTraffic(ctx context.Context, items []Traffic) error {
	type item struct {
		ID       int64 `json:"uid"`
		Upload   int64 `json:"upload"`
		Download int64 `json:"download"`
	}
	traffic := make([]item, 0, len(items))
	for _, t := range items {
		if t.Upload < 0 || t.Download < 0 {
			return errors.New("traffic counters cannot be negative")
		}
		traffic = append(traffic, item{t.ID, t.Upload, t.Download})
	}
	return c.post(ctx, "/v1/server/push", struct {
		Traffic []item `json:"traffic"`
	}{traffic})
}
func (c *PPanel) ReportAliveIPs(ctx context.Context, items []AliveIP) error {
	type online struct {
		ID int64  `json:"uid"`
		IP string `json:"ip"`
	}
	users := make([]online, 0, len(items))
	for _, u := range items {
		for _, ip := range u.IPs {
			users = append(users, online{u.ID, ip})
		}
	}
	return c.post(ctx, "/v1/server/online", struct {
		Users []online `json:"users"`
	}{users})
}
func (c *PPanel) ReportStatus(ctx context.Context, s Status) error {
	percent := func(u Usage) float64 {
		if u.Total == 0 {
			return 0
		}
		return float64(u.Used) / float64(u.Total) * 100
	}
	return c.post(ctx, "/v1/server/status", struct {
		CPU       float64 `json:"cpu"`
		Mem       float64 `json:"mem"`
		Disk      float64 `json:"disk"`
		UpdatedAt int64   `json:"updated_at"`
	}{s.CPU, percent(s.Mem), percent(s.Disk), time.Now().Unix()})
}
