package panel

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"strconv"
	"strings"
	"sync"
)

type Capabilities struct {
	AuditRules bool
	WhiteList  bool
	AliveIPs   bool
	AuditLogs  bool
	Status     bool
}

// CapableAPI is optional so callers can also supply their own API implementations.
type CapableAPI interface{ Capabilities() Capabilities }

func (c *Client) Capabilities() Capabilities {
	return Capabilities{true, true, true, true, true}
}

type UniProxy struct {
	*Client
	mu   sync.RWMutex
	node *Node
}

func NewUniProxy(opts Options) (*UniProxy, error) {
	if opts.Type != "v2board" && opts.Type != "xboard" && opts.Type != "xiaov2board" {
		return nil, fmt.Errorf("%w: %s", ErrUnsupported, opts.Type)
	}
	if opts.SubType != "" && !(opts.Type == "xiaov2board" && opts.SubType == "v2node") {
		return nil, fmt.Errorf("%w: UniProxy sub_type=%s", ErrUnsupported, opts.SubType)
	}
	opts.NodeType = NormalizeNodeType(opts.NodeType)
	if opts.Type == "v2board" {
		switch opts.NodeType {
		case "vmess", "shadowsocks", "trojan", "hysteria":
		default:
			return nil, fmt.Errorf("%w: V2Board protocol %s", ErrUnsupported, opts.NodeType)
		}
	}
	c, err := NewSogaV1(opts)
	if err != nil {
		return nil, err
	}
	c.uniProxy = true
	return &UniProxy{Client: c}, nil
}

func (c *UniProxy) Capabilities() Capabilities {
	return Capabilities{AliveIPs: c.opts.Type == "xboard" || c.opts.Type == "xiaov2board", Status: c.opts.Type == "xboard"}
}

const uniPath = "/api/v1/server/UniProxy"

// Older PHP models may serialize a database port as a decimal string.
type wireInteger int

func (n *wireInteger) UnmarshalJSON(raw []byte) error {
	var value json.Number
	if err := json.Unmarshal(raw, &value); err != nil {
		return err
	}
	v, err := strconv.Atoi(string(value))
	if err != nil {
		return err
	}
	*n = wireInteger(v)
	return nil
}

func (c *UniProxy) FetchNode(ctx context.Context) (node Node, err error) {
	err = c.get(ctx, uniPath+"/config", func(body []byte) error {
		var wire struct {
			Protocol        string          `json:"protocol"`
			Port            wireInteger     `json:"server_port"`
			Base            Basic           `json:"base_config"`
			Network         string          `json:"network"`
			NetworkSettings json.RawMessage `json:"networkSettings"`
			NetworkV2       json.RawMessage `json:"network_settings"`
			TLS             int             `json:"tls"`
			TLSSettings     struct {
				ServerName  string          `json:"server_name"`
				ServerPort  json.RawMessage `json:"server_port"`
				PrivateKey  string          `json:"private_key"`
				ShortID     string          `json:"short_id"`
				ShortIDs    []string        `json:"short_ids"`
				ServerNames []string        `json:"server_names"`
				Dest        string          `json:"dest"`
				CertMode    string          `json:"cert_mode"`
				Cert        string          `json:"tls_cert"`
				Key         string          `json:"tls_key"`
			} `json:"tls_settings"`
			Cipher             string          `json:"cipher"`
			ServerKey          string          `json:"server_key"`
			Host               string          `json:"host"`
			ServerName         string          `json:"server_name"`
			Obfs               string          `json:"obfs"`
			ObfsPassword       string          `json:"obfs-password"`
			ObfsPasswordV2     string          `json:"obfs_password"`
			ObfsSettings       json.RawMessage `json:"obfs_settings"`
			Version            int             `json:"version"`
			Flow               string          `json:"flow"`
			Decryption         string          `json:"decryption"`
			Encryption         string          `json:"encryption"`
			EncryptionSettings struct {
				Mode          string `json:"mode"`
				Ticket        string `json:"ticket"`
				ServerPadding string `json:"server_padding"`
				PrivateKey    string `json:"private_key"`
			} `json:"encryption_settings"`
			UpMbps         float64  `json:"up_mbps"`
			DownMbps       float64  `json:"down_mbps"`
			PaddingScheme  []string `json:"padding_scheme"`
			Transport      string   `json:"transport"`
			TrafficPattern string   `json:"traffic_pattern"`
		}
		if err := json.Unmarshal(body, &wire); err != nil {
			return err
		}
		if c.opts.SubType == "v2node" {
			if wire.Protocol == "" {
				return errors.New("Xiaov2board v2node config lacks protocol")
			}
			// The original adapter 0x179c420 normalizes this schema before
			// using its common UniProxy node conversion.
			wire.NetworkSettings = wire.NetworkV2
			wire.ObfsPassword = wire.ObfsPasswordV2
			if wire.Network == "splithttp" {
				wire.Network = "xhttp"
			}
			if wire.TLS == 1 && wire.TLSSettings.CertMode == "none" {
				wire.TLS = 0
			}
			if c.opts.NodeType == "hysteria" {
				wire.Version = 2
			}
			if c.opts.NodeType == "shadowsocks" {
				wire.Obfs = ""
				wire.ObfsSettings = wire.NetworkSettings
				var obfs struct{ Path, Host string }
				if len(wire.ObfsSettings) != 0 && string(wire.ObfsSettings) != "null" {
					if err := json.Unmarshal(wire.ObfsSettings, &obfs); err != nil {
						return err
					}
				}
				if obfs.Path != "" || obfs.Host != "" {
					wire.Obfs = "http"
				}
			}
		}
		if wire.Port < 1 || wire.Port > 65535 {
			return errors.New("UniProxy config lacks valid server_port")
		}
		if wire.Protocol != "" && NormalizeNodeType(wire.Protocol) != c.opts.NodeType {
			return fmt.Errorf("panel protocol %q differs from requested %q", wire.Protocol, c.opts.NodeType)
		}
		config := NodeConfig{
			Port: int(wire.Port), StreamType: wire.Network, Cipher: wire.Cipher, Password: wire.ServerKey,
			Host: wire.Host, Obfs: wire.Obfs, ObfsPassword: wire.ObfsPassword, Flow: wire.Flow, Decryption: wire.Decryption,
			UpMbps: wire.UpMbps, DownMbps: wire.DownMbps, PaddingScheme: wire.PaddingScheme,
			Transport: wire.Transport, TrafficPattern: wire.TrafficPattern,
		}
		encryptionHandled := false
		if wire.Encryption == "mlkem768x25519plus" {
			config.Decryption = strings.Join([]string{wire.Encryption, wire.EncryptionSettings.Mode,
				wire.EncryptionSettings.Ticket, wire.EncryptionSettings.ServerPadding,
				wire.EncryptionSettings.PrivateKey}, ".")
			encryptionHandled = true
		} else if wire.Encryption == "none" {
			// The current official PHP schema can emit the explicit disabled
			// value. This extends the original empty-string disabled value.
			config.Decryption = "none"
			encryptionHandled = true
		}
		switch wire.TLS {
		case 0:
			config.TLSType = "none"
		case 1:
			config.TLSType = "tls"
		case 2:
			config.TLSType = "reality"
		default:
			return fmt.Errorf("%w: tls=%d", ErrUnsupported, wire.TLS)
		}
		name := wire.TLSSettings.ServerName
		if name == "" {
			name = wire.ServerName
		}
		if name != "" {
			config.ServerNames = []string{name}
		}
		if len(wire.TLSSettings.ServerNames) != 0 {
			config.ServerNames = append([]string(nil), wire.TLSSettings.ServerNames...)
			name = config.ServerNames[0]
		}
		if wire.TLS == 2 {
			config.PrivateKey = wire.TLSSettings.PrivateKey
			config.ShortIDs = []string{wire.TLSSettings.ShortID}
			if len(wire.TLSSettings.ShortIDs) != 0 {
				config.ShortIDs = append([]string(nil), wire.TLSSettings.ShortIDs...)
			}
			port := "443"
			if len(wire.TLSSettings.ServerPort) > 0 && string(wire.TLSSettings.ServerPort) != "null" {
				port = strings.Trim(string(wire.TLSSettings.ServerPort), `"`)
				n, e := strconv.Atoi(port)
				if e != nil || n < 1 || n > 65535 {
					return errors.New("invalid Reality server_port")
				}
			}
			config.Dest = net.JoinHostPort(name, port)
			if wire.TLSSettings.Dest != "" {
				config.Dest = wire.TLSSettings.Dest
			}
		}
		if c.opts.NodeType == "trojan" && (c.opts.Type == "v2board" || (c.opts.Type == "xiaov2board" && c.opts.SubType != "v2node")) {
			config.TLSType = "tls"
		}
		if c.opts.SubType == "v2node" {
			config.CertMode = wire.TLSSettings.CertMode
			if wire.TLS == 1 && config.CertMode == "remote" {
				if wire.TLSSettings.Cert == "" || wire.TLSSettings.Key == "" {
					return errors.New("Xiaov2board remote certificate requires tls_cert and tls_key")
				}
				config.Certificate, config.CertificateKey = wire.TLSSettings.Cert, wire.TLSSettings.Key
			}
		}
		if c.opts.NodeType == "anytls" && c.opts.SubType != "v2node" {
			config.TLSType = "tls"
		}
		if c.opts.NodeType == "hysteria" {
			// The original V2Board master API is Hysteria 1. Passing that
			// config to a Hysteria 2 engine would produce a nonworking service.
			if wire.Version != 2 {
				return fmt.Errorf("%w: Hysteria version %d (requires version 2)", ErrUnsupported, wire.Version)
			}
			config.TLSType = "tls"
		}
		if len(wire.NetworkSettings) > 0 && string(wire.NetworkSettings) != "null" {
			var transport struct {
				Path        string            `json:"path"`
				Host        json.RawMessage   `json:"host"`
				Headers     map[string]string `json:"headers"`
				ServiceName string            `json:"serviceName"`
			}
			if err := json.Unmarshal(wire.NetworkSettings, &transport); err != nil {
				return fmt.Errorf("networkSettings: %w", err)
			}
			config.Path, config.ServiceName = transport.Path, transport.ServiceName
			if host := transport.Headers["Host"]; host != "" {
				config.Host = host
			}
			if len(transport.Host) > 0 {
				var host string
				if json.Unmarshal(transport.Host, &host) == nil {
					config.Host = host
				} else {
					var hosts []string
					if json.Unmarshal(transport.Host, &hosts) == nil && len(hosts) > 0 {
						config.Host = hosts[0]
					}
				}
			}
			if config.StreamType == "xhttp" {
				config.XHTTPSettings = append(json.RawMessage(nil), wire.NetworkSettings...)
			}
		}
		if len(wire.ObfsSettings) > 0 && string(wire.ObfsSettings) != "null" {
			var obfs struct{ Path, Host string }
			if err := json.Unmarshal(wire.ObfsSettings, &obfs); err != nil {
				return err
			}
			config.Path, config.Host = obfs.Path, obfs.Host
		}
		node = Node{Basic: wire.Base, Config: config, RawConfig: append(json.RawMessage(nil), body...)}
		var extra map[string]json.RawMessage
		if err := json.Unmarshal(body, &extra); err != nil {
			return err
		}
		if err := applyUniRoutes(&node, extra["routes"]); err != nil {
			return err
		}
		for _, key := range []string{"plugin", "plugin_opts", "custom_routes", "custom_outbounds", "cert_config", "multiplex", "encryption", "encryption_settings"} {
			if encryptionHandled && (key == "encryption" || key == "encryption_settings") {
				continue
			}
			if value, ok := extra[key]; ok && meaningfulJSON(value) {
				node.UnsupportedOptions = append(node.UnsupportedOptions, key)
			}
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

func meaningfulJSON(raw json.RawMessage) bool {
	s := strings.TrimSpace(string(raw))
	return s != "" && s != "null" && s != "false" && s != "0" && s != `""` && s != "{}" && s != "[]"
}

func (c *UniProxy) FetchUsers(ctx context.Context) (users []User, err error) {
	return c.fetchUUIDUsers(ctx, uniPath+"/user")
}

func (c *UniProxy) fetchUUIDUsers(ctx context.Context, path string) (users []User, err error) {
	err = c.get(ctx, path, func(body []byte) error {
		var wire struct {
			Users []User `json:"users"`
		}
		if err := json.Unmarshal(body, &wire); err != nil {
			return err
		}
		if wire.Users == nil {
			return errors.New("UniProxy response lacks users array")
		}
		for i := range wire.Users {
			wire.Users[i].Password = wire.Users[i].UUID
			wire.Users[i].Username = wire.Users[i].UUID
		}
		users = wire.Users
		return nil
	})
	if err != nil {
		return nil, err
	}
	// SS2022 subscriptions use base64 of the first key-length UUID bytes.
	// FetchNode must precede FetchUsers to select the cipher correctly.
	if c.opts.NodeType == "shadowsocks" {
		c.mu.RLock()
		node := c.node
		c.mu.RUnlock()
		if node == nil {
			return nil, errors.New("fetch node configuration before Shadowsocks users")
		}
		keyLen := 0
		switch node.Config.Cipher {
		case "2022-blake3-aes-128-gcm":
			keyLen = 16
		case "2022-blake3-aes-256-gcm":
			keyLen = 32
		case "2022-blake3-chacha20-poly1305":
			if c.ppanel {
				keyLen = 32
			}
		}
		if keyLen != 0 {
			for i := range users {
				if len(users[i].UUID) < keyLen {
					return nil, errors.New("SS2022 UUID is shorter than key length")
				}
				users[i].Password = base64.StdEncoding.EncodeToString([]byte(users[i].UUID[:keyLen]))
			}
		}
	}
	return users, nil
}

func (c *UniProxy) FetchAuditRules(context.Context) ([]AuditRule, error) { return nil, ErrUnsupported }
func (c *UniProxy) FetchWhiteList(context.Context) ([]string, error)     { return nil, ErrUnsupported }
func (c *UniProxy) ReportAuditLogs(context.Context, []AuditLog) error    { return ErrUnsupported }
func (c *UniProxy) ReportTraffic(ctx context.Context, traffic []Traffic) error {
	wire := make(map[string][2]int64, len(traffic))
	for _, item := range traffic {
		if item.Upload < 0 || item.Download < 0 {
			return errors.New("traffic counters cannot be negative")
		}
		key := strconv.FormatInt(item.ID, 10)
		sum := wire[key]
		if item.Upload > math.MaxInt64-sum[0] || item.Download > math.MaxInt64-sum[1] {
			return errors.New("traffic counter overflow")
		}
		wire[key] = [2]int64{sum[0] + item.Upload, sum[1] + item.Download}
	}
	return c.post(ctx, uniPath+"/push", wire)
}
func (c *UniProxy) ReportAliveIPs(ctx context.Context, alive []AliveIP) error {
	if c.opts.Type != "xboard" && c.opts.Type != "xiaov2board" {
		return ErrUnsupported
	}
	wire := make(map[string][]string, len(alive))
	for _, item := range alive {
		key := strconv.FormatInt(item.ID, 10)
		wire[key] = append(nonNil(wire[key]), item.IPs...)
	}
	return c.post(ctx, uniPath+"/alive", wire)
}
func (c *UniProxy) ReportStatus(ctx context.Context, status Status) error {
	if c.opts.Type != "xboard" {
		return ErrUnsupported
	}
	return c.post(ctx, uniPath+"/status", status)
}

func (c *UniProxy) FetchAliveCounts(ctx context.Context) (counts map[int64]int, err error) {
	if c.opts.Type != "xboard" && c.opts.Type != "xiaov2board" {
		return nil, ErrUnsupported
	}
	err = c.get(ctx, uniPath+"/alivelist", func(body []byte) error {
		var wire struct {
			Alive map[int64]int `json:"alive"`
		}
		if err := json.Unmarshal(body, &wire); err != nil {
			return err
		}
		if wire.Alive == nil {
			return errors.New("UniProxy response lacks alive map")
		}
		counts = wire.Alive
		return nil
	})
	return
}
