package panel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
)

// V2RaySocks uses its published node API and Xray configuration representation.
// It shares the historical WHMCS report shapes, but requires its documented ACK.
type V2RaySocks struct{ *WHMCS }

func NewV2RaySocks(opts Options) (*V2RaySocks, error) {
	opts.Type = "v2raysocks"
	opts.NodeType = NormalizeNodeType(opts.NodeType)
	switch opts.NodeType {
	case "vmess", "vless", "trojan", "shadowsocks", "hysteria":
	default:
		return nil, fmt.Errorf("%w: V2RaySocks protocol %s", ErrUnsupported, opts.NodeType)
	}
	if id, err := strconv.ParseInt(opts.NodeID, 10, 64); err != nil || id <= 0 {
		return nil, errors.New("V2RaySocks node ID must be a positive integer")
	}
	client, err := NewSogaV1(opts)
	if err != nil {
		return nil, err
	}
	client.whmcs = true
	return &V2RaySocks{&WHMCS{client}}, nil
}

type xrayPanelNode struct {
	Inbounds []struct {
		Tag      string      `json:"tag"`
		Port     wireInteger `json:"port"`
		Protocol string      `json:"protocol"`
		Settings struct {
			Method     string `json:"method"`
			Password   string `json:"password"`
			Decryption string `json:"decryption"`
			Clients    []struct {
				AlterID int    `json:"alterId"`
				Flow    string `json:"flow"`
			} `json:"clients"`
		} `json:"settings"`
		Stream struct {
			Network  string `json:"network"`
			Security string `json:"security"`
			WS       struct {
				Path    string            `json:"path"`
				Headers map[string]string `json:"headers"`
			} `json:"wsSettings"`
			GRPC struct {
				ServiceName string `json:"serviceName"`
			} `json:"grpcSettings"`
			HTTP struct {
				Path string   `json:"path"`
				Host []string `json:"host"`
			} `json:"httpSettings"`
			TLS struct {
				ServerName   string          `json:"serverName"`
				Certificates json.RawMessage `json:"certificates"`
			} `json:"tlsSettings"`
			Reality struct {
				Dest        json.RawMessage `json:"dest"`
				Target      json.RawMessage `json:"target"`
				ServerNames []string        `json:"serverNames"`
				PrivateKey  string          `json:"privateKey"`
				ShortIDs    []string        `json:"shortIds"`
			} `json:"realitySettings"`
			XHTTP json.RawMessage `json:"xhttpSettings"`
		} `json:"streamSettings"`
	} `json:"inbounds"`
	Routing struct {
		Rules []WHMCSRoutingRule `json:"rules"`
	} `json:"routing"`
	DNS       json.RawMessage   `json:"dns"`
	Outbounds []json.RawMessage `json:"outbounds"`
}

func (c *V2RaySocks) FetchNode(ctx context.Context) (node Node, err error) {
	err = c.get(ctx, "config", func(data []byte) error {
		var wire xrayPanelNode
		if err := json.Unmarshal(data, &wire); err != nil {
			return err
		}
		if len(wire.Inbounds) == 0 {
			return errors.New("V2RaySocks configuration has no inbound")
		}
		// Original ToPanelNode 0x174e480 selects the first tag="proxy".
		// A single untagged inbound is a compatibility extension.
		index := -1
		for i, in := range wire.Inbounds {
			if in.Tag == "proxy" {
				index = i
				break
			}
		}
		if index < 0 && len(wire.Inbounds) == 1 && wire.Inbounds[0].Tag == "" {
			index = 0
		}
		if index < 0 {
			return errors.New("V2RaySocks configuration has no inbound tagged proxy")
		}
		in := wire.Inbounds[index]
		// The original inbound RTTI has no protocol field. Accept its absence;
		// when an extended server supplies it, prevent cross-protocol loading.
		if in.Protocol != "" && NormalizeNodeType(in.Protocol) != c.opts.NodeType {
			return errors.New("V2RaySocks proxy inbound protocol differs from requested type")
		}
		cfg := NodeConfig{Port: int(in.Port), Cipher: in.Settings.Method, Method: in.Settings.Method,
			Password: in.Settings.Password, Decryption: in.Settings.Decryption,
			StreamType: in.Stream.Network, TLSType: in.Stream.Security,
			Path: in.Stream.WS.Path, Host: in.Stream.WS.Headers["Host"],
			ServiceName: in.Stream.GRPC.ServiceName, XHTTPSettings: in.Stream.XHTTP}
		if cfg.Port < 1 || cfg.Port > 65535 {
			return errors.New("V2RaySocks proxy inbound has invalid port")
		}
		if cfg.StreamType == "" {
			cfg.StreamType = "tcp"
		}
		if cfg.TLSType == "" {
			cfg.TLSType = "none"
		}
		if cfg.StreamType == "h2" || cfg.StreamType == "http" {
			cfg.Path = in.Stream.HTTP.Path
			if len(in.Stream.HTTP.Host) > 0 {
				cfg.Host = in.Stream.HTTP.Host[0]
			}
		}
		if len(in.Settings.Clients) > 0 {
			cfg.AlterID = in.Settings.Clients[0].AlterID
			cfg.Flow = in.Settings.Clients[0].Flow
		}
		if name := in.Stream.TLS.ServerName; name != "" {
			cfg.ServerNames = []string{name}
		}
		if cfg.TLSType == "reality" {
			r := in.Stream.Reality
			cfg.ServerNames, cfg.ShortIDs, cfg.PrivateKey = r.ServerNames, r.ShortIDs, r.PrivateKey
			dest := r.Dest
			if len(dest) == 0 {
				dest = r.Target
			}
			if json.Unmarshal(dest, &cfg.Dest) != nil {
				return errors.New("V2RaySocks Reality destination must be a host:port string")
			}
		}
		node = Node{Config: cfg, RawConfig: append(json.RawMessage(nil), data...)}
		// Original GetDetectors 0x174ea60 returns an empty list. Domain block
		// handling is an explicit compatibility extension shared with WHMCS.
		for _, rule := range wire.Routing.Rules {
			if rule.OutboundTag == "block" && len(rule.Protocol) == 0 {
				if node.Policy == nil {
					node.Policy = &Policy{Mode: "reject"}
				}
				for _, domain := range rule.Domain {
					node.Policy.Rules = append(node.Policy.Rules, PolicyRule{Rule: domain})
				}
			} else if len(rule.Domain) > 0 || len(rule.Protocol) > 0 {
				node.UnsupportedOptions = append(node.UnsupportedOptions, "routing.rules")
				break
			}
		}
		if meaningfulJSON(wire.DNS) {
			node.UnsupportedOptions = append(node.UnsupportedOptions, "dns")
		}
		for _, raw := range wire.Outbounds {
			var outbound struct{ Protocol string }
			if json.Unmarshal(raw, &outbound) != nil {
				return errors.New("invalid V2RaySocks outbound")
			}
			if outbound.Protocol != "freedom" && outbound.Protocol != "blackhole" {
				node.UnsupportedOptions = append(node.UnsupportedOptions, "outbounds")
				break
			}
		}
		if meaningfulJSON(in.Stream.TLS.Certificates) {
			// Remote filesystem paths cannot establish which local certificate to
			// use. Preserve them and let the runtime certificate layer resolve it.
			node.UnsupportedOptions = append(node.UnsupportedOptions, "tlsSettings.certificates")
		}
		return nil
	})
	return
}

func (c *V2RaySocks) FetchUsers(ctx context.Context) ([]User, error) {
	if c.opts.NodeType != "vless" && c.opts.NodeType != "hysteria" {
		return c.WHMCS.FetchUsers(ctx)
	}
	// These two protocols use the same UUID credential field as VMess. Decode
	// directly so concurrent fetches never mutate the shared adapter's options.
	var users []User
	err := c.get(ctx, "user", func(data []byte) error {
		var wire struct {
			Msg  string `json:"msg"`
			Data []struct {
				ID     int64   `json:"id"`
				UUID   string  `json:"uuid"`
				Speed  float64 `json:"st"`
				Device int     `json:"dt"`
			} `json:"data"`
		}
		if err := json.Unmarshal(data, &wire); err != nil {
			return err
		}
		if wire.Msg != "ok" || wire.Data == nil {
			return errors.New("V2RaySocks users require msg=ok and a data array")
		}
		users = make([]User, 0, len(wire.Data))
		for _, row := range wire.Data {
			users = append(users, User{ID: row.ID, UUID: row.UUID, Password: row.UUID,
				SpeedLimit: max(0, min(10000, row.Speed)), DeviceLimit: max(0, row.Device)})
		}
		return nil
	})
	return users, err
}
