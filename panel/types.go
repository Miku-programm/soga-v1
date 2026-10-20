// Package panel implements documented panel HTTP APIs. This is an independent
// compatibility implementation, not recovered original source.
package panel

import (
	"context"
	"encoding/json"
	"net/http"
)

type Options struct {
	Type       string
	SubType    string
	BaseURL    string
	APIKey     string
	NodeID     string
	NodeType   string
	HTTPClient *http.Client
}

// API deliberately leaves traffic accounting and acknowledgement persistence to
// its caller. A Report method succeeds only after a valid server acknowledgement.
type API interface {
	FetchNode(context.Context) (Node, error)
	FetchUsers(context.Context) ([]User, error)
	FetchAuditRules(context.Context) ([]AuditRule, error)
	FetchWhiteList(context.Context) ([]string, error)
	ReportTraffic(context.Context, []Traffic) error
	ReportAliveIPs(context.Context, []AliveIP) error
	ReportAuditLogs(context.Context, []AuditLog) error
	ReportStatus(context.Context, Status) error
}

type Basic struct {
	PullInterval int     `json:"pull_interval"`
	PushInterval int     `json:"push_interval"`
	SpeedLimit   float64 `json:"speed_limit"`
}

type PolicyRule struct {
	ID   int64  `json:"id"`
	Rule string `json:"rule"`
}

// Policy uses the original detector prefix syntax. Mode is reject, allow, or all.
type Policy struct {
	Mode  string       `json:"mode"`
	Rules []PolicyRule `json:"rules"`
}

type Node struct {
	DNSRules           []DNSRule       `json:"dns_rules,omitempty"`
	Carriers           []User          `json:"carriers,omitempty"`
	Policy             *Policy         `json:"policy,omitempty"`
	Basic              Basic           `json:"basic"`
	Config             NodeConfig      `json:"config"`
	RawConfig          json.RawMessage `json:"-"`
	UnsupportedOptions []string        `json:"-"`
}

// DNSRule is the normalized panel action=dns route. Domains retain the
// original detector prefix syntax, and Servers holds the action_value.
type DNSRule struct {
	Domains []string `json:"domains"`
	Servers []string `json:"servers"`
}

func (n *Node) UnmarshalJSON(data []byte) error {
	var wire struct {
		Basic  Basic           `json:"basic"`
		Config json.RawMessage `json:"config"`
	}
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	var config NodeConfig
	if len(wire.Config) != 0 {
		if err := json.Unmarshal(wire.Config, &config); err != nil {
			return err
		}
	}
	n.Basic, n.Config, n.RawConfig = wire.Basic, config, append(json.RawMessage(nil), wire.Config...)
	return nil
}

// Fields follow soga-v1.md and binary type GX5_vLs. RawConfig retains unknown
// fields; XHTTPSettings retains the complete nested object and range encodings.
// Certificate files are local runtime configuration, not documented node fields.
type NodeConfig struct {
	Certificate        string          `json:"certificate,omitempty"`
	CertificateKey     string          `json:"certificate_key,omitempty"`
	CertMode           string          `json:"cert_mode,omitempty"`
	OnlyMultiUserPorts bool            `json:"mu_only,omitempty"`
	LegacyPort         int             `json:"legacy_port,omitempty"`
	LegacySogaPort     int             `json:"legacy_soga_port,omitempty"`
	Port               int             `json:"port"`
	AlterID            int             `json:"alter_id"`
	StreamType         string          `json:"stream_type"`
	TLSType            string          `json:"tls_type"`
	Path               string          `json:"path"`
	ServiceName        string          `json:"service_name"`
	Cipher             string          `json:"cipher"`
	Password           string          `json:"password"`
	Host               string          `json:"host"`
	Obfs               string          `json:"obfs"`
	ObfsPassword       string          `json:"obfs_password"`
	Method             string          `json:"method"`
	Protocol           string          `json:"protocol"`
	ProtocolParam      string          `json:"protocol_param"`
	ObfsParam          string          `json:"obfs_param"`
	MultiUserPorts     bool            `json:"multi_user_ports"`
	SinglePortType     string          `json:"single_port_type"`
	Flow               string          `json:"flow"`
	ServerNames        []string        `json:"server_names"`
	PrivateKey         string          `json:"private_key"`
	ShortIDs           []string        `json:"short_ids"`
	Dest               string          `json:"dest"`
	Decryption         string          `json:"decryption"`
	XHTTPSettings      json.RawMessage `json:"xhttp_settings"`
	UpMbps             float64         `json:"up_mbps"`
	DownMbps           float64         `json:"down_mbps"`
	PaddingScheme      []string        `json:"padding_scheme"`
	Transport          string          `json:"transport"`
	TrafficPattern     string          `json:"traffic_pattern"`
}

type User struct {
	IsMultiUser   int     `json:"is_multi_user,omitempty"`
	ID            int64   `json:"id"`
	ProtocolID    uint32  `json:"protocol_id,omitempty"`
	UUID          string  `json:"uuid"`
	AlterID       int     `json:"alter_id,omitempty"`
	Password      string  `json:"password"`
	Username      string  `json:"username"`
	SpeedLimit    float64 `json:"speed_limit"`
	DeviceLimit   int     `json:"device_limit"`
	TCPLimit      int     `json:"tcp_limit"`
	Port          int     `json:"port,omitempty"`
	Method        string  `json:"method,omitempty"`
	Protocol      string  `json:"protocol,omitempty"`
	ProtocolParam string  `json:"protocol_param,omitempty"`
	Obfs          string  `json:"obfs,omitempty"`
	ObfsParam     string  `json:"obfs_param,omitempty"`
}

type Traffic struct {
	ID       int64 `json:"id"`
	Upload   int64 `json:"u"`
	Download int64 `json:"d"`
}

type AliveIP struct {
	ID  int64    `json:"id"`
	IPs []string `json:"ips"`
}

type AuditRule struct {
	ID   int    `json:"id"`
	Rule string `json:"rule"`
}

type AuditLog struct {
	UserID  int64 `json:"user_id"`
	AuditID int   `json:"audit_id"`
}

type Usage struct {
	Total uint64 `json:"total"`
	Used  uint64 `json:"used"`
}

type Status struct {
	Loads  [3]float64 `json:"-"`
	CPU    float64    `json:"cpu"`
	Mem    Usage      `json:"mem"`
	Swap   Usage      `json:"swap"`
	Disk   Usage      `json:"disk"`
	Uptime uint64     `json:"uptime"`
}
