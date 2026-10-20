// Package proxy adapts the independently maintained sing-box protocol engine.
// This is reconstruction code, not recovered original soga source.
package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	"reconstructed.local/soga/proxy/ssrcore"
	"reconstructed.local/soga/proxy/wireproxy"
	"reconstructed.local/soga/tunnel"
)

type User struct {
	Method, Protocol, Obfs string
	ID                     int64
	ProtocolID             uint32
	UUID                   string
	Username               string
	Password               string
	AlterID                int
	SpeedLimit             float64
	DeviceLimit            int
	IPLimit                int
	TCPLimit               int
}

// Request is the authenticated request, before dialing a target. Source and
// Destination are host:port strings; Network is "tcp" or "udp".
type Request struct {
	UserID           int64
	Network          string
	Source           string
	Destination      string
	Outbound         string
	SniffedDomain    string
	FirstPacket      []byte
	Unattributed     bool   // Carrier UDP has no authenticated ordinary-user identity.
	DeviceID         string // Authenticated SSR client ID, when the protocol exposes one.
	deviceLimitByCID bool
}

// AdmissionRequest contains authenticated identities and effective limits.
// IP is already CIDR-normalized. DeviceID is namespaced as ip: or cid:; an empty
// value means the wire protocol exposes no authenticated device identity.
type AdmissionRequest struct {
	UserID               int64
	IP, DeviceID         string
	IPLimit, DeviceLimit int
}

type Config struct {
	Protocol                           string
	Listen                             string
	Port                               uint16
	Users                              []User
	Method                             string
	Password                           string // Shadowsocks 2022 server key
	TLS                                *option.InboundTLSOptions
	Transport                          *option.V2RayTransportOptions
	Flow                               string
	UpMbps                             int
	DownMbps                           int
	ObfsPassword                       string
	PaddingScheme                      []string
	Hook                               func(Request) error
	Transform                          func(context.Context, Request) (Request, error)
	Outbounds                          []option.Outbound
	MieruTransport                     string
	MieruForceUserHint                 bool
	TrafficPattern                     string
	AllowPlaintextTLSProtocols         bool            // Explicit external TLS termination for Trojan/AnyTLS.
	XrayStream                         json.RawMessage // Native Xray streamSettings for VLESS extensions.
	Decryption                         string
	NodeSpeedLimit                     float64
	Limiter                            *Limiter
	IPPrefixV4                         *int
	IPPrefixV6                         *int
	SubmitRealIP                       bool
	UDPTimeoutMinutes                  int
	ProxyProtocol                      bool
	FallbackAddress                    string
	SSRProtocol                        string
	SSRObfs                            string
	SSRProtocolParam                   string
	SSRObfsParam                       string
	SSRSinglePortType                  string
	SSRClientIDLimit                   bool
	SSRCarrierID                       int64
	SSRObfsUDP                         bool
	MURegex, MUSuffix                  string
	DomainSniff                        []string
	SniffRedirect                      bool
	DetectPacketMaxLen                 int
	ForceProxyProtocol                 bool
	GlobalAdmission                    func(context.Context, AdmissionRequest) (func(), error)
	TCPFastOpen                        bool
	TCPMultiPath                       bool
	TCPTimeoutSeconds                  int
	DirectOptions                      *option.DirectOutboundOptions
	VMessAuthMode                      string
	VMessReduceMemory                  bool
	InvalidAccess                      *InvalidAccessConfig
	AuthCache                          *AuthenticationCache
	UDPProxyProtocol                   bool
	// ProxyProtocolTrusted limits whose PROXY headers are honoured; empty trusts all.
	ProxyProtocolTrusted               wireproxy.Trusted
	SSObfs, SSObfsMode, SSHost, SSPath string
	Tunnel                             *tunnel.Config
}

// Traffic counts authenticated application payload, not transport framing.
// Snapshots are cumulative for the lifetime of Server, including user updates.
type Traffic struct {
	Upload   uint64
	Download uint64
}

type Server struct {
	mu     sync.Mutex
	ctx    context.Context
	cfg    Config
	box    *box.Box
	tunnel *tunnelFrontend
	meter  *meter
	closed bool
	done   chan struct{}
}

func Protocols() []string {
	return []string{"vmess", "vless", "trojan", "shadowsocks", "ssr", "anytls", "hysteria", "hysteria2", "mieru"}
}

func normalize(protocol string) string {
	switch strings.ToLower(protocol) {
	case "ss":
		return "shadowsocks"
	case "shadowsocksr":
		return "ssr"
	case "v2ray":
		return "vmess"
	default:
		return strings.ToLower(protocol)
	}
}

// ValidateConfig checks adapter-level values without binding a listener. The
// selected core also validates certificates, keys and transport on Start.
func ValidateConfig(cfg Config) error {
	cfg.Protocol = normalize(cfg.Protocol)
	if cfg.Listen == "" {
		cfg.Listen = "0.0.0.0"
	}
	_, err := inboundOptions(cfg)
	return err
}

func Start(ctx context.Context, cfg Config) (*Server, error) {
	if ctx == nil {
		return nil, errors.New("proxy: nil context")
	}
	cfg.Protocol = normalize(cfg.Protocol)
	if cfg.Listen == "" {
		cfg.Listen = "0.0.0.0"
	}
	cfg.Users = slices.Clone(cfg.Users)
	if cfg.Limiter == nil {
		cfg.Limiter = NewLimiter()
	}
	s := &Server{ctx: ctx, cfg: cfg, meter: newMeter(), done: make(chan struct{})}
	v4, v6, err := normalizedPrefixes(cfg.IPPrefixV4, cfg.IPPrefixV6)
	if err != nil {
		return nil, err
	}
	s.meter.prefix4, s.meter.prefix6, s.meter.submitRealIP = v4, v6, cfg.SubmitRealIP
	if err := s.start(); err != nil {
		return nil, err
	}
	go func() {
		select {
		case <-ctx.Done():
			_ = s.Close()
		case <-s.done:
		}
	}()
	return s, nil
}

func (s *Server) start() error {
	in, err := inboundOptions(s.cfg)
	if err != nil {
		return err
	}
	if err := s.ctx.Err(); err != nil {
		return err
	}
	v4, v6, err := normalizedPrefixes(s.cfg.IPPrefixV4, s.cfg.IPPrefixV6)
	if err != nil {
		return err
	}
	if err := s.cfg.Limiter.SetIPPrefixes(v4, v6); err != nil {
		return err
	}
	for _, user := range s.cfg.Users {
		if err := s.cfg.Limiter.SetUserLimits(user); err != nil {
			return err
		}
	}
	if err := s.cfg.Limiter.SetNodeSpeedLimit(s.cfg.NodeSpeedLimit); err != nil {
		return err
	}
	// With no authorized users, keep the port closed. Some protocol backends
	// interpret an empty user list as their single-password configuration.
	if len(s.cfg.Users) == 0 {
		return nil
	}
	if s.cfg.Tunnel != nil && s.cfg.Protocol != "mieru" {
		return s.startTunnel()
	}
	ctx := protocolContext(s.ctx, s.meter, s.cfg.Hook, s.cfg.Transform, s.cfg.Limiter, s.cfg.MieruTransport, time.Duration(s.cfg.UDPTimeoutMinutes)*time.Minute, inspectionOptions{protocols: s.cfg.DomainSniff, redirect: s.cfg.SniffRedirect, maxPacket: s.cfg.DetectPacketMaxLen, cidMode: s.cfg.Protocol == "ssr" && s.cfg.SSRSinglePortType == "protocol" && s.cfg.SSRClientIDLimit, admission: s.cfg.GlobalAdmission, tcpTimeout: time.Duration(s.cfg.TCPTimeoutSeconds) * time.Second})
	directOptions := s.cfg.DirectOptions
	if directOptions == nil {
		directOptions = &option.DirectOutboundOptions{}
	}
	outbounds := []option.Outbound{{Type: "direct", Tag: "direct", Options: directOptions}}
	for _, out := range s.cfg.Outbounds {
		if out.Tag == "" || out.Tag == "direct" {
			return errors.New("proxy: extra outbound requires a nonempty tag other than direct")
		}
		outbounds = append(outbounds, out)
	}
	b, err := box.New(box.Options{
		Context: ctx,
		Options: option.Options{
			Log:       &option.LogOptions{Disabled: true},
			Inbounds:  []option.Inbound{in},
			Outbounds: outbounds,
		},
	})
	if err != nil {
		return fmt.Errorf("proxy: create %s: %w", s.cfg.Protocol, err)
	}
	if err = b.Start(); err != nil {
		_ = b.Close()
		return fmt.Errorf("proxy: start %s: %w", s.cfg.Protocol, err)
	}
	s.box = b
	return nil
}

func (s *Server) Addr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return net.JoinHostPort(s.cfg.Listen, strconv.Itoa(int(s.cfg.Port)))
}

// UpdateUsers recreates the listener on the same port, terminating existing
// sessions. This is not a seamless hot update. A failed restart leaves it closed.
func (s *Server) UpdateUsers(users []User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return net.ErrClosed
	}
	next := s.cfg
	next.Users = slices.Clone(users)
	if _, err := inboundOptions(next); err != nil {
		return err
	}
	if s.tunnel != nil {
		_ = s.tunnel.close()
		s.tunnel = nil
	}
	if s.box != nil {
		err := s.box.Close()
		s.box = nil
		if err != nil {
			return fmt.Errorf("proxy: close before update: %w", err)
		}
	}
	s.cfg = next
	return s.start()
}

func (s *Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	close(s.done)
	if s.tunnel != nil {
		_ = s.tunnel.close()
		s.tunnel = nil
	}
	if s.box != nil {
		err := s.box.Close()
		s.box = nil
		return err
	}
	return nil
}

func (s *Server) TrafficSnapshot() map[int64]Traffic { return s.meter.trafficSnapshot() }
func (s *Server) OnlineSnapshot() map[int64][]string { return s.meter.onlineSnapshot() }

func inboundOptions(c Config) (option.Inbound, error) {
	if c.Tunnel != nil {
		if err := tunnel.Validate(*c.Tunnel); err != nil {
			return option.Inbound{}, err
		}
		if c.Protocol == "hysteria" || c.Protocol == "hysteria2" {
			return option.Inbound{}, errors.New("proxy: tunnel encapsulation for this protocol has not been recovered")
		}
		if c.Protocol == "mieru" && strings.EqualFold(c.MieruTransport, "UDP") {
			return option.Inbound{}, errors.New("proxy: documented Mieru tunnel uses TCP transport; native UDP transport is an independent extension")
		}
	}
	if err := c.InvalidAccess.validate(); err != nil {
		return option.Inbound{}, err
	}
	if !slices.Contains(Protocols(), c.Protocol) {
		return option.Inbound{}, fmt.Errorf("proxy: unsupported protocol %q", c.Protocol)
	}
	if _, _, err := normalizedPrefixes(c.IPPrefixV4, c.IPPrefixV6); err != nil {
		return option.Inbound{}, err
	}
	if c.UDPTimeoutMinutes < 0 {
		return option.Inbound{}, errors.New("proxy: negative UDP timeout")
	}
	if c.TCPTimeoutSeconds < 0 {
		return option.Inbound{}, errors.New("proxy: negative TCP idle timeout")
	}
	if c.DetectPacketMaxLen < 0 || c.DetectPacketMaxLen > 65536 {
		return option.Inbound{}, errors.New("proxy: detect packet length must be between 0 and 65536")
	}
	for _, protocol := range c.DomainSniff {
		if protocol != "http" && protocol != "tls" && protocol != "quic" {
			return option.Inbound{}, fmt.Errorf("proxy: unsupported sniff protocol %q", protocol)
		}
	}
	addr, err := netip.ParseAddr(c.Listen)
	if err != nil || c.Port == 0 {
		return option.Inbound{}, errors.New("proxy: listen must be an IP and port must be nonzero")
	}
	seenIDs, seenCredentials := map[int64]bool{}, map[string]bool{}
	if !validSpeed(c.NodeSpeedLimit) {
		return option.Inbound{}, errors.New("proxy: invalid node speed")
	}
	for _, u := range c.Users {
		if !validSpeed(u.SpeedLimit) || u.DeviceLimit < 0 || u.IPLimit < 0 || u.TCPLimit < 0 {
			return option.Inbound{}, errors.New("proxy: invalid user limits")
		}
		if u.ID <= 0 || seenIDs[u.ID] {
			return option.Inbound{}, errors.New("proxy: user IDs must be positive and unique")
		}
		credential := u.Password
		if c.Protocol == "mieru" {
			if u.Username == "" || u.Password == "" {
				return option.Inbound{}, errors.New("proxy: Mieru requires username and password")
			}
			credential = u.Username
		}
		if c.Protocol == "vmess" || c.Protocol == "vless" {
			credential = strings.ToLower(u.UUID)
		}
		if credential == "" || (seenCredentials[credential] && c.Protocol != "ssr") {
			return option.Inbound{}, errors.New("proxy: credentials must be nonempty and unique")
		}
		if u.AlterID < 0 {
			return option.Inbound{}, errors.New("proxy: negative VMess alter-id")
		}
		seenIDs[u.ID], seenCredentials[credential] = true, true
	}
	if ((c.Protocol == "trojan" || c.Protocol == "anytls") && !c.AllowPlaintextTLSProtocols) || strings.HasPrefix(c.Protocol, "hysteria") {
		if c.TLS == nil || !c.TLS.Enabled {
			return option.Inbound{}, fmt.Errorf("proxy: %s requires explicit TLS configuration", c.Protocol)
		}
	}
	if c.Transport != nil && c.Protocol != "vmess" && c.Protocol != "vless" && c.Protocol != "trojan" {
		return option.Inbound{}, fmt.Errorf("proxy: transport is not supported for %s", c.Protocol)
	}
	listenAddr := badoption.Addr(addr)
	listen := option.ListenOptions{Listen: &listenAddr, ListenPort: c.Port, TCPFastOpen: c.TCPFastOpen, TCPMultiPath: c.TCPMultiPath}
	if c.UDPTimeoutMinutes > 0 {
		listen.UDPTimeout = option.UDPTimeoutCompat(time.Duration(c.UDPTimeoutMinutes) * time.Minute)
	}
	tls := option.InboundTLSOptionsContainer{TLS: c.TLS}
	in := option.Inbound{Type: c.Protocol, Tag: "soga-reconstruction"}
	if c.VMessAuthMode != "" && c.VMessAuthMode != "auto" && c.VMessAuthMode != "md5" && c.VMessAuthMode != "aead" {
		return option.Inbound{}, errors.New("proxy: invalid VMess authentication mode")
	}
	if c.FallbackAddress != "" && c.Protocol != "vless" && c.Protocol != "trojan" && c.Protocol != "vmess" && c.Protocol != "anytls" {
		return option.Inbound{}, errors.New("proxy: fallback adapter is not available for this protocol yet")
	}
	if c.FallbackAddress != "" {
		if _, _, err := net.SplitHostPort(c.FallbackAddress); err != nil {
			return option.Inbound{}, fmt.Errorf("proxy: invalid fallback address: %w", err)
		}
	}
	nativeH2Proxy := (c.Protocol == "vless" || c.Protocol == "trojan") && c.ProxyProtocol && c.Transport != nil && c.Transport.Type == "http" && len(c.XrayStream) == 0 && (c.Decryption == "" || c.Decryption == "none")
	if (c.Protocol == "anytls" && (c.ProxyProtocol || c.FallbackAddress != "")) || c.Protocol == "vmess" || nativeH2Proxy {
		if len(c.XrayStream) > 0 || (c.FallbackAddress != "" && c.Transport != nil) {
			return option.Inbound{}, errors.New("proxy: VMess/AnyTLS fallback uses native TCP TLS; VMess authentication modes cannot combine with XrayStream")
		}
		in.Type, in.Options = "tls-service", &tlsServiceOptions{Config: c}
		return in, nil
	}
	if len(c.XrayStream) > 0 || (c.ProxyProtocol && c.Protocol != "shadowsocks" && c.Protocol != "ssr") || (c.FallbackAddress != "" && (c.Protocol == "vless" || c.Protocol == "trojan")) || (c.Decryption != "" && c.Decryption != "none") {
		if c.Protocol != "vmess" && c.Protocol != "vless" && c.Protocol != "trojan" {
			return option.Inbound{}, errors.New("proxy: this protocol does not support the selected Xray/PROXY feature")
		}
		if len(c.XrayStream) > 0 && !json.Valid(c.XrayStream) {
			return option.Inbound{}, errors.New("proxy: XrayStream must be valid JSON")
		}
		in.Type, in.Options = "xray-core", &xrayOptions{Config: c}
		return in, nil
	}
	switch c.Protocol {
	case "ssr":
		if isSSObfsMulti(c) && isSSAEAD(c.Method) {
			if err := validateShadowsocks(c); err != nil {
				return option.Inbound{}, err
			}
			in.Type, in.Options = "ss-service", &shadowsocksOptions{Config: c}
			return in, nil
		}
		o := &ssrcore.Options{Listen: c.Listen, Port: c.Port, Method: c.Method, Password: c.Password,
			TCPFastOpen: c.TCPFastOpen, TCPMultiPath: c.TCPMultiPath,
			ProxyProtocol: c.ProxyProtocol, UDPProxyProtocol: c.UDPProxyProtocol, ForceProxyProtocol: c.ForceProxyProtocol,
			ProxyProtocolTrusted: c.ProxyProtocolTrusted,
			Protocol: c.SSRProtocol, Obfs: c.SSRObfs, ProtocolParam: c.SSRProtocolParam,
			ObfsParam: c.SSRObfsParam, SinglePortType: c.SSRSinglePortType}
		o.CarrierID, o.ObfsUDP, o.MURegex, o.MUSuffix = c.SSRCarrierID, c.SSRObfsUDP, c.MURegex, c.MUSuffix
		for _, u := range c.Users {
			o.Users = append(o.Users, ssrcore.User{ID: u.ID, ProtocolID: u.ProtocolID, Password: u.Password, Method: u.Method, Protocol: u.Protocol, Obfs: u.Obfs})
		}
		if len(o.Users) > 0 {
			if err := ssrcore.Validate(*o); err != nil {
				return option.Inbound{}, err
			}
		}
		in.Options = o
	case "mieru":
		if c.MieruTransport != "" && !strings.EqualFold(c.MieruTransport, "tcp") && !strings.EqualFold(c.MieruTransport, "udp") {
			return option.Inbound{}, errors.New("proxy: invalid Mieru transport")
		}
		in.Options = &mieruOptions{Config: c}
	case "vmess":
		o := &option.VMessInboundOptions{ListenOptions: listen, InboundTLSOptionsContainer: tls, Transport: c.Transport}
		for _, u := range c.Users {
			o.Users = append(o.Users, option.VMessUser{Name: strconv.FormatInt(u.ID, 10), UUID: u.UUID})
		}
		in.Options = o
	case "vless":
		o := &option.VLESSInboundOptions{ListenOptions: listen, InboundTLSOptionsContainer: tls, Transport: c.Transport}
		for _, u := range c.Users {
			o.Users = append(o.Users, option.VLESSUser{Name: strconv.FormatInt(u.ID, 10), UUID: u.UUID, Flow: c.Flow})
		}
		in.Options = o
	case "trojan":
		o := &option.TrojanInboundOptions{ListenOptions: listen, InboundTLSOptionsContainer: tls, Transport: c.Transport}
		for _, u := range c.Users {
			o.Users = append(o.Users, option.TrojanUser{Name: strconv.FormatInt(u.ID, 10), Password: u.Password})
		}
		in.Options = o
	case "shadowsocks":
		if err := validateShadowsocks(c); err != nil {
			return option.Inbound{}, err
		}
		if isSSAEAD(c.Method) {
			in.Type, in.Options = "ss-service", &shadowsocksOptions{Config: c}
		} else {
			o := ssLegacyOptions(c)
			in.Type, in.Options = "ssr", &o
		}
	case "anytls":
		o := &option.AnyTLSInboundOptions{ListenOptions: listen, InboundTLSOptionsContainer: tls, PaddingScheme: c.PaddingScheme}
		for _, u := range c.Users {
			o.Users = append(o.Users, option.AnyTLSUser{Name: strconv.FormatInt(u.ID, 10), Password: u.Password})
		}
		in.Options = o
	case "hysteria":
		if c.UpMbps <= 0 || c.DownMbps <= 0 {
			return option.Inbound{}, errors.New("proxy: Hysteria v1 requires positive up/down Mbps")
		}
		o := &option.HysteriaInboundOptions{ListenOptions: listen, InboundTLSOptionsContainer: tls, UpMbps: c.UpMbps, DownMbps: c.DownMbps, Obfs: c.ObfsPassword}
		for _, u := range c.Users {
			o.Users = append(o.Users, option.HysteriaUser{Name: strconv.FormatInt(u.ID, 10), AuthString: u.Password})
		}
		in.Options = o
	case "hysteria2":
		o := &option.Hysteria2InboundOptions{ListenOptions: listen, InboundTLSOptionsContainer: tls, UpMbps: c.UpMbps, DownMbps: c.DownMbps}
		if c.ObfsPassword != "" {
			o.Obfs = &option.Hysteria2Obfs{Type: "salamander", Password: c.ObfsPassword}
		}
		for _, u := range c.Users {
			o.Users = append(o.Users, option.Hysteria2User{Name: strconv.FormatInt(u.ID, 10), Password: u.Password})
		}
		in.Options = o
	}
	return in, nil
}
