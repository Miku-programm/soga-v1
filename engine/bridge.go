// Package engine assembles compatible protocol and panel implementations.
// These exported interfaces are new, not the original obfuscated Go API.
package engine

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"

	"reconstructed.local/soga/certificates"
	"reconstructed.local/soga/config"
	"reconstructed.local/soga/panel"
	"reconstructed.local/soga/proxy"
)

type Paths struct {
	BlockList, WhiteList, DNS, Routes string
	GeoSite, GeoIP, StateDir          string
	ACMEExecutable                    string
}

type listenerPlan struct {
	node    panel.Node
	users   []panel.User
	address string
	owner   int64
	carrier int64
}

func planListeners(node panel.Node, users []panel.User, addresses []string) ([]listenerPlan, error) {
	var plans []listenerPlan
	var ordinary, carriers []panel.User
	for _, user := range users {
		switch user.IsMultiUser {
		case 0:
			ordinary = append(ordinary, user)
		case 1, 2:
			carriers = append(carriers, user)
		default:
			return nil, fmt.Errorf("unknown multi-user mode %d for user %d", user.IsMultiUser, user.ID)
		}
	}
	if !node.Config.MultiUserPorts {
		for _, address := range addresses {
			plans = append(plans, listenerPlan{node: node, users: ordinary, address: address})
		}
		return plans, nil
	}
	seen := map[int]bool{}
	carriers = append(carriers, node.Carriers...)
	// Original AddSSRUser (0x1276180): apply soga_port first, then replace
	// a previous carrier at that port while keeping its original position.
	positions := map[int]int{}
	var selected []panel.User
	for _, carrier := range carriers {
		port := carrier.Port
		if node.Config.LegacySogaPort != 0 {
			port = node.Config.LegacySogaPort
		}
		if index, exists := positions[port]; exists {
			selected[index] = carrier
		} else {
			positions[port] = len(selected)
			selected = append(selected, carrier)
		}
	}
	carriers = selected
	add := func(user panel.User, mode string, members []panel.User) error {
		port := user.Port
		if mode != "" && node.Config.LegacySogaPort != 0 {
			port = node.Config.LegacySogaPort
		}
		if port < 1 || port > 65535 || seen[port] {
			return fmt.Errorf("multiport listener needs a unique valid port: user %d, port %d", user.ID, port)
		}
		seen[port] = true
		local := node
		local.Config.MultiUserPorts = false
		local.Config.Port = port
		local.Config.SinglePortType = mode
		local.Config.Password = user.Password
		if user.Method != "" {
			local.Config.Method = user.Method
			local.Config.Cipher = user.Method
		}
		if user.Protocol != "" {
			local.Config.Protocol = user.Protocol
		}
		if user.ProtocolParam != "" {
			local.Config.ProtocolParam = user.ProtocolParam
		}
		if user.Obfs != "" {
			local.Config.Obfs = user.Obfs
		}
		if user.ObfsParam != "" {
			local.Config.ObfsParam = user.ObfsParam
		}
		for _, address := range addresses {
			plan := listenerPlan{node: local, users: members, address: address, owner: user.ID}
			if mode != "" {
				plan.carrier = user.ID
			}
			plans = append(plans, plan)
		}
		return nil
	}
	if !node.Config.OnlyMultiUserPorts {
		for _, user := range ordinary {
			if err := add(user, "", []panel.User{user}); err != nil {
				return nil, err
			}
		}
	}
	for _, carrier := range carriers {
		var mode string
		switch carrier.IsMultiUser {
		case 1:
			mode = "obfs"
		case 2:
			mode = "protocol"
		default:
			return nil, fmt.Errorf("invalid carrier mode %d", carrier.IsMultiUser)
		}
		if err := add(carrier, mode, ordinary); err != nil {
			return nil, err
		}
	}
	return plans, nil
}

func buildProxy(ctx context.Context, c config.Config, values map[string]string, p Paths, node panel.Node, users []panel.User, listen string, carrierID ...int64) (proxy.Config, error) {
	cipherNames, err := tlsCipherNames(c.TlsCipherSuites)
	if err != nil {
		return proxy.Config{}, err
	}
	n := node.Config
	if n.Port < 1 || n.Port > 65535 {
		return proxy.Config{}, fmt.Errorf("invalid node port %d", n.Port)
	}
	if len(node.UnsupportedOptions) != 0 {
		return proxy.Config{}, fmt.Errorf("unmapped panel options: %s", strings.Join(node.UnsupportedOptions, ", "))
	}
	kind := panel.NormalizeNodeType(c.ServerType)
	if kind == "hysteria" {
		kind = "hysteria2" // The supplied soga-v1 contract specifies Salamander/BBR.
	}
	if kind == "shadowsocksr" {
		kind = "ssr"
	}
	result := proxy.Config{Protocol: kind, Listen: listen, Port: uint16(n.Port),
		Method: n.Cipher, Password: n.Password, Flow: n.Flow,
		UpMbps: int(n.UpMbps), DownMbps: int(n.DownMbps),
		ObfsPassword: n.ObfsPassword, PaddingScheme: n.PaddingScheme,
		MieruTransport: n.Transport, TrafficPattern: n.TrafficPattern}
	result.AllowPlaintextTLSProtocols = c.ForceCloseSsl ||
		(n.CertMode == "none" && (kind == "trojan" || kind == "anytls"))
	if len(carrierID) != 0 {
		result.SSRCarrierID = carrierID[0]
	}
	prefix4, prefix6 := int(c.UserIpLimitCidrPrefixV4), int(c.UserIpLimitCidrPrefixV6)
	result.IPPrefixV4, result.IPPrefixV6 = &prefix4, &prefix6
	result.SubmitRealIP = c.SubmitRealIp
	result.UDPTimeoutMinutes = int(c.UdpTimeout)
	result.MieruForceUserHint = c.MieruForceUserHint
	result.ProxyProtocol = c.ProxyProtocol
	result.UDPProxyProtocol = c.UdpProxyProtocol
	result.ForceProxyProtocol = c.ForceProxyProtocol
	result.SSRClientIDLimit = c.SsrCidLimit
	result.SSRObfsUDP = c.SsObfsUdp
	result.MURegex, result.MUSuffix = c.MuRegex, c.MuSuffix
	result.VMessReduceMemory = c.VmessReduceMemory || c.V2rayReduceMemory
	result.VMessAuthMode = c.VmessAuthMode
	if c.ForceVmessAead && (result.VMessAuthMode == "" || result.VMessAuthMode == "auto") {
		result.VMessAuthMode = "aead"
	}
	if kind == "vmess" && c.VmessAeadInvalidAccessEnable {
		result.InvalidAccess = &proxy.InvalidAccessConfig{Count: int(c.VmessAeadInvalidAccessCount),
			WindowSeconds: int(c.VmessAeadInvalidAccessDuration), ForbiddenSeconds: int(c.VmessAeadInvalidAccessForbiddenTime)}
	}
	if kind == "shadowsocks" && c.SsInvalidAccessEnable {
		result.InvalidAccess = &proxy.InvalidAccessConfig{Count: int(c.SsInvalidAccessCount),
			WindowSeconds: int(c.SsInvalidAccessDuration), ForbiddenSeconds: int(c.SsInvalidAccessForbiddenTime)}
	}
	result.TCPFastOpen, result.TCPMultiPath = c.Tfo, c.Mptcp
	if c.TcpTimeout < 0 || c.TcpTimeout > 525600 {
		return proxy.Config{}, errors.New("tcp_timeout must be 0..525600 minutes")
	}
	result.TCPTimeoutSeconds = int(c.TcpTimeout * 60)
	if c.AutoOutIp {
		ip, err := netip.ParseAddr(listen)
		if err != nil || ip.IsUnspecified() {
			return proxy.Config{}, errors.New("auto_out_ip requires individually configured listen IPs")
		}
		address := badoption.Addr(ip)
		options := &option.DirectOutboundOptions{}
		if ip.Is4() {
			options.Inet4BindAddress = &address
		} else {
			options.Inet6BindAddress = &address
		}
		result.DirectOptions = options
	}
	result.SSRProtocol, result.SSRObfs = n.Protocol, n.Obfs
	result.SSRProtocolParam, result.SSRObfsParam = n.ProtocolParam, n.ObfsParam
	result.SSRSinglePortType = n.SinglePortType
	if result.Method == "" {
		result.Method = n.Method
	}
	result.DomainSniff = c.DomainSniff
	result.SniffRedirect = c.SniffRedirect
	if c.DetectPacket || c.ForbiddenBitTorrent {
		if c.DetectPacketMaxLen < 1 || c.DetectPacketMaxLen > 65536 {
			return proxy.Config{}, errors.New("detect_packet_max_len must be 1..65536")
		}
		result.DetectPacketMaxLen = int(c.DetectPacketMaxLen)
	}
	var fallbackHost string
	var fallbackPort int64
	switch kind {
	case "trojan":
		fallbackHost, fallbackPort = c.TrojanRemoteAddr, c.TrojanRemotePort
	case "anytls":
		fallbackHost, fallbackPort = c.AnytlsFallbackAddr, c.AnytlsFallbackPort
	case "vmess":
		fallbackHost, fallbackPort = c.VmessFallbackAddr, c.VmessFallbackPort
		if fallbackHost == "" {
			fallbackHost, fallbackPort = c.V2rayFallbackAddr, c.V2rayFallbackPort
		}
	case "vless":
		fallbackHost, fallbackPort = c.V2rayFallbackAddr, c.V2rayFallbackPort
	}
	if fallbackHost != "" || fallbackPort != 0 {
		if fallbackHost == "" || fallbackPort < 1 || fallbackPort > 65535 {
			return proxy.Config{}, errors.New("fallback requires address and valid port")
		}
		result.FallbackAddress = net.JoinHostPort(fallbackHost, strconv.Itoa(int(fallbackPort)))
	}
	result.NodeSpeedLimit = lowerPositive(c.NodeSpeedLimit, node.Basic.SpeedLimit)
	for _, user := range users {
		alterID := n.AlterID
		if alterID < 0 {
			alterID = user.AlterID
		}
		u := proxy.User{ID: user.ID, ProtocolID: user.ProtocolID, UUID: user.UUID,
			Password: user.Password, Username: user.Username, AlterID: alterID,
			Method: user.Method, Protocol: user.Protocol, Obfs: user.Obfs,
			SpeedLimit:  lowerPositive(c.UserSpeedLimit, user.SpeedLimit),
			IPLimit:     int(c.UserConnLimit),
			DeviceLimit: user.DeviceLimit,
			TCPLimit:    int(lowerPositive(float64(c.UserTcpLimit), float64(user.TCPLimit)))}
		result.Users = append(result.Users, u)
	}
	useXray := kind == "vless" && (n.TLSType == "reality" || n.StreamType == "xhttp" || n.Decryption != "" && n.Decryption != "none")
	result.SSObfs, result.SSObfsMode, result.SSHost, result.SSPath = n.Obfs, c.SsObfsMode, n.Host, n.Path
	switch n.StreamType {
	case "", "tcp":
	case "ws":
		result.Transport = &option.V2RayTransportOptions{Type: "ws",
			WebsocketOptions: option.V2RayWebsocketOptions{Path: n.Path}}
	case "http", "h2":
		result.Transport = &option.V2RayTransportOptions{Type: "http",
			HTTPOptions: option.V2RayHTTPOptions{Path: n.Path}}
		if n.Host != "" {
			result.Transport.HTTPOptions.Host = []string{n.Host}
		}
	case "grpc":
		result.Transport = &option.V2RayTransportOptions{Type: "grpc",
			GRPCOptions: option.V2RayGRPCOptions{ServiceName: n.ServiceName}}
	case "xhttp":
		if !useXray {
			return proxy.Config{}, errors.New("XHTTP requires VLESS")
		}
	default:
		return proxy.Config{}, fmt.Errorf("unsupported stream_type %q", n.StreamType)
	}
	needsTLS := n.TLSType == "tls" || kind == "trojan" || kind == "anytls" || strings.HasPrefix(kind, "hysteria")
	if n.TLSType == "reality" {
		host, portText, err := net.SplitHostPort(n.Dest)
		if err != nil {
			return proxy.Config{}, fmt.Errorf("Reality dest: %w", err)
		}
		port, err := strconv.ParseUint(portText, 10, 16)
		if err != nil || port == 0 || n.PrivateKey == "" || len(n.ServerNames) == 0 {
			return proxy.Config{}, errors.New("Reality needs dest, server_names and private_key")
		}
		result.TLS = &option.InboundTLSOptions{Enabled: true, ServerName: n.ServerNames[0],
			Reality: &option.InboundRealityOptions{Enabled: true, PrivateKey: n.PrivateKey,
				ShortID: n.ShortIDs, Handshake: option.InboundRealityHandshakeOptions{
					ServerOptions: option.ServerOptions{Server: host, ServerPort: uint16(port)}}}}
	} else if needsTLS && !result.AllowPlaintextTLSProtocols && (n.Certificate != "" || n.CertificateKey != "") {
		if _, err := tls.X509KeyPair([]byte(n.Certificate), []byte(n.CertificateKey)); err != nil {
			return proxy.Config{}, fmt.Errorf("panel TLS certificate pair: %w", err)
		}
		result.TLS = &option.InboundTLSOptions{Enabled: true, ServerName: c.CertDomain,
			Certificate: []string{n.Certificate}, Key: []string{n.CertificateKey},
			MinVersion: c.TlsMinVersion, MaxVersion: c.TlsMaxVersion,
			ALPN: c.TlsAlpn, CipherSuites: cipherNames}
		if kind == "hysteria2" {
			result.TLS.ALPN = []string{"h3"}
		}
	} else if needsTLS && !result.AllowPlaintextTLSProtocols {
		mode, domain := c.CertMode, c.CertDomain
		if n.CertMode == "self" {
			mode = "self"
			if domain == "" && len(n.ServerNames) > 0 {
				domain = n.ServerNames[0]
			}
			if domain == "" {
				domain = n.Host
			}
			if domain == "" {
				domain = "localhost"
			}
		}
		paths, err := certificates.Resolve(ctx, certificates.Options{
			CertFile: c.CertFile, KeyFile: c.KeyFile, Domain: domain,
			Mode: mode, KeyLength: c.CertKeyLength, DNSProvider: c.DnsProvider,
			Variables: values, StateDir: filepath.Join(p.StateDir, "certificates"),
			ACMEExecutable: p.ACMEExecutable,
		})
		if err != nil {
			return proxy.Config{}, fmt.Errorf("TLS certificate: %w", err)
		}
		result.TLS = &option.InboundTLSOptions{Enabled: true, ServerName: c.CertDomain,
			CertificatePath: paths.CertFile, KeyPath: paths.KeyFile,
			MinVersion: c.TlsMinVersion, MaxVersion: c.TlsMaxVersion,
			ALPN: c.TlsAlpn, CipherSuites: cipherNames}
		if kind == "hysteria2" {
			result.TLS.ALPN = []string{"h3"}
		}
	} else if n.TLSType != "" && n.TLSType != "none" && n.TLSType != "tls" {
		return proxy.Config{}, fmt.Errorf("unknown tls_type %q", n.TLSType)
	}
	if useXray {
		result.Decryption = n.Decryption
		stream := map[string]any{"network": n.StreamType, "security": "none"}
		if n.StreamType == "" {
			stream["network"] = "tcp"
		}
		switch n.StreamType {
		case "xhttp":
			settings := map[string]any{}
			if len(n.XHTTPSettings) != 0 && string(n.XHTTPSettings) != "null" {
				if err := json.Unmarshal(n.XHTTPSettings, &settings); err != nil {
					return proxy.Config{}, fmt.Errorf("xhttp_settings: %w", err)
				}
			}
			if _, ok := settings["path"]; !ok && n.Path != "" {
				settings["path"] = n.Path
			}
			if _, ok := settings["host"]; !ok && n.Host != "" {
				settings["host"] = n.Host
			}
			stream["xhttpSettings"] = settings
		case "ws":
			stream["wsSettings"] = map[string]any{"path": n.Path, "headers": map[string]string{"Host": n.Host}}
		case "grpc":
			stream["grpcSettings"] = map[string]any{"serviceName": n.ServiceName}
		case "http", "h2":
			stream["network"] = "http"
			settings := map[string]any{"path": n.Path}
			if n.Host != "" {
				settings["host"] = []string{n.Host}
			}
			stream["httpSettings"] = settings
		}
		if result.TLS != nil && result.TLS.Enabled {
			if n.TLSType == "reality" {
				stream["security"] = "reality"
				stream["realitySettings"] = map[string]any{"dest": n.Dest,
					"serverNames": n.ServerNames, "privateKey": n.PrivateKey, "shortIds": n.ShortIDs}
			} else {
				stream["security"] = "tls"
				certificate := map[string]any{"certificateFile": result.TLS.CertificatePath, "keyFile": result.TLS.KeyPath}
				if len(result.TLS.Certificate) != 0 {
					certificate = map[string]any{"certificate": result.TLS.Certificate, "key": result.TLS.Key}
				}
				stream["tlsSettings"] = map[string]any{
					"serverName": c.CertDomain, "alpn": result.TLS.ALPN,
					"minVersion": c.TlsMinVersion, "maxVersion": c.TlsMaxVersion,
					"cipherSuites": strings.Join(cipherNames, ":"),
					"certificates": []any{certificate},
				}
			}
		}
		raw, err := json.Marshal(stream)
		if err != nil {
			return proxy.Config{}, err
		}
		result.XrayStream = raw
	}
	result.Tunnel, err = buildTunnel(ctx, c, values, p, cipherNames)
	if err != nil {
		return proxy.Config{}, err
	}
	return result, proxy.ValidateConfig(result)
}

func lowerPositive(a, b float64) float64 {
	if a == 0 {
		return b
	}
	if b == 0 {
		return a
	}
	return min(a, b)
}

func listenAddresses(value string) ([]string, error) {
	if value == "" {
		return []string{"::"}, nil
	}
	var texts []string
	if value == "all" {
		items, err := net.InterfaceAddrs()
		if err != nil {
			return nil, err
		}
		for _, item := range items {
			if p, err := netip.ParsePrefix(item.String()); err == nil {
				ip := p.Addr().Unmap()
				// Link-local IPv6 requires an interface zone, which InterfaceAddrs
				// does not provide. Keep ordinary assigned addresses only.
				if !ip.IsLinkLocalUnicast() && !ip.IsUnspecified() {
					texts = append(texts, ip.String())
				}
			}
		}
	} else {
		texts = config.SplitClean(value, ",", -1)
	}
	for _, text := range texts {
		if _, err := netip.ParseAddr(text); err != nil {
			return nil, fmt.Errorf("listen address %q: %w", text, err)
		}
	}
	slices.Sort(texts)
	texts = slices.Compact(texts)
	if len(texts) == 0 {
		return nil, errors.New("no listen addresses")
	}
	return texts, nil
}
