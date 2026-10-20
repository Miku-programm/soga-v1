// Package ssrcore adapts the GPL-3.0 VNet-SSR server protocol implementation.
// It is an independent compatibility reconstruction, not original soga code.
package ssrcore

import (
	"errors"
	"fmt"
	"math"
	"net"
	"strings"

	"reconstructed.local/soga/proxy/ssrcore/internal/vnet/common/ciphers/stream"
	"reconstructed.local/soga/proxy/ssrcore/internal/vnet/common/obfs"
	"reconstructed.local/soga/proxy/wireproxy"
)

const Type = "ssr"

type User struct {
	ID                     int64
	Password               string
	ProtocolID             uint32 // Zero uses ID. Nonzero separates wire UID from billing ID.
	Method, Protocol, Obfs string // Own panel fields used by the mu host digest.
}

func (u User) wireID() uint32 {
	if u.ProtocolID != 0 {
		return u.ProtocolID
	}
	return uint32(u.ID)
}

type Options struct {
	Listen                                              string
	Port                                                uint16
	Users                                               []User
	Method                                              string
	Password                                            string // Outer cipher password of a single-port carrier.
	Protocol                                            string
	Obfs                                                string
	ProtocolParam                                       string
	ObfsParam                                           string
	SinglePortType                                      string // "protocol", "obfs", or empty/"none" for one user per listener.
	MURegex, MUSuffix                                   string
	CarrierID                                           int64
	ObfsUDP                                             bool // Unattributed carrier UDP; disabled by default in obfs mode.
	TCPFastOpen                                         bool
	TCPMultiPath                                        bool
	ProxyProtocol, UDPProxyProtocol, ForceProxyProtocol bool
	ProxyProtocolTrusted                                wireproxy.Trusted
	// WrapConnection adapts an independent transport (for example official
	// simple-obfs) before the legacy stream cipher. It must preserve net.Conn
	// deadlines, addresses and closure. Do not use it to peel SSR obfs twice.
	WrapConnection func(net.Conn) (net.Conn, error)
}

func Protocols() []string {
	return []string{"origin", "auth_sha1_v4", "auth_aes128_md5", "auth_aes128_sha1",
		"auth_chain_a", "auth_chain_b", "auth_chain_c", "auth_chain_d", "auth_chain_e", "auth_chain_f"}
}

func Obfuscators() []string {
	return []string{"plain", "http_simple", "http_post", "tls1.2_ticket_auth", "tls1.2_ticket_fastauth"}
}

func Validate(o Options) error {
	_, err := normalize(o)
	return err
}

func normalize(o Options) (Options, error) {
	o.Users = append([]User(nil), o.Users...)
	if o.Listen == "" {
		o.Listen = "0.0.0.0"
	}
	if o.Protocol == "" {
		o.Protocol = "origin"
	}
	if o.Obfs == "" {
		o.Obfs = "plain"
	}
	simple := o.Obfs == "simple_obfs_http" || o.Obfs == "simple_obfs_tls"
	if !contains(Protocols(), o.Protocol) || (!contains(Obfuscators(), o.Obfs) && !simple) {
		return o, errors.New("ssr: unsupported protocol or obfs; compatible authentication fallback is disabled")
	}
	if simple && (o.SinglePortType != "obfs" || o.Protocol != "origin") {
		return o, errors.New("ssr: simple-obfs requires origin and obfs single-port; framed SSR obfuscators are different protocols")
	}
	// SSR's framed protocols require stream ciphers. The original documentation
	// explicitly excludes AEAD for SSR clients.
	if stream.GetStreamCipher(o.Method) == nil {
		return o, fmt.Errorf("ssr: unsupported stream cipher %q", o.Method)
	}
	if o.Method == "none" && o.Protocol == "origin" {
		return o, errors.New("ssr: origin with cipher none cannot authenticate a user")
	}
	if len(o.Users) == 0 {
		return o, errors.New("ssr: no authorized users")
	}
	seen := make(map[int64]bool)
	wireIDs := make(map[uint32]bool)
	for _, u := range o.Users {
		if u.ID <= 0 || u.Password == "" || seen[u.ID] {
			return o, errors.New("ssr: users require unique positive billing IDs and nonempty passwords")
		}
		seen[u.ID] = true
		if o.SinglePortType == "protocol" {
			if (u.ProtocolID == 0 && u.ID > math.MaxUint32) || wireIDs[u.wireID()] {
				return o, errors.New("ssr: protocol single-port requires unique uint32 wire IDs")
			}
			wireIDs[u.wireID()] = true
		}
	}
	switch o.SinglePortType {
	case "protocol":
		if !obfs.CarriesIdentity(o.Protocol) || o.Password == "" {
			return o, errors.New("ssr: protocol single-port requires identity-bearing auth and an outer password")
		}
	case "", "none":
		if len(o.Users) != 1 {
			return o, errors.New("ssr: one user is required per non-single-port listener")
		}
		o.Password = o.Users[0].Password
	case "obfs":
		if o.Password == "" || o.Obfs == "plain" {
			return o, errors.New("ssr: obfs single-port requires a carrier password and a Host/SNI obfuscator")
		}
		if o.ObfsUDP && o.CarrierID < 0 {
			return o, errors.New("ssr: obfs UDP carrier ID must not be negative")
		}
		if o.MURegex == "" {
			o.MURegex = "%5m%id.%suffix"
		}
		if o.MUSuffix == "" {
			o.MUSuffix = "microsoft.com"
		}
		hosts := make(map[string]bool)
		for _, u := range o.Users {
			host, err := HostForUser(u, o.MURegex, o.MUSuffix)
			if err != nil {
				return o, err
			}
			host = canonicalHost(host)
			if host == "" || hosts[host] {
				return o, errors.New("ssr: mu_regex produces empty or duplicate user hosts")
			}
			hosts[host] = true
		}
	default:
		return o, fmt.Errorf("ssr: unknown single_port_type %q", o.SinglePortType)
	}
	if strings.Contains(o.ProtocolParam, "#") {
		return o, errors.New("ssr: protocol_param must not supply a second user table")
	}
	return o, nil
}

func contains(items []string, item string) bool {
	for _, v := range items {
		if v == item {
			return true
		}
	}
	return false
}
