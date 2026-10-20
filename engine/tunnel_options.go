package engine

import (
	"context"
	"crypto/tls"
	"fmt"
	"path/filepath"
	"slices"

	"reconstructed.local/soga/certificates"
	"reconstructed.local/soga/config"
	"reconstructed.local/soga/tunnel"
)

// The tunnel's outer transport certificate is independent of panel-provided
// certificates and the inner proxy's TLS settings.
func buildTunnel(ctx context.Context, c config.Config, values map[string]string, p Paths, cipherNames []string) (*tunnel.Config, error) {
	if !c.TunnelEnable {
		return nil, nil
	}
	result := &tunnel.Config{
		Type: c.TunnelType, Method: c.TunnelMethod, Password: c.TunnelPassword,
		WSPath: c.TunnelWsPath, Mux: c.TunnelMux,
	}
	usesTLS := false
	switch c.TunnelType {
	case "", "tcp", "tcp-tunnel", "ws", "ws-tunnel":
	case "tls", "tls-tunnel", "ws-tls", "ws-tls-tunnel":
		usesTLS = true
	case "quic", "quic-tunnel":
		// Reject before certificate issuance until the transport is available.
		return nil, fmt.Errorf("QUIC tunnel transport has no validated wire implementation")
	default:
		return nil, fmt.Errorf("unknown tunnel_type %q", c.TunnelType)
	}
	// Check the shared cipher/password/path configuration before attempting
	// certificate issuance. TCP has the same framing and needs no certificate.
	preflight := *result
	preflight.Type = "tcp"
	if err := tunnel.Validate(preflight); err != nil {
		return nil, fmt.Errorf("tunnel configuration: %w", err)
	}
	if usesTLS {
		minVersion, err := tunnelTLSVersion(c.TlsMinVersion)
		if err != nil {
			return nil, fmt.Errorf("tunnel tls_min_version: %w", err)
		}
		maxVersion, err := tunnelTLSVersion(c.TlsMaxVersion)
		if err != nil {
			return nil, fmt.Errorf("tunnel tls_max_version: %w", err)
		}
		if minVersion != 0 && maxVersion != 0 && minVersion > maxVersion {
			return nil, fmt.Errorf("tunnel tls_min_version exceeds tls_max_version")
		}
		paths, err := certificates.Resolve(ctx, certificates.Options{
			CertFile: c.CertFile, KeyFile: c.KeyFile, Domain: c.CertDomain,
			Mode: c.CertMode, KeyLength: c.CertKeyLength, DNSProvider: c.DnsProvider,
			Variables: config.DNSVariables(values), StateDir: filepath.Join(p.StateDir, "tunnel-certificates"),
			ACMEExecutable: p.ACMEExecutable,
		})
		if err != nil {
			return nil, fmt.Errorf("tunnel TLS certificate: %w", err)
		}
		pair, err := tls.LoadX509KeyPair(paths.CertFile, paths.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("tunnel TLS certificate: %w", err)
		}
		result.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{pair}, ServerName: c.CertDomain,
			MinVersion: minVersion, MaxVersion: maxVersion, NextProtos: slices.Clone(c.TlsAlpn),
		}
		for _, name := range cipherNames {
			found := false
			for _, suite := range append(tls.CipherSuites(), tls.InsecureCipherSuites()...) {
				if name == suite.Name {
					result.TLSConfig.CipherSuites = append(result.TLSConfig.CipherSuites, suite.ID)
					found = true
					break
				}
			}
			if !found {
				return nil, fmt.Errorf("unknown tunnel TLS cipher %q", name)
			}
		}
	}
	if err := tunnel.Validate(*result); err != nil {
		return nil, fmt.Errorf("tunnel configuration: %w", err)
	}
	return result, nil
}

func tunnelTLSVersion(value string) (uint16, error) {
	switch value {
	case "":
		return 0, nil
	case "1.0":
		return tls.VersionTLS10, nil
	case "1.1":
		return tls.VersionTLS11, nil
	case "1.2":
		return tls.VersionTLS12, nil
	case "1.3":
		return tls.VersionTLS13, nil
	default:
		return 0, fmt.Errorf("unknown TLS version %q", value)
	}
}
