// Package certificates implements the documented certificate sources using new
// code. It does not reproduce the original program's certificate implementation.
package certificates

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Options struct {
	CertFile, KeyFile string
	Domain, Mode      string
	KeyLength         string
	DNSProvider       string
	// Variables contains documented DNS_* configuration entries. The DNS_
	// prefix is removed before passing credentials to acme.sh.
	Variables      map[string]string
	StateDir       string
	ACMEExecutable string
}

type Paths struct {
	CertFile string
	KeyFile  string
}

var resolveMu sync.Mutex

// Resolve validates custom files, creates or reuses a persistent self-signed
// pair, or invokes acme.sh for HTTP/DNS issuance. ACME certificates are reused
// while more than 30 days remain. Call Resolve again to check renewal.
// Only the HTTP/DNS modes perform network operations, through acme.sh.
func Resolve(ctx context.Context, opts Options) (Paths, error) {
	if err := ctx.Err(); err != nil {
		return Paths{}, err
	}
	if opts.CertFile != "" || opts.KeyFile != "" {
		if opts.CertFile == "" || opts.KeyFile == "" {
			return Paths{}, errors.New("cert_file and key_file must both be set")
		}
		paths := Paths{opts.CertFile, opts.KeyFile}
		_, err := validatePair(paths, opts.Domain, time.Now())
		return paths, err
	}
	mode := opts.Mode
	if mode == "" {
		mode = "http"
	}
	if mode != "self" && mode != "http" && mode != "dns" {
		return Paths{}, fmt.Errorf("unsupported cert_mode %q", mode)
	}
	domain, err := validDomain(opts.Domain, mode)
	if err != nil {
		return Paths{}, err
	}
	opts.Domain = domain
	if opts.StateDir == "" {
		return Paths{}, errors.New("certificate StateDir must be set")
	}
	opts.StateDir, err = filepath.Abs(opts.StateDir)
	if err != nil {
		return Paths{}, err
	}
	keyLength := opts.KeyLength
	if keyLength == "" {
		keyLength = "2048" // The supplied soga documentation defaults to RSA.
	}
	switch keyLength {
	case "2048", "3072", "4096", "8192", "ec-256", "ec-384", "ec-521":
	default:
		return Paths{}, fmt.Errorf("unsupported cert_key_length %q", keyLength)
	}
	opts.KeyLength = keyLength
	sum := sha256.Sum256([]byte(mode + "\x00" + domain + "\x00" + keyLength))
	dir := filepath.Join(opts.StateDir, mode, hex.EncodeToString(sum[:16]))
	paths := Paths{filepath.Join(dir, "fullchain.pem"), filepath.Join(dir, "key.pem")}

	// Serialize writes and ACME account updates within this process.
	resolveMu.Lock()
	defer resolveMu.Unlock()
	if err := ctx.Err(); err != nil {
		return Paths{}, err
	}
	if mode != "self" {
		return resolveACME(ctx, opts, mode, paths)
	}
	if leaf, err := validatePair(paths, domain, time.Now()); err == nil &&
		time.Until(leaf.NotAfter) > 24*time.Hour {
		return paths, nil
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return Paths{}, err
	}
	cert, key, err := selfSigned(domain, keyLength, time.Now())
	if err != nil {
		return Paths{}, err
	}
	if err := writeFileAtomic(paths.KeyFile, key, 0600); err != nil {
		return Paths{}, err
	}
	if err := writeFileAtomic(paths.CertFile, cert, 0644); err != nil {
		return Paths{}, err
	}
	_, err = validatePair(paths, domain, time.Now())
	return paths, err
}

func validDomain(domain, mode string) (string, error) {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	if domain == "" {
		return "", errors.New("cert_domain is required")
	}
	if ip := net.ParseIP(domain); ip != nil {
		if mode != "self" {
			return "", errors.New("HTTP/DNS ACME modes require a DNS domain; IP issuance is not configured")
		}
		return ip.String(), nil
	}
	name := domain
	if strings.HasPrefix(name, "*.") {
		if mode == "http" {
			return "", errors.New("wildcard certificates require DNS validation")
		}
		name = name[2:]
	}
	if len(name) > 253 {
		return "", errors.New("cert_domain is too long")
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", errors.New("cert_domain has an invalid DNS label")
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return "", errors.New("cert_domain must be an ASCII DNS name (use punycode for IDNs)")
			}
		}
	}
	return domain, nil
}

func validatePair(paths Paths, domain string, now time.Time) (*x509.Certificate, error) {
	pair, err := tls.LoadX509KeyPair(paths.CertFile, paths.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("load certificate pair: %w", err)
	}
	if len(pair.Certificate) == 0 {
		return nil, errors.New("empty certificate chain")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, err
	}
	if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return nil, errors.New("certificate is not currently valid")
	}
	if domain != "" {
		hostname := domain
		if strings.HasPrefix(hostname, "*.") {
			hostname = "certificate-check." + hostname[2:]
		}
		if err := leaf.VerifyHostname(hostname); err != nil {
			return nil, fmt.Errorf("certificate domain mismatch: %w", err)
		}
	}
	return leaf, nil
}

func selfSigned(domain, keyLength string, now time.Time) ([]byte, []byte, error) {
	var key crypto.Signer
	var err error
	switch keyLength {
	case "ec-256":
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "ec-384":
		key, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "ec-521":
		key, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	default:
		bits := map[string]int{"2048": 2048, "3072": 3072, "4096": 4096, "8192": 8192}[keyLength]
		key, err = rsa.GenerateKey(rand.Reader, bits)
	}
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: domain},
		NotBefore: now.Add(-5 * time.Minute), NotAfter: now.AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if _, ok := key.(*rsa.PrivateKey); ok {
		template.KeyUsage |= x509.KeyUsageKeyEncipherment
	}
	if ip := net.ParseIP(domain); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{domain}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		return nil, nil, err
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}), nil
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".cert-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if err = f.Chmod(mode); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(name, path)
}
