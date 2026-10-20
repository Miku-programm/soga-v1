package certificates

import (
	"bytes"
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const BundledACMEVersion = "3.1.6"

// Upstream source and license are retained verbatim in bundled/.
//
//go:embed bundled/acme.sh bundled/dnsapi/*.sh bundled/LICENSE.md bundled/SOURCE.json
var bundled embed.FS

var providerPattern = regexp.MustCompile(`^dns_[A-Za-z0-9_]+$`)
var variablePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
var shellIdentifier = regexp.MustCompile(`[A-Za-z_][A-Za-z0-9_]*`)

// SupportedDNSProviders reports actual scripts shipped in the pinned bundle.
func SupportedDNSProviders() []string {
	entries, _ := bundled.ReadDir("bundled/dnsapi")
	out := make([]string, 0, len(entries))
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".sh") {
			out = append(out, strings.TrimSuffix(entry.Name(), ".sh"))
		}
	}
	sort.Strings(out)
	return out
}

func resolveACME(ctx context.Context, opts Options, mode string, paths Paths) (Paths, error) {
	var script []byte
	if mode == "dns" {
		if !providerPattern.MatchString(opts.DNSProvider) {
			return Paths{}, errors.New("dns_provider must name an acme.sh dns_* provider")
		}
		var err error
		if script, err = bundled.ReadFile("bundled/dnsapi/" + opts.DNSProvider + ".sh"); err != nil {
			return Paths{}, fmt.Errorf("DNS provider %q is absent from bundled acme.sh %s", opts.DNSProvider, BundledACMEVersion)
		}
	}
	env, err := acmeEnvironment(providerVariables(opts.Variables, script))
	if err != nil {
		return Paths{}, err
	}
	if leaf, err := validatePair(paths, opts.Domain, time.Now()); err == nil &&
		time.Until(leaf.NotAfter) > 30*24*time.Hour {
		return paths, nil
	}
	// The pinned upstream client explicitly rejects spaces in --home.
	if strings.ContainsAny(opts.StateDir, " \t\r\n") {
		return Paths{}, errors.New("acme.sh requires a StateDir without whitespace")
	}
	home, err := installBundle(opts.StateDir)
	if err != nil {
		return Paths{}, err
	}
	executable := opts.ACMEExecutable
	if executable == "" {
		executable = filepath.Join(home, "acme.sh")
	}
	executable, err = exec.LookPath(executable)
	if err != nil {
		return Paths{}, fmt.Errorf("find ACME executable: %w", err)
	}
	configHome := filepath.Join(opts.StateDir, "acme-config")
	certHome := filepath.Join(opts.StateDir, "acme-certs")
	for _, dir := range []string{configHome, certHome, filepath.Dir(paths.CertFile)} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return Paths{}, err
		}
	}
	base := []string{"--home", home, "--config-home", configHome, "--cert-home", certHome}
	issue := append(append([]string{}, base...), "--issue", "--server", "letsencrypt",
		"--domain", opts.Domain, "--keylength", opts.KeyLength)
	if mode == "http" {
		issue = append(issue, "--standalone")
	} else {
		issue = append(issue, "--dns", opts.DNSProvider)
	}
	if err := runACME(ctx, executable, issue, env, opts.Variables, true); err != nil {
		return Paths{}, err
	}
	// The upstream README directs consumers to --install-cert rather than
	// depending on its internal certificate storage filenames.
	install := append(append([]string{}, base...), "--install-cert", "--domain", opts.Domain,
		"--key-file", paths.KeyFile, "--fullchain-file", paths.CertFile)
	if strings.HasPrefix(opts.KeyLength, "ec-") {
		install = append(install, "--ecc")
	}
	if err := runACME(ctx, executable, install, env, opts.Variables, false); err != nil {
		return Paths{}, err
	}
	if err := os.Chmod(paths.KeyFile, 0600); err != nil {
		return Paths{}, fmt.Errorf("ACME key output: %w", err)
	}
	if _, err := validatePair(paths, opts.Domain, time.Now()); err != nil {
		return Paths{}, fmt.Errorf("ACME did not install a valid certificate pair: %w", err)
	}
	return paths, nil
}

// providerVariables restores the spelling acme.sh expects. The configuration
// pipeline lowercases keys, so DNS_CF_Key arrives as dns_cf_key, while the
// provider scripts read case-sensitive names such as CF_Key. Names are matched
// against identifiers in the pinned provider script; other names only get the
// DNS_ prefix normalized. Keys without the prefix pass through unchanged and
// are rejected by acmeEnvironment.
func providerVariables(variables map[string]string, script []byte) map[string]string {
	spelling := map[string]string{}
	for _, name := range shellIdentifier.FindAllString(string(script), -1) {
		lower := strings.ToLower(name)
		if previous, seen := spelling[lower]; seen && previous != name {
			name = "" // Ambiguous spelling; keep the configured one.
		}
		spelling[lower] = name
	}
	keys := make([]string, 0, len(variables))
	for key := range variables {
		keys = append(keys, key)
	}
	sort.Strings(keys) // Exact upper-case DNS_ spellings win over lowered duplicates.
	result := make(map[string]string, len(variables))
	for _, key := range keys {
		value := variables[key]
		if len(key) > len("DNS_") && strings.EqualFold(key[:len("DNS_")], "DNS_") {
			name := key[len("DNS_"):]
			if spelled := spelling[strings.ToLower(name)]; spelled != "" {
				name = spelled
			}
			key = "DNS_" + name
		}
		if _, exists := result[key]; !exists {
			result[key] = value
		}
	}
	return result
}

func acmeEnvironment(variables map[string]string) ([]string, error) {
	// Do not pass arbitrary application environment variables to a shell script.
	// PATH uses conventional system tool directories; credentials arrive only
	// through documented DNS_* entries. No sh -c or configuration eval is used.
	env := []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C"}
	if home, ok := os.LookupEnv("HOME"); ok {
		env = append(env, "HOME="+home)
	}
	denied := map[string]bool{
		"PATH": true, "HOME": true, "SHELL": true, "ENV": true, "BASH_ENV": true,
		"IFS": true, "CDPATH": true, "LD_PRELOAD": true, "LD_LIBRARY_PATH": true,
		"OPENSSL_CONF": true, "OPENSSL_MODULES": true, "DYLD_INSERT_LIBRARIES": true,
		"ZDOTDIR": true, "SHELLOPTS": true, "BASHOPTS": true, "GLOBIGNORE": true,
	}
	keys := make([]string, 0, len(variables))
	for key := range variables {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if !strings.HasPrefix(key, "DNS_") {
			return nil, fmt.Errorf("certificate variable %q must use the documented DNS_ prefix", key)
		}
		name := strings.TrimPrefix(key, "DNS_")
		if !variablePattern.MatchString(name) || denied[name] || strings.HasPrefix(name, "BASH_FUNC_") ||
			strings.HasPrefix(name, "ACME_") || strings.HasPrefix(name, "LE_") ||
			strings.HasPrefix(name, "_") || strings.ContainsRune(variables[key], 0) {
			return nil, fmt.Errorf("invalid DNS credential variable name %q", key)
		}
		env = append(env, name+"="+variables[key])
	}
	return env, nil
}

func installBundle(stateDir string) (string, error) {
	dir := filepath.Join(stateDir, "tools", "acme.sh-"+BundledACMEVersion)
	err := fs.WalkDir(bundled, "bundled", func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		rel := strings.TrimPrefix(path, "bundled/")
		target := filepath.Join(dir, filepath.FromSlash(rel))
		data, err := bundled.ReadFile(path)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
			return err
		}
		mode := os.FileMode(0644)
		if rel == "acme.sh" {
			mode = 0755
		}
		if previous, err := os.ReadFile(target); err == nil && bytes.Equal(previous, data) {
			return os.Chmod(target, mode)
		}
		return writeFileAtomic(target, data, mode)
	})
	return dir, err
}

type limitedOutput struct{ data []byte }

func (b *limitedOutput) Write(p []byte) (int, error) {
	n := len(p)
	if remaining := 16*1024 - len(b.data); remaining > 0 {
		if len(p) > remaining {
			p = p[:remaining]
		}
		b.data = append(b.data, p...)
	}
	return n, nil
}

func runACME(ctx context.Context, executable string, args, env []string, secrets map[string]string, allowUnchanged bool) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable, args...)
	configureProcessCancellation(cmd)
	cmd.Env = env
	var output limitedOutput
	cmd.Stdout, cmd.Stderr = &output, &output
	err := cmd.Run()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err == nil {
		return nil
	}
	var exit *exec.ExitError
	// acme.sh uses 2 for a certificate that is not due for renewal. The
	// subsequent install and certificate validation must still succeed.
	if allowUnchanged && errors.As(err, &exit) && exit.ExitCode() == 2 {
		return nil
	}
	message := string(output.data)
	for _, value := range secrets {
		if value != "" {
			message = strings.ReplaceAll(message, value, "[redacted]")
		}
	}
	return fmt.Errorf("acme.sh command failed: %w: %s", err, strings.TrimSpace(message))
}
