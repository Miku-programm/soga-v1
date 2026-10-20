package certificates

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestSelfSignedPersistenceAndTLS(t *testing.T) {
	for _, keyLength := range []string{"", "ec-256", "ec-384"} {
		t.Run("key="+keyLength, func(t *testing.T) {
			opts := Options{Mode: "self", Domain: "127.0.0.1", StateDir: t.TempDir(), KeyLength: keyLength}
			first, err := Resolve(context.Background(), opts)
			if err != nil {
				t.Fatal(err)
			}
			before, _ := os.ReadFile(first.KeyFile)
			second, err := Resolve(context.Background(), opts)
			if err != nil || first != second {
				t.Fatalf("reuse: %v, %v", second, err)
			}
			after, _ := os.ReadFile(first.KeyFile)
			if !reflect.DeepEqual(before, after) {
				t.Fatal("reused certificate changed its private key")
			}
			pair, err := tls.LoadX509KeyPair(first.CertFile, first.KeyFile)
			if err != nil {
				t.Fatal(err)
			}
			switch pair.PrivateKey.(type) {
			case *rsa.PrivateKey:
				if keyLength != "" {
					t.Fatal("ECC request returned RSA")
				}
			case *ecdsa.PrivateKey:
				if keyLength == "" {
					t.Fatal("default must be RSA")
				}
			default:
				t.Fatal("unexpected private key")
			}
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNoContent)
			}))
			server.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}
			server.StartTLS()
			defer server.Close()
			certPEM, _ := os.ReadFile(first.CertFile)
			roots := x509.NewCertPool()
			if !roots.AppendCertsFromPEM(certPEM) {
				t.Fatal("parse self certificate")
			}
			client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
				RootCAs: roots, MinVersion: tls.VersionTLS12,
			}}, Timeout: 5 * time.Second}
			response, err := client.Get(server.URL)
			if err != nil {
				t.Fatal(err)
			}
			response.Body.Close()
			client.CloseIdleConnections()
			if response.StatusCode != http.StatusNoContent {
				t.Fatal(response.Status)
			}
			custom, err := Resolve(context.Background(), Options{CertFile: first.CertFile, KeyFile: first.KeyFile, Domain: opts.Domain})
			if err != nil || custom != first {
				t.Fatalf("custom certificate: %v", err)
			}
		})
	}
}

func TestCustomPairFailures(t *testing.T) {
	ctx := context.Background()
	first, err := Resolve(ctx, Options{Mode: "self", Domain: "a.example", StateDir: t.TempDir(), KeyLength: "ec-256"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := Resolve(ctx, Options{Mode: "self", Domain: "b.example", StateDir: t.TempDir(), KeyLength: "ec-256"})
	if err != nil {
		t.Fatal(err)
	}
	for _, opts := range []Options{
		{CertFile: first.CertFile},
		{KeyFile: first.KeyFile},
		{CertFile: first.CertFile, KeyFile: second.KeyFile},
		{CertFile: first.CertFile, KeyFile: first.KeyFile, Domain: "wrong.example"},
	} {
		if _, err := Resolve(ctx, opts); err == nil {
			t.Fatal("expected invalid pair/domain error")
		}
	}
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'" }

func fakeACME(t *testing.T, cert, key []byte, behavior string) (string, string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("acme.sh is a Unix shell client")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "source.pem"), cert, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "source.key"), key, 0600); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\nset -eu\nfixture=" + shellQuote(dir) + `
printf '%s\n' START "$@" >> "$fixture/argv"
printf '%s' "${CF_Key-}" > "$fixture/credential"
printf '%s' "${UNRELATED_PRIVATE_ENV-}" > "$fixture/unrelated"
`
	if behavior == "fail" {
		script += "printf '%s' \"${CF_Key-}\"\nexit 17\n"
	} else if behavior == "missing" {
		script += "exit 0\n"
	} else {
		script += `
install=no
while [ "$#" -gt 0 ]; do
  case "$1" in
    --install-cert) install=yes ;;
    --key-file) shift; keyfile=$1 ;;
    --fullchain-file) shift; certfile=$1 ;;
  esac
  shift
done
if [ "$install" = yes ]; then
  cp "$fixture/source.pem" "$certfile"
  cp "$fixture/source.key" "$keyfile"
fi
`
	}
	path := filepath.Join(dir, "fake-acme")
	if err := os.WriteFile(path, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	return path, dir
}

func TestACMEArgumentsEnvironmentAndInstalledCertificate(t *testing.T) {
	cert, key, err := selfSigned("node.example", "ec-256", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"http", "dns"} {
		t.Run(mode, func(t *testing.T) {
			executable, fixture := fakeACME(t, cert, key, "")
			marker := filepath.Join(t.TempDir(), "should-not-exist")
			secret := "literal ' ; $(touch " + marker + ") `touch " + marker + "`"
			t.Setenv("UNRELATED_PRIVATE_ENV", "must-not-reach-child")
			opts := Options{Mode: mode, Domain: "node.example", KeyLength: "ec-256",
				StateDir: t.TempDir(), ACMEExecutable: executable, DNSProvider: "dns_cf",
				Variables: map[string]string{"DNS_CF_Key": secret}}
			paths, err := Resolve(context.Background(), opts)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := tls.LoadX509KeyPair(paths.CertFile, paths.KeyFile); err != nil {
				t.Fatal(err)
			}
			gotSecret, _ := os.ReadFile(filepath.Join(fixture, "credential"))
			if string(gotSecret) != secret {
				t.Fatal("credential was not passed literally")
			}
			if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("credential text was executed")
			}
			unrelated, _ := os.ReadFile(filepath.Join(fixture, "unrelated"))
			if len(unrelated) != 0 {
				t.Fatal("unrelated environment leaked")
			}
			args, _ := os.ReadFile(filepath.Join(fixture, "argv"))
			for _, required := range []string{"--issue\n", "--server\nletsencrypt\n", "--domain\nnode.example\n",
				"--keylength\nec-256\n", "--install-cert\n", "--ecc\n", "--fullchain-file\n" + paths.CertFile + "\n"} {
				if !strings.Contains(string(args), required) {
					t.Fatalf("missing argument sequence %q in %q", required, args)
				}
			}
			if mode == "http" && !strings.Contains(string(args), "--standalone\n") ||
				mode == "dns" && !strings.Contains(string(args), "--dns\ndns_cf\n") {
				t.Fatal("wrong ACME challenge")
			}
			if _, err := Resolve(context.Background(), opts); err != nil {
				t.Fatal(err)
			}
			after, _ := os.ReadFile(filepath.Join(fixture, "argv"))
			if !reflect.DeepEqual(args, after) {
				t.Fatal("valid cached certificate triggered another issuance")
			}
		})
	}
}

func TestACMEReportsFailureAndRejectsUnsafeConfiguration(t *testing.T) {
	cert, key, _ := selfSigned("node.example", "ec-256", time.Now())
	for _, behavior := range []string{"fail", "missing"} {
		executable, _ := fakeACME(t, cert, key, behavior)
		_, err := Resolve(context.Background(), Options{Mode: "dns", Domain: "node.example",
			StateDir: t.TempDir(), ACMEExecutable: executable, DNSProvider: "dns_cf",
			Variables: map[string]string{"DNS_CF_Key": "super-secret-value"}})
		if err == nil {
			t.Fatalf("%s: falsely reported success", behavior)
		}
		if strings.Contains(err.Error(), "super-secret-value") {
			t.Fatal("error exposed credential")
		}
	}
	for _, key := range []string{"DNS_ENV", "DNS_BASH_ENV", "DNS_PATH", "DNS_LD_PRELOAD", "CF_Key", "DNS_a=b"} {
		if _, err := acmeEnvironment(map[string]string{key: "x"}); err == nil {
			t.Fatalf("accepted %s", key)
		}
	}
	for _, opts := range []Options{
		{Mode: "dns", Domain: "node.example", DNSProvider: "../../bad"},
		{Mode: "dns", Domain: "node.example", DNSProvider: "dns_not_real"},
		{Mode: "http", Domain: "*.example"},
		{Mode: "http", Domain: "node.example; touch /tmp/unsafe"},
		{Mode: "self", Domain: "node.example", KeyLength: "2048 --force"},
	} {
		opts.StateDir = t.TempDir()
		if _, err := Resolve(context.Background(), opts); err == nil {
			t.Fatalf("accepted %#v", opts)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Resolve(ctx, Options{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation: %v", err)
	}
}

func TestACMECancellation(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux process-group cancellation")
	}
	path := filepath.Join(t.TempDir(), "waiting-acme")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nsleep 60\n"), 0700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	started := time.Now()
	err := runACME(ctx, path, nil, []string{"PATH=/usr/bin:/bin"}, nil, false)
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(started) > 3*time.Second {
		t.Fatalf("cancellation was not propagated promptly: %v", err)
	}
}

func TestACMEUsesLoweredConfigurationCredentials(t *testing.T) {
	cert, key, err := selfSigned("node.example", "ec-256", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	executable, fixture := fakeACME(t, cert, key, "")
	// The configuration pipeline lowercases keys; acme.sh still needs CF_Key.
	_, err = Resolve(context.Background(), Options{Mode: "dns", Domain: "node.example", KeyLength: "ec-256",
		StateDir: t.TempDir(), ACMEExecutable: executable, DNSProvider: "dns_cf",
		Variables: map[string]string{"dns_cf_key": "lowered-secret"}})
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(filepath.Join(fixture, "credential")); string(got) != "lowered-secret" {
		t.Fatalf("credential = %q", got)
	}
}

func TestProviderVariablesRestoresScriptSpelling(t *testing.T) {
	script := []byte("CF_Key=\"${CF_Key:-}\"\nCF_Email=\"${CF_Email:-}\"\n")
	got := providerVariables(map[string]string{
		"dns_cf_key": "a", "DNS_CF_Email": "b", "dns_custom_name": "c", "CF_Key": "d",
	}, script)
	want := map[string]string{"DNS_CF_Key": "a", "DNS_CF_Email": "b", "DNS_custom_name": "c", "CF_Key": "d"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("providerVariables = %v, want %v", got, want)
	}
}
