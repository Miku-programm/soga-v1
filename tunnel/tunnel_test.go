package tunnel

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xtaci/smux"
)

func testTLS(t *testing.T) (*tls.Config, *tls.Config) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: private}))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	parsed, _ := x509.ParseCertificate(der)
	roots.AddCert(parsed)
	return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}, &tls.Config{RootCAs: roots, ServerName: "localhost", MinVersion: tls.VersionTLS12}
}

func echoListener(t *testing.T, cfg Config) *Listener {
	t.Helper()
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l, err := WrapListener(raw, cfg)
	if err != nil {
		_ = raw.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				if c.(*Conn).Mode == TCP {
					_, _ = io.Copy(c, c)
					return
				}
				b := make([]byte, 65535)
				for {
					n, err := c.Read(b)
					if err != nil {
						return
					}
					if _, err = c.Write(b[:n]); err != nil {
						return
					}
				}
			}()
		}
	}()
	return l
}

func TestTunnelTransportCipherModes(t *testing.T) {
	serverTLS, clientTLS := testTLS(t)
	for _, transport := range []string{"tcp", "tls", "ws", "ws-tls"} {
		for _, mux := range []bool{false, true} {
			for _, method := range []string{"aes-128-gcm", "aes-192-gcm", "aes-256-gcm", "chacha20-ietf-poly1305"} {
				for _, mode := range []byte{TCP, UDP} {
					t.Run(fmt.Sprintf("%s/mux=%t/%s/mode=%d", transport, mux, method, mode), func(t *testing.T) {
						cfg := Config{Type: transport, Method: method, Password: "static-proof-test", WSPath: "/tunnel", Mux: mux, TLSConfig: serverTLS}
						l := echoListener(t, cfg)
						cfg.TLSConfig = clientTLS
						ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
						defer cancel()
						client, err := DialClient(ctx, l.Addr().String(), cfg)
						if err != nil {
							t.Fatal(err)
						}
						defer client.Close()
						conn, err := client.Open(mode)
						if err != nil {
							t.Fatal(err)
						}
						defer conn.Close()
						_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
						for _, n := range []int{1, 512, 32768, 65535} {
							payload := bytes.Repeat([]byte{byte(n % 251)}, n)
							errch := make(chan error, 1)
							go func() { _, e := conn.Write(payload); errch <- e }()
							got := make([]byte, n)
							if mode == TCP {
								_, err = io.ReadFull(conn, got)
							} else {
								var read int
								read, err = conn.Read(got)
								if read != n {
									t.Fatalf("datagram %d != %d", read, n)
								}
							}
							if err != nil {
								t.Fatal(err)
							}
							if err = <-errch; err != nil {
								t.Fatal(err)
							}
							if !bytes.Equal(got, payload) {
								t.Fatal("payload mismatch")
							}
						}
					})
				}
			}
		}
	}
}

func TestTunnelConcurrentMultiplexedStreams(t *testing.T) {
	cfg := Config{Type: "tcp", Method: "aes-256-gcm", Password: "mux-test", Mux: true}
	l := echoListener(t, cfg)
	cl, err := DialClient(context.Background(), l.Addr().String(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	var wg sync.WaitGroup
	errs := make(chan error, 12)
	for i := range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := cl.Open(byte(i%2 + 1))
			if err != nil {
				errs <- err
				return
			}
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(10 * time.Second))
			p := bytes.Repeat([]byte{byte(i)}, 32768)
			if _, err = c.Write(p); err != nil {
				errs <- err
				return
			}
			out := make([]byte, len(p))
			if c.Mode == TCP {
				_, err = io.ReadFull(c, out)
			} else {
				_, err = c.Read(out)
			}
			if err != nil {
				errs <- err
				return
			}
			if !bytes.Equal(p, out) {
				errs <- fmt.Errorf("stream %d payload mismatch", i)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

func TestTunnelNegotiatesSMuxVersion2(t *testing.T) {
	cfg := Config{Type: "tcp", Method: "aes-256-gcm", Password: "mux-v2-test", Mux: true}
	l := echoListener(t, cfg)
	raw, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
	k, err := makeKeys(cfg.Method, cfg.Password)
	if err != nil {
		t.Fatal(err)
	}
	muxOptions := muxConfig()
	muxOptions.Version = 2
	session, err := smux.Client(&wireConn{Conn: raw, keys: k}, muxOptions)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	stream, err := session.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	conn, err := clientSession(stream, k, TCP)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	payload := bytes.Repeat([]byte("v2 window and flow control"), 10000)
	go func() { _, _ = conn.Write(payload) }()
	got := make([]byte, len(payload))
	if _, err = io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("smux2 payload mismatch")
	}
}

func TestTunnelIndependentPythonPeer(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("Python unavailable for independent cryptographic peer")
	}
	for _, method := range []string{"aes-128-gcm", "aes-192-gcm", "aes-256-gcm", "chacha20-ietf-poly1305"} {
		for _, mode := range []byte{TCP, UDP} {
			t.Run(fmt.Sprintf("%s/%d", method, mode), func(t *testing.T) {
				cfg := Config{Type: "tcp", Method: method, Password: "independent-peer"}
				l := echoListener(t, cfg)
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				defer cancel()
				out, err := exec.CommandContext(ctx, python, "testdata/peer.py", l.Addr().String(), method, cfg.Password, fmt.Sprint(mode)).CombinedOutput()
				if err != nil {
					t.Fatalf("independent peer: %v: %s", err, out)
				}
				if !strings.Contains(string(out), "PASS") {
					t.Fatalf("no success: %s", out)
				}
			})
		}
	}
}

func TestTunnelRejectWrongPasswordAndTruncatedFrame(t *testing.T) {
	cfg := Config{Type: "tcp", Method: "aes-256-gcm", Password: "correct"}
	l := echoListener(t, cfg)
	wrong := cfg
	wrong.Password = "wrong"
	client, err := DialClient(context.Background(), l.Addr().String(), wrong)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	c, err := client.Open(TCP)
	if err == nil {
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(time.Second))
		_, err = c.Read(make([]byte, 1))
	}
	if err == nil {
		t.Fatal("wrong password accepted")
	}
	raw, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_, _ = raw.Write([]byte{1, 2, 3})
	_ = raw.Close()
	// A malformed connection must not poison future accepts.
	valid, err := DialClient(context.Background(), l.Addr().String(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer valid.Close()
	good, err := valid.Open(TCP)
	if err != nil {
		t.Fatal(err)
	}
	defer good.Close()
	_ = good.SetDeadline(time.Now().Add(time.Second))
	_, err = good.Write([]byte("ok"))
	if err != nil {
		t.Fatal(err)
	}
	p := make([]byte, 2)
	_, err = io.ReadFull(good, p)
	if err != nil || string(p) != "ok" {
		t.Fatalf("%q %v", p, err)
	}
}
