package redislimit

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"sync"
	"testing"
	"time"
)

type realRedis struct {
	command *exec.Cmd
	address string
	log     *os.File
	once    sync.Once
}

func startRedis(t *testing.T, address string) *realRedis {
	t.Helper()
	exe := os.Getenv("REDIS_SERVER")
	if exe == "" {
		t.Skip("REDIS_SERVER must name a real Redis 8+ executable for integration tests")
	}
	if address == "" {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		address = l.Addr().String()
		l.Close()
	}
	_, port, _ := net.SplitHostPort(address)
	f, err := os.CreateTemp(t.TempDir(), "redis-*.log")
	if err != nil {
		t.Fatal(err)
	}
	r := &realRedis{address: address, log: f}
	r.command = exec.Command(exe, "--bind", "127.0.0.1", "--port", port, "--save", "", "--appendonly", "no", "--requirepass", "test-password", "--protected-mode", "yes")
	r.command.Stdout = f
	r.command.Stderr = f
	if err = r.command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.stop)
	eventually(t, 3*time.Second, func() bool {
		c, err := net.DialTimeout("tcp", address, 50*time.Millisecond)
		if err != nil {
			return false
		}
		c.Close()
		return true
	})
	return r
}
func (r *realRedis) stop() {
	r.once.Do(func() { _ = r.command.Process.Kill(); _ = r.command.Wait(); r.log.Close() })
}
func testOptions(addr string) Options {
	return Options{Addr: addr, Password: "test-password", Expiry: 180 * time.Millisecond, LeaseTTL: 120 * time.Millisecond, Timeout: 500 * time.Millisecond}
}
func manager(t *testing.T, o Options) *Manager {
	t.Helper()
	m, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { m.Close() })
	return m
}
func eventually(t *testing.T, d time.Duration, f func() bool) {
	t.Helper()
	end := time.Now().Add(d)
	for time.Now().Before(end) {
		if f() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition did not become true before deadline")
}
func acquire(t *testing.T, m *Manager, r Request) func() {
	t.Helper()
	release, err := m.Acquire(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	return release
}
func denied(t *testing.T, m *Manager, r Request, kind string) {
	t.Helper()
	release, err := m.Acquire(context.Background(), r)
	if release != nil {
		release()
	}
	var quota *QuotaError
	if !errors.As(err, &quota) || quota.Kind != kind {
		t.Fatalf("expected %s quota denial, got %v", kind, err)
	}
}

func TestAtomicCrossNodeAdmission(t *testing.T) {
	r := startRedis(t, "")
	nodes := []*Manager{manager(t, testOptions(r.address)), manager(t, testOptions(r.address)), manager(t, testOptions(r.address))}
	var wg sync.WaitGroup
	var mu sync.Mutex
	var accepted []func()
	for i := 0; i < 48; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			release, err := nodes[i%len(nodes)].Acquire(context.Background(), Request{UserID: 7, IP: fmt.Sprintf("192.0.2.%d", i), DeviceID: fmt.Sprintf("cid:%d", i), IPLimit: 3, DeviceLimit: 2})
			if err == nil {
				mu.Lock()
				accepted = append(accepted, release)
				mu.Unlock()
			} else if !errors.Is(err, ErrQuotaExceeded) {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	if len(accepted) != 2 {
		t.Fatalf("accepted %d distinct identities; device quota is 2", len(accepted))
	}
	for _, release := range accepted {
		release()
	}
}

func TestSharedIdentityRetentionAndRenewal(t *testing.T) {
	r := startRedis(t, "")
	a := manager(t, testOptions(r.address))
	b := manager(t, testOptions(r.address))
	one := Request{UserID: 1, IP: "192.0.2.1", IPLimit: 1}
	two := one
	two.IP = "192.0.2.2"
	releaseA := acquire(t, a, one)
	releaseB := acquire(t, b, one)
	// More than the lease + grace passes; active connections still count.
	time.Sleep(450 * time.Millisecond)
	denied(t, b, two, "IP")
	releaseA()
	releaseA()
	time.Sleep(230 * time.Millisecond)
	denied(t, a, two, "IP")
	releaseB()
	denied(t, a, two, "IP")
	time.Sleep(230 * time.Millisecond)
	acquire(t, a, two)()
}

func TestDualQuotaChecksDoNotPartiallyReserve(t *testing.T) {
	r := startRedis(t, "")
	m := manager(t, testOptions(r.address))
	r1 := Request{UserID: 2, IP: "192.0.2.1", DeviceID: "cid:1", IPLimit: 2, DeviceLimit: 1}
	defer acquire(t, m, r1)()
	r2 := r1
	r2.IP = "192.0.2.2"
	r2.DeviceID = "cid:2"
	denied(t, m, r2, "device")
	// The rejected request must not consume its new IP slot.
	r3 := r1
	r3.IP = "192.0.2.3"
	defer acquire(t, m, r3)()
	denied(t, m, r2, "IP")
}

func TestContextCancellationAndDBIsolation(t *testing.T) {
	r := startRedis(t, "")
	o := testOptions(r.address)
	a := manager(t, o)
	o.DB = 1
	b := manager(t, o)
	ctx, cancel := context.WithCancel(context.Background())
	request := Request{UserID: 3, IP: "192.0.2.1", IPLimit: 1}
	release, err := a.Acquire(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	other := request
	other.IP = "192.0.2.2"
	defer acquire(t, b, other)()
	denied(t, a, other, "IP")
	cancel()
	time.Sleep(250 * time.Millisecond)
	acquire(t, a, other)()
}

func TestOutageFallbackRestoresLiveLeases(t *testing.T) {
	r := startRedis(t, "")
	o := testOptions(r.address)
	o.Timeout = 60 * time.Millisecond
	a := manager(t, o)
	b := manager(t, o)
	req := Request{UserID: 4, IP: "192.0.2.1", IPLimit: 1}
	original := acquire(t, a, req)
	r.stop()
	fallback, err := b.Acquire(context.Background(), req)
	if err == nil || errors.Is(err, ErrQuotaExceeded) || fallback == nil {
		t.Fatalf("expected fallback release and availability error, got %v", err)
	}
	original()
	restarted := startRedis(t, r.address)
	_ = restarted
	other := req
	other.IP = "192.0.2.2"
	eventually(t, 2*time.Second, func() bool {
		// Inspect actual Redis state rather than admitting a competing identity.
		v, err := b.client.get(context.Background())
		if err != nil {
			return false
		}
		value, err := b.client.command(context.Background(), v, "ZSCORE", oNamespace(o)+":{4}:ip", hash(req.IP))
		b.client.put(v)
		return err == nil && value != nil
	})
	denied(t, a, other, "IP")
	fallback()
	time.Sleep(250 * time.Millisecond)
	acquire(t, a, other)()
}
func oNamespace(o Options) string {
	if o.Namespace == "" {
		return "soga:limits:v1"
	}
	return o.Namespace
}

func TestScriptCacheFlushAndConcurrentClose(t *testing.T) {
	r := startRedis(t, "")
	m := manager(t, testOptions(r.address))
	req := Request{UserID: 5, IP: "192.0.2.1", IPLimit: 1}
	release := acquire(t, m, req)
	v, err := m.client.get(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	_, err = m.client.command(context.Background(), v, "SCRIPT", "FLUSH")
	m.client.put(v)
	if err != nil {
		t.Fatal(err)
	}
	second := acquire(t, m, req)
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); release(); second(); m.Close() }()
	}
	wg.Wait()
}

func TestCrashedNodeLeaseExpiresAndMissingCIDIsNotInvented(t *testing.T) {
	r := startRedis(t, "")
	a := manager(t, testOptions(r.address))
	b := manager(t, testOptions(r.address))
	req := Request{UserID: 6, IP: "192.0.2.1", IPLimit: 1, DeviceLimit: 1}
	release := acquire(t, a, req)
	defer release()
	// Stop only renewal, modelling a node crash without a successful release.
	a.cancel()
	<-a.done
	other := req
	other.IP = "192.0.2.2"
	denied(t, b, other, "IP")
	time.Sleep(350 * time.Millisecond)
	acquire(t, b, other)()
	// Empty CID must not consume a shared synthetic device slot.
	req.UserID = 7
	req.IPLimit = 0
	acquire(t, b, req)()
	req.IP = "192.0.2.3"
	acquire(t, b, req)()
}

func TestRealRedisViaVerifiedTLSAndAuthentication(t *testing.T) {
	r := startRedis(t, "")
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(key)
	cert, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	if err != nil {
		t.Fatal(err)
	}
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			from, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer from.Close()
				to, err := net.Dial("tcp", r.address)
				if err != nil {
					return
				}
				defer to.Close()
				go func() { io.Copy(to, from); to.Close() }()
				io.Copy(from, to)
			}()
		}
	}()
	roots := x509.NewCertPool()
	roots.AddCert(mustCertificate(t, der))
	o := testOptions(listener.Addr().String())
	o.TLS = true
	o.TLSConfig = &tls.Config{RootCAs: roots}
	m := manager(t, o)
	acquire(t, m, Request{UserID: 1, IP: "192.0.2.1", IPLimit: 1})()
	o.TLSConfig = nil
	untrusted := manager(t, o)
	release, err := untrusted.Acquire(context.Background(), Request{UserID: 2, IP: "192.0.2.1", IPLimit: 1})
	if release != nil {
		release()
	}
	if err == nil {
		t.Fatal("untrusted certificate accepted")
	}
	o = testOptions(r.address)
	o.Password = "wrong"
	wrong := manager(t, o)
	release, err = wrong.Acquire(context.Background(), Request{UserID: 2, IP: "192.0.2.1", IPLimit: 1})
	if release != nil {
		release()
	}
	if err == nil {
		t.Fatal("wrong Redis password accepted")
	}
}
func mustCertificate(t *testing.T, der []byte) *x509.Certificate {
	t.Helper()
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestValidation(t *testing.T) {
	for _, o := range []Options{{}, {Addr: "localhost:6379", DB: -1}, {Addr: "localhost:6379", Expiry: -1}, {Addr: "localhost:6379", Namespace: "bad{slot}"}} {
		if m, err := New(o); err == nil {
			m.Close()
			t.Fatalf("invalid options accepted: %+v", o)
		}
	}
}
