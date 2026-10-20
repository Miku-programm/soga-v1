package tls

import (
	"bytes"
	gotls "crypto/tls"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/protocol/tls/cert"
)

func TestCertificateReloadPublishesImmutableSnapshots(t *testing.T) {
	original, _ := cert.MustGenerate(nil, cert.CommonName("old.example"))
	replacement, _ := cert.MustGenerate(nil, cert.CommonName("new.example"))
	oldCert := ParseCertificate(original)
	newCert := ParseCertificate(replacement)
	dir := t.TempDir()
	oldCert.CertificatePath = filepath.Join(dir, "cert.pem")
	oldCert.KeyPath = filepath.Join(dir, "key.pem")
	if e := os.WriteFile(oldCert.CertificatePath, newCert.Certificate, 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(oldCert.KeyPath, newCert.Key, 0600); e != nil {
		t.Fatal(e)
	}
	beforeCert, beforeKey := bytes.Clone(oldCert.Certificate), bytes.Clone(oldCert.Key)
	c := (&Config{Certificate: []*Certificate{oldCert}}).GetTLSConfig()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 1000; j++ {
				got, e := c.GetCertificate(&gotls.ClientHelloInfo{})
				if e != nil {
					t.Error(e)
					return
				}
				if got.Leaf.Subject.CommonName != "old.example" && got.Leaf.Subject.CommonName != "new.example" {
					t.Error("corrupted certificate")
					return
				}
			}
		}()
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		got, e := c.GetCertificate(&gotls.ClientHelloInfo{})
		if e != nil {
			t.Fatal(e)
		}
		if got.Leaf.Subject.CommonName == "new.example" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("reload was not published")
		}
		time.Sleep(time.Millisecond)
	}
	wg.Wait()
	if !bytes.Equal(beforeCert, oldCert.Certificate) || !bytes.Equal(beforeKey, oldCert.Key) {
		t.Fatal("reload mutated shared source Config")
	}
}
