package simpleobfs

import (
	"bytes"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	client "github.com/sagernet/sing-box/transport/simple-obfs"
)

// Independent sing-box clients exercise large, fragmented bidirectional data
// against our server, including the first-payload-in-ClientHello convention.
func TestOfficialClients(t *testing.T) {
	for _, protocol := range []string{"http", "tls"} {
		t.Run(protocol, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			done := make(chan error, 1)
			payload := bytes.Repeat([]byte("ciphertext-test\x00\xff"), 16000)
			go func() {
				raw, e := ln.Accept()
				if e != nil {
					done <- e
					return
				}
				defer raw.Close()
				raw.SetDeadline(time.Now().Add(5 * time.Second))
				s, meta, e := Server(raw, Options{Protocol: protocol, Mode: "strict", Host: "example.com", Path: "/"})
				if e != nil {
					done <- e
					return
				}
				if !strings.HasPrefix(meta.Host, "example.com") {
					done <- io.ErrUnexpectedEOF
					return
				}
				b := make([]byte, len(payload))
				if _, e = io.ReadFull(s, b); e != nil {
					done <- e
					return
				}
				if !bytes.Equal(b, payload) {
					done <- io.ErrUnexpectedEOF
					return
				}
				_, e = writeAll(s, b)
				done <- e
			}()
			raw, err := net.Dial("tcp", ln.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer raw.Close()
			raw.SetDeadline(time.Now().Add(5 * time.Second))
			var c net.Conn
			if protocol == "http" {
				c = client.NewHTTPObfs(raw, "example.com", "8080")
			} else {
				c = client.NewTLSObfs(raw, "example.com")
			}
			for start := 0; start < len(payload); start += 1379 {
				end := min(start+1379, len(payload))
				if _, err = c.Write(payload[start:end]); err != nil {
					t.Fatal(err)
				}
			}
			got := make([]byte, len(payload))
			if _, err = io.ReadFull(c, got); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, payload) {
				t.Fatal("payload changed")
			}
			if err = <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestHTTPModesAndMalformed(t *testing.T) {
	for _, tc := range []struct {
		mode, host, path string
		want             bool
	}{
		{"relaxed", "wrong", "/wrong", true}, {"strict", "site.test", "/ok", true},
		{"strict", "wrong", "/ok", false}, {"strict", "site.test", "/wrong", false},
		{"strict_host", "site.test", "/wrong", true}, {"strict_path", "wrong", "/ok", true},
	} {
		t.Run(tc.mode+tc.host+tc.path, func(t *testing.T) {
			a, b := net.Pipe()
			defer a.Close()
			defer b.Close()
			go func() {
				b.Write([]byte("GET /ok HTTP/1.1\r\nHost: site.test:80\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\nDATA"))
			}()
			c, _, err := Server(a, Options{Protocol: "http", Mode: tc.mode, Host: tc.host, Path: tc.path})
			if (err == nil) != tc.want {
				t.Fatalf("error=%v want success=%v", err, tc.want)
			}
			if err == nil {
				data := make([]byte, 4)
				if _, err = io.ReadFull(c, data); err != nil || string(data) != "DATA" {
					t.Fatalf("%q %v", data, err)
				}
			}
		})
	}
	for n := 0; n < 100; n++ {
		if _, err := ParseClientHelloSNI(make([]byte, n)); err == nil {
			t.Fatalf("accepted malformed size %d", n)
		}
	}
}
