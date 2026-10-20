package proxy

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	quic "github.com/sagernet/quic-go"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/sniff"
	M "github.com/sagernet/sing/common/metadata"
)

func tlsHello(t *testing.T, name string) []byte {
	t.Helper()
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	go tls.Client(a, &tls.Config{ServerName: name}).Handshake()
	header := make([]byte, 5)
	if _, err := io.ReadFull(b, header); err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, int(binary.BigEndian.Uint16(header[3:])))
	if _, err := io.ReadFull(b, payload); err != nil {
		t.Fatal(err)
	}
	return append(header, payload...)
}

func TestInspectionHTTPAndTLSBytePreservation(t *testing.T) {
	target, _ := echoTCP(t)
	for _, protocol := range []string{"http", "tls"} {
		t.Run(protocol, func(t *testing.T) {
			payload := []byte("GET /sniff HTTP/1.1\r\nHost: inspect.example\r\n\r\n")
			if protocol == "tls" {
				payload = tlsHello(t, "inspect.example")
			}
			seen := make(chan Request, 1)
			user := User{ID: 42, UUID: testUUID}
			cfg := Config{Protocol: "vless", Listen: "127.0.0.1", Port: freePort(t, false), Users: []User{user},
				DomainSniff: []string{protocol}, DetectPacketMaxLen: 17, Hook: func(r Request) error { seen <- r; return nil }}
			s, err := Start(context.Background(), cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			if err = roundTripTCP(client(t, cfg, user, nil), target, payload, time.Second); err != nil {
				t.Fatal(err)
			}
			req := <-seen
			if req.SniffedDomain != "inspect.example" || req.Destination != target || string(req.FirstPacket) != string(payload[:17]) {
				t.Fatalf("inspection mismatch %+v", req)
			}
			if s.TrafficSnapshot()[42].Upload != uint64(len(payload)) {
				t.Fatal("peek must be counted once")
			}
		})
	}
}

func TestSniffRedirectAndPayloadDenialBeforeDial(t *testing.T) {
	target, accepts := echoTCP(t)
	user := User{ID: 42, UUID: testUUID}
	for _, deny := range []bool{false, true} {
		cfg := Config{Protocol: "vless", Listen: "127.0.0.1", Port: freePort(t, false), Users: []User{user},
			DomainSniff: []string{"http"}, SniffRedirect: true, DetectPacketMaxLen: 4096,
			Hook: func(r Request) error {
				if !strings.HasPrefix(r.Destination, "redirect.example:") {
					return errors.New("redirect missing")
				}
				if deny {
					return errors.New("packet policy")
				}
				return nil
			},
			Transform: func(_ context.Context, r Request) (Request, error) { r.Destination = target; return r, nil }}
		s, err := Start(context.Background(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		before := accepts.Load()
		err = roundTripTCP(client(t, cfg, user, nil), target, []byte("GET / HTTP/1.1\r\nHost: redirect.example\r\n\r\n"), time.Second)
		s.Close()
		if deny && (err == nil || accepts.Load() != before) {
			t.Fatal("denied packet reached target")
		}
		if !deny && err != nil {
			t.Fatal(err)
		}
	}
}

func TestInspectionServerFirstBounded(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		c, e := listener.Accept()
		if e == nil {
			defer c.Close()
			c.Write([]byte("server-first"))
		}
	}()
	user := User{ID: 42, UUID: testUUID}
	cfg := Config{Protocol: "vless", Listen: "127.0.0.1", Port: freePort(t, false), Users: []User{user}, DomainSniff: []string{"tls", "http", "quic"}}
	s, err := Start(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	c, err := client(t, cfg, user, nil).DialContext(context.Background(), "tcp", M.ParseSocksaddr(listener.Addr().String()))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(2 * time.Second))
	// VLESS lazy writer emits its authenticated header on the first Write.
	c.Write(nil)
	b := make([]byte, len("server-first"))
	if _, err = io.ReadFull(c, b); err != nil {
		t.Fatal(err)
	}
	if string(b) != "server-first" {
		t.Fatal("corrupted server response")
	}
}

func TestInspectionQUICInitialDomain(t *testing.T) {
	capture, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer capture.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	go quic.DialAddr(ctx, capture.LocalAddr().String(), &tls.Config{ServerName: "quic.inspect.example", NextProtos: []string{"h3"}, CurvePreferences: []tls.CurveID{tls.X25519}}, nil)
	b := make([]byte, 65535)
	capture.SetReadDeadline(time.Now().Add(time.Second))
	n, _, err := capture.ReadFrom(b)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	var check adapter.InboundContext
	if err := sniff.QUICClientHello(context.Background(), &check, b[:n]); err != nil {
		t.Fatalf("captured QUIC Initial could not be decoded: %v", err)
	}
	if check.Domain != "quic.inspect.example" {
		t.Fatalf("capture SNI = %s", check.Domain)
	}
	target := echoUDP(t)
	seen := make(chan Request, 10)
	user := User{ID: 42, UUID: testUUID}
	cfg := Config{Protocol: "vless", Listen: "127.0.0.1", Port: freePort(t, false), Users: []User{user}, DomainSniff: []string{"quic"}, Hook: func(r Request) error { seen <- r; return nil }}
	s, err := Start(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err = roundTripUDP(client(t, cfg, user, nil), target, b[:n]); err != nil {
		t.Fatal(err)
	}
	req := <-seen
	if req.SniffedDomain != "quic.inspect.example" {
		t.Fatalf("QUIC SNI not found: %+v", req)
	}
}
