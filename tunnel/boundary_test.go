package tunnel

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// This connection permits deterministic corruption of a valid encrypted
// record. It is used only for local framing boundaries, not as a wire oracle.
type boundaryBytesConn struct {
	*bytes.Reader
	output bytes.Buffer
}

func (c *boundaryBytesConn) Write(p []byte) (int, error) { return c.output.Write(p) }
func (c *boundaryBytesConn) Close() error                { return nil }
func (c *boundaryBytesConn) LocalAddr() net.Addr         { return &net.TCPAddr{} }
func (c *boundaryBytesConn) RemoteAddr() net.Addr        { return &net.TCPAddr{} }
func (c *boundaryBytesConn) SetDeadline(time.Time) error { return nil }
func (c *boundaryBytesConn) SetReadDeadline(time.Time) error {
	return nil
}
func (c *boundaryBytesConn) SetWriteDeadline(time.Time) error {
	return nil
}

func boundaryRecord(t *testing.T, payload []byte) (*keys, []byte) {
	t.Helper()
	k, err := makeKeys("aes-256-gcm", "boundary-test-password")
	if err != nil {
		t.Fatal(err)
	}
	raw := &boundaryBytesConn{Reader: bytes.NewReader(nil)}
	if _, err = (&wireConn{Conn: raw, keys: k}).Write(payload); err != nil {
		t.Fatal(err)
	}
	return k, bytes.Clone(raw.output.Bytes())
}

func boundaryReader(k *keys, data []byte, replay *replayCache) *wireConn {
	return &wireConn{Conn: &boundaryBytesConn{Reader: bytes.NewReader(data)}, keys: k, replay: replay}
}

func TestTunnelBoundaryReplaySalt(t *testing.T) {
	payload := []byte("only the first authenticated copy may pass")
	k, record := boundaryRecord(t, payload)
	var replay replayCache
	first := boundaryReader(k, record, &replay)
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(first, got); err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("initial record: %q %v", got, err)
	}
	second := boundaryReader(k, record, &replay)
	if n, err := second.Read(got); n != 0 || err == nil || !strings.Contains(err.Error(), "replay") {
		t.Fatalf("replayed salt admitted: n=%d err=%v", n, err)
	}
	// A forged header must not reserve a salt before authentication succeeds.
	var cleanCache replayCache
	forged := bytes.Clone(record)
	forged[12] ^= 1
	if n, err := boundaryReader(k, forged, &cleanCache).Read(got); n != 0 || err == nil {
		t.Fatal("forged header admitted", n, err)
	}
	if _, err := io.ReadFull(boundaryReader(k, record, &cleanCache), got); err != nil {
		t.Fatal("unauthenticated header poisoned replay state", err)
	}
}

func TestTunnelBoundaryCorruptAndTruncatedRecords(t *testing.T) {
	k, record := boundaryRecord(t, []byte("authenticated body"))
	for _, name := range []string{"header-tag", "body-ciphertext", "body-tag", "short-header", "short-body"} {
		t.Run(name, func(t *testing.T) {
			data := bytes.Clone(record)
			switch name {
			case "header-tag":
				data[12+17] ^= 1
			case "body-ciphertext":
				data[12+18] ^= 1
			case "body-tag":
				data[len(data)-1] ^= 1
			case "short-header":
				data = data[:12+17]
			case "short-body":
				data = data[:len(data)-1]
			}
			reader := boundaryReader(k, data, nil)
			var buf [128]byte
			n, firstErr := reader.Read(buf[:])
			if n != 0 || firstErr == nil {
				t.Fatal("invalid frame released plaintext", n, firstErr)
			}
			if n, err := reader.Read(buf[:]); n != 0 || err != firstErr {
				t.Fatal("failed reader resumed after frame desynchronization", n, err)
			}
		})
	}
}

func TestTunnelBoundaryUDPShortBufferPreservesNextPacket(t *testing.T) {
	k, _ := boundaryRecord(t, []byte("unused"))
	raw := &boundaryBytesConn{Reader: bytes.NewReader(nil)}
	writer := &Conn{Conn: &wireConn{Conn: raw, keys: k}, Mode: UDP}
	for _, payload := range [][]byte{[]byte("first datagram"), []byte("second"), nil, []byte("after-empty")} {
		if _, err := writer.Write(payload); err != nil {
			t.Fatal(err)
		}
	}
	reader := &Conn{Conn: boundaryReader(k, raw.output.Bytes(), nil), Mode: UDP}
	var short [3]byte
	if n, err := reader.Read(short[:]); n != 3 || !errors.Is(err, io.ErrShortBuffer) || string(short[:]) != "fir" {
		t.Fatalf("short datagram result: %q %d %v", short, n, err)
	}
	buf := make([]byte, 64)
	for _, want := range []string{"second", "", "after-empty"} {
		n, err := reader.Read(buf)
		if err != nil || string(buf[:n]) != want {
			t.Fatalf("datagram boundary lost: got=%q want=%q err=%v", buf[:n], want, err)
		}
	}
	if _, err := writer.Write(make([]byte, 65536)); err == nil {
		t.Fatal("oversized UDP datagram accepted")
	}
}

func TestTunnelBoundaryCloseWithPendingHandshakeAndMux(t *testing.T) {
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{Type: "tcp", Method: "aes-256-gcm", Password: "close-boundary", Mux: true}
	listener, err := WrapListener(raw, cfg)
	if err != nil {
		raw.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { raw.Close() })
	pending, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pending.Close() })
	if _, err = pending.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	client, err := DialClient(context.Background(), listener.Addr().String(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	const streamCount = 12
	readDone := make(chan error, streamCount)
	for range streamCount {
		stream, err := client.Open(TCP)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { stream.Close() })
		accepted, err := listener.Accept()
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			defer accepted.Close()
			_, err := accepted.Read(make([]byte, 1))
			readDone <- err
		}()
	}
	var operations sync.WaitGroup
	operations.Add(2)
	go func() {
		defer operations.Done()
		for range 20 {
			if stream, err := client.Open(UDP); err == nil {
				stream.Close()
			}
		}
	}()
	go func() {
		defer operations.Done()
		var closes sync.WaitGroup
		for range 4 {
			closes.Add(1)
			go func() { defer closes.Done(); listener.Close() }()
		}
		closes.Wait()
	}()
	done := make(chan struct{})
	go func() { operations.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Close blocked on pending authentication or multiplexed streams")
	}
	for range streamCount {
		select {
		case err := <-readDone:
			if err == nil {
				t.Fatal("closed stream unexpectedly returned success")
			}
		case <-time.After(time.Second):
			t.Fatal("blocked stream read survived listener Close")
		}
	}
	if _, err := listener.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatal("closed listener accepted a queued connection", err)
	}
}
