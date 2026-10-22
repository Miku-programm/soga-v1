package proxy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/pires/go-proxyproto"
)

// tcpPair returns both ends of one loopback TCP connection as *net.TCPConn.
func tcpPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	accepted := make(chan net.Conn, 1)
	failed := make(chan error, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			failed <- err
			return
		}
		accepted <- c
	}()
	dialed, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	var server net.Conn
	select {
	case server = <-accepted:
	case err := <-failed:
		dialed.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { dialed.Close(); server.Close() })
	return dialed.(*net.TCPConn), server.(*net.TCPConn)
}

// plainConn hides the TCP socket so relay must take the generic path. It has
// no CloseWrite, like tunnel or HTTP/2 stream connections.
type plainConn struct{ net.Conn }

func startRelay(ctx context.Context, a, b net.Conn, idle time.Duration) (<-chan error, func() error) {
	result := make(chan error, 1)
	go func() { result <- relay(ctx, a, b, idle) }()
	return result, func() error {
		select {
		case err := <-result:
			return err
		case <-time.After(5 * time.Second):
			return errors.New("relay did not return")
		}
	}
}

func expectRead(t *testing.T, c net.Conn, want string) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	got := make([]byte, len(want))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatalf("read %q: %v", want, err)
	}
	if string(got) != want {
		t.Fatalf("read %q, want %q", got, want)
	}
	_ = c.SetReadDeadline(time.Time{})
}

func expectEOF(t *testing.T, c net.Conn) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := c.Read(make([]byte, 1))
	if n != 0 || err == nil {
		t.Fatalf("expected EOF, got %d bytes, err %v", n, err)
	}
}

func TestRelayBidirectionalAndHalfClose(t *testing.T) {
	// Real TCP sockets on both relay sides exercise the kernel fast path.
	client, left := tcpPair(t)
	right, server := tcpPair(t)
	_, wait := startRelay(context.Background(), left, right, time.Minute)
	if _, err := client.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	expectRead(t, server, "ping")
	if _, err := server.Write([]byte("pong")); err != nil {
		t.Fatal(err)
	}
	expectRead(t, client, "pong")
	// Client half-close reaches the server as EOF while the server can still
	// answer.
	if err := client.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	expectEOF(t, server)
	if _, err := server.Write([]byte("late answer")); err != nil {
		t.Fatal(err)
	}
	expectRead(t, client, "late answer")
	if err := server.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	expectEOF(t, client)
	if err := wait(); err != nil {
		t.Fatalf("clean relay returned %v", err)
	}
}

func TestRelayGenericPathWithoutCloseWrite(t *testing.T) {
	client, left := tcpPair(t)
	right, server := tcpPair(t)
	_, wait := startRelay(context.Background(), plainConn{left}, right, time.Minute)
	if _, err := client.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	expectRead(t, server, "ping")
	if _, err := server.Write([]byte("pong")); err != nil {
		t.Fatal(err)
	}
	expectRead(t, client, "pong")
	// The TCP side still gets a half-close when the wrapped side ends.
	if err := client.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	expectEOF(t, server)
	if _, err := server.Write([]byte("late")); err != nil {
		t.Fatal(err)
	}
	expectRead(t, client, "late")
	// A wrapper without CloseWrite cannot half-close: the relay ends.
	if err := server.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	expectEOF(t, client)
	if err := wait(); err != nil {
		t.Fatalf("clean relay returned %v", err)
	}
}

func TestRelayIdleTimeoutClosesBothSides(t *testing.T) {
	for _, generic := range []bool{false, true} {
		t.Run(fmt.Sprintf("generic=%t", generic), func(t *testing.T) {
			client, left := tcpPair(t)
			right, server := tcpPair(t)
			var a net.Conn = left
			if generic {
				a = plainConn{left}
			}
			idle := 300 * time.Millisecond
			start := time.Now()
			_, wait := startRelay(context.Background(), a, right, idle)
			err := wait()
			elapsed := time.Since(start)
			if !errors.Is(err, errRelayIdle) {
				t.Fatalf("relay returned %v, want idle timeout", err)
			}
			if elapsed < idle {
				t.Fatalf("relay ended after %v, before the idle period %v", elapsed, idle)
			}
			if elapsed > 3*idle {
				t.Fatalf("idle relay lingered for %v", elapsed)
			}
			expectEOF(t, client)
			expectEOF(t, server)
		})
	}
}

func TestRelaySlowTransferIsNotIdle(t *testing.T) {
	for _, generic := range []bool{false, true} {
		t.Run(fmt.Sprintf("generic=%t", generic), func(t *testing.T) {
			client, left := tcpPair(t)
			right, server := tcpPair(t)
			var a net.Conn = left
			if generic {
				a = plainConn{left}
			}
			idle := 300 * time.Millisecond
			result, wait := startRelay(context.Background(), a, right, idle)
			// One byte every idle/3 in a single direction for several idle
			// periods must keep the relay alive, including the quiet direction.
			for i := 0; i < 12; i++ {
				time.Sleep(idle / 3)
				if _, err := client.Write([]byte{byte('a' + i)}); err != nil {
					t.Fatal(err)
				}
				expectRead(t, server, string(rune('a'+i)))
				select {
				case err := <-result:
					t.Fatalf("relay ended during active transfer: %v", err)
				default:
				}
			}
			if _, err := server.Write([]byte("reply")); err != nil {
				t.Fatal(err)
			}
			expectRead(t, client, "reply")
			client.Close()
			server.Close()
			if err := wait(); err != nil {
				t.Fatalf("relay after active transfer returned %v", err)
			}
		})
	}
}

func TestRelayContextCancel(t *testing.T) {
	client, left := tcpPair(t)
	right, server := tcpPair(t)
	ctx, cancel := context.WithCancel(context.Background())
	_, wait := startRelay(ctx, left, right, time.Minute)
	if _, err := client.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	expectRead(t, server, "x")
	cancel()
	if err := wait(); !errors.Is(err, context.Canceled) {
		t.Fatalf("relay returned %v, want context.Canceled", err)
	}
	expectEOF(t, client)
	expectEOF(t, server)
}

// Bytes that arrive together with the PROXY header stay in the header
// reader's buffer. The relay must forward them before switching to the raw
// socket, and must still forward the source address the header carried.
func TestRelayProxyProtocolBufferedBytes(t *testing.T) {
	client, left := tcpPair(t)
	right, server := tcpPair(t)
	payload := bytes.Repeat([]byte("buffered-after-header "), 8)
	var first bytes.Buffer
	first.WriteString("PROXY TCP4 192.0.2.77 127.0.0.1 41414 443\r\n")
	first.Write(payload)
	if _, err := client.Write(first.Bytes()); err != nil {
		t.Fatal(err)
	}
	// Give the kernel a moment so header and payload are read together.
	time.Sleep(50 * time.Millisecond)
	wrapped := proxyproto.NewConn(left, proxyproto.WithPolicy(proxyproto.REQUIRE), proxyproto.SetReadHeaderTimeout(5*time.Second))
	if _, err := wrapped.Read(nil); err != nil {
		t.Fatal(err)
	}
	if got := wrapped.RemoteAddr().String(); got != "192.0.2.77:41414" {
		t.Fatalf("header source lost: %s", got)
	}
	_, wait := startRelay(context.Background(), wrapped, right, time.Minute)
	expectRead(t, server, string(payload))
	if _, err := client.Write([]byte("second write")); err != nil {
		t.Fatal(err)
	}
	expectRead(t, server, "second write")
	if _, err := server.Write([]byte("answer")); err != nil {
		t.Fatal(err)
	}
	expectRead(t, client, "answer")
	if err := client.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	expectEOF(t, server)
	if err := server.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	expectEOF(t, client)
	if err := wait(); err != nil {
		t.Fatalf("clean relay returned %v", err)
	}
}
