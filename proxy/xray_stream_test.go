package proxy

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"

	xbuf "github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net/cnc"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

// A sniffing peek with a deadline must time out on a silent client and the
// bytes that arrive later must still be delivered in order.
func TestSniffDeadlineConnTimesOutThenDelivers(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	conn := newSniffDeadlineConn(server)
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	buffer := make([]byte, 16)
	if _, err := conn.Read(buffer); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("silent client: %v", err)
	}
	_ = conn.SetReadDeadline(time.Time{})
	go func() {
		_, _ = client.Write([]byte("hello world"))
		_, _ = client.Write([]byte("!"))
	}()
	got := make([]byte, 0, 12)
	for len(got) < 12 {
		n, err := conn.Read(buffer)
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, buffer[:n]...)
	}
	if string(got) != "hello world!" {
		t.Fatalf("got %q", got)
	}
	if conn.pending != nil {
		t.Fatal("background read left in flight after delivery")
	}
}

func TestSniffDeadlineConnReadsDirectlyWithoutDeadline(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	conn := newSniffDeadlineConn(server)
	defer conn.Close()
	go func() { _, _ = client.Write([]byte("direct")) }()
	buffer := make([]byte, 16)
	n, err := conn.Read(buffer)
	if err != nil || string(buffer[:n]) != "direct" {
		t.Fatalf("direct read: %q %v", buffer[:n], err)
	}
	if conn.pending != nil {
		t.Fatal("direct read spawned a background read")
	}
}

// Half-closing a pipe-backed link must keep the buffered tail and end with
// EOF, which a full close (interrupt) would discard.
func TestXrayLinkConnCloseWriteKeepsBufferedTail(t *testing.T) {
	reader, writer := pipe.New(pipe.WithSizeLimit(64 * 1024))
	link := &transport.Link{Reader: reader, Writer: writer}
	stream := &xrayLinkConn{link: link, Connection: cnc.NewConnection(cnc.ConnectionInputMulti(writer), cnc.ConnectionOutputMulti(reader))}
	if _, err := stream.Write([]byte("tail-of-response")); err != nil {
		t.Fatal(err)
	}
	if err := stream.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	var got []byte
	for {
		mb, err := reader.ReadMultiBuffer()
		if err != nil {
			if !errors.Is(err, io.EOF) {
				t.Fatal(err)
			}
			break
		}
		for _, b := range mb {
			got = append(got, b.Bytes()...)
		}
		xbuf.ReleaseMulti(mb)
	}
	if !bytes.Equal(got, []byte("tail-of-response")) {
		t.Fatalf("buffered tail lost: %q", got)
	}
	direct := &xrayLinkConn{link: &transport.Link{Writer: xbuf.NewWriter(io.Discard)}}
	if err := direct.CloseWrite(); !errors.Is(err, errNoHalfClose) {
		t.Fatal("direct link reported half-close support", err)
	}
}
