package splithttp

import (
	"bytes"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/transport/pipe"
)

type countedBody struct {
	io.ReadCloser
	closes atomic.Int32
}

func (b *countedBody) Close() error { b.closes.Add(1); return b.ReadCloser.Close() }
func awaitResult[T any](t *testing.T, c <-chan T) T {
	t.Helper()
	select {
	case r := <-c:
		return r
	case <-time.After(3 * time.Second):
		t.Fatal("operation did not unblock")
		var zero T
		return zero
	}
}

func TestWaitReadCloserPublishesBody(t *testing.T) {
	for i := 0; i < 100; i++ {
		w := &WaitReadCloser{Wait: make(chan struct{})}
		got := make(chan string, 1)
		go func() {
			p, e := io.ReadAll(w)
			if e != nil {
				got <- "error: " + e.Error()
				return
			}
			got <- string(p)
		}()
		body := &countedBody{ReadCloser: io.NopCloser(bytes.NewBufferString("complete response"))}
		w.Set(body)
		if s := awaitResult(t, got); s != "complete response" {
			t.Fatal(s)
		}
		w.Close()
		w.Close()
		if body.closes.Load() != 1 {
			t.Fatal("body not closed exactly once")
		}
	}
}
func TestWaitReadCloserCloseBeforeSet(t *testing.T) {
	w := &WaitReadCloser{Wait: make(chan struct{})}
	result := make(chan error, 1)
	go func() { _, e := w.Read(make([]byte, 1)); result <- e }()
	w.Close()
	if e := awaitResult(t, result); e != io.ErrClosedPipe {
		t.Fatal(e)
	}
	body := &countedBody{ReadCloser: io.NopCloser(bytes.NewReader(nil))}
	w.Set(body)
	if body.closes.Load() != 1 {
		t.Fatal("late body leaked")
	}
}
func TestWaitReadCloserSetCloseRace(t *testing.T) {
	for i := 0; i < 100; i++ {
		w := &WaitReadCloser{Wait: make(chan struct{})}
		r, p := io.Pipe()
		body := &countedBody{ReadCloser: r}
		var wg sync.WaitGroup
		wg.Add(3)
		go func() { defer wg.Done(); w.Set(body) }()
		go func() { defer wg.Done(); w.Close() }()
		go func() { defer wg.Done(); w.Read(make([]byte, 1)) }()
		done := make(chan bool, 1)
		go func() { wg.Wait(); done <- true }()
		awaitResult(t, done)
		p.Close()
		if body.closes.Load() != 1 {
			t.Fatal("racing body not closed exactly once")
		}
	}
}
func TestUploadQueueOrderedPartialReads(t *testing.T) {
	q := NewUploadQueue(4)
	defer q.Close()
	for _, p := range []Packet{{Seq: 2, Payload: []byte("ef")}, {Seq: 0, Payload: []byte("ab")}, {Seq: 1, Payload: []byte("cd")}} {
		if e := q.Push(p); e != nil {
			t.Fatal(e)
		}
	}
	var got []byte
	for len(got) < 6 {
		b := make([]byte, 1)
		n, e := q.Read(b)
		if e != nil {
			t.Fatal(e)
		}
		got = append(got, b[:n]...)
	}
	if string(got) != "abcdef" {
		t.Fatal(string(got))
	}
}
func TestUploadQueueCloseUnblocksFullPush(t *testing.T) {
	q := NewUploadQueue(1)
	q.Push(Packet{Seq: 0, Payload: []byte("a")})
	pushed := make(chan error, 1)
	go func() { pushed <- q.Push(Packet{Seq: 1}) }()
	closed := make(chan error, 1)
	go func() { closed <- q.Close() }()
	awaitResult(t, closed)
	if e := awaitResult(t, pushed); e == nil {
		t.Fatal("push after cancellation succeeded")
	}
}
func TestUploadQueueCloseUnblocksEmptyRead(t *testing.T) {
	q := NewUploadQueue(1)
	read := make(chan error, 1)
	go func() { _, e := q.Read(make([]byte, 1)); read <- e }()
	q.Close()
	if e := awaitResult(t, read); e != io.EOF {
		t.Fatal(e)
	}
}
func TestUploadQueueReaderCloseRace(t *testing.T) {
	for i := 0; i < 100; i++ {
		q := NewUploadQueue(1)
		r, p := io.Pipe()
		body := &countedBody{ReadCloser: r}
		if e := q.Push(Packet{Reader: body}); e != nil {
			t.Fatal(e)
		}
		read := make(chan error, 1)
		go func() { _, e := q.Read(make([]byte, 1)); read <- e }()
		q.Close()
		q.Close()
		awaitResult(t, read)
		p.Close()
		if body.closes.Load() != 1 {
			t.Fatalf("body closes: %d", body.closes.Load())
		}
	}
}
func TestUploadQueueClosesQueuedReader(t *testing.T) {
	q := NewUploadQueue(1)
	body := &countedBody{ReadCloser: io.NopCloser(bytes.NewReader(nil))}
	q.Push(Packet{Reader: body})
	q.Close()
	if body.closes.Load() != 1 {
		t.Fatal("queued body leaked")
	}
}

func TestUploadWriterTransfersBufferOwnership(t *testing.T) {
	reader, writer := pipe.New(pipe.WithSizeLimit(0))
	w := uploadWriter{Writer: writer, maxLen: buf.Size}
	result := make(chan int, 1)
	go func() {
		total := 0
		for {
			data, err := reader.ReadMultiBuffer()
			if err != nil {
				result <- total
				return
			}
			total += int(data.Len())
			buf.ReleaseMulti(data)
		}
	}()
	payload := bytes.Repeat([]byte("x"), int(buf.Size)*3+17)
	for i := 0; i < 500; i++ {
		n, err := w.Write(payload)
		if err != nil || n != len(payload) {
			t.Fatalf("write %d: %d, %v", i, n, err)
		}
	}
	writer.Close()
	if got := awaitResult(t, result); got != len(payload)*500 {
		t.Fatalf("received %d bytes", got)
	}
}
