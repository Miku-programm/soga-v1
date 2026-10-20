package splithttp

// upload_queue is a specialized priorityqueue + channel to reorder generic
// packets by a sequence number

import (
	"container/heap"
	"io"
	"sync"

	"github.com/xtls/xray-core/common/errors"
)

type Packet struct {
	Reader  io.ReadCloser
	Payload []byte
	Seq     uint64
}

// The read mutex owns heap/sequence state. State mutex only protects the active
// body; Close must never wait for a potentially blocking Read while holding it.
type uploadQueue struct {
	reader          io.ReadCloser
	readerMutex     sync.Mutex
	readMutex       sync.Mutex
	nomore          bool
	pushedPackets   chan Packet
	writeCloseMutex sync.Mutex
	done            chan struct{}
	closeOnce       sync.Once
	heap            uploadHeap
	nextSeq         uint64
	maxPackets      int
}

func NewUploadQueue(maxPackets int) *uploadQueue {
	return &uploadQueue{
		pushedPackets: make(chan Packet, maxPackets),
		done:          make(chan struct{}),
		heap:          uploadHeap{},
		maxPackets:    maxPackets,
	}
}

func (h *uploadQueue) isClosed() bool {
	select {
	case <-h.done:
		return true
	default:
		return false
	}
}

func (h *uploadQueue) Push(p Packet) error {
	h.writeCloseMutex.Lock()
	defer h.writeCloseMutex.Unlock()
	if h.isClosed() {
		return errors.New("packet queue closed")
	}
	if h.nomore {
		return errors.New("h.reader already exists")
	}
	select {
	case <-h.done:
		return errors.New("packet queue closed")
	case h.pushedPackets <- p:
		if p.Reader != nil {
			h.nomore = true
		}
		return nil
	}
}

func (h *uploadQueue) Close() error {
	var closeErr error
	h.closeOnce.Do(func() {
		// Cancel first so a Push blocked on a full channel can release its lock.
		close(h.done)
		h.writeCloseMutex.Lock()
		var queued []io.ReadCloser
	drain:
		for {
			select {
			case p := <-h.pushedPackets:
				if p.Reader != nil {
					queued = append(queued, p.Reader)
				}
			default:
				break drain
			}
		}
		h.writeCloseMutex.Unlock()
		h.readerMutex.Lock()
		rc := h.reader
		h.readerMutex.Unlock()
		if rc != nil {
			closeErr = rc.Close()
		}
		for _, rc := range queued {
			if err := rc.Close(); closeErr == nil {
				closeErr = err
			}
		}
	})
	return closeErr
}

// acceptReader transfers ownership exactly once, even when Close races with a
// channel receive. A receiver that loses to Close must close its own body.
func (h *uploadQueue) acceptReader(rc io.ReadCloser) bool {
	h.readerMutex.Lock()
	if h.isClosed() {
		h.readerMutex.Unlock()
		rc.Close()
		return false
	}
	h.reader = rc
	h.readerMutex.Unlock()
	return true
}

func (h *uploadQueue) nextPacket() (Packet, bool) {
	select {
	case <-h.done:
		return Packet{}, false
	case p := <-h.pushedPackets:
		return p, true
	}
}

func (h *uploadQueue) Read(b []byte) (int, error) {
	h.readMutex.Lock()
	defer h.readMutex.Unlock()
	if h.isClosed() {
		return 0, io.EOF
	}
	h.readerMutex.Lock()
	rc := h.reader
	h.readerMutex.Unlock()
	if rc != nil {
		return rc.Read(b)
	}
	if len(h.heap) == 0 {
		p, more := h.nextPacket()
		if !more {
			return 0, io.EOF
		}
		if p.Reader != nil {
			if !h.acceptReader(p.Reader) {
				return 0, io.EOF
			}
			return p.Reader.Read(b)
		}
		heap.Push(&h.heap, p)
	}
	for len(h.heap) > 0 {
		if h.isClosed() {
			return 0, io.EOF
		}
		packet := heap.Pop(&h.heap).(Packet)
		if packet.Seq == h.nextSeq {
			n := copy(b, packet.Payload)
			if n < len(packet.Payload) {
				packet.Payload = packet.Payload[n:]
				heap.Push(&h.heap, packet)
			} else {
				h.nextSeq = packet.Seq + 1
			}
			return n, nil
		}
		if packet.Seq > h.nextSeq {
			if len(h.heap) > h.maxPackets {
				return 0, errors.New("packet queue is too large")
			}
			heap.Push(&h.heap, packet)
			p, more := h.nextPacket()
			if !more {
				return 0, io.EOF
			}
			if p.Reader != nil {
				if !h.acceptReader(p.Reader) {
					return 0, io.EOF
				}
				return p.Reader.Read(b)
			}
			heap.Push(&h.heap, p)
		}
	}
	return 0, nil
}

// heap code directly taken from https://pkg.go.dev/container/heap
type uploadHeap []Packet

func (h uploadHeap) Len() int           { return len(h) }
func (h uploadHeap) Less(i, j int) bool { return h[i].Seq < h[j].Seq }
func (h uploadHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }

func (h *uploadHeap) Push(x any) {
	// Push and Pop use pointer receivers because they modify the slice's length,
	// not just its contents.
	*h = append(*h, x.(Packet))
}

func (h *uploadHeap) Pop() any {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[0 : n-1]
	return x
}
