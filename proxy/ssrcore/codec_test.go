package ssrcore

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"reconstructed.local/soga/proxy/ssrcore/internal/vnet/common/obfs"
)

// codecRouter records the codec behind every routed TCP connection and UDP
// association, then routes like testRouter.
type codecRouter struct {
	*testRouter
	codecMu sync.Mutex
	codecs  []*codec
}

func (r *codecRouter) remember(c *codec) {
	r.codecMu.Lock()
	defer r.codecMu.Unlock()
	r.codecs = append(r.codecs, c)
}

func (r *codecRouter) recorded() []*codec {
	r.codecMu.Lock()
	defer r.codecMu.Unlock()
	return append([]*codec(nil), r.codecs...)
}

func (r *codecRouter) RouteConnectionEx(ctx context.Context, c net.Conn, m adapter.InboundContext, done N.CloseHandlerFunc) {
	if sc, ok := c.(*streamConn); ok {
		r.remember(sc.codec)
	}
	r.testRouter.RouteConnectionEx(ctx, c, m, done)
}

func (r *codecRouter) RoutePacketConnectionEx(ctx context.Context, c N.PacketConn, m adapter.InboundContext, done N.CloseHandlerFunc) {
	if pc, ok := c.(*packetConn); ok {
		r.remember(pc.codec)
	}
	r.testRouter.RoutePacketConnectionEx(ctx, c, m, done)
}

func startRecordingServer(t *testing.T, o Options) (*server, *codecRouter) {
	t.Helper()
	r := &codecRouter{testRouter: &testRouter{}}
	in, err := NewInbound(context.Background(), r, nil, "test", o)
	if err != nil {
		t.Fatal(err)
	}
	s := in.(*server)
	scope := adapter.NewScope(context.Background(), nil)
	if err = s.Start(adapter.StartStateStart, scope); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { scope.Close() })
	return s, r
}

// checkSharedIndex fails unless every codec, and both plugins of each codec,
// use the listener's single user index.
func checkSharedIndex(t *testing.T, s *server, codecs []*codec) {
	t.Helper()
	passwords := reflect.ValueOf(s.users.passwords).Pointer()
	for i, c := range codecs {
		if c.users != s.users {
			t.Fatalf("codec %d built a private user index", i)
		}
		for _, part := range []obfs.Plain{c.protocol, c.obfs} {
			if reflect.ValueOf(part.GetServerInfo().GetUsers()).Pointer() != passwords {
				t.Fatalf("codec %d plugin %T got a private users map", i, part)
			}
		}
		for j := 0; j < i; j++ {
			if codecs[j] == c {
				t.Fatalf("codecs %d and %d are the same codec", j, i)
			}
		}
	}
}

func TestConnectionsShareListenerUserIndex(t *testing.T) {
	o := Options{Listen: "127.0.0.1", Method: "aes-128-cfb", Password: "outer-secret",
		Protocol: "auth_chain_a", Obfs: "tls1.2_ticket_auth", SinglePortType: "protocol",
		Users: []User{{ID: 101, Password: "user-one"}, {ID: 202, Password: "user-two"},
			{ID: 5000000000, ProtocolID: 303, Password: "user-three"}}}
	s, r := startRecordingServer(t, o)
	if s.users == nil || len(s.users.passwords) != len(o.Users) || len(s.users.billing) != len(o.Users) {
		t.Fatalf("listener user index not built: %+v", s.users)
	}
	header, _ := appendAddress(nil, M.ParseSocksaddr("example.com:443"))
	var want []int64
	for i := 0; i < 2*len(o.Users); i++ {
		u := o.Users[i%len(o.Users)]
		want = append(want, u.ID)
		raw, err := net.Dial("tcp", s.tcp.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		raw.SetDeadline(time.Now().Add(3 * time.Second))
		c := &streamConn{Conn: raw, codec: clientCodec(t, o, int64(u.wireID()), u.Password)}
		payload := bytes.Repeat([]byte{byte('a' + i)}, 3000)
		if _, err = c.Write(append(header, payload...)); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, len(payload))
		_, err = io.ReadFull(c, got)
		c.Close()
		if err != nil || !bytes.Equal(got, payload) {
			t.Fatalf("connection %d roundtrip: %v", i, err)
		}
	}
	codecs := r.recorded()
	if len(codecs) != len(want) {
		t.Fatalf("recorded %d codecs, want %d", len(codecs), len(want))
	}
	checkSharedIndex(t, s, codecs)
	// The billing user stays per codec state.
	for i, c := range codecs {
		if c.userID != want[i] {
			t.Fatalf("codec %d attributed to %d, want %d", i, c.userID, want[i])
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if fmt.Sprint(r.users) != fmt.Sprint(want) {
		t.Fatalf("route identities %v, want %v", r.users, want)
	}
}

// udpExchange sends one client datagram and returns the decoded reply.
func udpExchange(t *testing.T, raw net.Conn, c *codec, data []byte) []byte {
	t.Helper()
	wire, err := c.protocol.ClientUDPPreEncrypt(data)
	if err == nil {
		wire, err = c.enc.EncryptAll(wire, c.enc.MustNewIV())
	}
	if err != nil {
		t.Fatal(err)
	}
	if _, err = raw.Write(wire); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 65535)
	n, err := raw.Read(b)
	if err != nil {
		t.Fatal(err)
	}
	reply, _, err := c.enc.DecryptAll(b[:n])
	if err == nil {
		reply, err = c.protocol.ClientUDPPostDecrypt(reply)
	}
	if err != nil {
		t.Fatal(err)
	}
	return reply
}

func TestUDPProtocolSinglePortAttributesSeveralUsers(t *testing.T) {
	for _, protocol := range []string{"auth_aes128_md5", "auth_aes128_sha1", "auth_chain_a", "auth_chain_f"} {
		t.Run(protocol, func(t *testing.T) {
			o := Options{Listen: "127.0.0.1", Method: "aes-128-cfb", Password: "outer-secret",
				Protocol: protocol, Obfs: "plain", SinglePortType: "protocol",
				Users: []User{{ID: 101, Password: "one"}, {ID: 202, Password: "two"},
					{ID: 5000000000, ProtocolID: 303, Password: "three"}, {ID: 404, ProtocolID: 7, Password: "four"}}}
			s, r := startRecordingServer(t, o)
			conns := make([]net.Conn, len(o.Users))
			clients := make([]*codec, len(o.Users))
			for i, u := range o.Users {
				raw, err := net.Dial("udp", s.udp.LocalAddr().String())
				if err != nil {
					t.Fatal(err)
				}
				defer raw.Close()
				raw.SetDeadline(time.Now().Add(3 * time.Second))
				conns[i] = raw
				clients[i] = clientCodec(t, o, int64(u.wireID()), u.Password)
			}
			// Interleave users so each datagram's codec looks its user up in
			// the shared index right after another user's datagram.
			for round := 0; round < 3; round++ {
				for i, u := range o.Users {
					header, _ := appendAddress(nil, M.ParseSocksaddr(fmt.Sprintf("192.0.2.%d:53", i+1)))
					want := append(header, bytes.Repeat([]byte{byte('A' + round), byte('0' + i)}, 500)...)
					if got := udpExchange(t, conns[i], clients[i], want); !bytes.Equal(got, want) {
						t.Fatalf("round %d user %d: reply differs", round, u.ID)
					}
				}
			}
			// A UID absent from the shared index must still be dropped.
			bad := clientCodec(t, o, 999, "one")
			header, _ := appendAddress(nil, M.ParseSocksaddr("192.0.2.1:53"))
			wire, _ := bad.protocol.ClientUDPPreEncrypt(append(header, "unknown"...))
			wire, _ = bad.enc.EncryptAll(wire, bad.enc.MustNewIV())
			conns[0].Write(wire)
			conns[0].SetReadDeadline(time.Now().Add(50 * time.Millisecond))
			if _, err := conns[0].Read(make([]byte, 65535)); err == nil {
				t.Fatal("unknown user accepted")
			}
			r.mu.Lock()
			users := fmt.Sprint(r.users)
			r.mu.Unlock()
			if users != "[101 202 5000000000 404]" {
				t.Fatalf("UDP user attribution: %v", users)
			}
			codecs := r.recorded()
			if len(codecs) != len(o.Users) {
				t.Fatalf("recorded %d UDP associations, want %d", len(codecs), len(o.Users))
			}
			checkSharedIndex(t, s, codecs)
		})
	}
}

// chunkConn replays a scripted byte stream in reads of varying size. Each read
// first overwrites the whole destination, so a decoder that kept a reference
// into an earlier read buffer sees garbage. Writes are recorded.
type chunkConn struct {
	net.Conn
	data    []byte
	sizes   []int
	reads   int
	written bytes.Buffer
}

func (c *chunkConn) Read(p []byte) (int, error) {
	if len(c.data) == 0 {
		return 0, io.EOF
	}
	for i := range p {
		p[i] = 0xA5
	}
	size := c.sizes[c.reads%len(c.sizes)]
	c.reads++
	n := copy(p[:min(len(p), size)], c.data)
	c.data = c.data[n:]
	return n, nil
}

func (c *chunkConn) Write(p []byte) (int, error) {
	return c.written.Write(p)
}

func (c *chunkConn) Close() error {
	return nil
}

// streamMessages returns distinct messages, small and larger than one read.
func streamMessages() [][]byte {
	sizes := []int{1, 700, 5000, 40000, 3, 70000, 20}
	msgs := make([][]byte, len(sizes))
	for i, size := range sizes {
		m := make([]byte, size)
		for j := range m {
			m[j] = byte(i*37 + j*13 + j>>8)
		}
		msgs[i] = m
	}
	return msgs
}

// clientStream returns every byte a client sends for msgs. A throwaway server
// answers the obfs handshake so the client releases data it buffered behind
// the TLS ClientHello; the server under test sees the same client bytes and
// answers on its own.
func clientStream(t *testing.T, o Options, client *codec, msgs [][]byte) []byte {
	t.Helper()
	probe, err := newCodec(o, obfs.NewObfsAuthChainData(o.Protocol), nil)
	if err != nil {
		t.Fatal(err)
	}
	var stream []byte
	for i, msg := range msgs {
		wire, err := client.encode(msg)
		if err != nil {
			t.Fatal(err)
		}
		stream = append(stream, wire...)
		for rounds := 0; i == 0 && len(wire) > 0 && rounds < 5; rounds++ {
			_, back, err := probe.decode(wire)
			if err != nil {
				t.Fatal(err)
			}
			wire = nil
			if len(back) > 0 {
				if _, wire, err = client.decode(back); err != nil {
					t.Fatal(err)
				}
				stream = append(stream, wire...)
			}
		}
	}
	return stream
}

// handshakePair returns client and server codecs that completed the protocol
// and obfs handshakes in process, as in TestFragmentedProtocolAndObfs.
func handshakePair(t *testing.T, o Options, id int64, password string) (*codec, *codec) {
	t.Helper()
	client := clientCodec(t, o, id, password)
	server, err := newCodec(o, obfs.NewObfsAuthChainData(o.Protocol), nil)
	if err != nil {
		t.Fatal(err)
	}
	first := []byte("\x01\x08\x08\x08\x08\x00\x35handshake")
	wire, err := client.encode(first)
	if err != nil {
		t.Fatal(err)
	}
	var decoded []byte
	for rounds := 0; len(wire) > 0 && rounds < 5; rounds++ {
		plain, back, err := server.decode(wire)
		if err != nil {
			t.Fatal(err)
		}
		decoded = append(decoded, plain...)
		wire = nil
		if len(back) > 0 {
			if _, wire, err = client.decode(back); err != nil {
				t.Fatal(err)
			}
		}
	}
	if !bytes.Equal(decoded, first) {
		t.Fatalf("handshake delivered %x", decoded)
	}
	return client, server
}

// readInPieces reads total bytes from s with reads of the given sizes and
// checks that every wire read reuses one connection buffer.
func readInPieces(t *testing.T, s *streamConn, total int, sizes []int) []byte {
	t.Helper()
	got := make([]byte, 0, total)
	var first *byte
	for i := 0; len(got) < total; i++ {
		p := make([]byte, min(sizes[i%len(sizes)], total-len(got)))
		n, err := s.Read(p)
		got = append(got, p[:n]...)
		if err != nil {
			t.Fatalf("read failed after %d of %d bytes: %v", len(got), total, err)
		}
		if len(s.readBuf) != streamReadSize {
			t.Fatalf("read buffer has %d bytes", len(s.readBuf))
		}
		if first == nil {
			first = &s.readBuf[0]
		} else if first != &s.readBuf[0] {
			t.Fatal("read buffer reallocated between reads")
		}
	}
	if n, err := s.Read(make([]byte, 1)); n != 0 || err != io.EOF {
		t.Fatalf("after the stream: n=%d err=%v", n, err)
	}
	return got
}

func firstDiff(a, b []byte) int {
	for i := range min(len(a), len(b)) {
		if a[i] != b[i] {
			return i
		}
	}
	return min(len(a), len(b))
}

func TestStreamConnSequentialReadsReuseBuffer(t *testing.T) {
	chunks := []int{1, 2, 5, 11, 64, 1500, 4093, 1 << 20}
	reads := []int{1, 3, 64, 1000, 7, 16384, 50000}
	for _, protocol := range []string{"auth_aes128_md5", "auth_chain_a", "auth_chain_e"} {
		for _, obfuscator := range Obfuscators() {
			t.Run(protocol+"/"+obfuscator, func(t *testing.T) {
				o := Options{Method: "aes-128-cfb", Password: "outer-secret", Protocol: protocol, Obfs: obfuscator,
					SinglePortType: "protocol", Users: []User{{ID: 101, Password: "user-one"}, {ID: 202, Password: "user-two"}}}
				msgs := streamMessages()
				want := bytes.Join(msgs, nil)

				// Server read path, handshake included, with frames split
				// across wire reads and plaintext split across caller reads.
				client := clientCodec(t, o, 202, "user-two")
				stream := clientStream(t, o, client, msgs)
				server, err := newCodec(o, obfs.NewObfsAuthChainData(protocol), nil)
				if err != nil {
					t.Fatal(err)
				}
				in := &streamConn{Conn: &chunkConn{data: stream, sizes: chunks}, codec: server}
				if got := readInPieces(t, in, len(want), reads); !bytes.Equal(got, want) {
					t.Fatalf("server read path differs at byte %d of %d", firstDiff(got, want), len(want))
				}
				if server.userID != 202 {
					t.Fatalf("server attributed the stream to %d", server.userID)
				}

				// Client read path after an in-process handshake.
				client, server = handshakePair(t, o, 101, "user-one")
				var replies []byte
				for _, m := range msgs {
					wire, err := server.encode(m)
					if err != nil {
						t.Fatal(err)
					}
					replies = append(replies, wire...)
				}
				out := &streamConn{Conn: &chunkConn{data: replies, sizes: chunks}, codec: client}
				if got := readInPieces(t, out, len(want), reads); !bytes.Equal(got, want) {
					t.Fatalf("client read path differs at byte %d of %d", firstDiff(got, want), len(want))
				}
			})
		}
	}
}

func TestStreamConnDropsLargeDrainedPending(t *testing.T) {
	s := &streamConn{Conn: &chunkConn{}}
	big := bytes.Repeat([]byte("x"), maxIdlePending+1)
	s.pending.Write(big)
	got := make([]byte, len(big))
	if _, err := io.ReadFull(s, got[:len(big)/2]); err != nil {
		t.Fatal(err)
	}
	if s.pending.Cap() == 0 {
		t.Fatal("pending buffer dropped before it was drained")
	}
	if _, err := io.ReadFull(s, got[len(big)/2:]); err != nil || !bytes.Equal(got, big) {
		t.Fatalf("pending data: %v", err)
	}
	if s.pending.Cap() != 0 {
		t.Fatalf("drained pending buffer kept %d bytes", s.pending.Cap())
	}
	s.pending.Write([]byte("small"))
	kept := s.pending.Cap()
	if _, err := io.ReadFull(s, got[:5]); err != nil || string(got[:5]) != "small" {
		t.Fatalf("small pending data: %v", err)
	}
	if s.pending.Cap() != kept {
		t.Fatal("small drained pending buffer was not kept for reuse")
	}
}

func TestRemotePortMatchesSscanf(t *testing.T) {
	for _, port := range []string{"0", "1", "443", "65535", "", "abc", "80abc", "+80", "-1", "-", " 8080", "0x10",
		"99999999999999999999"} {
		var want int
		fmt.Sscanf(port, "%d", &want)
		if got := remotePort(port); got != want {
			t.Errorf("remotePort(%q) = %d, fmt.Sscanf gave %d", port, got, want)
		}
	}
}
