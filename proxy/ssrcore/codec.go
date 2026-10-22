package ssrcore

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"

	"reconstructed.local/soga/proxy/ssrcore/internal/vnet/common/ciphers"
	"reconstructed.local/soga/proxy/ssrcore/internal/vnet/common/obfs"
	"reconstructed.local/soga/proxy/ssrcore/internal/vnet/core"
)

type codec struct {
	enc             *ciphers.Encryptor
	protocol        obfs.Plain
	obfs            obfs.Plain
	userID          int64
	users           *userIndex
	client          bool
	clientHandshake []byte
}

// userIndex maps packed little-endian wire UIDs to user passwords and billing
// IDs for protocol single-port. It is immutable once built: the auth plugins
// only look passwords up (GetUsers()[uid], len(GetUsers())) and nothing calls
// SetUsers again, so one index is shared read-only by every codec of a
// listener. Users only change by rebuilding the listener (proxy.Server
// UpdateUsers recreates the inbound), which builds a fresh index.
type userIndex struct {
	passwords map[string]string
	billing   map[string]int64
}

// newUserIndex builds the index for o. Outside protocol single-port both maps
// are empty, as before.
func newUserIndex(o Options) *userIndex {
	if o.SinglePortType != "protocol" {
		return &userIndex{passwords: make(map[string]string), billing: make(map[string]int64)}
	}
	idx := &userIndex{
		passwords: make(map[string]string, len(o.Users)),
		billing:   make(map[string]int64, len(o.Users)),
	}
	for _, u := range o.Users {
		uid := string(uidBytes(int64(u.wireID())))
		idx.passwords[uid] = u.Password
		idx.billing[uid] = u.ID
	}
	return idx
}

func uidBytes(id int64) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, uint32(id))
	return b
}

// remotePort parses the port half of net.SplitHostPort. Decimal ports take the
// strconv path. Other input keeps the former fmt.Sscanf("%d") result as far as
// possible: leading blanks, an optional sign and the leading decimal digits are
// parsed; no digits or an out-of-range value yields 0.
func remotePort(port string) int {
	if n, err := strconv.Atoi(port); err == nil {
		return n
	}
	i := 0
	for i < len(port) && (port[i] == ' ' || port[i] == '\t') {
		i++
	}
	start := i
	if i < len(port) && (port[i] == '+' || port[i] == '-') {
		i++
	}
	digits := i
	for i < len(port) && port[i] >= '0' && port[i] <= '9' {
		i++
	}
	if i == digits {
		return 0
	}
	n, err := strconv.Atoi(port[start:i])
	if err != nil {
		return 0
	}
	return n
}

// newCodec builds a codec with its own user index. Listeners use
// newCodecWithUsers so all their connections and datagrams share one index.
func newCodec(o Options, replay core.ObfsProtocolService, remote net.Addr) (*codec, error) {
	return newCodecWithUsers(o, newUserIndex(o), replay, remote)
}

// newCodecWithUsers builds a per-connection (or per-datagram) codec on top of
// a shared, read-only user index built by newUserIndex from options with the
// same SinglePortType and Users. A nil index is built from o.
func newCodecWithUsers(o Options, users *userIndex, replay core.ObfsProtocolService, remote net.Addr) (*codec, error) {
	if users == nil {
		users = newUserIndex(o)
	}
	enc, err := ciphers.NewEncryptor(o.Method, o.Password)
	if err != nil {
		return nil, err
	}
	p, err := obfs.GetObfs(o.Protocol)
	if err != nil {
		return nil, err
	}
	b, err := obfs.GetObfs(o.Obfs)
	if err != nil {
		return nil, err
	}
	c := &codec{enc: enc, protocol: p, obfs: b, users: users}
	if o.SinglePortType != "protocol" {
		c.userID = o.Users[0].ID
	}
	var clientIP net.IP
	var clientPort int
	if remote != nil {
		host, port, _ := net.SplitHostPort(remote.String())
		clientIP = net.ParseIP(host)
		clientPort = remotePort(port)
	}
	// The billing user is per codec state; only the lookup tables are shared.
	updateUser := func(uid []byte) {
		if len(uid) == 4 && users.passwords[string(uid)] != "" {
			c.userID = users.billing[string(uid)]
		}
	}
	overhead := p.GetOverhead(false) + b.GetOverhead(false)
	for _, part := range []obfs.Plain{p, b} {
		info := obfs.NewServerInfo()
		info.SetProtocolService(replay)
		info.SetHost(o.Listen)
		info.SetPort(int(o.Port))
		if remote != nil {
			info.SetClient(clientIP)
			info.SetClientPort(clientPort)
		}
		info.SetKey(enc.Key)
		info.SetKeyStr(enc.KeyStr)
		info.SetIv(enc.IVOut)
		info.SetTCPMss(obfs.TCP_MSS)
		info.SetBufferSize(obfs.BUF_SIZE - overhead)
		info.SetOverhead(overhead)
		info.SetUsers(users.passwords)
		if c.userID != 0 {
			info.SetIdentity(uidBytes(int64(o.Users[0].wireID())))
		}
		info.SetUpdateUserFunc(updateUser)
		if part == p {
			info.SetProtocolParam(o.ProtocolParam)
		} else {
			info.SetObfsParam(o.ObfsParam)
		}
		part.SetServerInfo(info)
	}
	return c, nil
}

func (c *codec) authState() (authenticated, failed bool) {
	switch p := c.protocol.(type) {
	case *obfs.AuthAes128Sha1:
		return p.HasRecvHeader, p.RawTrans
	case *obfs.AuthChainA:
		return p.HasRecvHeader, p.RawTrans
	case *obfs.AuthSha1V4:
		return p.HasRecvHead, p.RawTrans
	default:
		return true, false
	}
}

func (c *codec) encode(data []byte) (out []byte, err error) {
	defer func() {
		if recover() != nil {
			out, err = nil, errors.New("ssr: invalid encode state")
		}
	}()
	if c.client {
		b, e := c.protocol.ClientPreEncrypt(data)
		if e == nil {
			b, e = c.enc.Encrypt(b)
		}
		if e == nil {
			b, e = c.obfs.ClientEncode(b)
		}
		return b, e
	}
	b, err := c.protocol.ServerPreEncrypt(data)
	if err == nil {
		b, err = c.enc.Encrypt(b)
	}
	if err == nil {
		b, err = c.obfs.ServerEncode(b)
	}
	return b, err
}

// decode returns optional handshake responses. No upstream "compatible" raw
// fallback may reach the router, even after the claimed UID was observed.
//
// decode does not retain data after it returns: the obfs and protocol plugins
// copy whatever they buffer (bytesx.ContactSlice, conbineToBytes, append to a
// nil or owned slice), and slices they hand back unchanged are always
// decrypted into a fresh buffer before use. streamConn relies on this to reuse
// its read buffer.
func (c *codec) decode(data []byte) (plain, response []byte, err error) {
	defer func() {
		if recover() != nil {
			plain, response, err = nil, nil, errors.New("ssr: malformed frame")
		}
	}()
	if c.client {
		var trailing []byte
		if tls, ok := c.obfs.(*obfs.ObfsTLS); ok && tls.HandshakeStatus != 8 {
			c.clientHandshake = append(c.clientHandshake, data...)
			if len(c.clientHandshake) > 65536 {
				return nil, nil, errors.New("ssr: TLS obfs handshake too large")
			}
			finished := 0
			changed := false
			for pos := 0; pos+5 <= len(c.clientHandshake); {
				end := pos + 5 + int(binary.BigEndian.Uint16(c.clientHandshake[pos+3:pos+5]))
				if end > len(c.clientHandshake) {
					break
				}
				typ := c.clientHandshake[pos]
				if changed && typ == 0x16 {
					finished = end
					break
				}
				if typ == 0x14 {
					changed = true
				}
				pos = end
			}
			if finished == 0 {
				return nil, nil, nil
			}
			data = c.clientHandshake[:finished]
			trailing = c.clientHandshake[finished:]
		}
		b, back, e := c.obfs.ClientDecode(data)
		if e != nil {
			return nil, nil, e
		}
		if back {
			response, e = c.obfs.ClientEncode(nil)
			if e != nil {
				return nil, nil, e
			}
			if len(trailing) > 0 {
				next, _, nextErr := c.obfs.ClientDecode(trailing)
				if nextErr != nil {
					return nil, nil, nextErr
				}
				b = append(b, next...)
			}
			c.clientHandshake = nil
		}
		b, e = c.enc.Decrypt(b)
		if e != nil {
			return nil, nil, e
		}
		c.protocol.GetServerInfo().SetRecvIv(c.enc.IVIn)
		plain, e = c.protocol.ClientPostDecrypt(b)
		return plain, response, e
	}
	data, decrypt, back, err := c.obfs.ServerDecode(data)
	if err != nil {
		return nil, nil, err
	}
	if back {
		response, err = c.obfs.ServerEncode(nil)
		if err != nil || len(data) == 0 {
			return nil, response, err
		}
	}
	if decrypt {
		data, err = c.enc.Decrypt(data)
		c.protocol.GetServerInfo().SetRecvIv(c.enc.IVIn)
		if err != nil {
			return nil, nil, err
		}
	}
	data, back, err = c.protocol.ServerPostDecrypt(data)
	authed, failed := c.authState()
	if err != nil || failed {
		return nil, nil, errors.New("ssr: authentication or framing failed")
	}
	if back {
		more, e := c.encode(nil)
		response, err = append(response, more...), e
	}
	if !authed || c.userID == 0 {
		return nil, response, err
	}
	return data, response, err
}

const (
	// streamReadSize is the wire read size of one streamConn.Read.
	streamReadSize = 32 * 1024
	// maxIdlePending is the largest drained pending capacity kept for reuse.
	maxIdlePending = 64 * 1024
)

type streamConn struct {
	net.Conn
	codec   *codec
	stateMu sync.Mutex
	readMu  sync.Mutex
	writeMu sync.Mutex
	pending bytes.Buffer
	readBuf []byte // wire buffer reused by Read, allocated lazily; guarded by readMu
	once    sync.Once
}

func (s *streamConn) Read(p []byte) (n int, err error) {
	s.readMu.Lock()
	defer s.readMu.Unlock()
	defer func() {
		if r := recover(); r != nil {
			err = errors.New("ssr: malformed frame")
			n = 0
		}
	}()
	if len(p) == 0 {
		return 0, nil
	}
	if s.pending.Len() > 0 {
		return s.readPending(p)
	}
	if s.readBuf == nil {
		s.readBuf = make([]byte, streamReadSize)
	}
	// decode never retains its input and its outputs are copied into pending
	// or written out before the next Conn.Read, so the buffer can be reused.
	b := s.readBuf
	for {
		n, readErr := s.Conn.Read(b)
		if n == 0 {
			return 0, readErr
		}
		s.writeMu.Lock()
		s.stateMu.Lock()
		plain, response, decodeErr := s.codec.decode(b[:n])
		s.stateMu.Unlock()
		if decodeErr == nil && len(response) > 0 {
			decodeErr = writeAll(s.Conn, response)
		}
		s.writeMu.Unlock()
		if decodeErr != nil {
			return 0, decodeErr
		}
		if len(plain) > 0 {
			s.pending.Write(plain)
			return s.readPending(p)
		}
		if readErr != nil {
			return 0, readErr
		}
	}
}

// readPending serves p from pending. Once drained, a pending buffer that grew
// beyond maxIdlePending is dropped so a burst does not pin its memory for the
// rest of the connection; smaller buffers are kept for reuse.
func (s *streamConn) readPending(p []byte) (int, error) {
	n, err := s.pending.Read(p)
	if s.pending.Len() == 0 && s.pending.Cap() > maxIdlePending {
		s.pending = bytes.Buffer{}
	}
	return n, err
}

func (s *streamConn) Write(p []byte) (int, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	s.stateMu.Lock()
	wire, err := s.codec.encode(p)
	s.stateMu.Unlock()
	if err == nil {
		err = writeAll(s.Conn, wire)
	}
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (s *streamConn) Close() error {
	err := s.Conn.Close()
	s.once.Do(func() {
		s.stateMu.Lock()
		defer s.stateMu.Unlock()
		s.codec.protocol.Dispose()
		s.codec.obfs.Dispose()
	})
	return err
}

func writeAll(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		p = p[n:]
	}
	return nil
}
