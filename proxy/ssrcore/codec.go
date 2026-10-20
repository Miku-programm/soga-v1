package ssrcore

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
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
	billingIDs      map[string]int64
	client          bool
	clientHandshake []byte
}

func uidBytes(id int64) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, uint32(id))
	return b
}

func newCodec(o Options, replay core.ObfsProtocolService, remote net.Addr) (*codec, error) {
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
	c := &codec{enc: enc, protocol: p, obfs: b}
	users := make(map[string]string)
	c.billingIDs = make(map[string]int64)
	if o.SinglePortType == "protocol" {
		for _, u := range o.Users {
			uid := string(uidBytes(int64(u.wireID())))
			users[uid] = u.Password
			c.billingIDs[uid] = u.ID
		}
	} else {
		c.userID = o.Users[0].ID
	}
	overhead := p.GetOverhead(false) + b.GetOverhead(false)
	for _, part := range []obfs.Plain{p, b} {
		info := obfs.NewServerInfo()
		info.SetProtocolService(replay)
		info.SetHost(o.Listen)
		info.SetPort(int(o.Port))
		if remote != nil {
			host, port, _ := net.SplitHostPort(remote.String())
			info.SetClient(net.ParseIP(host))
			var n int
			fmt.Sscanf(port, "%d", &n)
			info.SetClientPort(n)
		}
		info.SetKey(enc.Key)
		info.SetKeyStr(enc.KeyStr)
		info.SetIv(enc.IVOut)
		info.SetTCPMss(obfs.TCP_MSS)
		info.SetBufferSize(obfs.BUF_SIZE - overhead)
		info.SetOverhead(overhead)
		info.SetUsers(users)
		if c.userID != 0 {
			info.SetIdentity(uidBytes(int64(o.Users[0].wireID())))
		}
		info.SetUpdateUserFunc(func(uid []byte) {
			if len(uid) == 4 && users[string(uid)] != "" {
				c.userID = c.billingIDs[string(uid)]
			}
		})
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

type streamConn struct {
	net.Conn
	codec   *codec
	stateMu sync.Mutex
	readMu  sync.Mutex
	writeMu sync.Mutex
	pending bytes.Buffer
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
		return s.pending.Read(p)
	}
	b := make([]byte, 32*1024)
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
			return s.pending.Read(p)
		}
		if readErr != nil {
			return 0, readErr
		}
	}
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
