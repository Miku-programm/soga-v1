package ssrcore

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	"reconstructed.local/soga/proxy/wireproxy"
)

func (s *server) acceptPackets() {
	b := make([]byte, 65535)
	for {
		n, source, err := s.udp.ReadFrom(b)
		if err != nil {
			return
		}
		s.handlePacket(b[:n], source)
	}
}

func (s *server) handlePacket(wire []byte, source net.Addr) {
	// Upstream parsers use slices; malformed unauthenticated packets must not
	// terminate the UDP reader or the process.
	defer func() { _ = recover() }()
	peer := source
	if s.options.UDPProxyProtocol {
		var err error
		wire, source, err = wireproxy.Datagram(wire, source, s.options.ForceProxyProtocol, s.options.ProxyProtocolTrusted)
		if err != nil {
			return
		}
	}
	options := s.options
	if options.SinglePortType == "obfs" {
		if !options.ObfsUDP {
			return
		}
		options.Users = []User{{ID: options.CarrierID, Password: options.Password}}
		options.Obfs = "plain" // UDP has no Host/SNI framing.
		options.ObfsParam = ""
	}
	// Each datagram still decodes with its own codec; only the user index is
	// shared (obfs mode narrows Users, but its index is empty either way).
	c, err := newCodecWithUsers(options, s.users, s.replay, source)
	if err != nil {
		return
	}
	data, iv, err := c.enc.DecryptAll(wire)
	if err != nil || len(data) == 0 {
		return
	}
	c.protocol.GetServerInfo().SetIv(iv)
	data, uid, err := c.protocol.ServerUDPPostDecrypt(data)
	if err != nil || len(data) == 0 {
		return
	}
	id := c.userID
	if s.options.SinglePortType == "protocol" {
		if len(uid) != 4 {
			return
		}
		id = c.users.billing[uid]
		if c.protocol.GetServerInfo().GetUsers()[uid] == "" {
			return
		}
	}
	r := bytes.NewReader(data)
	destination, err := readAddress(r)
	if err != nil {
		return
	}
	payload, _ := io.ReadAll(r)
	key := peer.String() + "/" + source.String() + "/" + strconv.FormatInt(id, 10)
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	pc := s.packets[key]
	created := pc == nil
	if pc == nil {
		if len(s.packets) >= 4096 {
			s.mu.Unlock()
			return
		}
		pc = &packetConn{server: s, source: peer, codec: c, uid: []byte(uid),
			key: key, queue: make(chan packet, 32), done: make(chan struct{}), changed: make(chan struct{}, 1)}
		s.packets[key] = pc
	}
	s.mu.Unlock()
	select {
	case pc.queue <- packet{data: payload, destination: destination}:
	default:
	}
	if created {
		ctx := s.ctx
		if s.options.SinglePortType == "obfs" {
			ctx = context.WithValue(ctx, unattributedKey{}, true)
		}
		go s.router.RoutePacketConnectionEx(ctx, pc, adapter.InboundContext{
			Inbound: s.Tag(), InboundType: Type, User: strconv.FormatInt(id, 10),
			Source: M.SocksaddrFromNet(source), Destination: destination,
		}, func(error) { pc.Close() })
	}
}

type packet struct {
	data        []byte
	destination M.Socksaddr
}

type packetConn struct {
	server   *server
	source   net.Addr
	codec    *codec
	uid      []byte
	key      string
	queue    chan packet
	done     chan struct{}
	changed  chan struct{}
	once     sync.Once
	writeMu  sync.Mutex
	mu       sync.Mutex
	deadline time.Time
}

func (p *packetConn) ReadPacket(b *buf.Buffer) (M.Socksaddr, error) {
	for {
		p.mu.Lock()
		deadline := p.deadline
		p.mu.Unlock()
		wait := 2 * time.Minute
		if !deadline.IsZero() && time.Until(deadline) < wait {
			wait = time.Until(deadline)
		}
		timer := time.NewTimer(wait)
		select {
		case packet := <-p.queue:
			timer.Stop()
			if len(packet.data) > b.FreeLen() {
				return M.Socksaddr{}, io.ErrShortBuffer
			}
			_, err := b.Write(packet.data)
			return packet.destination, err
		case <-p.done:
			timer.Stop()
			return M.Socksaddr{}, net.ErrClosed
		case <-p.changed:
			timer.Stop()
			continue
		case <-timer.C:
			return M.Socksaddr{}, os.ErrDeadlineExceeded
		}
	}
}

func (p *packetConn) WritePacket(b *buf.Buffer, destination M.Socksaddr) (err error) {
	defer b.Release()
	defer func() {
		if recover() != nil {
			err = errors.New("ssr: invalid UDP response")
		}
	}()
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	select {
	case <-p.done:
		return net.ErrClosed
	default:
	}
	data, err := appendAddress(nil, destination)
	if err != nil {
		return err
	}
	data = append(data, b.Bytes()...)
	data, err = p.codec.protocol.ServerUDPPreEncrypt(data, p.uid)
	if err != nil {
		return err
	}
	iv, err := p.codec.enc.NewIV()
	if err != nil {
		return err
	}
	data, err = p.codec.enc.EncryptAll(data, iv)
	if err != nil {
		return err
	}
	_, err = p.server.udp.WriteTo(data, p.source)
	return err
}

func (p *packetConn) Close() error {
	p.once.Do(func() {
		close(p.done)
		p.server.mu.Lock()
		if p.server.packets[p.key] == p {
			delete(p.server.packets, p.key)
		}
		p.server.mu.Unlock()
	})
	return nil
}

func (p *packetConn) LocalAddr() net.Addr { return p.server.udp.LocalAddr() }
func (p *packetConn) SetDeadline(t time.Time) error {
	return p.SetReadDeadline(t)
}
func (p *packetConn) SetReadDeadline(t time.Time) error {
	p.mu.Lock()
	p.deadline = t
	p.mu.Unlock()
	select {
	case p.changed <- struct{}{}:
	default:
	}
	return nil
}
func (p *packetConn) SetWriteDeadline(t time.Time) error { return nil }
