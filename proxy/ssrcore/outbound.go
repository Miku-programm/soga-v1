package ssrcore

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"reconstructed.local/soga/proxy/ssrcore/internal/vnet/common/ciphers/stream"
	"reconstructed.local/soga/proxy/ssrcore/internal/vnet/common/obfs"
)

type OutboundOptions struct {
	option.DialerOptions
	Server        string `json:"server"`
	ServerPort    uint16 `json:"server_port"`
	Method        string `json:"method"`
	Password      string `json:"password"`
	Protocol      string `json:"protocol"`
	Obfs          string `json:"obfs"`
	ProtocolParam string `json:"protocol_param,omitempty"`
	ObfsParam     string `json:"obfs_param,omitempty"`
}

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[OutboundOptions](registry, Type, NewOutbound)
}

type clientOutbound struct {
	outbound.Adapter
	dialer N.Dialer
	server M.Socksaddr
	config Options
}

func NewOutbound(ctx context.Context, _ adapter.Router, _ log.ContextLogger, tag string, o OutboundOptions) (adapter.Outbound, error) {
	if o.Protocol == "" {
		o.Protocol = "origin"
	}
	if o.Obfs == "" {
		o.Obfs = "plain"
	}
	address := M.ParseSocksaddrHostPort(o.Server, o.ServerPort)
	if !address.IsValid() || o.ServerPort == 0 || o.Password == "" ||
		!contains(Protocols(), o.Protocol) || !contains(Obfuscators(), o.Obfs) ||
		stream.GetStreamCipher(o.Method) == nil {
		return nil, errors.New("ssr: invalid outbound server, cipher, protocol or obfs")
	}
	d, err := dialer.New(ctx, o.DialerOptions, address.IsFqdn())
	if err != nil {
		return nil, err
	}
	return &clientOutbound{
		Adapter: outbound.NewAdapterWithDialerOptions(Type, tag, []string{"tcp", "udp"}, o.DialerOptions),
		dialer:  d, server: address,
		config: Options{Listen: o.Server, Port: o.ServerPort, Method: o.Method,
			Password: o.Password, Protocol: o.Protocol, Obfs: o.Obfs,
			ProtocolParam: o.ProtocolParam, ObfsParam: o.ObfsParam, SinglePortType: "protocol"},
	}, nil
}

func (c *clientOutbound) newCodec() (*codec, error) {
	k, err := newCodec(c.config, obfs.NewObfsAuthChainData(c.config.Protocol), nil)
	if err == nil {
		k.client = true
	}
	return k, err
}

func (c *clientOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if N.NetworkName(network) == "udp" {
		p, err := c.ListenPacket(ctx, destination)
		if err != nil {
			return nil, err
		}
		return bufio.NewBindPacketConn(p, destination), nil
	}
	if N.NetworkName(network) != "tcp" {
		return nil, errors.New("ssr: unsupported network")
	}
	k, err := c.newCodec()
	if err != nil {
		return nil, err
	}
	raw, err := c.dialer.DialContext(ctx, "tcp", c.server)
	if err != nil {
		return nil, err
	}
	conn := &streamConn{Conn: raw, codec: k}
	header, err := appendAddress(nil, destination)
	if err == nil {
		_, err = conn.Write(header)
	}
	if err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

func (c *clientOutbound) ListenPacket(ctx context.Context, _ M.Socksaddr) (net.PacketConn, error) {
	k, err := c.newCodec()
	if err != nil {
		return nil, err
	}
	raw, err := c.dialer.DialContext(ctx, "udp", c.server)
	if err != nil {
		return nil, err
	}
	return &clientPacketConn{Conn: raw, codec: k}, nil
}

type clientPacketConn struct {
	net.Conn
	codec  *codec
	mu     sync.Mutex
	readMu sync.Mutex
}

func (c *clientPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	defer func() {
		if recover() != nil {
			n, err = 0, errors.New("ssr: invalid UDP encoding")
		}
	}()
	c.mu.Lock()
	defer c.mu.Unlock()
	data, err := appendAddress(nil, M.SocksaddrFromNet(addr))
	if err != nil {
		return 0, err
	}
	data = append(data, p...)
	data, err = c.codec.protocol.ClientUDPPreEncrypt(data)
	if err != nil {
		return 0, err
	}
	iv, err := c.codec.enc.NewIV()
	if err != nil {
		return 0, err
	}
	data, err = c.codec.enc.EncryptAll(data, iv)
	if err == nil {
		_, err = c.Conn.Write(data)
	}
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *clientPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	defer func() {
		if recover() != nil {
			n, addr, err = 0, nil, errors.New("ssr: malformed UDP response")
		}
	}()
	c.readMu.Lock()
	defer c.readMu.Unlock()
	wire := make([]byte, 65535)
	for {
		n, err = c.Conn.Read(wire)
		if err != nil {
			return 0, nil, err
		}
		data, decodeErr := func() ([]byte, error) {
			c.mu.Lock()
			defer c.mu.Unlock()
			data, _, e := c.codec.enc.DecryptAll(wire[:n])
			if e == nil {
				data, e = c.codec.protocol.ClientUDPPostDecrypt(data)
			}
			return data, e
		}()
		if decodeErr != nil {
			return 0, nil, decodeErr
		}
		if len(data) == 0 {
			continue
		}
		r := bytes.NewReader(data)
		dest, err := readAddress(r)
		if err != nil {
			return 0, nil, err
		}
		if r.Len() > len(p) {
			return 0, nil, io.ErrShortBuffer
		}
		n, err = r.Read(p)
		if err == io.EOF {
			err = nil
		}
		return n, dest, err
	}
}
