package proxy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/sniff"
	C "github.com/sagernet/sing-box/constant"
)

// sniffTLSClientHello is a drop-in replacement for sniff.TLSClientHello. The
// vendored sniffer runs a full crypto/tls server handshake (allocating a
// tls.Conn plus handshake state) on every inspected stream just to read the
// server_name extension. This parser walks the ClientHello directly, using
// pooled buffers, and only falls back to the reference implementation when the
// bytes are not something it recognises, so any divergence in rejection is
// limited to "we were stricter than crypto/tls" and is corrected by the
// fallback. It sets exactly what the vendored sniffer sets on success:
// metadata.Protocol = C.ProtocolTLS and metadata.Domain = server_name (which
// may be empty).
//
// Like crypto/tls it reassembles a ClientHello that is fragmented across
// consecutive handshake records, bounded to 64 KiB of handshake payload, waits
// for a partial record to complete, requires each record to be non-empty and
// at most 16640 bytes (crypto/tls's pre-negotiation record cap), requires a
// non-empty server_name without a trailing dot, rejects a second host_name
// entry and duplicate extensions, and requires exact length framing. crypto/tls
// does not otherwise validate hostname characters, so neither does this.
// The bodies of extensions other than server_name are not validated: a
// malformed unrelated extension that crypto/tls would reject still yields the
// SNI here (the one place this parser is more lenient than the vendored one).
func sniffTLSClientHello(ctx context.Context, metadata *adapter.InboundContext, reader io.Reader) error {
	b := tlsSniffPool.Get().(*tlsSniffBuffers)
	defer tlsSniffPool.Put(b)
	n, err := io.ReadFull(reader, b.raw[:])
	full := err == nil
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return err
	}
	if n == 0 {
		return io.EOF
	}
	domain, err := parseClientHello(b.raw[:n], b.hello[:])
	if err == nil {
		metadata.Protocol = C.ProtocolTLS
		metadata.Domain = domain
		return nil
	}
	if errors.Is(err, sniff.ErrNeedMoreData) && !full {
		return err
	}
	// Not recognised, or larger than the reassembly bound: defer to the
	// reference implementation on the very same bytes (plus whatever is left
	// of the reader when our buffer filled up).
	replay := io.Reader(bytes.NewReader(b.raw[:n]))
	if full {
		replay = io.MultiReader(replay, reader)
	}
	return sniff.TLSClientHello(ctx, metadata, replay)
}

const (
	tlsRecordTypeHandshake  = 22
	tlsHandshakeClientHello = 1
	tlsExtensionServerName  = 0
	tlsRecordHeaderLen      = 5
	tlsHandshakeHeaderLen   = 4
	// crypto/tls maxCiphertextTLS13: the record payload cap enforced before
	// the protocol version has been negotiated, i.e. for the ClientHello.
	tlsMaxRecordPayload = 16384 + 256
	// crypto/tls maxHandshake: the largest handshake message it will buffer.
	tlsMaxHandshakeLen = 65536
	tlsSniffHelloCap   = tlsHandshakeHeaderLen + tlsMaxHandshakeLen
	// Raw input cap: a full-size ClientHello plus room for record headers.
	// Input that still looks incomplete at this size goes to the fallback.
	tlsSniffRawCap = tlsSniffHelloCap + 4096
	// Upper bound on distinct extensions tracked for the duplicate check.
	tlsSniffMaxExtensions = 64
)

var errNotClientHello = errors.New("not a TLS ClientHello")

type tlsSniffBuffers struct {
	raw   [tlsSniffRawCap]byte
	hello [tlsSniffHelloCap]byte
}

var tlsSniffPool = sync.Pool{New: func() any { return new(tlsSniffBuffers) }}

// parseClientHello reads one or more TLS handshake records from raw,
// reassembles the ClientHello they carry into hello (which must hold at least
// tlsSniffHelloCap bytes) and returns the server_name, or "" when the hello
// carries none. It returns sniff.ErrNeedMoreData when raw is a valid but
// incomplete prefix and errNotClientHello when the bytes cannot be a
// ClientHello. It never allocates except for the returned string.
func parseClientHello(raw []byte, hello []byte) (string, error) {
	// off is the next unread byte in raw, got the number of handshake bytes
	// copied into hello so far, and need the number required, which grows
	// from the handshake header to the full message once the header is known.
	off, got, need := 0, 0, tlsHandshakeHeaderLen
	for got < need {
		if len(raw)-off < tlsRecordHeaderLen {
			return "", sniff.ErrNeedMoreData
		}
		hdr := raw[off : off+tlsRecordHeaderLen]
		if hdr[0] != tlsRecordTypeHandshake || hdr[1] != 3 {
			return "", errNotClientHello
		}
		n := int(hdr[3])<<8 | int(hdr[4])
		if n == 0 || n > tlsMaxRecordPayload {
			return "", errNotClientHello
		}
		off += tlsRecordHeaderLen
		if len(raw)-off < n {
			// crypto/tls waits for the whole record before looking at it.
			return "", sniff.ErrNeedMoreData
		}
		got += copy(hello[got:], raw[off:off+n])
		off += n
		if need == tlsHandshakeHeaderLen && got >= tlsHandshakeHeaderLen {
			if hello[0] != tlsHandshakeClientHello {
				return "", errNotClientHello
			}
			msgLen := int(hello[1])<<16 | int(hello[2])<<8 | int(hello[3])
			if msgLen > tlsMaxHandshakeLen {
				return "", errNotClientHello
			}
			need += msgLen
		}
	}
	return parseClientHelloBody(hello[tlsHandshakeHeaderLen:need])
}

// parseClientHelloBody mirrors the framing checks of crypto/tls's
// clientHelloMsg.unmarshal for everything up to and including the server_name
// extension.
func parseClientHelloBody(s []byte) (string, error) {
	// client_version(2) random(32) session_id<0..32>
	if len(s) < 2+32+1 {
		return "", errNotClientHello
	}
	s = s[2+32:]
	sidLen := int(s[0])
	s = s[1:]
	if len(s) < sidLen {
		return "", errNotClientHello
	}
	s = s[sidLen:]
	// cipher_suites<2..2^16-2>
	if len(s) < 2 {
		return "", errNotClientHello
	}
	csLen := int(s[0])<<8 | int(s[1])
	s = s[2:]
	if csLen%2 != 0 || len(s) < csLen {
		return "", errNotClientHello
	}
	s = s[csLen:]
	// compression_methods<1..2^8-1>
	if len(s) < 1 {
		return "", errNotClientHello
	}
	cmLen := int(s[0])
	s = s[1:]
	if len(s) < cmLen {
		return "", errNotClientHello
	}
	s = s[cmLen:]
	if len(s) == 0 {
		// Extensions are optional; no SNI.
		return "", nil
	}
	if len(s) < 2 {
		return "", errNotClientHello
	}
	extLen := int(s[0])<<8 | int(s[1])
	s = s[2:]
	if len(s) != extLen {
		return "", errNotClientHello
	}
	var (
		seen   [tlsSniffMaxExtensions]uint16
		nSeen  int
		domain string
	)
	for len(s) > 0 {
		if len(s) < 4 {
			return "", errNotClientHello
		}
		typ := uint16(s[0])<<8 | uint16(s[1])
		l := int(s[2])<<8 | int(s[3])
		s = s[4:]
		if len(s) < l {
			return "", errNotClientHello
		}
		for i := 0; i < nSeen; i++ {
			if seen[i] == typ {
				return "", errNotClientHello
			}
		}
		if nSeen == len(seen) {
			return "", errNotClientHello
		}
		seen[nSeen] = typ
		nSeen++
		ext := s[:l]
		s = s[l:]
		if typ != tlsExtensionServerName {
			continue
		}
		// RFC 6066, Section 3: ServerNameList<1..2^16-1>
		if len(ext) < 2 {
			return "", errNotClientHello
		}
		listLen := int(ext[0])<<8 | int(ext[1])
		ext = ext[2:]
		if listLen == 0 || len(ext) != listLen {
			return "", errNotClientHello
		}
		for len(ext) > 0 {
			if len(ext) < 3 {
				return "", errNotClientHello
			}
			nameType := ext[0]
			nameLen := int(ext[1])<<8 | int(ext[2])
			ext = ext[3:]
			if nameLen == 0 || len(ext) < nameLen {
				return "", errNotClientHello
			}
			name := ext[:nameLen]
			ext = ext[nameLen:]
			if nameType != 0 {
				continue
			}
			// Multiple names of the same name_type are prohibited, and an
			// SNI value may not include a trailing dot.
			if domain != "" || name[nameLen-1] == '.' {
				return "", errNotClientHello
			}
			domain = string(name)
		}
	}
	return domain, nil
}
