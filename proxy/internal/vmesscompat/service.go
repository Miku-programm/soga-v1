package vmess

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"encoding/binary"
	"hash"
	"hash/crc32"
	"io"
	"math"
	"net"
	"slices"
	"sync"
	"time"
	"unsafe"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/replay"
	"github.com/sagernet/sing/common/rw"

	"github.com/gofrs/uuid/v5"
)

type Handler interface {
	N.TCPConnectionHandlerEx
	N.UDPConnectionHandlerEx
}

var (
	ErrBadHeader    = E.New("bad header")
	ErrBadTimestamp = E.New("bad timestamp")
	ErrReplay       = E.New("replayed request")
	ErrBadRequest   = E.New("bad request")
	ErrBadVersion   = E.New("bad version")
)

type Service[U comparable] struct {
	userKey              map[U][16]byte
	userIdCipher         map[U]cipher.Block
	replayFilter         replay.Filter
	handler              Handler
	time                 func() time.Time
	disableHeaderProtect bool
	authMode             string
	reducedMemory        bool
	authCache            AuthenticationCache
	legacyAccess         sync.RWMutex
	legacyUpdate         sync.Mutex
	legacyUsers          []U
	legacyIDs            []legacyIdentity
	alterIdMap           map[[16]byte]legacyEntry
	legacyBase           int64
	legacyFrom           int64
	legacyTo             int64
	alterIdUpdateTask    *time.Ticker
	alterIdUpdateDone    chan struct{}
}

// Legacy (MD5/alterId) authentication table.
//
// alterIdMap maps HMAC-MD5(key, big-endian unix second) to a compact
// legacyEntry, for every identity in legacyIDs and every second in the
// retained range [legacyFrom, legacyTo] = [now-window, now+window+10] as of
// the last refresh. The clock window itself is enforced at lookup by
// validLegacyTime. A periodic refresh only hashes the seconds that enter and
// leave the range; the table is built from scratch only when the user set
// changes or the clock jumps backwards or by more than the window.
//
// Lookups read alterIdMap, legacyUsers, legacyIDs and legacyBase under
// legacyAccess.RLock. Writers hold legacyUpdate for their whole run and take
// the legacyAccess write lock only to install changes, so they may read those
// fields, and the writer-only legacyFrom and legacyTo, without legacyAccess.
// legacyUsers and legacyIDs change only in UpdateUsers, which also writes
// userKey and userIdCipher.

const (
	// legacyRefreshSeconds is the refresh period of the legacy table, which
	// also covers that much clock lookahead beyond the window.
	legacyRefreshSeconds = 10

	// legacyApplyBatch bounds the map changes applied per write-lock hold.
	legacyApplyBatch = 4096
)

type legacyIdentity struct {
	key   [16]byte // HMAC key: an alterId UUID, or the user UUID for alterId=0
	user  uint32   // index into legacyUsers
	index uint32   // alterId index of key for this user
}

type legacyEntry struct {
	id     uint32 // index into legacyIDs
	second uint32 // unix second minus legacyBase
}

type legacyOp struct {
	authID [16]byte
	entry  legacyEntry
	remove bool
}

func NewService[U comparable](handler Handler, options ...ServiceOption) *Service[U] {
	service := &Service[U]{
		replayFilter: replay.NewSimple(time.Second * 120),
		handler:      handler,
		time:         time.Now,
	}
	anyService := (*Service[string])(unsafe.Pointer(service))
	for _, option := range options {
		option(anyService)
	}
	return service
}

func (s *Service[U]) UpdateUsers(userList []U, userIdList []string, alterIdList []int) error {
	userKeyMap := make(map[U][16]byte)
	userIdCipherMap := make(map[U]cipher.Block)
	userAlterIds := make(map[U][][16]byte)
	// legacyUsers keeps first-appearance order so that an unchanged user list
	// yields an identical identity set and skips the table rebuild.
	var legacyUsers []U
	for i, user := range userList {
		userId := userIdList[i]
		userUUID, err := uuid.FromString(userId)
		if err != nil {
			userUUID = uuid.NewV5(uuid.Nil, userId)
		}
		userCmdKey := Key(userUUID)
		userKeyMap[user] = userCmdKey
		userIdCipher, err := aes.NewCipher(KDF(userCmdKey[:], KDFSaltConstAuthIDEncryptionKey)[:16])
		if err != nil {
			return err
		}
		alterId := alterIdList[i]
		if s.authMode == "aead" || (s.authMode != "md5" && alterId == 0) {
			userIdCipherMap[user] = userIdCipher
		}
		if s.authMode == "aead" {
			continue
		}
		var alterIds [][16]byte
		if alterId > 0 {
			alterIds = make([][16]byte, 0, alterId)
			currentId := userUUID
			for j := 0; j < alterId; j++ {
				currentId = AlterId(currentId)
				alterIds = append(alterIds, currentId)
			}
		} else {
			// Documented compatibility: alterId=0 accepts UUID-based MD5.
			alterIds = [][16]byte{[16]byte(userUUID)}
		}
		if _, loaded := userAlterIds[user]; !loaded {
			legacyUsers = append(legacyUsers, user)
		}
		userAlterIds[user] = alterIds
	}
	var legacyIDs []legacyIdentity
	for userIndex, user := range legacyUsers {
		for alterIndex, key := range userAlterIds[user] {
			legacyIDs = append(legacyIDs, legacyIdentity{key: key, user: uint32(userIndex), index: uint32(alterIndex)})
		}
	}
	s.userKey = userKeyMap
	s.userIdCipher = userIdCipherMap
	s.updateLegacyIdentities(legacyUsers, legacyIDs)
	return nil
}

func (s *Service[U]) Start() error {
	if len(s.legacyIDs) > 0 {
		s.alterIdUpdateTask = time.NewTicker(legacyRefreshSeconds * time.Second)
		s.alterIdUpdateDone = make(chan struct{})
		go s.loopGenerateLegacyKeys()
	}
	return nil
}

func (s *Service[U]) Close() error {
	if s.alterIdUpdateTask != nil {
		s.alterIdUpdateTask.Stop()
		close(s.alterIdUpdateDone)
	}
	return nil
}

func (s *Service[U]) loopGenerateLegacyKeys() {
	for {
		select {
		case <-s.alterIdUpdateDone:
			return
		case <-s.alterIdUpdateTask.C:
		}
		s.generateLegacyKeys()
	}
}

// generateLegacyKeys moves the legacy table to the current time.
func (s *Service[U]) generateLegacyKeys() {
	s.legacyUpdate.Lock()
	defer s.legacyUpdate.Unlock()
	s.refreshLegacyKeys(s.time().Unix())
}

// updateLegacyIdentities installs a new identity set with a full table build,
// unless it equals the installed set, in which case the table is only
// refreshed.
func (s *Service[U]) updateLegacyIdentities(users []U, ids []legacyIdentity) {
	s.legacyUpdate.Lock()
	defer s.legacyUpdate.Unlock()
	nowSec := s.time().Unix()
	if slices.Equal(users, s.legacyUsers) && slices.Equal(ids, s.legacyIDs) {
		s.refreshLegacyKeys(nowSec)
		return
	}
	from, to := s.legacyRange(nowSec)
	table := buildLegacyTable(ids, from, to)
	s.legacyAccess.Lock()
	s.legacyUsers = users
	s.legacyIDs = ids
	s.swapLegacyTable(table, from, to)
	s.legacyAccess.Unlock()
}

// refreshLegacyKeys moves the retained range to nowSec. Only the seconds that
// enter or leave the range are hashed, outside legacyAccess; the resulting map
// changes are applied in batches, each under a short write lock. A lookup may
// observe a partly applied refresh, which differs from the states before and
// after it only in seconds that validLegacyTime rejects at that time. The
// caller holds legacyUpdate.
func (s *Service[U]) refreshLegacyKeys(nowSec int64) {
	ids := s.legacyIDs
	if len(ids) == 0 {
		return
	}
	from, to := s.legacyRange(nowSec)
	shift := from - s.legacyFrom
	if shift == 0 {
		return
	}
	if shift < 0 || shift > s.legacyWindow() || to-s.legacyBase > math.MaxUint32 {
		// The clock went backwards or jumped further than the window.
		table := buildLegacyTable(ids, from, to)
		s.legacyAccess.Lock()
		s.swapLegacyTable(table, from, to)
		s.legacyAccess.Unlock()
		return
	}
	// 0 < shift <= window < to-from, so [legacyFrom, from) leaves the range
	// and (legacyTo, to] enters it, shift seconds each per identity.
	base := s.legacyBase
	perIdentity := 2 * int(shift)
	batchIdentities := max(1, legacyApplyBatch/perIdentity)
	ops := make([]legacyOp, 0, min(len(ids), batchIdentities)*perIdentity)
	for start := 0; start < len(ids); start += batchIdentities {
		end := min(start+batchIdentities, len(ids))
		ops = ops[:0]
		for i := start; i < end; i++ {
			mac := hmac.New(md5.New, ids[i].key[:])
			for ts := s.legacyFrom; ts < from; ts++ {
				ops = append(ops, legacyOp{authID: legacyAuthID(mac, ts), entry: legacyEntry{id: uint32(i), second: uint32(ts - base)}, remove: true})
			}
			for ts := s.legacyTo + 1; ts <= to; ts++ {
				ops = append(ops, legacyOp{authID: legacyAuthID(mac, ts), entry: legacyEntry{id: uint32(i), second: uint32(ts - base)}})
			}
		}
		s.applyLegacyOps(ops)
	}
	s.legacyFrom, s.legacyTo = from, to
}

// applyLegacyOps applies one batch of refresh changes under the write lock.
// A removal only deletes the entry it computed, never a different one stored
// under the same auth ID.
func (s *Service[U]) applyLegacyOps(ops []legacyOp) {
	s.legacyAccess.Lock()
	defer s.legacyAccess.Unlock()
	for _, op := range ops {
		if !op.remove {
			s.alterIdMap[op.authID] = op.entry
		} else if current, loaded := s.alterIdMap[op.authID]; loaded && current == op.entry {
			delete(s.alterIdMap, op.authID)
		}
	}
}

// swapLegacyTable installs a complete table covering [from, to]. The caller
// holds legacyUpdate and the legacyAccess write lock.
func (s *Service[U]) swapLegacyTable(table map[[16]byte]legacyEntry, from, to int64) {
	s.alterIdMap = table
	s.legacyBase = from
	s.legacyFrom = from
	s.legacyTo = to
}

// buildLegacyTable hashes every second of [from, to] for every identity into
// a presized map whose entry seconds are relative to from.
func buildLegacyTable(ids []legacyIdentity, from, to int64) map[[16]byte]legacyEntry {
	if len(ids) == 0 {
		return nil
	}
	table := make(map[[16]byte]legacyEntry, len(ids)*int(to-from+1))
	for i := range ids {
		mac := hmac.New(md5.New, ids[i].key[:])
		for ts := from; ts <= to; ts++ {
			table[legacyAuthID(mac, ts)] = legacyEntry{id: uint32(i), second: uint32(ts - from)}
		}
	}
	return table
}

// legacyAuthID returns the legacy auth ID HMAC-MD5(key, big-endian ts), where
// mac is a freshly created or reset hmac.New(md5.New, key). It leaves mac
// reset.
func legacyAuthID(mac hash.Hash, ts int64) (authID [16]byte) {
	var stamp [8]byte
	binary.BigEndian.PutUint64(stamp[:], uint64(ts))
	common.Must1(mac.Write(stamp[:]))
	mac.Sum(authID[:0])
	mac.Reset()
	return
}

// legacyWindow is the accepted MD5 clock skew in seconds.
func (s *Service[U]) legacyWindow() int64 {
	if s.reducedMemory {
		return 25
	}
	return CacheDurationSeconds
}

// legacyRange is the retained range of seconds at nowSec: the clock window
// plus one refresh period of lookahead.
func (s *Service[U]) legacyRange(nowSec int64) (from, to int64) {
	window := s.legacyWindow()
	return nowSec - window, nowSec + window + legacyRefreshSeconds
}

// lookupLegacyAuthID resolves a legacy MD5 auth ID to its user, alterId index
// and timestamp if it is in the table and inside the clock window.
func (s *Service[U]) lookupLegacyAuthID(authID [16]byte) (user U, alterIndex int, timestamp int64, ok bool) {
	s.legacyAccess.RLock()
	defer s.legacyAccess.RUnlock()
	entry, loaded := s.alterIdMap[authID]
	if !loaded {
		return
	}
	timestamp = s.legacyBase + int64(entry.second)
	if !s.validLegacyTime(timestamp) {
		return user, 0, 0, false
	}
	identity := s.legacyIDs[entry.id]
	return s.legacyUsers[identity.user], int(identity.index), timestamp, true
}

func (s *Service[U]) NewConnection(ctx context.Context, conn net.Conn, source M.Socksaddr, onClose N.CloseHandlerFunc) error {
	const headerLenBufferLen = 2 + CipherOverhead
	const aeadMinHeaderLen = 16 + headerLenBufferLen + 8 + CipherOverhead + 42
	minHeaderLen := aeadMinHeaderLen
	if len(s.legacyIDs) > 0 {
		minHeaderLen = 16 + 38
	}

	requestBuffer := buf.New()
	defer requestBuffer.Release()

	if !s.disableHeaderProtect {
		n, err := requestBuffer.ReadOnceFrom(conn)
		if err != nil {
			return err
		}
		if n < minHeaderLen {
			return ErrBadHeader
		}
	} else {
		_, err := requestBuffer.ReadAtLeastFrom(conn, minHeaderLen)
		if err != nil {
			return err
		}
	}

	authId := requestBuffer.To(16)
	var decodedId [16]byte
	var user U
	var found bool
	authenticate := func(currUser U, userIdBlock cipher.Block) (bool, error) {
		userIdBlock.Decrypt(decodedId[:], authId)
		timestamp := int64(binary.BigEndian.Uint64(decodedId[:]))
		checksum := binary.BigEndian.Uint32(decodedId[12:])
		if crc32.ChecksumIEEE(decodedId[:12]) != checksum {
			return false, nil
		}
		if math.Abs(math.Abs(float64(timestamp))-float64(time.Now().Unix())) > 120 {
			return false, ErrBadTimestamp
		}
		if !s.replayFilter.Check(decodedId[:]) {
			return false, ErrReplay
		}
		user = currUser
		return true, nil
	}
	var cached U
	var cachedPresent bool
	if s.authCache != nil {
		cached, cachedPresent = any(s.authCache.Candidate(source.Addr.String())).(U)
		if block, ok := s.userIdCipher[cached]; cachedPresent && ok {
			var err error
			found, err = authenticate(cached, block)
			if err != nil {
				return err
			}
		}
	}
	if !found {
		for currUser, userIdBlock := range s.userIdCipher {
			if cachedPresent && currUser == cached {
				continue
			}
			var err error
			found, err = authenticate(currUser, userIdBlock)
			if err != nil {
				return err
			}
			if found {
				break
			}
		}
	}

	var legacyProtocol bool
	var legacyTimestamp uint64
	if !found {
		copy(decodedId[:], authId)
		if currUser, _, timestamp, loaded := s.lookupLegacyAuthID(decodedId); loaded {
			found = true
			legacyProtocol = true
			user = currUser
			legacyTimestamp = uint64(timestamp)
		}
	}
	if !found {
		return ErrBadRequest
	}

	ctx = auth.ContextWithUser(ctx, user)
	cmdKey := s.userKey[user]
	var headerReader io.Reader
	var headerBuffer []byte

	var reader io.Reader
	var err error
	if legacyProtocol {
		requestBuffer.Advance(16)
		reader = io.MultiReader(bytes.NewReader(requestBuffer.Bytes()), conn)

		timeHash := md5.New()
		common.Must(binary.Write(timeHash, binary.BigEndian, legacyTimestamp))
		common.Must(binary.Write(timeHash, binary.BigEndian, legacyTimestamp))
		common.Must(binary.Write(timeHash, binary.BigEndian, legacyTimestamp))
		common.Must(binary.Write(timeHash, binary.BigEndian, legacyTimestamp))
		userKey := s.userKey[user]
		headerReader = NewStreamReader(reader, userKey[:], timeHash.Sum(nil))
		headerBuffer = make([]byte, 38)
		_, err = io.ReadFull(headerReader, headerBuffer)
		if err != nil {
			return E.Extend(ErrBadHeader, io.ErrShortBuffer)
		}
	} else {
		if requestBuffer.Len() < aeadMinHeaderLen {
			// Auto mode initially permits the shorter MD5 header. After AEAD
			// identity is confirmed, collect the rest of its fixed header.
			missing := aeadMinHeaderLen - requestBuffer.Len()
			if _, err := io.ReadFull(conn, requestBuffer.Extend(missing)); err != nil {
				return ErrBadHeader
			}
		}

		reader = conn

		const nonceIndex = 16 + headerLenBufferLen
		connectionNonce := requestBuffer.Range(nonceIndex, nonceIndex+8)

		lengthKey := KDF(cmdKey[:], KDFSaltConstVMessHeaderPayloadLengthAEADKey, authId, connectionNonce)[:16]
		lengthNonce := KDF(cmdKey[:], KDFSaltConstVMessHeaderPayloadLengthAEADIV, authId, connectionNonce)[:12]
		lengthBuffer, err := newAesGcm(lengthKey).Open(requestBuffer.Index(16), lengthNonce, requestBuffer.Range(16, nonceIndex), authId)
		if err != nil {
			return err
		}

		const headerIndex = nonceIndex + 8
		headerLength := int(binary.BigEndian.Uint16(lengthBuffer))
		needRead := headerLength + headerIndex + CipherOverhead - requestBuffer.Len()
		if needRead > 0 {
			_, err = requestBuffer.ReadFullFrom(conn, needRead)
			if err != nil {
				return err
			}
		}

		headerKey := KDF(cmdKey[:], KDFSaltConstVMessHeaderPayloadAEADKey, authId, connectionNonce)[:16]
		headerNonce := KDF(cmdKey[:], KDFSaltConstVMessHeaderPayloadAEADIV, authId, connectionNonce)[:12]
		headerBuffer, err = newAesGcm(headerKey).Open(requestBuffer.Index(headerIndex), headerNonce, requestBuffer.Range(headerIndex, headerIndex+headerLength+CipherOverhead), authId)
		if err != nil {
			return err
		}
		// replace with < if support mux
		if len(headerBuffer) <= 38 {
			return E.Extend(ErrBadHeader, io.ErrShortBuffer)
		}
		requestBuffer.Advance(headerIndex + headerLength + CipherOverhead)
		headerReader = bytes.NewReader(headerBuffer[38:])
	}

	version := headerBuffer[0]
	if version != Version {
		return E.Extend(ErrBadVersion, version)
	}

	requestBodyKey := make([]byte, 16)
	requestBodyNonce := make([]byte, 16)

	copy(requestBodyKey, headerBuffer[17:33])
	copy(requestBodyNonce, headerBuffer[1:17])

	responseHeader := headerBuffer[33]
	option := headerBuffer[34]
	paddingLen := int(headerBuffer[35] >> 4)
	security := headerBuffer[35] & 0x0F
	switch security {
	case SecurityTypeNone, SecurityTypeLegacy, SecurityTypeAes128Gcm, SecurityTypeChacha20Poly1305:
	default:
		return E.New("unknown security type: ", security)
	}
	command := headerBuffer[37]
	switch command {
	case CommandTCP, CommandUDP, CommandMux:
	default:
		return E.New("unknown command: ", command)
	}
	if command == CommandUDP && option == 0 {
		return E.New("bad packet connection")
	}
	var destination M.Socksaddr
	if command != CommandMux {
		destination, err = AddressSerializer.ReadAddrPort(headerReader)
		if err != nil {
			return err
		}
	}
	if paddingLen > 0 {
		_, err = io.CopyN(io.Discard, headerReader, int64(paddingLen))
		if err != nil {
			return E.Extend(ErrBadHeader, "bad padding")
		}
	}
	err = rw.SkipN(headerReader, 4)
	if err != nil {
		return err
	}
	if !legacyProtocol && requestBuffer.Len() > 0 {
		reader = bufio.NewCachedReader(reader, requestBuffer.ToOwned())
	}
	reader = CreateReader(reader, nil, requestBodyKey, requestBodyNonce, requestBodyKey, requestBodyNonce, security, option)
	if option&RequestOptionChunkStream != 0 && command == CommandTCP || command == CommandMux {
		reader = bufio.NewChunkReader(reader, ReadChunkSize)
	}
	rawConn := rawServerConn{
		Conn:           conn,
		legacyProtocol: legacyProtocol,
		requestKey:     requestBodyKey,
		requestNonce:   requestBodyNonce,
		responseHeader: responseHeader,
		security:       security,
		option:         option,
		reader:         bufio.NewExtendedReader(reader),
	}

	switch command {
	case CommandTCP:
		if s.authCache != nil {
			if name, ok := any(user).(string); ok {
				s.authCache.Remember(source.Addr.String(), name)
			}
		}
		s.handler.NewConnectionEx(ctx, &serverConn{rawConn}, source, destination, onClose)
	case CommandUDP:
		if s.authCache != nil {
			if name, ok := any(user).(string); ok {
				s.authCache.Remember(source.Addr.String(), name)
			}
		}
		s.handler.NewPacketConnectionEx(ctx, &serverPacketConn{rawConn, destination}, source, destination, onClose)
	case CommandMux:
		if s.authCache != nil {
			if name, ok := any(user).(string); ok {
				s.authCache.Remember(source.Addr.String(), name)
			}
		}
		return HandleMuxConnection(ctx, &serverConn{rawConn}, source, s.handler)
	default:
		return E.New("unknown command: ", command)
	}
	return nil
}

// IsLegacyAuthID recognizes an already generated, time-valid MD5 identity.
// Used only to preserve documented MD5 access while an AEAD source is blocked.
func (s *Service[U]) IsLegacyAuthID(header []byte) bool {
	if len(header) < 16 {
		return false
	}
	var id [16]byte
	copy(id[:], header)
	_, _, _, ok := s.lookupLegacyAuthID(id)
	return ok
}
func (s *Service[U]) validLegacyTime(ts int64) bool {
	window := s.legacyWindow()
	delta := ts - s.time().Unix()
	return delta >= -window && delta <= window
}

var _ N.EarlyWriter = (*rawServerConn)(nil)

type rawServerConn struct {
	net.Conn
	legacyProtocol bool
	requestKey     []byte
	requestNonce   []byte
	responseHeader byte
	security       byte
	option         byte
	reader         N.ExtendedReader
	writer         N.ExtendedWriter
}

func (c *rawServerConn) writeResponse() error {
	if c.legacyProtocol {
		responseKey := md5.Sum(c.requestKey)
		responseNonce := md5.Sum(c.requestNonce)
		headerWriter := NewStreamWriter(c.Conn, responseKey[:], responseNonce[:])
		_, err := headerWriter.Write([]byte{c.responseHeader, c.option, 0, 0})
		if err != nil {
			return E.Cause(err, "write response")
		}
		c.writer = bufio.NewExtendedWriter(CreateWriter(c.Conn, headerWriter, c.requestKey, c.requestNonce, responseKey[:], responseNonce[:], c.security, c.option))
	} else {
		responseBuffer := buf.NewSize(2 + CipherOverhead + 4 + CipherOverhead)
		defer responseBuffer.Release()

		_responseKey := sha256.Sum256(c.requestKey[:])
		responseKey := _responseKey[:16]
		_responseNonce := sha256.Sum256(c.requestNonce[:])
		responseNonce := _responseNonce[:16]

		headerLenKey := KDF(responseKey, KDFSaltConstAEADRespHeaderLenKey)[:16]
		headerLenNonce := KDF(responseNonce, KDFSaltConstAEADRespHeaderLenIV)[:12]
		headerLenCipher := newAesGcm(headerLenKey)
		binary.BigEndian.PutUint16(responseBuffer.Extend(2), 4)
		headerLenCipher.Seal(responseBuffer.Index(0), headerLenNonce, responseBuffer.Bytes(), nil)
		responseBuffer.Extend(CipherOverhead)

		headerKey := KDF(responseKey, KDFSaltConstAEADRespHeaderPayloadKey)[:16]
		headerNonce := KDF(responseNonce, KDFSaltConstAEADRespHeaderPayloadIV)[:12]
		headerCipher := newAesGcm(headerKey)
		common.Must(
			responseBuffer.WriteByte(c.responseHeader),
			responseBuffer.WriteByte(c.option),
			responseBuffer.WriteZeroN(2),
		)
		const headerIndex = 2 + CipherOverhead
		headerCipher.Seal(responseBuffer.Index(headerIndex), headerNonce, responseBuffer.From(headerIndex), nil)
		responseBuffer.Extend(CipherOverhead)

		_, err := c.Conn.Write(responseBuffer.Bytes())
		if err != nil {
			return err
		}

		c.writer = bufio.NewExtendedWriter(CreateWriter(c.Conn, nil, c.requestKey, c.requestNonce, responseKey, responseNonce, c.security, c.option))
	}
	return nil
}

func (c *rawServerConn) Close() error {
	return common.Close(
		c.Conn,
		c.reader,
	)
}

func (c *rawServerConn) FrontHeadroom() int {
	return MaxFrontHeadroom
}

func (c *rawServerConn) RearHeadroom() int {
	return MaxRearHeadroom
}

func (c *rawServerConn) ReaderOverhead() int {
	return ReaderOverhead(c.security, c.option)
}

func (c *rawServerConn) NeedHandshakeForWrite() bool {
	return c.writer == nil
}

func (c *rawServerConn) NeedAdditionalReadDeadline() bool {
	return true
}

func (c *rawServerConn) Upstream() any {
	return c.Conn
}

type serverConn struct {
	rawServerConn
}

func (c *serverConn) Read(b []byte) (n int, err error) {
	return c.reader.Read(b)
}

func (c *serverConn) Write(b []byte) (n int, err error) {
	if c.writer == nil {
		err = c.writeResponse()
		if err != nil {
			return
		}
	}
	return c.writer.Write(b)
}

func (c *serverConn) ReadBuffer(buffer *buf.Buffer) error {
	return c.reader.ReadBuffer(buffer)
}

func (c *serverConn) WriteBuffer(buffer *buf.Buffer) error {
	if c.writer == nil {
		err := c.writeResponse()
		if err != nil {
			buffer.Release()
			return err
		}
	}
	return c.writer.WriteBuffer(buffer)
}

func (c *serverConn) WriteTo(w io.Writer) (n int64, err error) {
	return bufio.Copy(w, c.reader)
}

func (c *serverConn) ReadFrom(r io.Reader) (n int64, err error) {
	if c.writer == nil {
		err = c.writeResponse()
		if err != nil {
			return
		}
	}
	return bufio.Copy(c.writer, r)
}

var _ PacketConn = (*serverPacketConn)(nil)

type serverPacketConn struct {
	rawServerConn
	destination M.Socksaddr
}

func (c *serverPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, err = c.reader.Read(p)
	if err != nil {
		return
	}
	addr = c.destination.UDPAddr()
	return
}

func (c *serverPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	if c.writer == nil {
		err = c.writeResponse()
		if err != nil {
			return
		}
	}
	return c.writer.Write(p)
}

func (c *serverPacketConn) ReadPacket(buffer *buf.Buffer) (destination M.Socksaddr, err error) {
	err = c.reader.ReadBuffer(buffer)
	if err != nil {
		return
	}
	destination = c.destination
	return
}

func (c *serverPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	if c.writer == nil {
		err := c.writeResponse()
		if err != nil {
			return err
		}
	}
	return c.writer.WriteBuffer(buffer)
}
