package vmess

import (
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"github.com/gofrs/uuid/v5"
)

// legacyTestClock is an injectable clock in whole seconds that is safe for
// concurrent use.
type legacyTestClock struct {
	sec atomic.Int64
}

func newLegacyTestClock(sec int64) *legacyTestClock {
	clock := &legacyTestClock{}
	clock.sec.Store(sec)
	return clock
}

func (c *legacyTestClock) now() time.Time { return time.Unix(c.sec.Load(), 0) }

func (c *legacyTestClock) unix() int64 { return c.sec.Load() }

func (c *legacyTestClock) advance(seconds int64) { c.sec.Add(seconds) }

type legacyTestUser struct {
	name    string
	id      string
	alterId int
}

var legacyTestUsers = []legacyTestUser{
	{name: "a", id: "91c43637-0cdc-46c7-bb6c-cf1b09f52c2c", alterId: 0},
	{name: "b", id: "5c0b6d1e-8a7e-4c43-9a8f-2f9d1f0d6b11", alterId: 2},
	{name: "c", id: "c-legacy-user", alterId: 3},
}

func newLegacyTestService(t *testing.T, clock *legacyTestClock, mode string, reduced bool, users []legacyTestUser) *Service[string] {
	t.Helper()
	s := NewService[string](nil, ServiceWithAuthMode(mode), ServiceWithReducedMemory(reduced), ServiceWithTimeFunc(clock.now))
	updateLegacyTestUsers(t, s, users)
	return s
}

func updateLegacyTestUsers(t *testing.T, s *Service[string], users []legacyTestUser) {
	t.Helper()
	names := make([]string, len(users))
	ids := make([]string, len(users))
	alterIds := make([]int, len(users))
	for i, user := range users {
		names[i], ids[i], alterIds[i] = user.name, user.id, user.alterId
	}
	if err := s.UpdateUsers(names, ids, alterIds); err != nil {
		t.Fatal(err)
	}
}

// legacyTestKeys returns the HMAC keys a legacy client of user signs with,
// in alterId index order.
func legacyTestKeys(user legacyTestUser) [][16]byte {
	id, err := uuid.FromString(user.id)
	if err != nil {
		id = uuid.NewV5(uuid.Nil, user.id)
	}
	if user.alterId == 0 {
		return [][16]byte{[16]byte(id)}
	}
	keys := make([][16]byte, 0, user.alterId)
	for i := 0; i < user.alterId; i++ {
		id = AlterId(id)
		keys = append(keys, [16]byte(id))
	}
	return keys
}

func legacyTestIdentities(users []legacyTestUser) int {
	count := 0
	for _, user := range users {
		count += len(legacyTestKeys(user))
	}
	return count
}

// legacyTestAuthID computes a legacy auth ID the way a client does.
func legacyTestAuthID(key [16]byte, ts int64) [16]byte {
	mac := hmac.New(md5.New, key[:])
	var stamp [8]byte
	binary.BigEndian.PutUint64(stamp[:], uint64(ts))
	mac.Write(stamp[:])
	var authID [16]byte
	mac.Sum(authID[:0])
	return authID
}

func legacyTestAccepted(s *Service[string], key [16]byte, ts int64) bool {
	authID := legacyTestAuthID(key, ts)
	return s.IsLegacyAuthID(authID[:])
}

func legacyTestWindow(reduced bool) int64 {
	if reduced {
		return 25
	}
	return CacheDurationSeconds
}

// checkLegacyTable asserts that the table holds exactly the seconds
// [now-window, now+window+10] of every identity of users, that auth IDs
// inside the clock window resolve to the right user, alterId index and
// timestamp, and that auth IDs outside it are rejected.
func checkLegacyTable(t *testing.T, s *Service[string], clock *legacyTestClock, users []legacyTestUser, window int64) {
	t.Helper()
	now := clock.unix()
	identities := legacyTestIdentities(users)
	perIdentity := int(2*window + legacyRefreshSeconds + 1)
	if len(s.alterIdMap) != identities*perIdentity {
		t.Fatalf("now %d: table size %d, want %d identities x %d seconds", now, len(s.alterIdMap), identities, perIdentity)
	}
	for _, user := range users {
		for index, key := range legacyTestKeys(user) {
			for ts := now - window - 3; ts <= now+window+legacyRefreshSeconds+3; ts++ {
				authID := legacyTestAuthID(key, ts)
				_, stored := s.alterIdMap[authID]
				wantStored := ts >= now-window && ts <= now+window+legacyRefreshSeconds
				if stored != wantStored {
					t.Fatalf("now %d: user %s alterId #%d second %+d stored %v, want %v", now, user.name, index, ts-now, stored, wantStored)
				}
				gotUser, gotIndex, gotTime, ok := s.lookupLegacyAuthID(authID)
				wantOK := ts >= now-window && ts <= now+window
				if ok != wantOK || s.IsLegacyAuthID(authID[:]) != wantOK {
					t.Fatalf("now %d: user %s alterId #%d second %+d accepted %v, want %v", now, user.name, index, ts-now, ok, wantOK)
				}
				if ok && (gotUser != user.name || gotIndex != index || gotTime != ts) {
					t.Fatalf("now %d: second %+d resolved to %s #%d at %d, want %s #%d at %d", now, ts-now, gotUser, gotIndex, gotTime, user.name, index, ts)
				}
			}
		}
	}
}

func TestLegacyTableEntryIsCompact(t *testing.T) {
	if size := unsafe.Sizeof(legacyEntry{}); size != 8 {
		t.Fatalf("legacy table value is %d bytes, want 8", size)
	}
}

func TestLegacyTableIncrementalRefresh(t *testing.T) {
	steps := []int64{10, 10, 9, 11, 10, 1, 10, 25}
	for _, reduced := range []bool{false, true} {
		clock := newLegacyTestClock(1700000000)
		s := newLegacyTestService(t, clock, "auto", reduced, legacyTestUsers)
		window := legacyTestWindow(reduced)
		checkLegacyTable(t, s, clock, legacyTestUsers, window)
		base := s.legacyBase
		for tick := 0; tick < 40; tick++ {
			clock.advance(steps[tick%len(steps)])
			s.generateLegacyKeys()
			checkLegacyTable(t, s, clock, legacyTestUsers, window)
		}
		if s.legacyBase != base {
			t.Fatalf("reduced=%v: periodic refresh rebuilt the table", reduced)
		}
		// The incrementally maintained table equals a fresh full build.
		fresh := newLegacyTestService(t, clock, "auto", reduced, legacyTestUsers)
		if len(fresh.alterIdMap) != len(s.alterIdMap) {
			t.Fatalf("reduced=%v: table size %d, fresh build %d", reduced, len(s.alterIdMap), len(fresh.alterIdMap))
		}
		for authID, entry := range s.alterIdMap {
			freshEntry, ok := fresh.alterIdMap[authID]
			if !ok || freshEntry.id != entry.id || fresh.legacyBase+int64(freshEntry.second) != s.legacyBase+int64(entry.second) {
				t.Fatalf("reduced=%v: refreshed entry %+v differs from the fresh build", reduced, entry)
			}
		}
	}
}

func TestLegacyTableClockJumpRebuilds(t *testing.T) {
	for _, reduced := range []bool{false, true} {
		clock := newLegacyTestClock(1700000000)
		s := newLegacyTestService(t, clock, "auto", reduced, legacyTestUsers)
		window := legacyTestWindow(reduced)
		for _, step := range []int64{window + 1, 3, -30, -1, 10, 5 * window, window} {
			base := s.legacyBase
			clock.advance(step)
			s.generateLegacyKeys()
			checkLegacyTable(t, s, clock, legacyTestUsers, window)
			wantRebuild := step < 0 || step > window
			if rebuilt := s.legacyBase != base; rebuilt != wantRebuild {
				t.Fatalf("reduced=%v step %d: rebuilt %v, want %v", reduced, step, rebuilt, wantRebuild)
			}
		}
	}
}

func TestLegacyTableUserUpdate(t *testing.T) {
	clock := newLegacyTestClock(1700000000)
	s := newLegacyTestService(t, clock, "auto", false, legacyTestUsers)
	window := legacyTestWindow(false)

	// Reloading an unchanged user list only refreshes the table.
	base := s.legacyBase
	clock.advance(10)
	updateLegacyTestUsers(t, s, legacyTestUsers)
	if s.legacyBase != base {
		t.Fatal("unchanged user list rebuilt the table")
	}
	checkLegacyTable(t, s, clock, legacyTestUsers, window)

	// Drop b, shrink c from three alterIds to one and add d.
	updated := []legacyTestUser{
		legacyTestUsers[0],
		{name: "c", id: legacyTestUsers[2].id, alterId: 1},
		{name: "d", id: "0f1e2d3c-4b5a-4968-8776-a5b4c3d2e1f0", alterId: 0},
	}
	clock.advance(10)
	updateLegacyTestUsers(t, s, updated)
	checkLegacyTable(t, s, clock, updated, window)
	removed := legacyTestKeys(legacyTestUsers[1])
	removed = append(removed, legacyTestKeys(legacyTestUsers[2])[1:]...)
	for tick := 0; tick < 30; tick++ {
		for _, key := range removed {
			if legacyTestAccepted(s, key, clock.unix()) {
				t.Fatalf("tick %d: auth ID of a removed identity accepted", tick)
			}
		}
		clock.advance(10)
		s.generateLegacyKeys()
		checkLegacyTable(t, s, clock, updated, window)
	}
}

func TestLegacyTableAuthModes(t *testing.T) {
	users := []legacyTestUser{
		{name: "zero", id: "91c43637-0cdc-46c7-bb6c-cf1b09f52c2c", alterId: 0},
		{name: "alter", id: "5c0b6d1e-8a7e-4c43-9a8f-2f9d1f0d6b11", alterId: 2},
	}
	alterUUID := uuid.Must(uuid.FromString(users[1].id))
	for _, mode := range []string{"auto", "md5", "aead"} {
		clock := newLegacyTestClock(1700000000)
		s := newLegacyTestService(t, clock, mode, false, users)
		_, zeroAEAD := s.userIdCipher["zero"]
		_, alterAEAD := s.userIdCipher["alter"]
		if zeroAEAD != (mode != "md5") || alterAEAD != (mode == "aead") {
			t.Fatalf("%s: AEAD identities zero=%v alter=%v", mode, zeroAEAD, alterAEAD)
		}
		if mode == "aead" {
			if s.alterIdMap != nil || len(s.legacyIDs) != 0 || len(s.legacyUsers) != 0 {
				t.Fatalf("aead: built a legacy table of %d entries", len(s.alterIdMap))
			}
			clock.advance(10)
			s.generateLegacyKeys()
			if s.alterIdMap != nil {
				t.Fatal("aead: refresh built a legacy table")
			}
			for _, user := range users {
				for _, key := range legacyTestKeys(user) {
					if legacyTestAccepted(s, key, clock.unix()) {
						t.Fatalf("aead: legacy auth ID of %s accepted", user.name)
					}
				}
			}
		} else {
			// alterId=0 users authenticate with their UUID, alterId>0 users
			// with their alterIds but not with their UUID.
			checkLegacyTable(t, s, clock, users, legacyTestWindow(false))
			if legacyTestAccepted(s, [16]byte(alterUUID), clock.unix()) {
				t.Fatalf("%s: UUID-based MD5 accepted for an alterId>0 user", mode)
			}
		}
		if err := s.Start(); err != nil {
			t.Fatal(err)
		}
		if started := s.alterIdUpdateTask != nil; started != (mode != "aead") {
			t.Fatalf("%s: refresh loop started %v", mode, started)
		}
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestLegacyTableConcurrentRefresh(t *testing.T) {
	// Enough identities that one refresh spans several write-lock batches.
	users := make([]legacyTestUser, 300)
	for i := range users {
		users[i] = legacyTestUser{name: "u" + strconv.Itoa(i), id: "legacy-user-" + strconv.Itoa(i), alterId: i % 3}
	}
	clock := newLegacyTestClock(1700000000)
	s := newLegacyTestService(t, clock, "auto", true, users)
	window := legacyTestWindow(true)
	perIdentity := int(2*window + legacyRefreshSeconds + 1)
	if ops := legacyTestIdentities(users) * 2 * legacyRefreshSeconds; ops <= legacyApplyBatch {
		t.Fatalf("a refresh of %d changes fits in one batch", ops)
	}
	key := legacyTestKeys(users[0])[0]

	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				authID := legacyTestAuthID(key, clock.unix())
				s.IsLegacyAuthID(authID[:])
			}
		}()
	}
	current := users
	for tick := 0; tick < 60; tick++ {
		clock.advance(10)
		switch tick % 20 {
		case 10:
			current = users[:200]
			updateLegacyTestUsers(t, s, current)
		case 15:
			current = users
			updateLegacyTestUsers(t, s, current)
		default:
			s.generateLegacyKeys()
		}
		if want := legacyTestIdentities(current) * perIdentity; len(s.alterIdMap) != want {
			t.Fatalf("tick %d: table size %d, want %d", tick, len(s.alterIdMap), want)
		}
		if !legacyTestAccepted(s, key, clock.unix()) {
			t.Fatalf("tick %d: current auth ID rejected", tick)
		}
	}
	close(stop)
	wg.Wait()
	checkLegacyTable(t, s, clock, current, window)
}
