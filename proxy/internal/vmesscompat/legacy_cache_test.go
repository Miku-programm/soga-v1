package vmess

import (
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
	"github.com/gofrs/uuid/v5"
	"testing"
	"time"
)

func TestLegacyCacheRefreshRetainsPastAndReducesTable(t *testing.T) {
	id := "91c43637-0cdc-46c7-bb6c-cf1b09f52c2c"
	now := time.Unix(1700000000, 0)
	for _, reduced := range []bool{false, true} {
		s := NewService[string](nil, ServiceWithReducedMemory(reduced), ServiceWithAuthMode("auto"), ServiceWithTimeFunc(func() time.Time { return now }))
		if err := s.UpdateUsers([]string{"42"}, []string{id}, []int{0}); err != nil {
			t.Fatal(err)
		}
		maximum := 2*CacheDurationSeconds + 11
		if reduced {
			maximum = 61
		}
		if len(s.alterIdMap) != maximum {
			t.Fatalf("table size %d want %d", len(s.alterIdMap), maximum)
		}
		now = now.Add(10 * time.Second)
		s.generateLegacyKeys()
		u := uuid.Must(uuid.FromString(id))
		h := hmac.New(md5.New, u[:])
		binary.Write(h, binary.BigEndian, uint64(now.Add(-15*time.Second).Unix()))
		if !s.IsLegacyAuthID(h.Sum(nil)) {
			t.Fatal("refresh discarded still-valid past identity")
		}
	}
}
