package panel

import (
	"fmt"
	"sort"
	"sync"
)

type UserDelta struct {
	Added   []User
	Updated []User
	Removed []User
}

// UserStore is reconstruction infrastructure, not an assertion that the
// original used this data structure. Replace applies an entire valid snapshot.
type UserStore struct {
	mu    sync.RWMutex
	users map[int64]User
}

func (s *UserStore) Replace(snapshot []User) (UserDelta, error) {
	next := make(map[int64]User, len(snapshot))
	for _, user := range snapshot {
		if _, ok := next[user.ID]; ok {
			return UserDelta{}, fmt.Errorf("duplicate panel user ID %d", user.ID)
		}
		next[user.ID] = user
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delta := UserDelta{}
	for id, user := range next {
		old, exists := s.users[id]
		if !exists {
			delta.Added = append(delta.Added, user)
		} else if old != user {
			delta.Updated = append(delta.Updated, user)
		}
	}
	for id, user := range s.users {
		if _, exists := next[id]; !exists {
			delta.Removed = append(delta.Removed, user)
		}
	}
	sortUsers(delta.Added)
	sortUsers(delta.Updated)
	sortUsers(delta.Removed)
	s.users = next
	return delta, nil
}

func (s *UserStore) Snapshot() []User {
	s.mu.RLock()
	defer s.mu.RUnlock()
	users := make([]User, 0, len(s.users))
	for _, user := range s.users {
		users = append(users, user)
	}
	sortUsers(users)
	return users
}

func sortUsers(users []User) {
	sort.Slice(users, func(i, j int) bool { return users[i].ID < users[j].ID })
}
