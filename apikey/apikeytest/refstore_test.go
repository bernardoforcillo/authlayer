package apikeytest

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/bernardoforcillo/authlayer/apikey"
)

// errDuplicateTokenHash is what [refStore] reports on a hash collision.
// [apikey.Store] classifies no hash collision — it names ErrIDTaken for an id
// and nothing for a hash — so this is deliberately not a package sentinel,
// exactly as store/drops lets PostgreSQL's own unique violation through and
// store/memory answers with its own package-local error. Nothing in the suite
// looks at it; the checks require only that the write failed.
var errDuplicateTokenHash = errors.New("apikeytest: token hash already exists")

// refStore is a compliant [apikey.Store] written for this package's own
// tests. It exists so the deliberately non-compliant doubles in
// negative_test.go can each be exactly ONE defect away from a correct store:
// every one of them embeds a *refStore and overrides a single method,
// reaching this type's maps directly, which is why it lives here rather than
// being replaced by store/memory's APIKeyStore (whose internals are
// unexported, and which is a backend under test by this suite rather than the
// fixture that defines what passing it looks like).
//
// Every method holds mu for its entire body, so no check-then-write in it can
// be split by a concurrent call — the in-process shape both of the port's
// atomicity MUSTs name. TestTheReferenceStorePassesTheContract is what makes
// the negative controls mean anything.
type refStore struct {
	mu       sync.Mutex
	accounts map[string]apikey.ServiceAccount
	keys     map[string]apikey.Key
}

func newRefStore() *refStore {
	return &refStore{
		accounts: map[string]apikey.ServiceAccount{},
		keys:     map[string]apikey.Key{},
	}
}

var _ apikey.Store = (*refStore)(nil)

// hashTaken reports whether any key already holds tokenHash. Callers hold mu.
func (s *refStore) hashTaken(tokenHash string) bool {
	for _, k := range s.keys {
		if k.TokenHash == tokenHash {
			return true
		}
	}
	return false
}

func (s *refStore) CreateServiceAccount(_ context.Context, sa apikey.ServiceAccount) (apikey.ServiceAccount, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, taken := s.accounts[sa.ID]; taken {
		return apikey.ServiceAccount{}, apikey.ErrIDTaken
	}
	s.accounts[sa.ID] = sa
	return sa, nil
}

func (s *refStore) FindServiceAccount(_ context.Context, id string) (apikey.ServiceAccount, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sa, ok := s.accounts[id]
	if !ok {
		return apikey.ServiceAccount{}, apikey.ErrServiceAccountNotFound
	}
	return sa, nil
}

func (s *refStore) ListServiceAccounts(_ context.Context, containerID string) ([]apikey.ServiceAccount, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []apikey.ServiceAccount
	for _, sa := range s.accounts {
		if sa.ContainerID == containerID {
			out = append(out, sa)
		}
	}
	return out, nil
}

func (s *refStore) SetServiceAccountDisabled(_ context.Context, id string, at *time.Time, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	sa, ok := s.accounts[id]
	if !ok {
		return apikey.ErrServiceAccountNotFound
	}
	sa.DisabledAt = at
	sa.UpdatedAt = now
	s.accounts[id] = sa
	return nil
}

func (s *refStore) DeleteServiceAccount(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.accounts[id]; !ok {
		return apikey.ErrServiceAccountNotFound
	}
	for kid, k := range s.keys {
		if k.ServiceAccountID == id {
			delete(s.keys, kid)
		}
	}
	delete(s.accounts, id)
	return nil
}

func (s *refStore) CreateKey(_ context.Context, k apikey.Key) (apikey.Key, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, taken := s.keys[k.ID]; taken {
		return apikey.Key{}, apikey.ErrIDTaken
	}
	if _, ok := s.accounts[k.ServiceAccountID]; !ok {
		return apikey.Key{}, apikey.ErrServiceAccountNotFound
	}
	if s.hashTaken(k.TokenHash) {
		return apikey.Key{}, errDuplicateTokenHash
	}
	s.keys[k.ID] = k
	return k, nil
}

func (s *refStore) FindKeyByHash(_ context.Context, tokenHash string) (apikey.Key, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, k := range s.keys {
		if k.TokenHash == tokenHash {
			return k, nil
		}
	}
	return apikey.Key{}, apikey.ErrKeyNotFound
}

func (s *refStore) FindKey(_ context.Context, id string) (apikey.Key, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.keys[id]
	if !ok {
		return apikey.Key{}, apikey.ErrKeyNotFound
	}
	return k, nil
}

func (s *refStore) ListKeys(_ context.Context, serviceAccountID string) ([]apikey.Key, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []apikey.Key
	for _, k := range s.keys {
		if k.ServiceAccountID == serviceAccountID {
			out = append(out, k)
		}
	}
	return out, nil
}

func (s *refStore) RevokeKey(_ context.Context, id string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.keys[id]
	if !ok {
		return apikey.ErrKeyNotFound
	}
	k.RevokedAt = &now
	s.keys[id] = k
	return nil
}

func (s *refStore) TouchKey(_ context.Context, id string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.keys[id]
	if !ok {
		return apikey.ErrKeyNotFound
	}
	k.LastUsedAt = &now
	s.keys[id] = k
	return nil
}

func (s *refStore) DeleteKey(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.keys[id]; !ok {
		return apikey.ErrKeyNotFound
	}
	delete(s.keys, id)
	return nil
}

func (s *refStore) PurgeExpired(_ context.Context, before time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for id, k := range s.keys {
		if (k.ExpiresAt != nil && k.ExpiresAt.Before(before)) || (k.RevokedAt != nil && k.RevokedAt.Before(before)) {
			delete(s.keys, id)
			n++
		}
	}
	return n, nil
}
