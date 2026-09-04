package memory

import (
	"context"
	"sync"
	"time"

	"github.com/bernardoforcillo/authlayer/apikey"
)

// APIKeyStore is a concurrency-safe in-memory apikey.Store: service accounts
// and their keys, and nothing else. It is the reference implementation of
// the port, and every method holds mu for its entire body, so a
// check-then-write sequence can never be split by a concurrent call — the
// discipline [InviteStore] and [MFAStore] follow, and the shape the port's
// two atomicity MUSTs name for an in-process store.
//
// It enforces all three MUSTs [apikey.Store] states: [apikey.Key.TokenHash]
// is unique (a collision is [ErrTokenHashTaken], the same error a colliding
// session or invitation hash gets here — same column, same meaning),
// [APIKeyStore.DeleteServiceAccount] removes the account and its keys under
// one acquisition of mu, and [APIKeyStore.CreateKey] refuses a key naming an
// account it does not hold. Unlike [InviteStore] it also refuses an id
// collision, with apikey.ErrIDTaken, because that port names one.
//
// It stores what it is handed: the token hash arrives already computed and
// the permissions already encoded; this type hashes nothing and interprets
// no permission bytes.
type APIKeyStore struct {
	mu sync.Mutex
	// accounts is keyed by service-account id.
	accounts map[string]apikey.ServiceAccount
	// keys is keyed by key id. Finding one by token hash, or an account's
	// keys, is a linear scan rather than a second map: a reference store
	// trades speed for having exactly one copy of the data and therefore no
	// way for two indexes to disagree, the same trade every other store in
	// this package makes. store/drops indexes the columns.
	keys map[string]apikey.Key
}

// NewAPIKeyStore returns an empty in-memory apikey.Store.
func NewAPIKeyStore() *APIKeyStore {
	return &APIKeyStore{
		accounts: map[string]apikey.ServiceAccount{},
		keys:     map[string]apikey.Key{},
	}
}

// Compile-time proof the memory store satisfies the port.
var _ apikey.Store = (*APIKeyStore)(nil)

// CreateServiceAccount stores sa under its ID and returns it unchanged, or
// returns apikey.ErrIDTaken if an account with that id already exists. The
// check and the write happen under one acquisition of mu.
func (s *APIKeyStore) CreateServiceAccount(_ context.Context, sa apikey.ServiceAccount) (apikey.ServiceAccount, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, taken := s.accounts[sa.ID]; taken {
		return apikey.ServiceAccount{}, apikey.ErrIDTaken
	}
	s.accounts[sa.ID] = sa
	return sa, nil
}

// FindServiceAccount returns the account, or apikey.ErrServiceAccountNotFound.
func (s *APIKeyStore) FindServiceAccount(_ context.Context, id string) (apikey.ServiceAccount, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sa, ok := s.accounts[id]
	if !ok {
		return apikey.ServiceAccount{}, apikey.ErrServiceAccountNotFound
	}
	return sa, nil
}

// ListServiceAccounts returns every account in containerID, disabled or not.
// Order follows Go map iteration and is therefore randomised — sort the
// result if a test depends on it.
func (s *APIKeyStore) ListServiceAccounts(_ context.Context, containerID string) ([]apikey.ServiceAccount, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]apikey.ServiceAccount, 0)
	for _, sa := range s.accounts {
		if sa.ContainerID == containerID {
			out = append(out, sa)
		}
	}
	return out, nil
}

// SetServiceAccountDisabled writes DisabledAt = at and UpdatedAt = now, or
// returns apikey.ErrServiceAccountNotFound. Idempotent: the timestamps are
// overwritten whatever they held.
func (s *APIKeyStore) SetServiceAccountDisabled(_ context.Context, id string, at *time.Time, now time.Time) error {
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

// DeleteServiceAccount removes the account and every key naming it under
// ONE acquisition of mu — the port's cascade MUST, in the in-process shape —
// or returns apikey.ErrServiceAccountNotFound when there is no such account,
// touching no key in that case.
func (s *APIKeyStore) DeleteServiceAccount(_ context.Context, id string) error {
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

// CreateKey stores k under its ID and returns it unchanged, or returns
// apikey.ErrIDTaken if a key with that id exists, apikey.ErrServiceAccountNotFound
// if k.ServiceAccountID names no account, or [ErrTokenHashTaken] if another
// key already holds k.TokenHash. All three checks and the write happen under
// one acquisition of mu, so two concurrent creates contending for an id or a
// hash cannot both pass. The id is checked first, then the account, then the
// hash — a key failing more than one reports the first.
func (s *APIKeyStore) CreateKey(_ context.Context, k apikey.Key) (apikey.Key, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, taken := s.keys[k.ID]; taken {
		return apikey.Key{}, apikey.ErrIDTaken
	}
	if _, ok := s.accounts[k.ServiceAccountID]; !ok {
		return apikey.Key{}, apikey.ErrServiceAccountNotFound
	}
	for _, other := range s.keys {
		if other.TokenHash == k.TokenHash {
			return apikey.Key{}, ErrTokenHashTaken
		}
	}
	s.keys[k.ID] = k
	return k, nil
}

// FindKeyByHash scans for the key whose TokenHash matches, or returns
// apikey.ErrKeyNotFound. At most one row can match, because CreateKey
// refuses a colliding hash. Revoked and expired keys are returned.
func (s *APIKeyStore) FindKeyByHash(_ context.Context, tokenHash string) (apikey.Key, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, k := range s.keys {
		if k.TokenHash == tokenHash {
			return k, nil
		}
	}
	return apikey.Key{}, apikey.ErrKeyNotFound
}

// FindKey returns the key, or apikey.ErrKeyNotFound.
func (s *APIKeyStore) FindKey(_ context.Context, id string) (apikey.Key, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.keys[id]
	if !ok {
		return apikey.Key{}, apikey.ErrKeyNotFound
	}
	return k, nil
}

// ListKeys returns every key of serviceAccountID, revoked or expired or not.
// Order follows Go map iteration and is therefore randomised.
func (s *APIKeyStore) ListKeys(_ context.Context, serviceAccountID string) ([]apikey.Key, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]apikey.Key, 0)
	for _, k := range s.keys {
		if k.ServiceAccountID == serviceAccountID {
			out = append(out, k)
		}
	}
	return out, nil
}

// RevokeKey stamps RevokedAt with now, or returns apikey.ErrKeyNotFound.
// Revoking a revoked key overwrites the timestamp.
func (s *APIKeyStore) RevokeKey(_ context.Context, id string, now time.Time) error {
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

// TouchKey stamps LastUsedAt with now, or returns apikey.ErrKeyNotFound.
func (s *APIKeyStore) TouchKey(_ context.Context, id string, now time.Time) error {
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

// DeleteKey removes the key, or returns apikey.ErrKeyNotFound.
func (s *APIKeyStore) DeleteKey(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.keys[id]; !ok {
		return apikey.ErrKeyNotFound
	}
	delete(s.keys, id)
	return nil
}

// PurgeExpired deletes every key whose ExpiresAt or RevokedAt is strictly
// before before, and returns how many went. A key exactly at the cutoff
// survives one more pass; a live key with no expiry, and every account, is
// left alone.
func (s *APIKeyStore) PurgeExpired(_ context.Context, before time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for id, k := range s.keys {
		expired := k.ExpiresAt != nil && k.ExpiresAt.Before(before)
		revoked := k.RevokedAt != nil && k.RevokedAt.Before(before)
		if expired || revoked {
			delete(s.keys, id)
			n++
		}
	}
	return n, nil
}
