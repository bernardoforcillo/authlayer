package authtest

import (
	"bytes"
	"context"
	"sync"
	"time"

	"github.com/bernardoforcillo/authlayer/auth"
)

// refCredentialStore is a compliant [auth.CredentialStore] written for this
// package's own tests, and it exists for exactly the reason [refStore] does:
// so the deliberately non-compliant doubles in negative_test.go can each be
// ONE defect away from a correct store, reaching these maps directly.
// store/memory's CredentialStore cannot serve that purpose — its internals
// are unexported, and it is a backend UNDER TEST by this suite rather than
// the fixture that defines what passing it looks like.
//
// Every method holds mu for its entire body, so no check-then-write in it can
// be split by a concurrent call.
// TestTheReferenceCredentialStorePassesTheContract is what makes the negative
// controls mean anything.
type refCredentialStore struct {
	mu          sync.Mutex
	credentials map[string]auth.Credential
	challenges  map[string]auth.Challenge
}

func newRefCredentialStore() *refCredentialStore {
	return &refCredentialStore{
		credentials: map[string]auth.Credential{},
		challenges:  map[string]auth.Challenge{},
	}
}

var _ auth.CredentialStore = (*refCredentialStore)(nil)

func (s *refCredentialStore) CreateCredential(_ context.Context, c auth.Credential) (auth.Credential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.credentials[c.ID]; exists {
		return auth.Credential{}, auth.ErrIDTaken
	}
	for _, existing := range s.credentials {
		if bytes.Equal(existing.CredentialID, c.CredentialID) {
			return auth.Credential{}, auth.ErrCredentialRegistered
		}
	}
	s.credentials[c.ID] = c
	return c, nil
}

func (s *refCredentialStore) FindCredentialByCredentialID(_ context.Context, credentialID []byte) (auth.Credential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.credentials {
		if bytes.Equal(c.CredentialID, credentialID) {
			return c, nil
		}
	}
	return auth.Credential{}, auth.ErrCredentialNotFound
}

func (s *refCredentialStore) ListCredentialsByUser(_ context.Context, userID string) ([]auth.Credential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]auth.Credential, 0)
	for _, c := range s.credentials {
		if c.UserID == userID {
			out = append(out, c)
		}
	}
	return out, nil
}

func (s *refCredentialStore) UpdateSignCount(_ context.Context, id string, newCount uint32, now time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.credentials[id]
	if !ok {
		return false, auth.ErrCredentialNotFound
	}
	if newCount <= c.SignCount {
		return false, nil
	}
	c.SignCount = newCount
	c.LastUsedAt = &now
	s.credentials[id] = c
	return true, nil
}

func (s *refCredentialStore) TouchCredential(_ context.Context, id string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.credentials[id]
	if !ok {
		return auth.ErrCredentialNotFound
	}
	c.LastUsedAt = &now
	s.credentials[id] = c
	return nil
}

func (s *refCredentialStore) DeleteCredential(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.credentials[id]; !ok {
		return auth.ErrCredentialNotFound
	}
	delete(s.credentials, id)
	return nil
}

func (s *refCredentialStore) DeleteCredentialIfNotLast(_ context.Context, userID, id string, userHasOtherCredential bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	doomed, ok := s.credentials[id]
	if !ok || doomed.UserID != userID {
		return auth.ErrCredentialNotFound
	}
	survivors := 0
	for otherID, c := range s.credentials {
		if c.UserID == userID && otherID != id {
			survivors++
		}
	}
	if survivors == 0 && !userHasOtherCredential {
		return auth.ErrLastCredential
	}
	delete(s.credentials, id)
	return nil
}

func (s *refCredentialStore) DeleteCredentialsByUser(_ context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, c := range s.credentials {
		if c.UserID == userID {
			delete(s.credentials, id)
		}
	}
	return nil
}

func (s *refCredentialStore) CreateChallenge(_ context.Context, c auth.Challenge) (auth.Challenge, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.challenges[c.ID]; exists {
		return auth.Challenge{}, auth.ErrIDTaken
	}
	for _, existing := range s.challenges {
		if existing.Hash == c.Hash {
			return auth.Challenge{}, errDuplicateTokenHash
		}
	}
	s.challenges[c.ID] = c
	return c, nil
}

func (s *refCredentialStore) FindChallengeByHash(_ context.Context, hash string) (auth.Challenge, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.challenges {
		if c.Hash == hash {
			return c, nil
		}
	}
	return auth.Challenge{}, auth.ErrChallengeNotFound
}

func (s *refCredentialStore) DeleteChallenge(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.challenges[id]; !ok {
		return auth.ErrChallengeNotFound
	}
	delete(s.challenges, id)
	return nil
}

func (s *refCredentialStore) PurgeExpiredChallenges(_ context.Context, before time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for id, c := range s.challenges {
		if c.ExpiresAt.Before(before) {
			delete(s.challenges, id)
			n++
		}
	}
	return n, nil
}
