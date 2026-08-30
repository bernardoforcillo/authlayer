package authtest

import (
	"context"
	"sync"
	"time"

	"github.com/bernardoforcillo/authlayer/auth"
)

// refStore is a compliant [auth.Store] written for this package's own tests.
// It exists so the deliberately non-compliant doubles in negative_test.go can
// each be exactly ONE defect away from a correct store: every one of them
// embeds a *refStore and overrides a single method, reaching this type's maps
// directly, which is why it lives here rather than being replaced by
// store/memory's AuthStore (whose internals are unexported, and which is a
// backend under test by this suite rather than the fixture that defines what
// passing it looks like).
//
// Every method holds mu for its entire body, so no check-then-write in it can
// be split by a concurrent call. TestTheReferenceStorePassesTheContract is
// what makes the negative controls mean anything: without it, a double
// failing a check would be evidence about the double's base, not about the
// defect injected on top of it.
type refStore struct {
	mu            sync.Mutex
	users         map[string]auth.UserBase
	sessions      map[string]auth.Session
	verifications map[string]auth.Verification
}

func newRefStore() *refStore {
	return &refStore{
		users:         map[string]auth.UserBase{},
		sessions:      map[string]auth.Session{},
		verifications: map[string]auth.Verification{},
	}
}

var _ auth.Store = (*refStore)(nil)

// emailHeldBy reports whether some user other than exceptID holds email.
// Callers hold mu.
func (s *refStore) emailHeldBy(email, exceptID string) bool {
	for id, u := range s.users {
		if id != exceptID && u.Email == email {
			return true
		}
	}
	return false
}

// sessionHashTaken reports whether any session already holds tokenHash.
// Callers hold mu.
func (s *refStore) sessionHashTaken(tokenHash string) bool {
	for _, sess := range s.sessions {
		if sess.TokenHash == tokenHash {
			return true
		}
	}
	return false
}

func (s *refStore) CreateUser(_ context.Context, u auth.UserBase) (auth.UserBase, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.users[u.ID]; exists {
		return auth.UserBase{}, auth.ErrIDTaken
	}
	u.Email = auth.NormalizeEmail(u.Email)
	if s.emailHeldBy(u.Email, "") {
		return auth.UserBase{}, auth.ErrEmailTaken
	}
	s.users[u.ID] = u
	return u, nil
}

func (s *refStore) FindUserByID(_ context.Context, id string) (auth.UserBase, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[id]
	if !ok {
		return auth.UserBase{}, auth.ErrUserNotFound
	}
	return u, nil
}

func (s *refStore) FindUserByEmail(_ context.Context, email string) (auth.UserBase, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	email = auth.NormalizeEmail(email)
	for _, u := range s.users {
		if u.Email == email {
			return u, nil
		}
	}
	return auth.UserBase{}, auth.ErrUserNotFound
}

func (s *refStore) MarkEmailVerified(_ context.Context, userID, email string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[userID]
	if !ok {
		return auth.ErrUserNotFound
	}
	if u.Email != auth.NormalizeEmail(email) {
		return auth.ErrEmailMismatch
	}
	u.EmailVerifiedAt = &now
	u.UpdatedAt = now
	s.users[userID] = u
	return nil
}

func (s *refStore) UpdateUserPassword(_ context.Context, userID, passwordHash string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[userID]
	if !ok {
		return auth.ErrUserNotFound
	}
	u.PasswordHash = passwordHash
	u.UpdatedAt = now
	s.users[userID] = u
	return nil
}

func (s *refStore) UpdateUserEmail(_ context.Context, userID, email string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[userID]
	if !ok {
		return auth.ErrUserNotFound
	}
	email = auth.NormalizeEmail(email)
	if s.emailHeldBy(email, userID) {
		return auth.ErrEmailTaken
	}
	u.Email = email
	u.EmailVerifiedAt = nil
	u.UpdatedAt = now
	s.users[userID] = u
	return nil
}

func (s *refStore) DeleteUser(_ context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[userID]; !ok {
		return auth.ErrUserNotFound
	}
	delete(s.users, userID)
	return nil
}

func (s *refStore) CreateSession(_ context.Context, sess auth.Session) (auth.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.sessions[sess.ID]; exists {
		return auth.Session{}, auth.ErrIDTaken
	}
	if s.sessionHashTaken(sess.TokenHash) {
		return auth.Session{}, errDuplicateTokenHash
	}
	s.sessions[sess.ID] = sess
	return sess, nil
}

func (s *refStore) FindSessionByHash(_ context.Context, tokenHash string) (auth.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, sess := range s.sessions {
		if sess.TokenHash == tokenHash {
			return sess, nil
		}
	}
	return auth.Session{}, auth.ErrSessionNotFound
}

func (s *refStore) ListSessionsByUser(_ context.Context, userID string) ([]auth.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []auth.Session
	for _, sess := range s.sessions {
		if sess.UserID == userID {
			out = append(out, sess)
		}
	}
	return out, nil
}

func (s *refStore) DeleteSession(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.sessions[id]; !ok {
		return auth.ErrSessionNotFound
	}
	delete(s.sessions, id)
	return nil
}

func (s *refStore) DeleteSessionsByFamily(_ context.Context, familyID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, sess := range s.sessions {
		if sess.FamilyID == familyID {
			delete(s.sessions, id)
		}
	}
	return nil
}

func (s *refStore) DeleteSessionsByUser(_ context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, sess := range s.sessions {
		if sess.UserID == userID {
			delete(s.sessions, id)
		}
	}
	return nil
}

func (s *refStore) MarkRotated(_ context.Context, tokenHash string, now time.Time) (auth.Session, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, sess := range s.sessions {
		if sess.TokenHash != tokenHash {
			continue
		}
		if sess.RotatedAt != nil {
			return sess, false, nil
		}
		sess.RotatedAt = &now
		s.sessions[id] = sess
		return sess, true, nil
	}
	return auth.Session{}, false, auth.ErrSessionNotFound
}

func (s *refStore) CreateSuccessorSession(_ context.Context, predecessorID string, sess auth.Session) (auth.Session, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.sessions[sess.ID]; exists {
		return auth.Session{}, false, auth.ErrIDTaken
	}
	if _, exists := s.sessions[predecessorID]; !exists {
		return auth.Session{}, false, nil
	}
	if s.sessionHashTaken(sess.TokenHash) {
		return auth.Session{}, false, errDuplicateTokenHash
	}
	s.sessions[sess.ID] = sess
	return sess, true, nil
}

func (s *refStore) CreateVerification(_ context.Context, v auth.Verification) (auth.Verification, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.verifications[v.ID]; exists {
		return auth.Verification{}, auth.ErrIDTaken
	}
	for _, existing := range s.verifications {
		if existing.TokenHash == v.TokenHash {
			return auth.Verification{}, errDuplicateTokenHash
		}
	}
	v.Email = auth.NormalizeEmail(v.Email)
	s.verifications[v.ID] = v
	return v, nil
}

func (s *refStore) FindVerificationByHash(_ context.Context, tokenHash string) (auth.Verification, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, v := range s.verifications {
		if v.TokenHash == tokenHash {
			return v, nil
		}
	}
	return auth.Verification{}, auth.ErrVerificationNotFound
}

func (s *refStore) DeleteVerification(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.verifications[id]; !ok {
		return auth.ErrVerificationNotFound
	}
	delete(s.verifications, id)
	return nil
}

func (s *refStore) DeleteVerificationsByUserAndPurpose(_ context.Context, userID, purpose string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, v := range s.verifications {
		if v.UserID == userID && v.Purpose == purpose {
			delete(s.verifications, id)
		}
	}
	return nil
}

func (s *refStore) DeleteVerificationsByUser(_ context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, v := range s.verifications {
		if v.UserID == userID {
			delete(s.verifications, id)
		}
	}
	return nil
}

func (s *refStore) PurgeExpired(_ context.Context, before time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for id, sess := range s.sessions {
		if sess.ExpiresAt.Before(before) {
			delete(s.sessions, id)
			n++
		}
	}
	for id, v := range s.verifications {
		if v.ExpiresAt.Before(before) {
			delete(s.verifications, id)
			n++
		}
	}
	return n, nil
}
