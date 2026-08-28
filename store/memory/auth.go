package memory

import (
	"context"
	"sync"
	"time"

	"github.com/bernardoforcillo/authlayer/auth"
)

// AuthStore is a concurrency-safe in-memory auth.Store. It is the reference
// implementation of the Store contract, in particular for
// [AuthStore.MarkRotated]'s atomicity requirement: every method holds mu for
// its entire body, so a check-then-write sequence can never be split by a
// concurrent call — see that method's doc comment on [auth.Store] for why
// that split would be a security bug, not a cosmetic one.
//
// Like [InviteStore] and unlike [Store], it is not generic — auth.UserBase,
// auth.Session and auth.Verification are fixed shapes — and, matching
// InviteStore's stance on EmailInvite.TokenHash and Link.Code (see that
// type's package doc), it does not enforce uniqueness of Session.TokenHash or
// Verification.TokenHash here, even though [auth.Store] requires a backend to
// — see auth.Session.TokenHash's and auth.Verification.TokenHash's doc
// comments for why that is a MUST on the port and what breaks without it.
// That enforcement is deferred to store/drops, exactly where InviteStore
// defers EmailInvite.TokenHash and Link.Code. UserBase.Email is the one
// exception — CreateUser does check for a normalized-email collision here,
// because "one email, one account" is the property this whole package exists
// to guarantee, not an optional application-level constraint the way a token
// hash collision is.
//
// It also enforces the id-collision contract [auth.Store] documents on every
// Create* method: CreateUser, CreateSession and CreateVerification all check
// for an existing row under the same id before writing, and return
// auth.ErrIDTaken rather than silently overwriting it.
type AuthStore struct {
	mu            sync.Mutex
	users         map[string]auth.UserBase
	sessions      map[string]auth.Session
	verifications map[string]auth.Verification
}

// NewAuthStore returns an empty in-memory auth.Store.
func NewAuthStore() *AuthStore {
	return &AuthStore{
		users:         map[string]auth.UserBase{},
		sessions:      map[string]auth.Session{},
		verifications: map[string]auth.Verification{},
	}
}

// --- Users ---

// CreateUser normalizes u.Email (see [auth.NormalizeEmail]), stores u under
// its ID, and returns what was stored. The id check, the email uniqueness
// check against every existing user, and the write all happen under one
// acquisition of mu, so two concurrent CreateUser calls for the same id or
// the same address cannot both succeed: the second to reach the lock sees
// the first's row already present and returns auth.ErrIDTaken (checked
// first) or auth.ErrEmailTaken (checked second), never overwriting it.
func (s *AuthStore) CreateUser(_ context.Context, u auth.UserBase) (auth.UserBase, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.users[u.ID]; exists {
		return auth.UserBase{}, auth.ErrIDTaken
	}
	u.Email = auth.NormalizeEmail(u.Email)
	for _, existing := range s.users {
		if existing.Email == u.Email {
			return auth.UserBase{}, auth.ErrEmailTaken
		}
	}
	s.users[u.ID] = u
	return u, nil
}

// FindUserByID returns the user, or auth.ErrUserNotFound.
func (s *AuthStore) FindUserByID(_ context.Context, id string) (auth.UserBase, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[id]
	if !ok {
		return auth.UserBase{}, auth.ErrUserNotFound
	}
	return u, nil
}

// FindUserByEmail normalizes email (see [auth.NormalizeEmail]) and scans for
// the user whose Email matches, or returns auth.ErrUserNotFound. A linear
// scan is fine for a reference store; store/drops indexes the column.
func (s *AuthStore) FindUserByEmail(_ context.Context, email string) (auth.UserBase, error) {
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

// MarkEmailVerified stamps EmailVerifiedAt and UpdatedAt with now on the
// user, but only when email (normalized) matches the user's current
// Email — otherwise returns auth.ErrEmailMismatch without writing anything,
// closing the race auth.Store.MarkEmailVerified's doc describes: a
// concurrent UpdateUserEmail changing the row's address between when a
// verification token was minted and when it is redeemed must not let the
// redemption silently certify whatever address the row now holds. Returns
// auth.ErrUserNotFound when userID matches no row. The find, the comparison,
// and the write all happen under one acquisition of mu, matching every
// other mutating method in this store.
func (s *AuthStore) MarkEmailVerified(_ context.Context, userID, email string, now time.Time) error {
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

// UpdateUserPassword overwrites PasswordHash and stamps UpdatedAt with now
// on the user, or returns auth.ErrUserNotFound. The find and the write
// happen under one acquisition of mu, matching every other mutating method
// in this store.
func (s *AuthStore) UpdateUserPassword(_ context.Context, userID, passwordHash string, now time.Time) error {
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

// UpdateUserEmail normalizes email (see [auth.NormalizeEmail]), and — under
// one acquisition of mu spanning the not-found check, the uniqueness check
// against every *other* user, and the write — overwrites the user's Email,
// unconditionally clears EmailVerifiedAt to nil, and stamps UpdatedAt with
// now. Returns auth.ErrUserNotFound when userID matches no row, or
// auth.ErrEmailTaken when a different user already holds the normalized
// address; see [auth.Store.UpdateUserEmail]'s doc for why EmailVerifiedAt is
// always cleared rather than conditionally preserved or set.
//
// The uniqueness scan excludes userID's own row, so updating a user to the
// email it already holds is a harmless no-op-ish rewrite (it still clears
// EmailVerifiedAt and re-stamps UpdatedAt), not a self-conflict.
func (s *AuthStore) UpdateUserEmail(_ context.Context, userID, email string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[userID]
	if !ok {
		return auth.ErrUserNotFound
	}
	email = auth.NormalizeEmail(email)
	for otherID, other := range s.users {
		if otherID != userID && other.Email == email {
			return auth.ErrEmailTaken
		}
	}
	u.Email = email
	u.EmailVerifiedAt = nil
	u.UpdatedAt = now
	s.users[userID] = u
	return nil
}

// --- Sessions ---

// CreateSession stores the session under its ID and returns it unchanged, or
// returns auth.ErrIDTaken if a session with this ID already exists — the
// check and the write happen under one acquisition of mu, so the row is
// never silently overwritten.
func (s *AuthStore) CreateSession(_ context.Context, sess auth.Session) (auth.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.sessions[sess.ID]; exists {
		return auth.Session{}, auth.ErrIDTaken
	}
	s.sessions[sess.ID] = sess
	return sess, nil
}

// FindSessionByHash scans for the session whose TokenHash matches, or
// returns auth.ErrSessionNotFound. A linear scan is fine for a reference
// store; store/drops indexes the column.
func (s *AuthStore) FindSessionByHash(_ context.Context, tokenHash string) (auth.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, sess := range s.sessions {
		if sess.TokenHash == tokenHash {
			return sess, nil
		}
	}
	return auth.Session{}, auth.ErrSessionNotFound
}

// ListSessionsByUser returns every session belonging to userID. Order
// follows Go map iteration and is therefore randomised — sort the result if
// a test depends on it.
func (s *AuthStore) ListSessionsByUser(_ context.Context, userID string) ([]auth.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]auth.Session, 0)
	for _, sess := range s.sessions {
		if sess.UserID == userID {
			out = append(out, sess)
		}
	}
	return out, nil
}

// DeleteSession removes the session, or returns auth.ErrSessionNotFound.
func (s *AuthStore) DeleteSession(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.sessions[id]; !ok {
		return auth.ErrSessionNotFound
	}
	delete(s.sessions, id)
	return nil
}

// DeleteSessionsByFamily removes every session sharing familyID. Deleting
// zero rows is not an error.
func (s *AuthStore) DeleteSessionsByFamily(_ context.Context, familyID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, sess := range s.sessions {
		if sess.FamilyID == familyID {
			delete(s.sessions, id)
		}
	}
	return nil
}

// MarkRotated implements the compare-and-set at the center of refresh
// rotation — see the full contract on [auth.Store.MarkRotated]. The check
// (does a session with this hash exist, and is it still unrotated) and the
// mark (stamp RotatedAt) happen inside a single acquisition of mu: the
// method never unlocks between deciding a caller has won and recording that
// win, so no concurrent caller reading the map can ever observe the
// unrotated state after this call has already committed to returning
// ok=true for it. This is the one method in this package where that
// single-acquisition discipline is load-bearing rather than a generic
// concurrency-safety habit — see this package's mandatory concurrency test
// and the mutation experiment recorded in its doc comment.
func (s *AuthStore) MarkRotated(_ context.Context, tokenHash string, now time.Time) (auth.Session, bool, error) {
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

// --- Verifications ---

// CreateVerification normalizes v.Email (see [auth.NormalizeEmail]) —
// unconditionally, regardless of v.Purpose; see Verification.Email's doc for
// why this must never be purpose-conditional — stores the result under v's
// ID, and returns it, or returns auth.ErrIDTaken if a verification with this
// ID already exists — the check, the normalization, and the write happen
// under one acquisition of mu, so the row is never silently overwritten.
func (s *AuthStore) CreateVerification(_ context.Context, v auth.Verification) (auth.Verification, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.verifications[v.ID]; exists {
		return auth.Verification{}, auth.ErrIDTaken
	}
	v.Email = auth.NormalizeEmail(v.Email)
	s.verifications[v.ID] = v
	return v, nil
}

// FindVerificationByHash scans for the verification whose TokenHash
// matches, or returns auth.ErrVerificationNotFound. A linear scan is fine
// for a reference store; store/drops indexes the column.
func (s *AuthStore) FindVerificationByHash(_ context.Context, tokenHash string) (auth.Verification, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, v := range s.verifications {
		if v.TokenHash == tokenHash {
			return v, nil
		}
	}
	return auth.Verification{}, auth.ErrVerificationNotFound
}

// DeleteVerification removes the verification, or returns
// auth.ErrVerificationNotFound.
func (s *AuthStore) DeleteVerification(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.verifications[id]; !ok {
		return auth.ErrVerificationNotFound
	}
	delete(s.verifications, id)
	return nil
}

// DeleteVerificationsByUserAndPurpose removes every verification for
// (userID, purpose). Deleting zero rows is not an error.
func (s *AuthStore) DeleteVerificationsByUserAndPurpose(_ context.Context, userID, purpose string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, v := range s.verifications {
		if v.UserID == userID && v.Purpose == purpose {
			delete(s.verifications, id)
		}
	}
	return nil
}

// --- Housekeeping ---

// PurgeExpired deletes every Session and Verification expired strictly
// before before — both by ExpiresAt — and returns how many rows were
// removed in total. UserBase rows are never purged.
func (s *AuthStore) PurgeExpired(_ context.Context, before time.Time) (int, error) {
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
