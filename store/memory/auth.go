package memory

import (
	"context"
	"errors"
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
// auth.Session and auth.Verification are fixed shapes.
//
// It enforces every uniqueness constraint [auth.Store] states, including the
// two on the record types: UserBase.Email (one email, one account),
// Session.TokenHash and Verification.TokenHash. It did NOT always enforce the
// two TokenHash ones — they were deferred to store/drops, matching
// InviteStore's stance on EmailInvite.TokenHash and Link.Code, on the reading
// that a hash collision is an application-level constraint the way a slug is.
// That reading does not survive the port's own text: auth.Session.TokenHash
// says a shared hash breaks MarkRotated's single-winner contract "with no
// atomicity defect at all", because two concurrent callers can each
// atomically win a DIFFERENT one of the colliding rows and both report a
// successful rotation. That is the same property refresh-token rotation rests
// on, defeated by another route — not a nicety — so this store honours it
// too, and a caller who develops here and deploys against store/drops no
// longer meets the constraint for the first time in production. See
// [ErrTokenHashTaken] for what a collision reports.
//
// [InviteStore]'s equivalent split is untouched and remains as its own doc
// describes; invite.Store is a separate port with its own obligations.
//
// It also enforces the id-collision contract [auth.Store] documents on every
// Create* method: CreateUser, CreateSession and CreateVerification all check
// for an existing row under the same id before writing, and return
// auth.ErrIDTaken rather than silently overwriting it. Every one of those
// checks — id, email, token hash — happens under the same acquisition of mu
// as the write it guards.
type AuthStore struct {
	mu            sync.Mutex
	users         map[string]auth.UserBase
	sessions      map[string]auth.Session
	verifications map[string]auth.Verification
}

// ErrTokenHashTaken reports that a Create* call would have stored a second
// Session or Verification under a token hash another row of the same kind
// already holds — the uniqueness [auth.Session.TokenHash] and
// [auth.Verification.TokenHash] require of a backend.
//
// It is deliberately NOT one of authlayer/auth's sentinels, and deliberately
// not auth.ErrIDTaken. [auth.Store]'s error contract classifies exactly one
// conflict on the Create* methods — ErrIDTaken, defined as "an id that
// already identifies a row of that same kind" — and says of token-hash
// uniqueness that CreateSession "does not itself check" it, leaving it to the
// backend's own constraint. Reporting a hash collision as ErrIDTaken would
// therefore tell a caller something false about which column collided. This
// store answers with its own backend-level error instead, exactly as
// store/drops answers with the driver's own unique violation
// (pg.ErrUniqueViolation) unwrapped on the same path — so the two backends
// agree that the write must fail, and neither pretends the port classifies
// it.
var ErrTokenHashTaken = errors.New("authlayer/store/memory: token hash already exists")

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
//
// This checks before writing, which [auth.Store.CreateUser]'s own doc
// says a backend generally MUST NOT do (deciding ErrEmailTaken from a
// separate read whose authorization can differ from the write's reopens
// authlayer/auth's enumeration oracle from inside a single Store method —
// see that doc for the full reasoning). It is compliant here anyway,
// deliberately, not by oversight: a Go map assignment (s.users[u.ID] = u)
// has no failure mode of its own at all — it cannot be independently
// denied, rejected, or rate-limited the way a database write can — so
// there is no condition under which the map read above succeeds while
// the map write below would independently fail. Check-then-write and
// write-then-classify are indistinguishable outcomes against this
// specific backend, which is exactly the carve-out the port doc allows.
// A future change that makes this store's write path capable of failing
// on its own (a size cap, a quota, anything with its own error) would
// invalidate this reasoning and require restructuring to write first.
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
// returns auth.ErrIDTaken if a session with this ID already exists, or
// [ErrTokenHashTaken] if another session already holds sess.TokenHash — all
// three checks and the write happen under one acquisition of mu, so the row
// is never silently overwritten and no two rows can end up sharing a hash.
// See [ErrTokenHashTaken] for why a hash collision is not reported as
// ErrIDTaken.
func (s *AuthStore) CreateSession(_ context.Context, sess auth.Session) (auth.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.sessions[sess.ID]; exists {
		return auth.Session{}, auth.ErrIDTaken
	}
	if s.sessionHashTaken(sess.TokenHash) {
		return auth.Session{}, ErrTokenHashTaken
	}
	s.sessions[sess.ID] = sess
	return sess, nil
}

// sessionHashTaken reports whether any stored session already holds
// tokenHash. Callers hold mu. A linear scan is fine for a reference store;
// store/drops has a UNIQUE index do the same job.
func (s *AuthStore) sessionHashTaken(tokenHash string) bool {
	for _, sess := range s.sessions {
		if sess.TokenHash == tokenHash {
			return true
		}
	}
	return false
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

// CreateSuccessorSession implements the second half of the rotation-race
// fix documented on [auth.Store]: it inserts sess only if predecessorID
// still identifies a row, checked and written under the SAME acquisition of
// mu — a DeleteSessionsByFamily call landing between the check and the
// insert (which, in this single-mutex store, cannot happen: DeleteSessionsByFamily
// itself blocks on mu for its own entire body) is exactly the race this
// method exists to close, the identical discipline [AuthStore.MarkRotated]
// already applies to ITS OWN check-and-mark.
//
// It carries [AuthStore.CreateSession]'s [ErrTokenHashTaken] check too, since
// it is the store's other insert path for a Session — checked after the
// predecessor's liveness, so a rotation that has already lost its family
// reports that loss (ok=false, nil) rather than a hash conflict it would
// never have reached.
func (s *AuthStore) CreateSuccessorSession(_ context.Context, predecessorID string, sess auth.Session) (auth.Session, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.sessions[sess.ID]; exists {
		return auth.Session{}, false, auth.ErrIDTaken
	}
	if _, exists := s.sessions[predecessorID]; !exists {
		return auth.Session{}, false, nil
	}
	if s.sessionHashTaken(sess.TokenHash) {
		return auth.Session{}, false, ErrTokenHashTaken
	}
	s.sessions[sess.ID] = sess
	return sess, true, nil
}

// --- Verifications ---

// CreateVerification normalizes v.Email (see [auth.NormalizeEmail]) —
// unconditionally, regardless of v.Purpose; see Verification.Email's doc for
// why this must never be purpose-conditional — stores the result under v's
// ID, and returns it, or returns auth.ErrIDTaken if a verification with this
// ID already exists, or [ErrTokenHashTaken] if another verification already
// holds v.TokenHash — every check, the normalization, and the write happen
// under one acquisition of mu, so the row is never silently overwritten and
// no two rows can end up sharing a hash.
func (s *AuthStore) CreateVerification(_ context.Context, v auth.Verification) (auth.Verification, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.verifications[v.ID]; exists {
		return auth.Verification{}, auth.ErrIDTaken
	}
	if s.verificationHashTaken(v.TokenHash) {
		return auth.Verification{}, ErrTokenHashTaken
	}
	v.Email = auth.NormalizeEmail(v.Email)
	s.verifications[v.ID] = v
	return v, nil
}

// verificationHashTaken reports whether any stored verification already
// holds tokenHash. Callers hold mu. Mirrors [AuthStore.sessionHashTaken];
// see it for why a linear scan is enough here.
func (s *AuthStore) verificationHashTaken(tokenHash string) bool {
	for _, v := range s.verifications {
		if v.TokenHash == tokenHash {
			return true
		}
	}
	return false
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
