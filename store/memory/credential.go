package memory

import (
	"bytes"
	"context"
	"sync"
	"time"

	"github.com/bernardoforcillo/authlayer/auth"
)

// CredentialStore is a concurrency-safe in-memory auth.CredentialStore: the
// WebAuthn credentials ("passkeys") of
// [github.com/bernardoforcillo/authlayer/auth.Service] and the ceremony
// challenges that bracket them, and nothing else. It is wired with
// auth.WithCredentialStore and is entirely optional; an application offering
// no passkeys never constructs one.
//
// It verifies NOTHING about a WebAuthn ceremony — neither does the port it
// implements. See auth/credential.go's package doc for the list of what the
// application owes.
//
// It follows [IdentityStore]'s discipline exactly, and for the same reason:
// every method holds mu for its entire body, so a check-then-write sequence
// can never be split by a concurrent call.
// [CredentialStore.UpdateSignCount] and
// [CredentialStore.DeleteCredentialIfNotLast] are where that stops being a
// generic habit and becomes the point of the type — a split in the first
// admits a replayed assertion, a split in the second locks an account out
// permanently.
//
// Like IdentityStore it enforces every uniqueness constraint its port
// declares: Credential.ID, Credential.CredentialID, Challenge.ID and
// Challenge.Hash. CredentialID is the one that keeps one authenticator from
// signing in as two people.
type CredentialStore struct {
	mu sync.Mutex
	// credentials is keyed by Credential.ID. The credential-id index that
	// FindCredentialByCredentialID needs is a linear scan rather than a
	// second map — a reference store trades speed for having exactly one
	// copy of the data and therefore no way for two indexes to disagree, the
	// same trade FindUserByEmail and FindIdentityByProviderSubject already
	// make. []byte cannot key a Go map anyway. store/drops indexes the
	// column.
	credentials map[string]auth.Credential
	// challenges is keyed by Challenge.ID, with the hash lookup a scan for
	// the same reason.
	challenges map[string]auth.Challenge
}

// NewCredentialStore returns an empty in-memory auth.CredentialStore.
func NewCredentialStore() *CredentialStore {
	return &CredentialStore{
		credentials: map[string]auth.Credential{},
		challenges:  map[string]auth.Challenge{},
	}
}

// Compile-time proof this store satisfies the port.
var _ auth.CredentialStore = (*CredentialStore)(nil)

// CreateCredential stores c under its ID and returns what was stored. The id
// check, the credential-id uniqueness scan and the write all happen under one
// acquisition of mu, so two concurrent registrations of the same
// authenticator credential cannot both succeed: the second to reach the lock
// sees the first's row and returns auth.ErrIDTaken (checked first) or
// auth.ErrCredentialRegistered (checked second), never overwriting the row
// and never re-pointing it at a different user.
//
// CredentialID is compared byte-for-byte — never decoded, re-encoded or
// folded — matching auth.Credential.CredentialID's doc.
//
// Like [AuthStore.CreateUser] this checks before writing, which
// auth.Store.CreateUser's doc says a backend generally MUST NOT do, and it is
// compliant here for the identical reason: a Go map assignment has no
// independent failure mode, so there is no condition under which the scan
// succeeds while the write would independently fail. A future change that
// gave this store's write path a failure mode of its own would invalidate the
// reasoning and require restructuring to write first.
func (s *CredentialStore) CreateCredential(_ context.Context, c auth.Credential) (auth.Credential, error) {
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

// FindCredentialByCredentialID scans for the credential whose CredentialID
// matches byte-for-byte, or returns auth.ErrCredentialNotFound. A linear scan
// is fine for a reference store; store/drops indexes the column.
//
// At most one row can match, because [CredentialStore.CreateCredential]
// refuses to create a second: that is what makes "the row IS the account" a
// fact rather than a coin flip over map iteration order.
func (s *CredentialStore) FindCredentialByCredentialID(_ context.Context, credentialID []byte) (auth.Credential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.credentials {
		if bytes.Equal(c.CredentialID, credentialID) {
			return c, nil
		}
	}
	return auth.Credential{}, auth.ErrCredentialNotFound
}

// ListCredentialsByUser returns every credential belonging to userID, and
// only that user's. A user with none yields an empty, non-nil slice and a nil
// error — but callers MUST NOT depend on which of empty or nil they get,
// because the port leaves that unspecified and a compliant backend may return
// the other. Order follows Go map iteration and is therefore randomised.
func (s *CredentialStore) ListCredentialsByUser(_ context.Context, userID string) ([]auth.Credential, error) {
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

// UpdateSignCount is the port's compare-and-set: it applies newCount and
// stamps LastUsedAt only when newCount is strictly greater than the stored
// counter, reporting (false, nil) when it refuses and
// auth.ErrCredentialNotFound when id matches no row.
//
// The read, the comparison and the write happen under ONE acquisition of mu.
// That is the whole contract — see auth.CredentialStore.UpdateSignCount's "It
// MUST refuse a count that did not increase, atomically": a split lets two
// concurrent presentations of the same assertion both observe the old value,
// both conclude their counter is greater and both win, which is the replay
// this method exists to refuse and the only clone detection the package has.
//
// The predicate is strictly-greater, deliberately. An equal counter is
// refused: an authenticator that maintains one increments it on every
// assertion, so "the same value again" is as much evidence of a replay as a
// lower one. The one authenticator family that legitimately never increments
// — the ones reporting zero forever — never reaches this method at all; the
// service calls [CredentialStore.TouchCredential] for those.
func (s *CredentialStore) UpdateSignCount(_ context.Context, id string, newCount uint32, now time.Time) (bool, error) {
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

// TouchCredential stamps LastUsedAt with now and leaves SignCount alone, or
// returns auth.ErrCredentialNotFound when id matches no row. It is what a
// counter-less authenticator's login calls instead of UpdateSignCount — see
// that method's doc.
func (s *CredentialStore) TouchCredential(_ context.Context, id string, now time.Time) error {
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

// DeleteCredential removes the one row named by its surrogate id, or returns
// auth.ErrCredentialNotFound when id matches no row. It touches nothing else.
//
// Unlike [CredentialStore.DeleteCredentialIfNotLast] it makes no reachability
// check at all, and will remove an account's last credential if asked — see
// auth.CredentialStore.DeleteCredential for which callers may ask and why.
func (s *CredentialStore) DeleteCredential(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.credentials[id]; !ok {
		return auth.ErrCredentialNotFound
	}
	delete(s.credentials, id)
	return nil
}

// DeleteCredentialIfNotLast removes userID's credential named by id, but only
// when the account is still reachable afterwards — either another of that
// user's credentials survives or userHasOtherCredential is true. Otherwise it
// returns auth.ErrLastCredential and removes NOTHING.
// auth.ErrCredentialNotFound means id names no credential of that user, which
// includes the case where it names somebody else's.
//
// The scan, the reachability decision and the delete all happen under ONE
// acquisition of mu. That is the whole contract of this method — see
// auth.CredentialStore.DeleteCredentialIfNotLast's "It MUST be atomic" for
// what a split produces: two concurrent removals of a password-less,
// identity-less user's last two passkeys each observe the other's row, each
// conclude the account stays reachable, and each delete, leaving nothing that
// can sign the user in and both requests reporting success. The lockout is
// permanent and silent.
//
// A credential belonging to another user is ErrCredentialNotFound rather than
// a delete: the id is the caller's input, and one account must never be able
// to remove another's way in by naming it.
func (s *CredentialStore) DeleteCredentialIfNotLast(_ context.Context, userID, id string, userHasOtherCredential bool) error {
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

// CreateChallenge stores c under its ID and returns what was stored. The id
// check, the hash uniqueness scan and the write happen under one acquisition
// of mu, matching [AuthStore.CreateVerification], whose duplicate-hash stance
// this mirrors: a collision is [ErrTokenHashTaken], this store's own
// backend-level error, because the port classifies only ErrIDTaken on a
// create.
func (s *CredentialStore) CreateChallenge(_ context.Context, c auth.Challenge) (auth.Challenge, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.challenges[c.ID]; exists {
		return auth.Challenge{}, auth.ErrIDTaken
	}
	for _, existing := range s.challenges {
		if existing.Hash == c.Hash {
			return auth.Challenge{}, ErrTokenHashTaken
		}
	}
	s.challenges[c.ID] = c
	return c, nil
}

// FindChallengeByHash scans for the challenge whose Hash matches, or returns
// auth.ErrChallengeNotFound. It checks neither expiry nor ceremony: both
// belong to the service layer, which checks them before claiming so a
// wrongly-presented challenge is not burned.
func (s *CredentialStore) FindChallengeByHash(_ context.Context, hash string) (auth.Challenge, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.challenges {
		if c.Hash == hash {
			return c, nil
		}
	}
	return auth.Challenge{}, auth.ErrChallengeNotFound
}

// DeleteChallenge removes the challenge named by id, or returns
// auth.ErrChallengeNotFound when no row matched. This is the CLAIM, and the
// existence check and the delete happen under one acquisition of mu — which
// is what makes exactly one of any number of concurrent presentations of the
// same challenge see a nil error. A split here admits two.
func (s *CredentialStore) DeleteChallenge(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.challenges[id]; !ok {
		return auth.ErrChallengeNotFound
	}
	delete(s.challenges, id)
	return nil
}

// PurgeExpiredChallenges deletes every challenge whose ExpiresAt is strictly
// before `before`, returning how many rows went. Housekeeping only: an
// expired challenge is refused by the service long before it is purged. It
// mirrors [AuthStore.PurgeExpired]'s strictly-before comparison so the two
// janitors agree on the boundary instant.
func (s *CredentialStore) PurgeExpiredChallenges(_ context.Context, before time.Time) (int, error) {
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
