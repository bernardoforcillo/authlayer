// Package passkey is the ceremony engine behind WebAuthn sign-in as a
// standalone module: minting single-use challenges, claiming them, and
// deciding whether an assertion's signature counter proves a cloned
// authenticator. It does not verify WebAuthn signatures — the application
// does that with a WebAuthn library and hands over the verified result — and
// it knows nothing about users or sessions: a [Backend] persists, and
// auth.Service does everything around the ceremony.
package passkey

import (
	"context"
	"errors"
	"time"

	"github.com/bernardoforcillo/authlayer/token"
)

var (
	// ErrChallengeExpired: the challenge's ExpiresAt has passed.
	ErrChallengeExpired = errors.New("passkey: challenge expired")
	// ErrChallengeCeremony: the challenge was minted for another ceremony
	// (a login challenge cannot finish a registration, or the reverse).
	ErrChallengeCeremony = errors.New("passkey: challenge was minted for a different ceremony")
	// ErrChallengeOwner: the challenge was minted for another account, or
	// for none.
	ErrChallengeOwner = errors.New("passkey: challenge was minted for a different account")
	// ErrCloned: the signature counter did not advance, so the authenticator
	// may have been cloned.
	ErrCloned = errors.New("passkey: sign counter did not increase; authenticator may be cloned")
)

// DefaultChallengeTTL is how long a challenge stays claimable.
const DefaultChallengeTTL = 5 * time.Minute

// Challenge is a stored, single-use ceremony challenge. Hash is the digest
// of the secret handed to the client; the secret is never stored.
type Challenge struct {
	ID        string
	OwnerID   *string // nil for a login challenge: nobody is identified yet
	Ceremony  string
	Hash      string
	ExpiresAt time.Time
	CreatedAt time.Time
}

// Backend is the persistence the engine needs. FindChallenge's "not found"
// is returned as the Backend's own error and passed through unchanged.
type Backend interface {
	PutChallenge(ctx context.Context, c Challenge) error
	FindChallenge(ctx context.Context, hash string) (Challenge, error)
	DeleteChallenge(ctx context.Context, id string) error
	// Touch records a use of a credential whose counter is not in play.
	Touch(ctx context.Context, credentialRowID string, now time.Time) error
	// AdvanceSignCount stores count if and only if it is strictly greater
	// than the stored one, atomically, and reports whether it did.
	AdvanceSignCount(ctx context.Context, credentialRowID string, count uint32, now time.Time) (bool, error)
}

// Engine runs ceremonies over a [Backend].
type Engine struct {
	b     Backend
	ttl   time.Duration
	newID func() string
}

// New builds an Engine. A non-positive ttl takes [DefaultChallengeTTL].
func New(b Backend, ttl time.Duration, newID func() string) *Engine {
	if ttl <= 0 {
		ttl = DefaultChallengeTTL
	}
	return &Engine{b: b, ttl: ttl, newID: newID}
}

// Begin mints a challenge for a ceremony and returns its plaintext. owner is
// the account a registration is for, nil for login.
func (e *Engine) Begin(ctx context.Context, ceremony string, owner *string, now time.Time) (string, error) {
	plain, hash, err := token.GenerateOpaque()
	if err != nil {
		return "", err
	}
	if err := e.b.PutChallenge(ctx, Challenge{
		ID:        e.newID(),
		OwnerID:   owner,
		Ceremony:  ceremony,
		Hash:      hash,
		ExpiresAt: now.Add(e.ttl),
		CreatedAt: now,
	}); err != nil {
		return "", err
	}
	return plain, nil
}

// Claim consumes a challenge: it must exist, be unexpired, belong to the
// ceremony, and — when forUser is non-nil — to that account. The challenge
// is deleted only once every check passes, so a mismatched presentation does
// not burn someone else's challenge.
func (e *Engine) Claim(ctx context.Context, plain, ceremony string, forUser *string, now time.Time) error {
	c, err := e.b.FindChallenge(ctx, token.HashOpaque(plain))
	if err != nil {
		return err
	}
	if !now.Before(c.ExpiresAt) {
		return ErrChallengeExpired
	}
	if c.Ceremony != ceremony {
		return ErrChallengeCeremony
	}
	if forUser != nil && (c.OwnerID == nil || *c.OwnerID != *forUser) {
		return ErrChallengeOwner
	}
	return e.b.DeleteChallenge(ctx, c.ID)
}

// CheckAssertion applies an assertion's signature counter. Authenticators
// that never count (both zero) are only touched; otherwise the counter must
// advance, or [ErrCloned] is returned.
func (e *Engine) CheckAssertion(ctx context.Context, credentialRowID string, stored, presented uint32, now time.Time) error {
	if presented == 0 && stored == 0 {
		return e.b.Touch(ctx, credentialRowID, now)
	}
	applied, err := e.b.AdvanceSignCount(ctx, credentialRowID, presented, now)
	if err != nil {
		return err
	}
	if !applied {
		return ErrCloned
	}
	return nil
}
