// Package magiclink is the passwordless-link engine as a standalone module:
// how a link is requested without revealing which addresses exist, and what
// redeeming one must check. It knows nothing about users, sessions, MFA or
// the auth Store — a [Backend] supplies persistence, and the caller
// (auth.Service) does everything after a successful redemption.
//
// That boundary is the point. The engine can be unit-tested against a
// fake Backend, replaced wholesale (an OTP-code engine implementing the
// same shape), and reused by a different identity store.
//
// The security argument for this flow — the enumeration property, the
// error folding, the timing caveats — is written once, at
// auth.Service.RequestMagicLink, whose doc is normative; this package
// implements that argument and its comments only note the order that
// matters.
package magiclink

import (
	"context"
	"errors"
	"time"

	"github.com/bernardoforcillo/authlayer/core"
	"github.com/bernardoforcillo/authlayer/token"
)

// ErrExpired: the presented link's ExpiresAt has passed. Checked before the
// link is burned.
var ErrExpired = errors.New("magiclink: link has expired")

// ErrWrongPurpose: the presented token is a real verification, but not a
// magic link — it must not be redeemable here.
var ErrWrongPurpose = errors.New("magiclink: token is not a magic link")

// ErrAccountGone: the account a link points at is anonymized.
var ErrAccountGone = errors.New("magiclink: account is gone")

// Account is the engine's view of the identity behind an address.
type Account struct {
	ID       string
	Email    string
	Deleted  bool // anonymized: refused through every path
	Verified bool // the address has already been proven
}

// Link is a stored magic-link credential. TokenHash is the digest of the
// secret; the secret itself is never stored.
type Link struct {
	ID        string
	AccountID string
	Email     string
	TokenHash string
	ExpiresAt time.Time
	CreatedAt time.Time
	// Genuine is set by the Backend on lookup: the stored row is a magic
	// link, not another purpose's token that happens to share the table.
	Genuine bool
}

// Backend is the persistence the engine needs. Every method's error is
// returned to the caller unchanged unless documented as folded below, so a
// Backend may use its own sentinels. "Not found" from FindByEmail is
// reported through found, never as an error.
//
// The calls are deliberately fine-grained — DeleteLinks and PutLink are two
// operations, not one — because the order of store calls is part of the
// enumeration argument and callers pin it in tests.
type Backend interface {
	FindByEmail(ctx context.Context, email string) (acc Account, found bool, err error)
	FindByID(ctx context.Context, id string) (Account, error)
	// Create registers an unverified account with no password credential.
	Create(ctx context.Context, id, email string, now time.Time) (Account, error)
	// DeleteLinks removes every outstanding link for the account.
	DeleteLinks(ctx context.Context, accountID string) error
	PutLink(ctx context.Context, l Link) error
	// FindLink looks a link up by token digest, any purpose.
	FindLink(ctx context.Context, tokenHash string) (Link, error)
	DeleteLink(ctx context.Context, linkID string) error
	MarkVerified(ctx context.Context, accountID, email string, now time.Time) error
}

// Config tunes an [Engine]. Zero fields take the documented defaults.
type Config struct {
	// TTL is how long a link stays redeemable. Default 15 minutes.
	TTL time.Duration
	// Provisioning creates an account for an unrecognised address.
	Provisioning bool
	// AddressLimiter, if set, is consulted keyed by the normalized address.
	// A denial looks like an unknown address, never like a rate limit.
	AddressLimiter core.RateLimiter
	// Runtime supplies the clock and ids.
	Runtime core.Runtime
}

// DefaultTTL is the default link lifetime.
const DefaultTTL = 15 * time.Minute

// Engine requests and redeems magic links over a [Backend].
type Engine struct {
	b   Backend
	cfg Config
}

// New builds an Engine.
func New(b Backend, cfg Config) *Engine {
	if cfg.TTL <= 0 {
		cfg.TTL = DefaultTTL
	}
	return &Engine{b: b, cfg: cfg}
}

// Request mints a link for the normalized address. It returns (token, true,
// nil) when a link was minted and ("", false, nil) for EVERY refusal — an
// unknown address, an anonymized account, an address-limiter denial, and any
// failure of a branch-exclusive write — so the response never reveals which.
// Failures of calls that run on every invocation (the address limiter, the
// lookup, token generation) are returned as-is.
func (e *Engine) Request(ctx context.Context, email string) (string, bool, error) {
	addressAllowed := true
	if e.cfg.AddressLimiter != nil {
		allowed, err := e.cfg.AddressLimiter.Allow(ctx, email)
		if err != nil {
			return "", false, err
		}
		addressAllowed = allowed
	}

	acc, known, err := e.b.FindByEmail(ctx, email)
	if err != nil {
		return "", false, err
	}

	// Unconditional, whether or not the result is used.
	plain, hash, gerr := token.GenerateOpaque()
	if gerr != nil {
		return "", false, gerr
	}

	if !addressAllowed {
		return "", false, nil
	}
	now := e.cfg.Runtime.Now()

	if known && acc.Deleted {
		return "", false, nil
	}
	if !known {
		if !e.cfg.Provisioning {
			return "", false, nil
		}
		created, cerr := e.b.Create(ctx, e.cfg.Runtime.NewID(), email, now)
		if cerr != nil {
			return "", false, nil
		}
		acc = created
	}

	if derr := e.b.DeleteLinks(ctx, acc.ID); derr != nil {
		return "", false, nil
	}
	if perr := e.b.PutLink(ctx, Link{
		ID:        e.cfg.Runtime.NewID(),
		AccountID: acc.ID,
		Email:     acc.Email,
		TokenHash: hash,
		ExpiresAt: now.Add(e.cfg.TTL),
		CreatedAt: now,
	}); perr != nil {
		return "", false, nil
	}
	return plain, true, nil
}

// Redeem consumes a link: it checks expiry and purpose, burns the link
// BEFORE touching the account, refuses an anonymized account, and stamps
// the address verified when the link was delivered to the address on file.
// It returns the account, with Verified reflecting that stamp. It does not
// sign anyone in — that is the caller's.
func (e *Engine) Redeem(ctx context.Context, plainToken string) (Account, error) {
	l, err := e.b.FindLink(ctx, token.HashOpaque(plainToken))
	if err != nil {
		return Account{}, err
	}
	now := e.cfg.Runtime.Now()
	if !now.Before(l.ExpiresAt) {
		return Account{}, ErrExpired
	}
	if !l.Genuine {
		return Account{}, ErrWrongPurpose
	}
	if err := e.b.DeleteLink(ctx, l.ID); err != nil {
		return Account{}, err
	}
	acc, err := e.b.FindByID(ctx, l.AccountID)
	if err != nil {
		return Account{}, err
	}
	if acc.Deleted {
		return Account{}, ErrAccountGone
	}
	if !acc.Verified && acc.Email == l.Email {
		if err := e.b.MarkVerified(ctx, l.AccountID, l.Email, now); err != nil {
			return Account{}, err
		}
		acc.Verified = true
	}
	return acc, nil
}
