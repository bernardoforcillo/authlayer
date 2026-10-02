package auth

import (
	"context"
	"errors"
	"time"

	"github.com/bernardoforcillo/authlayer/auth/magiclink"
	"github.com/bernardoforcillo/authlayer/core"
)

// magicBackend adapts the auth [Store] to [magiclink.Backend]. One is built
// per call: it remembers the last UserBase it loaded and when it stamped the
// address, so the Service can finish a redemption (MFA, session) with the
// full account without a second read.
type magicBackend struct {
	store    Store
	user     UserBase
	verified *time.Time
}

func (m *magicBackend) acc(u UserBase) magiclink.Account {
	return magiclink.Account{ID: u.ID, Email: u.Email, Deleted: u.DeletedAt != nil, Verified: u.EmailVerifiedAt != nil}
}

func (m *magicBackend) FindByEmail(ctx context.Context, email string) (magiclink.Account, bool, error) {
	u, err := m.store.FindUserByEmail(ctx, email)
	switch {
	case errors.Is(err, ErrUserNotFound):
		return magiclink.Account{}, false, nil
	case err != nil:
		return magiclink.Account{}, false, err
	}
	m.user = u
	return m.acc(u), true, nil
}

func (m *magicBackend) FindByID(ctx context.Context, id string) (magiclink.Account, error) {
	u, err := m.store.FindUserByID(ctx, id)
	if err != nil {
		return magiclink.Account{}, err
	}
	m.user = u
	return m.acc(u), nil
}

func (m *magicBackend) Create(ctx context.Context, id, email string, now time.Time) (magiclink.Account, error) {
	u, err := m.store.CreateUser(ctx, UserBase{ID: id, Email: email, CreatedAt: now, UpdatedAt: now})
	if err != nil {
		return magiclink.Account{}, err
	}
	m.user = u
	return m.acc(u), nil
}

func (m *magicBackend) DeleteLinks(ctx context.Context, accountID string) error {
	return m.store.DeleteVerificationsByUserAndPurpose(ctx, accountID, PurposeMagicLink)
}

func (m *magicBackend) PutLink(ctx context.Context, l magiclink.Link) error {
	_, err := m.store.CreateVerification(ctx, Verification{
		ID:        l.ID,
		UserID:    l.AccountID,
		TokenHash: l.TokenHash,
		Purpose:   PurposeMagicLink,
		Email:     l.Email,
		ExpiresAt: l.ExpiresAt,
		CreatedAt: l.CreatedAt,
	})
	return err
}

func (m *magicBackend) FindLink(ctx context.Context, tokenHash string) (magiclink.Link, error) {
	v, err := m.store.FindVerificationByHash(ctx, tokenHash)
	if err != nil {
		return magiclink.Link{}, err
	}
	return magiclink.Link{
		ID: v.ID, AccountID: v.UserID, Email: v.Email, TokenHash: v.TokenHash,
		ExpiresAt: v.ExpiresAt, CreatedAt: v.CreatedAt, Genuine: v.Purpose == PurposeMagicLink,
	}, nil
}

func (m *magicBackend) DeleteLink(ctx context.Context, linkID string) error {
	return m.store.DeleteVerification(ctx, linkID)
}

func (m *magicBackend) MarkVerified(ctx context.Context, accountID, email string, now time.Time) error {
	if err := m.store.MarkEmailVerified(ctx, accountID, email, now); err != nil {
		return err
	}
	stamped := now
	m.verified = &stamped
	return nil
}

// magicEngine builds the link engine over the Service's own store and
// configuration, with the backend that records what a redemption loaded.
func (s *Service) magicEngine() (magiclink.Flow, *magicBackend) {
	b := &magicBackend{store: s.store}
	factory := s.cfg.magicFlow
	if factory == nil {
		factory = magiclink.NewFlow
	}
	return factory(b, magiclink.Config{
		TTL:            s.cfg.magicLinkTTL,
		Provisioning:   s.cfg.magicLinkProvisioning,
		AddressLimiter: s.cfg.magicLinkLimiter,
		Runtime:        core.Runtime{Clock: s.cfg.clock, IDs: s.cfg.idGen},
	}), b
}

// mapMagicErr translates the engine's sentinels into the auth package's
// long-standing ones, so callers and tests keep matching on them.
func mapMagicErr(err error) error {
	switch {
	case errors.Is(err, magiclink.ErrExpired):
		return ErrVerificationExpired
	case errors.Is(err, magiclink.ErrWrongPurpose):
		return ErrVerificationPurpose
	case errors.Is(err, magiclink.ErrAccountGone):
		return ErrUserNotFound
	}
	return err
}

// WithMagicLinkEngine replaces the link engine behind [Service.RequestMagicLink]
// and [Service.RedeemMagicLink] — see [magiclink.Flow] for the contract a
// replacement must keep. nil restores the default [magiclink.Engine].
func WithMagicLinkEngine(f magiclink.Factory) Option {
	return func(c *config) { c.magicFlow = f }
}
