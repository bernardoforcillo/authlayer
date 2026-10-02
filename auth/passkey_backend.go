package auth

import (
	"context"
	"errors"
	"time"

	"github.com/bernardoforcillo/authlayer/auth/passkey"
)

// passkeyBackend adapts a [CredentialStore] to [passkey.Backend].
type passkeyBackend struct{ creds CredentialStore }

func (p passkeyBackend) PutChallenge(ctx context.Context, c passkey.Challenge) error {
	_, err := p.creds.CreateChallenge(ctx, Challenge{
		ID: c.ID, UserID: c.OwnerID, Ceremony: c.Ceremony, Hash: c.Hash,
		ExpiresAt: c.ExpiresAt, CreatedAt: c.CreatedAt,
	})
	return err
}

func (p passkeyBackend) FindChallenge(ctx context.Context, hash string) (passkey.Challenge, error) {
	c, err := p.creds.FindChallengeByHash(ctx, hash)
	if err != nil {
		return passkey.Challenge{}, err
	}
	return passkey.Challenge{ID: c.ID, OwnerID: c.UserID, Ceremony: c.Ceremony, Hash: c.Hash, ExpiresAt: c.ExpiresAt, CreatedAt: c.CreatedAt}, nil
}

func (p passkeyBackend) DeleteChallenge(ctx context.Context, id string) error {
	return p.creds.DeleteChallenge(ctx, id)
}

func (p passkeyBackend) Touch(ctx context.Context, rowID string, now time.Time) error {
	return p.creds.TouchCredential(ctx, rowID, now)
}

func (p passkeyBackend) AdvanceSignCount(ctx context.Context, rowID string, count uint32, now time.Time) (bool, error) {
	return p.creds.UpdateSignCount(ctx, rowID, count, now)
}

// passkeyEngine builds the ceremony engine over the Service's credential
// store and settings.
func (s *Service) passkeyEngine(creds CredentialStore) *passkey.Engine {
	return passkey.New(passkeyBackend{creds}, s.cfg.passkeyChallengeTTL, s.cfg.idGen)
}

// mapPasskeyErr translates the engine's sentinels into the auth package's
// long-standing ones.
func mapPasskeyErr(err error) error {
	switch {
	case errors.Is(err, passkey.ErrChallengeExpired):
		return ErrChallengeExpired
	case errors.Is(err, passkey.ErrChallengeCeremony):
		return ErrChallengeCeremony
	case errors.Is(err, passkey.ErrChallengeOwner):
		return ErrChallengeUser
	case errors.Is(err, passkey.ErrCloned):
		return ErrClonedAuthenticator
	}
	return err
}
