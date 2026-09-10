package oauth

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/bernardoforcillo/authlayer/token"
)

// issueRefresh mints a refresh token for g, starting a new family when
// familyID is "" and continuing it otherwise, and returns the plaintext —
// which is never stored — and the row.
func (s *Service) issueRefresh(ctx context.Context, g Grant, clientID, familyID string, now time.Time) (string, RefreshToken, error) {
	plain, hash, err := token.GenerateOpaque()
	if err != nil {
		return "", RefreshToken{}, err
	}
	id := s.cfg.idgen()
	if familyID == "" {
		familyID = id
	}
	rt, err := s.st.CreateRefreshToken(ctx, RefreshToken{
		ID:        id,
		TokenHash: hash,
		GrantID:   g.ID,
		ClientID:  clientID,
		FamilyID:  familyID,
		ExpiresAt: now.Add(s.cfg.refreshTTL),
		CreatedAt: now,
	})
	if err != nil {
		return "", RefreshToken{}, err
	}
	return plain, rt, nil
}

// issueDelegated mints the access token, and the refresh token when c holds
// GrantRefreshToken, for one grant — the tail every delegated grant shares.
// familyID continues an existing family (Refresh) or starts one ("").
func (s *Service) issueDelegated(ctx context.Context, c Client, g Grant, familyID string, now time.Time) (TokenResponse, error) {
	raw, expiresIn, err := s.mintAccess(mint{
		subject: g.UserID, clientID: c.ID, scope: g.Scope,
		containerID: g.ContainerID, grantID: g.ID, capBytes: g.Permissions,
	})
	if err != nil {
		return TokenResponse{}, err
	}
	resp := TokenResponse{AccessToken: raw, TokenType: "Bearer", ExpiresIn: expiresIn, Scope: g.Scope}
	if slices.Contains(c.GrantTypes, GrantRefreshToken) {
		plain, _, err := s.issueRefresh(ctx, g, c.ID, familyID, now)
		if err != nil {
			return TokenResponse{}, err
		}
		resp.RefreshToken = plain
	}
	// Best-effort: a grant whose LastUsedAt lags is bookkeeping, not a
	// security state, and a store hiccup there must not fail a mint.
	_ = s.st.TouchGrant(ctx, g.ID, now)
	return resp, nil
}

// revokeFamilyAndGrant is the response to a refresh-token replay, or to a
// refresh token presented by the wrong client: the whole family goes
// ([Store.DeleteRefreshFamily]) and so does the grant ([Store.RevokeGrant],
// which deletes the grant's other families too). Errors from either are
// joined onto sentinel, never substituted for it.
func (s *Service) revokeFamilyAndGrant(ctx context.Context, c Client, rt RefreshToken, detail string, sentinel error) error {
	ferr := s.st.DeleteRefreshFamily(ctx, rt.FamilyID)
	err := s.revokeAfterMisuse(ctx, c, rt.GrantID, detail, sentinel)
	if ferr != nil {
		return errors.Join(err, ferr)
	}
	return err
}

// Refresh is RFC 6749 §6 with rotation: the client authenticates, presents
// its refresh token, and receives a new access token and a NEW refresh
// token in the same family; the presented one is superseded and will never
// refresh again.
//
// Rotation runs through [Store.MarkRefreshRotated]'s compare-and-set, so
// however many callers present one token at once, exactly one wins. A
// presentation of an already-rotated token is a replay — a legitimate
// client retrying with a stale token, or an attacker replaying a stolen
// one, and this package cannot tell which — so it is treated as a
// compromise: the whole family is deleted, the grant is revoked, and the
// caller gets [ErrTokenReuse]. Returned alone, the revocation succeeded;
// joined with another error it did not and the family may still be live —
// test with errors.Is before anything else, exactly as with
// auth.ErrTokenReuse. A token presented by a client other than the one it
// was issued to gets the same revocation and [ErrInvalidGrant].
//
// Then, all [ErrInvalidGrant]: an unknown token (wrapping
// ErrRefreshNotFound), an expired one (checked after the rotation, so it
// is consumed and a later replay of it still detected), a grant that is
// gone. A revoked or expired grant is [ErrGrantRevoked] or
// [ErrGrantExpired]. Client authentication comes first:
// [ErrInvalidClient], [ErrClientDisabled], [ErrUnauthorizedClient] when the
// client does not hold GrantRefreshToken. The new access token carries the
// grant's cap exactly as the first did; nothing is re-approved.
func (s *Service) Refresh(ctx context.Context, clientID, clientSecret, refreshToken string) (TokenResponse, error) {
	c, err := s.authenticateClient(ctx, clientID, clientSecret)
	if err != nil {
		return TokenResponse{}, err
	}
	if err := requireGrantType(c, GrantRefreshToken); err != nil {
		return TokenResponse{}, err
	}
	now := s.cfg.clock()
	rt, won, err := s.st.MarkRefreshRotated(ctx, token.HashOpaque(refreshToken), now)
	if err != nil {
		if errors.Is(err, ErrRefreshNotFound) {
			return TokenResponse{}, fmt.Errorf("%w: %w", ErrInvalidGrant, err)
		}
		return TokenResponse{}, err
	}
	if !won {
		return TokenResponse{}, s.revokeFamilyAndGrant(ctx, c, rt, DetailRefreshReplayed, ErrTokenReuse)
	}
	if rt.ClientID != c.ID {
		return TokenResponse{}, s.revokeFamilyAndGrant(ctx, c, rt, DetailWrongClient,
			fmt.Errorf("%w: refresh token was issued to another client", ErrInvalidGrant))
	}
	if !now.Before(rt.ExpiresAt) {
		return TokenResponse{}, fmt.Errorf("%w: refresh token expired", ErrInvalidGrant)
	}
	g, err := s.liveGrant(ctx, rt.GrantID, now)
	if err != nil {
		if errors.Is(err, ErrGrantNotFound) {
			return TokenResponse{}, fmt.Errorf("%w: %w", ErrInvalidGrant, err)
		}
		return TokenResponse{}, err
	}
	resp, err := s.issueDelegated(ctx, c, g, rt.FamilyID, now)
	if err != nil {
		return TokenResponse{}, err
	}
	if err := s.emit(ctx, Event{
		Kind: TokenRefreshed, ContainerID: g.ContainerID, ActorID: g.UserID,
		ClientID: c.ID, GrantID: g.ID, At: now,
	}); err != nil {
		return TokenResponse{}, err
	}
	return resp, nil
}

// Revoke is RFC 7009: the client authenticates and names a token of its
// own, and the server invalidates what it can. A refresh token: its whole
// family is deleted and its grant revoked. A delegated access token: its
// grant is revoked — the JWT itself cannot be recalled, and keeps verifying
// offline until it expires ([WithAccessTTL]); with online verification
// [Service.Authenticate] refuses it from this call on. A client-credentials
// access token: nothing to invalidate, since it is bound to no grant; it
// expires. An unknown or malformed token is nil, because the RFC says the
// server responds with success whether or not it recognised the token — a
// revocation endpoint that said "unknown" would be a validity oracle.
//
// A token issued to a DIFFERENT client is [ErrInvalidGrant] and nothing is
// revoked: RFC 7009 §2.1 requires the server to verify the token belongs
// to the requesting client and refuse otherwise. Client authentication
// comes first ([ErrInvalidClient], [ErrClientDisabled]); a disabled client
// cannot revoke, and does not need to — its refresh is already refused,
// and the operator's DeleteClient revokes everything of it.
func (s *Service) Revoke(ctx context.Context, clientID, clientSecret, rawToken string) error {
	c, err := s.authenticateClient(ctx, clientID, clientSecret)
	if err != nil {
		return err
	}
	now := s.cfg.clock()
	rt, err := s.st.FindRefreshTokenByHash(ctx, token.HashOpaque(rawToken))
	switch {
	case err == nil:
		if rt.ClientID != c.ID {
			return fmt.Errorf("%w: token was issued to another client", ErrInvalidGrant)
		}
		if err := s.st.DeleteRefreshFamily(ctx, rt.FamilyID); err != nil {
			return err
		}
		return s.revokeGrantAs(ctx, c, rt.GrantID, DetailClientRevoked, now)
	case !errors.Is(err, ErrRefreshNotFound):
		return err
	}
	claims, err := s.signer.Parse(rawToken)
	if err != nil {
		return nil // unknown token: success, per the RFC
	}
	if claims.ClientID != c.ID {
		return fmt.Errorf("%w: token was issued to another client", ErrInvalidGrant)
	}
	if claims.Actor == nil {
		return nil // a client-credentials token: nothing to revoke
	}
	if grantID := extraString(claims, ExtraGrantID); grantID != "" {
		return s.revokeGrantAs(ctx, c, grantID, DetailClientRevoked, now)
	}
	return nil
}

// revokeGrantAs revokes grantID on a client's behalf, treating an
// already-gone grant as success (the RFC's stance on unknown tokens), and
// emits GrantRevoked.
func (s *Service) revokeGrantAs(ctx context.Context, c Client, grantID, detail string, now time.Time) error {
	if err := s.st.RevokeGrant(ctx, grantID, now); err != nil && !errors.Is(err, ErrGrantNotFound) {
		return err
	}
	return s.emit(ctx, Event{Kind: GrantRevoked, ContainerID: c.ContainerID, ClientID: c.ID, GrantID: grantID, Detail: detail, At: now})
}
