package memory

import (
	"context"
	"errors"
	"slices"
	"sync"
	"time"

	"github.com/bernardoforcillo/authlayer/oauth"
)

// ErrUserCodeTaken reports that CreateDeviceAuthorization would have stored a
// second row under a user code another pending or finished authorization
// already holds — the uniqueness [oauth.DeviceAuthorization.UserCode]
// states. It is this package's own error rather than an oauth sentinel for
// the reason [ErrTokenHashTaken] gives: the port classifies no collision on
// that column, store/drops lets PostgreSQL's unique violation through, and a
// caller treats any non-nil error as "this authorization was not created".
var ErrUserCodeTaken = errors.New("authlayer/store/memory: user code already exists")

// OAuthStore is a concurrency-safe in-memory oauth.Store: clients, grants,
// authorization codes, device authorizations and refresh tokens. It is the
// reference implementation of the port, and every method holds mu for its
// entire body, so no check-then-write in it can be split by a concurrent
// call — the in-process shape every atomicity MUST on the port names, and
// the discipline [APIKeyStore] and [AuthStore] follow.
//
// It enforces every MUST [oauth.Store] states: the four uniqueness
// obligations (a colliding code, device-code or refresh-token hash is
// [ErrTokenHashTaken], a colliding user code [ErrUserCodeTaken]), the three
// compare-and-sets under one acquisition of mu, the two atomic cascades
// (DeleteClient, RevokeGrant) under one acquisition, the referential
// refusals (a grant or device authorization naming no client, a code or
// refresh token naming no grant), and the id check on every Create*.
//
// It stores what it is handed: hashes arrive already computed, permissions
// already encoded, and this type hashes nothing, signs nothing and
// interprets no bytes.
type OAuthStore struct {
	mu      sync.Mutex
	clients map[string]oauth.Client
	grants  map[string]oauth.Grant
	codes   map[string]oauth.AuthorizationCode
	devices map[string]oauth.DeviceAuthorization
	refresh map[string]oauth.RefreshToken
}

// NewOAuthStore returns an empty in-memory oauth.Store.
func NewOAuthStore() *OAuthStore {
	return &OAuthStore{
		clients: map[string]oauth.Client{},
		grants:  map[string]oauth.Grant{},
		codes:   map[string]oauth.AuthorizationCode{},
		devices: map[string]oauth.DeviceAuthorization{},
		refresh: map[string]oauth.RefreshToken{},
	}
}

// Compile-time proof the memory store satisfies the port.
var _ oauth.Store = (*OAuthStore)(nil)

// cloneClient copies the slice fields so a caller mutating a returned Client
// — or the value it passed in — cannot reach into the store's own row.
func cloneClient(c oauth.Client) oauth.Client {
	c.RedirectURIs = slices.Clone(c.RedirectURIs)
	c.GrantTypes = slices.Clone(c.GrantTypes)
	c.Scopes = slices.Clone(c.Scopes)
	c.Permissions = slices.Clone(c.Permissions)
	return c
}

// ── Clients ─────────────────────────────────────────────────────────────

// CreateClient stores c under its ID and returns it unchanged, or returns
// oauth.ErrIDTaken if a client with that id exists. The check and the write
// happen under one acquisition of mu.
func (s *OAuthStore) CreateClient(_ context.Context, c oauth.Client) (oauth.Client, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, taken := s.clients[c.ID]; taken {
		return oauth.Client{}, oauth.ErrIDTaken
	}
	s.clients[c.ID] = cloneClient(c)
	return c, nil
}

// FindClient returns the client, or oauth.ErrClientNotFound. Disabled
// clients are returned.
func (s *OAuthStore) FindClient(_ context.Context, id string) (oauth.Client, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.clients[id]
	if !ok {
		return oauth.Client{}, oauth.ErrClientNotFound
	}
	return cloneClient(c), nil
}

// ListClients returns every client whose ContainerID is containerID —
// "" selects the application-level ones — disabled or not. Order follows
// Go map iteration and is therefore randomised.
func (s *OAuthStore) ListClients(_ context.Context, containerID string) ([]oauth.Client, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]oauth.Client, 0)
	for _, c := range s.clients {
		if c.ContainerID == containerID {
			out = append(out, cloneClient(c))
		}
	}
	return out, nil
}

// UpdateClient replaces the mutable fields of the stored client with c's,
// leaving ID, ContainerID, Public, CreatedBy and CreatedAt as they were, or
// returns oauth.ErrClientNotFound.
func (s *OAuthStore) UpdateClient(_ context.Context, c oauth.Client) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, ok := s.clients[c.ID]
	if !ok {
		return oauth.ErrClientNotFound
	}
	c = cloneClient(c)
	cur.Name = c.Name
	cur.SecretHash = c.SecretHash
	cur.RedirectURIs = c.RedirectURIs
	cur.GrantTypes = c.GrantTypes
	cur.Scopes = c.Scopes
	cur.ServiceAccountID = c.ServiceAccountID
	cur.Permissions = c.Permissions
	cur.UpdatedAt = c.UpdatedAt
	cur.DisabledAt = c.DisabledAt
	s.clients[c.ID] = cur
	return nil
}

// DeleteClient removes the client and every grant, code, device
// authorization and refresh token naming it under ONE acquisition of mu —
// the port's cascade MUST in the in-process shape — or returns
// oauth.ErrClientNotFound, touching nothing in that case.
func (s *OAuthStore) DeleteClient(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.clients[id]; !ok {
		return oauth.ErrClientNotFound
	}
	for k, r := range s.refresh {
		if r.ClientID == id {
			delete(s.refresh, k)
		}
	}
	for k, c := range s.codes {
		if c.ClientID == id {
			delete(s.codes, k)
		}
	}
	for k, d := range s.devices {
		if d.ClientID == id {
			delete(s.devices, k)
		}
	}
	for k, g := range s.grants {
		if g.ClientID == id {
			delete(s.grants, k)
		}
	}
	delete(s.clients, id)
	return nil
}

// ── Grants ──────────────────────────────────────────────────────────────

// CreateGrant stores g under its ID and returns it unchanged, or returns
// oauth.ErrIDTaken if a grant with that id exists or oauth.ErrClientNotFound
// if g.ClientID names no client. Both checks and the write happen under one
// acquisition of mu; the id is checked first.
func (s *OAuthStore) CreateGrant(_ context.Context, g oauth.Grant) (oauth.Grant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, taken := s.grants[g.ID]; taken {
		return oauth.Grant{}, oauth.ErrIDTaken
	}
	if _, ok := s.clients[g.ClientID]; !ok {
		return oauth.Grant{}, oauth.ErrClientNotFound
	}
	g.Permissions = slices.Clone(g.Permissions)
	s.grants[g.ID] = g
	return g, nil
}

// FindGrant returns the grant, or oauth.ErrGrantNotFound. Revoked and
// expired grants are returned.
func (s *OAuthStore) FindGrant(_ context.Context, id string) (oauth.Grant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.grants[id]
	if !ok {
		return oauth.Grant{}, oauth.ErrGrantNotFound
	}
	return g, nil
}

// ListGrantsByUser returns every grant of userID, revoked or not. Order
// follows Go map iteration and is therefore randomised.
func (s *OAuthStore) ListGrantsByUser(_ context.Context, userID string) ([]oauth.Grant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]oauth.Grant, 0)
	for _, g := range s.grants {
		if g.UserID == userID {
			out = append(out, g)
		}
	}
	return out, nil
}

// RevokeGrant stamps RevokedAt with now and deletes every refresh token of
// the grant under one acquisition of mu, or returns oauth.ErrGrantNotFound.
// Revoking a revoked grant overwrites the timestamp.
func (s *OAuthStore) RevokeGrant(_ context.Context, id string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.grants[id]
	if !ok {
		return oauth.ErrGrantNotFound
	}
	for k, r := range s.refresh {
		if r.GrantID == id {
			delete(s.refresh, k)
		}
	}
	g.RevokedAt = &now
	s.grants[id] = g
	return nil
}

// TouchGrant stamps LastUsedAt with now, or returns oauth.ErrGrantNotFound.
func (s *OAuthStore) TouchGrant(_ context.Context, id string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.grants[id]
	if !ok {
		return oauth.ErrGrantNotFound
	}
	g.LastUsedAt = &now
	s.grants[id] = g
	return nil
}

// ── Authorization codes ─────────────────────────────────────────────────

// CreateCode stores c under its ID and returns it unchanged, or returns
// oauth.ErrIDTaken if a code with that id exists, oauth.ErrGrantNotFound if
// c.GrantID names no grant, or [ErrTokenHashTaken] if another code already
// holds c.CodeHash. All three checks and the write happen under one
// acquisition of mu, in that order.
func (s *OAuthStore) CreateCode(_ context.Context, c oauth.AuthorizationCode) (oauth.AuthorizationCode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, taken := s.codes[c.ID]; taken {
		return oauth.AuthorizationCode{}, oauth.ErrIDTaken
	}
	if _, ok := s.grants[c.GrantID]; !ok {
		return oauth.AuthorizationCode{}, oauth.ErrGrantNotFound
	}
	for _, other := range s.codes {
		if other.CodeHash == c.CodeHash {
			return oauth.AuthorizationCode{}, ErrTokenHashTaken
		}
	}
	s.codes[c.ID] = c
	return c, nil
}

// RedeemCode implements the port's compare-and-set under one acquisition of
// mu: the code whose CodeHash matches gets RedeemedAt = now if and only if
// it was nil, and the caller is told whether it made that transition. An
// already-redeemed code is (row, false, nil); no row is oauth.ErrCodeNotFound.
// Expiry is not consulted.
func (s *OAuthStore) RedeemCode(_ context.Context, codeHash string, now time.Time) (oauth.AuthorizationCode, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, c := range s.codes {
		if c.CodeHash != codeHash {
			continue
		}
		if c.RedeemedAt != nil {
			return c, false, nil
		}
		c.RedeemedAt = &now
		s.codes[id] = c
		return c, true, nil
	}
	return oauth.AuthorizationCode{}, false, oauth.ErrCodeNotFound
}

// ── Device authorizations ───────────────────────────────────────────────

// CreateDeviceAuthorization stores d under its ID and returns it unchanged,
// or returns oauth.ErrIDTaken if a row with that id exists,
// oauth.ErrClientNotFound if d.ClientID names no client, [ErrTokenHashTaken]
// if another row holds d.DeviceCodeHash, or [ErrUserCodeTaken] if another
// row holds d.UserCode. All four checks and the write happen under one
// acquisition of mu, in that order.
func (s *OAuthStore) CreateDeviceAuthorization(_ context.Context, d oauth.DeviceAuthorization) (oauth.DeviceAuthorization, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, taken := s.devices[d.ID]; taken {
		return oauth.DeviceAuthorization{}, oauth.ErrIDTaken
	}
	if _, ok := s.clients[d.ClientID]; !ok {
		return oauth.DeviceAuthorization{}, oauth.ErrClientNotFound
	}
	for _, other := range s.devices {
		if other.DeviceCodeHash == d.DeviceCodeHash {
			return oauth.DeviceAuthorization{}, ErrTokenHashTaken
		}
	}
	for _, other := range s.devices {
		if other.UserCode == d.UserCode {
			return oauth.DeviceAuthorization{}, ErrUserCodeTaken
		}
	}
	s.devices[d.ID] = d
	return d, nil
}

// FindDeviceByCodeHash scans for the authorization whose DeviceCodeHash
// matches, or returns oauth.ErrDeviceNotFound. Every status is returned.
func (s *OAuthStore) FindDeviceByCodeHash(_ context.Context, deviceCodeHash string) (oauth.DeviceAuthorization, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, d := range s.devices {
		if d.DeviceCodeHash == deviceCodeHash {
			return d, nil
		}
	}
	return oauth.DeviceAuthorization{}, oauth.ErrDeviceNotFound
}

// FindDeviceByUserCode scans for the authorization whose UserCode matches
// exactly, or returns oauth.ErrDeviceNotFound.
func (s *OAuthStore) FindDeviceByUserCode(_ context.Context, userCode string) (oauth.DeviceAuthorization, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, d := range s.devices {
		if d.UserCode == userCode {
			return d, nil
		}
	}
	return oauth.DeviceAuthorization{}, oauth.ErrDeviceNotFound
}

// SetDeviceStatus implements the port's compare-and-set under one
// acquisition of mu: the row moves from Status == from to to, writing
// GrantID when to is approved, and the caller is told whether this call made
// the transition. A row in any other status is (false, nil); no row is
// oauth.ErrDeviceNotFound.
func (s *OAuthStore) SetDeviceStatus(_ context.Context, id string, from, to oauth.DeviceStatus, grantID string, _ time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.devices[id]
	if !ok {
		return false, oauth.ErrDeviceNotFound
	}
	if d.Status != from {
		return false, nil
	}
	d.Status = to
	if to == oauth.DeviceStatusApproved {
		d.GrantID = grantID
	}
	s.devices[id] = d
	return true, nil
}

// TouchDevicePoll stamps LastPolledAt with now, or returns
// oauth.ErrDeviceNotFound.
func (s *OAuthStore) TouchDevicePoll(_ context.Context, id string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.devices[id]
	if !ok {
		return oauth.ErrDeviceNotFound
	}
	d.LastPolledAt = &now
	s.devices[id] = d
	return nil
}

// ── Refresh tokens ──────────────────────────────────────────────────────

// CreateRefreshToken stores r under its ID and returns it unchanged, or
// returns oauth.ErrIDTaken if a token with that id exists,
// oauth.ErrGrantNotFound if r.GrantID names no grant, or [ErrTokenHashTaken]
// if another token holds r.TokenHash. All three checks and the write happen
// under one acquisition of mu, in that order.
func (s *OAuthStore) CreateRefreshToken(_ context.Context, r oauth.RefreshToken) (oauth.RefreshToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, taken := s.refresh[r.ID]; taken {
		return oauth.RefreshToken{}, oauth.ErrIDTaken
	}
	if _, ok := s.grants[r.GrantID]; !ok {
		return oauth.RefreshToken{}, oauth.ErrGrantNotFound
	}
	for _, other := range s.refresh {
		if other.TokenHash == r.TokenHash {
			return oauth.RefreshToken{}, ErrTokenHashTaken
		}
	}
	s.refresh[r.ID] = r
	return r, nil
}

// FindRefreshTokenByHash scans for the token whose TokenHash matches, or
// returns oauth.ErrRefreshNotFound. Rotated and expired tokens are returned.
func (s *OAuthStore) FindRefreshTokenByHash(_ context.Context, tokenHash string) (oauth.RefreshToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.refresh {
		if r.TokenHash == tokenHash {
			return r, nil
		}
	}
	return oauth.RefreshToken{}, oauth.ErrRefreshNotFound
}

// MarkRefreshRotated implements the port's compare-and-set under one
// acquisition of mu, exactly as [AuthStore.MarkRotated] does: the token
// whose TokenHash matches gets RotatedAt = now if and only if it was nil.
// An already-rotated token is (row, false, nil); no row is
// oauth.ErrRefreshNotFound. Expiry is not consulted.
func (s *OAuthStore) MarkRefreshRotated(_ context.Context, tokenHash string, now time.Time) (oauth.RefreshToken, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, r := range s.refresh {
		if r.TokenHash != tokenHash {
			continue
		}
		if r.RotatedAt != nil {
			return r, false, nil
		}
		r.RotatedAt = &now
		s.refresh[id] = r
		return r, true, nil
	}
	return oauth.RefreshToken{}, false, oauth.ErrRefreshNotFound
}

// DeleteRefreshFamily removes every token whose FamilyID matches. A family
// with no rows is not an error.
func (s *OAuthStore) DeleteRefreshFamily(_ context.Context, familyID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, r := range s.refresh {
		if r.FamilyID == familyID {
			delete(s.refresh, id)
		}
	}
	return nil
}

// ── Housekeeping ────────────────────────────────────────────────────────

// PurgeExpired deletes every code, device authorization and refresh token
// expired strictly before before, and every grant expired or revoked
// strictly before it together with its codes and refresh tokens, and
// returns how many rows went. A row exactly at the cutoff survives one more
// pass; live rows and clients are left alone.
func (s *OAuthStore) PurgeExpired(_ context.Context, before time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	dead := map[string]bool{}
	for id, g := range s.grants {
		expired := g.ExpiresAt != nil && g.ExpiresAt.Before(before)
		revoked := g.RevokedAt != nil && g.RevokedAt.Before(before)
		if expired || revoked {
			dead[id] = true
			delete(s.grants, id)
			n++
		}
	}
	for id, c := range s.codes {
		if c.ExpiresAt.Before(before) || dead[c.GrantID] {
			delete(s.codes, id)
			n++
		}
	}
	for id, d := range s.devices {
		if d.ExpiresAt.Before(before) {
			delete(s.devices, id)
			n++
		}
	}
	for id, r := range s.refresh {
		if r.ExpiresAt.Before(before) || dead[r.GrantID] {
			delete(s.refresh, id)
			n++
		}
	}
	return n, nil
}
