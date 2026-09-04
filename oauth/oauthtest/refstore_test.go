package oauthtest

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/bernardoforcillo/authlayer/oauth"
)

// errDuplicate is what [refStore] reports on a hash or user-code collision.
// [oauth.Store] classifies no such collision — it names ErrIDTaken for an id
// and nothing for a hash — so this is deliberately not a package sentinel,
// exactly as store/drops lets PostgreSQL's own unique violation through and
// store/memory answers with its own errors. Nothing in the suite looks at
// it; the checks require only that the write failed.
var errDuplicate = errors.New("oauthtest: value already exists")

// refStore is a compliant [oauth.Store] written for this package's own
// tests. It exists so the deliberately non-compliant doubles in
// negative_test.go can each be exactly ONE defect away from a correct
// store: every one of them embeds a *refStore and overrides a single method,
// reaching this type's maps directly, which is why it lives here rather than
// being replaced by store/memory's OAuthStore (whose internals are
// unexported, and which is a backend under test by this suite rather than
// the fixture that defines what passing it looks like).
//
// Every method holds mu for its entire body, so no check-then-write in it
// can be split by a concurrent call — the in-process shape every atomicity
// MUST on the port names. TestTheReferenceStorePassesTheContract is what
// makes the negative controls mean anything.
type refStore struct {
	mu      sync.Mutex
	clients map[string]oauth.Client
	grants  map[string]oauth.Grant
	codes   map[string]oauth.AuthorizationCode
	devices map[string]oauth.DeviceAuthorization
	refresh map[string]oauth.RefreshToken
}

func newRefStore() *refStore {
	return &refStore{
		clients: map[string]oauth.Client{},
		grants:  map[string]oauth.Grant{},
		codes:   map[string]oauth.AuthorizationCode{},
		devices: map[string]oauth.DeviceAuthorization{},
		refresh: map[string]oauth.RefreshToken{},
	}
}

var _ oauth.Store = (*refStore)(nil)

// The *Taken helpers report whether a value is already held. Callers hold mu.

func (s *refStore) codeHashTaken(h string) bool {
	for _, c := range s.codes {
		if c.CodeHash == h {
			return true
		}
	}
	return false
}

func (s *refStore) deviceHashTaken(h string) bool {
	for _, d := range s.devices {
		if d.DeviceCodeHash == h {
			return true
		}
	}
	return false
}

func (s *refStore) userCodeTaken(u string) bool {
	for _, d := range s.devices {
		if d.UserCode == u {
			return true
		}
	}
	return false
}

func (s *refStore) refreshHashTaken(h string) bool {
	for _, r := range s.refresh {
		if r.TokenHash == h {
			return true
		}
	}
	return false
}

// cascadeClient removes every row naming clientID. Callers hold mu.
func (s *refStore) cascadeClient(clientID string) {
	for k, r := range s.refresh {
		if r.ClientID == clientID {
			delete(s.refresh, k)
		}
	}
	for k, c := range s.codes {
		if c.ClientID == clientID {
			delete(s.codes, k)
		}
	}
	for k, d := range s.devices {
		if d.ClientID == clientID {
			delete(s.devices, k)
		}
	}
	for k, g := range s.grants {
		if g.ClientID == clientID {
			delete(s.grants, k)
		}
	}
}

func (s *refStore) CreateClient(_ context.Context, c oauth.Client) (oauth.Client, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, taken := s.clients[c.ID]; taken {
		return oauth.Client{}, oauth.ErrIDTaken
	}
	s.clients[c.ID] = c
	return c, nil
}

func (s *refStore) FindClient(_ context.Context, id string) (oauth.Client, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.clients[id]
	if !ok {
		return oauth.Client{}, oauth.ErrClientNotFound
	}
	return c, nil
}

func (s *refStore) ListClients(_ context.Context, containerID string) ([]oauth.Client, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []oauth.Client
	for _, c := range s.clients {
		if c.ContainerID == containerID {
			out = append(out, c)
		}
	}
	return out, nil
}

func (s *refStore) UpdateClient(_ context.Context, c oauth.Client) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, ok := s.clients[c.ID]
	if !ok {
		return oauth.ErrClientNotFound
	}
	cur.Name, cur.SecretHash, cur.RedirectURIs, cur.GrantTypes, cur.Scopes = c.Name, c.SecretHash, c.RedirectURIs, c.GrantTypes, c.Scopes
	cur.ServiceAccountID, cur.Permissions, cur.UpdatedAt, cur.DisabledAt = c.ServiceAccountID, c.Permissions, c.UpdatedAt, c.DisabledAt
	s.clients[c.ID] = cur
	return nil
}

func (s *refStore) DeleteClient(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.clients[id]; !ok {
		return oauth.ErrClientNotFound
	}
	s.cascadeClient(id)
	delete(s.clients, id)
	return nil
}

func (s *refStore) CreateGrant(_ context.Context, g oauth.Grant) (oauth.Grant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, taken := s.grants[g.ID]; taken {
		return oauth.Grant{}, oauth.ErrIDTaken
	}
	if _, ok := s.clients[g.ClientID]; !ok {
		return oauth.Grant{}, oauth.ErrClientNotFound
	}
	s.grants[g.ID] = g
	return g, nil
}

func (s *refStore) FindGrant(_ context.Context, id string) (oauth.Grant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.grants[id]
	if !ok {
		return oauth.Grant{}, oauth.ErrGrantNotFound
	}
	return g, nil
}

func (s *refStore) ListGrantsByUser(_ context.Context, userID string) ([]oauth.Grant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []oauth.Grant
	for _, g := range s.grants {
		if g.UserID == userID {
			out = append(out, g)
		}
	}
	return out, nil
}

func (s *refStore) RevokeGrant(_ context.Context, id string, now time.Time) error {
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

func (s *refStore) TouchGrant(_ context.Context, id string, now time.Time) error {
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

func (s *refStore) CreateCode(_ context.Context, c oauth.AuthorizationCode) (oauth.AuthorizationCode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, taken := s.codes[c.ID]; taken {
		return oauth.AuthorizationCode{}, oauth.ErrIDTaken
	}
	if _, ok := s.grants[c.GrantID]; !ok {
		return oauth.AuthorizationCode{}, oauth.ErrGrantNotFound
	}
	if s.codeHashTaken(c.CodeHash) {
		return oauth.AuthorizationCode{}, errDuplicate
	}
	s.codes[c.ID] = c
	return c, nil
}

func (s *refStore) RedeemCode(_ context.Context, codeHash string, now time.Time) (oauth.AuthorizationCode, bool, error) {
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

func (s *refStore) CreateDeviceAuthorization(_ context.Context, d oauth.DeviceAuthorization) (oauth.DeviceAuthorization, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, taken := s.devices[d.ID]; taken {
		return oauth.DeviceAuthorization{}, oauth.ErrIDTaken
	}
	if _, ok := s.clients[d.ClientID]; !ok {
		return oauth.DeviceAuthorization{}, oauth.ErrClientNotFound
	}
	if s.deviceHashTaken(d.DeviceCodeHash) || s.userCodeTaken(d.UserCode) {
		return oauth.DeviceAuthorization{}, errDuplicate
	}
	s.devices[d.ID] = d
	return d, nil
}

func (s *refStore) FindDeviceByCodeHash(_ context.Context, h string) (oauth.DeviceAuthorization, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, d := range s.devices {
		if d.DeviceCodeHash == h {
			return d, nil
		}
	}
	return oauth.DeviceAuthorization{}, oauth.ErrDeviceNotFound
}

func (s *refStore) FindDeviceByUserCode(_ context.Context, u string) (oauth.DeviceAuthorization, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, d := range s.devices {
		if d.UserCode == u {
			return d, nil
		}
	}
	return oauth.DeviceAuthorization{}, oauth.ErrDeviceNotFound
}

func (s *refStore) SetDeviceStatus(_ context.Context, id string, from, to oauth.DeviceStatus, grantID string, _ time.Time) (bool, error) {
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

func (s *refStore) TouchDevicePoll(_ context.Context, id string, now time.Time) error {
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

func (s *refStore) CreateRefreshToken(_ context.Context, r oauth.RefreshToken) (oauth.RefreshToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, taken := s.refresh[r.ID]; taken {
		return oauth.RefreshToken{}, oauth.ErrIDTaken
	}
	if _, ok := s.grants[r.GrantID]; !ok {
		return oauth.RefreshToken{}, oauth.ErrGrantNotFound
	}
	if s.refreshHashTaken(r.TokenHash) {
		return oauth.RefreshToken{}, errDuplicate
	}
	s.refresh[r.ID] = r
	return r, nil
}

func (s *refStore) FindRefreshTokenByHash(_ context.Context, h string) (oauth.RefreshToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.refresh {
		if r.TokenHash == h {
			return r, nil
		}
	}
	return oauth.RefreshToken{}, oauth.ErrRefreshNotFound
}

func (s *refStore) MarkRefreshRotated(_ context.Context, h string, now time.Time) (oauth.RefreshToken, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, r := range s.refresh {
		if r.TokenHash != h {
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

func (s *refStore) DeleteRefreshFamily(_ context.Context, familyID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, r := range s.refresh {
		if r.FamilyID == familyID {
			delete(s.refresh, id)
		}
	}
	return nil
}

func (s *refStore) PurgeExpired(_ context.Context, before time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	dead := map[string]bool{}
	for id, g := range s.grants {
		if (g.ExpiresAt != nil && g.ExpiresAt.Before(before)) || (g.RevokedAt != nil && g.RevokedAt.Before(before)) {
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
