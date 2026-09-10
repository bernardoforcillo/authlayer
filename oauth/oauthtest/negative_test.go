package oauthtest

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/bernardoforcillo/authlayer/oauth"
)

// gap is how long the deliberately non-atomic doubles below hold their
// check-then-write window open. A real split implementation's window is
// sub-microsecond, far too narrow for a control whose whole job is to prove
// a check bites; widening it to milliseconds makes each control
// deterministic. What these controls therefore prove is that the check
// DETECTS the defect when the interleaving occurs, not that it forces the
// interleaving on a subtly broken backend — a limit the checks' own doc
// comments state.
const gap = 5 * time.Millisecond

// ── The non-compliant doubles ───────────────────────────────────────────
//
// Each is exactly one defect away from [refStore]: it embeds one and
// overrides a single method (or the two halves of one policy) with a
// deliberately wrong shape.

// droppedFields loses one field of each record kind on the way in: a
// client's redirect URIs (the exact-match allowlist), a grant's Permissions
// (the cap, so a capped delegation is stored uncapped), a code's challenge,
// a device authorization's grant id, a refresh token's rotation stamp.
type droppedFields struct{ *refStore }

func (s droppedFields) CreateClient(ctx context.Context, c oauth.Client) (oauth.Client, error) {
	c.RedirectURIs = nil
	return s.refStore.CreateClient(ctx, c)
}

func (s droppedFields) CreateGrant(ctx context.Context, g oauth.Grant) (oauth.Grant, error) {
	g.Permissions = nil
	return s.refStore.CreateGrant(ctx, g)
}

func (s droppedFields) CreateCode(ctx context.Context, c oauth.AuthorizationCode) (oauth.AuthorizationCode, error) {
	c.CodeChallenge = ""
	return s.refStore.CreateCode(ctx, c)
}

func (s droppedFields) CreateDeviceAuthorization(ctx context.Context, d oauth.DeviceAuthorization) (oauth.DeviceAuthorization, error) {
	d.GrantID = ""
	return s.refStore.CreateDeviceAuthorization(ctx, d)
}

func (s droppedFields) CreateRefreshToken(ctx context.Context, r oauth.RefreshToken) (oauth.RefreshToken, error) {
	r.RotatedAt = nil
	return s.refStore.CreateRefreshToken(ctx, r)
}

// overwritingIDs accepts a second row of every kind under a taken id.
type overwritingIDs struct{ *refStore }

func (s overwritingIDs) CreateClient(_ context.Context, c oauth.Client) (oauth.Client, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clients[c.ID] = c
	return c, nil
}

func (s overwritingIDs) CreateGrant(_ context.Context, g oauth.Grant) (oauth.Grant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.clients[g.ClientID]; !ok {
		return oauth.Grant{}, oauth.ErrClientNotFound
	}
	s.grants[g.ID] = g
	return g, nil
}

func (s overwritingIDs) CreateCode(_ context.Context, c oauth.AuthorizationCode) (oauth.AuthorizationCode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.grants[c.GrantID]; !ok {
		return oauth.AuthorizationCode{}, oauth.ErrGrantNotFound
	}
	if s.codeHashTaken(c.CodeHash) {
		return oauth.AuthorizationCode{}, errDuplicate
	}
	s.codes[c.ID] = c
	return c, nil
}

func (s overwritingIDs) CreateDeviceAuthorization(_ context.Context, d oauth.DeviceAuthorization) (oauth.DeviceAuthorization, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.clients[d.ClientID]; !ok {
		return oauth.DeviceAuthorization{}, oauth.ErrClientNotFound
	}
	if s.deviceHashTaken(d.DeviceCodeHash) || s.userCodeTaken(d.UserCode) {
		return oauth.DeviceAuthorization{}, errDuplicate
	}
	s.devices[d.ID] = d
	return d, nil
}

func (s overwritingIDs) CreateRefreshToken(_ context.Context, r oauth.RefreshToken) (oauth.RefreshToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.grants[r.GrantID]; !ok {
		return oauth.RefreshToken{}, oauth.ErrGrantNotFound
	}
	if s.refreshHashTaken(r.TokenHash) {
		return oauth.RefreshToken{}, errDuplicate
	}
	s.refresh[r.ID] = r
	return r, nil
}

// sharedHashes lets two codes share a code hash, two device authorizations
// a device-code hash, two refresh tokens a token hash — the uniqueness MUSTs
// on those three record types.
type sharedHashes struct{ *refStore }

func (s sharedHashes) CreateCode(_ context.Context, c oauth.AuthorizationCode) (oauth.AuthorizationCode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, taken := s.codes[c.ID]; taken {
		return oauth.AuthorizationCode{}, oauth.ErrIDTaken
	}
	if _, ok := s.grants[c.GrantID]; !ok {
		return oauth.AuthorizationCode{}, oauth.ErrGrantNotFound
	}
	s.codes[c.ID] = c
	return c, nil
}

func (s sharedHashes) CreateDeviceAuthorization(_ context.Context, d oauth.DeviceAuthorization) (oauth.DeviceAuthorization, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, taken := s.devices[d.ID]; taken {
		return oauth.DeviceAuthorization{}, oauth.ErrIDTaken
	}
	if _, ok := s.clients[d.ClientID]; !ok {
		return oauth.DeviceAuthorization{}, oauth.ErrClientNotFound
	}
	if s.userCodeTaken(d.UserCode) {
		return oauth.DeviceAuthorization{}, errDuplicate
	}
	s.devices[d.ID] = d
	return d, nil
}

func (s sharedHashes) CreateRefreshToken(_ context.Context, r oauth.RefreshToken) (oauth.RefreshToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, taken := s.refresh[r.ID]; taken {
		return oauth.RefreshToken{}, oauth.ErrIDTaken
	}
	if _, ok := s.grants[r.GrantID]; !ok {
		return oauth.RefreshToken{}, oauth.ErrGrantNotFound
	}
	s.refresh[r.ID] = r
	return r, nil
}

// sharedUserCodes lets two device authorizations share a user code.
type sharedUserCodes struct{ *refStore }

func (s sharedUserCodes) CreateDeviceAuthorization(_ context.Context, d oauth.DeviceAuthorization) (oauth.DeviceAuthorization, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, taken := s.devices[d.ID]; taken {
		return oauth.DeviceAuthorization{}, oauth.ErrIDTaken
	}
	if _, ok := s.clients[d.ClientID]; !ok {
		return oauth.DeviceAuthorization{}, oauth.ErrClientNotFound
	}
	if s.deviceHashTaken(d.DeviceCodeHash) {
		return oauth.DeviceAuthorization{}, errDuplicate
	}
	s.devices[d.ID] = d
	return d, nil
}

// orphans writes a grant or device authorization for a client that does not
// exist, and a code or refresh token for a grant that does not.
type orphans struct{ *refStore }

func (s orphans) CreateGrant(_ context.Context, g oauth.Grant) (oauth.Grant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, taken := s.grants[g.ID]; taken {
		return oauth.Grant{}, oauth.ErrIDTaken
	}
	s.grants[g.ID] = g
	return g, nil
}

func (s orphans) CreateCode(_ context.Context, c oauth.AuthorizationCode) (oauth.AuthorizationCode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, taken := s.codes[c.ID]; taken {
		return oauth.AuthorizationCode{}, oauth.ErrIDTaken
	}
	if s.codeHashTaken(c.CodeHash) {
		return oauth.AuthorizationCode{}, errDuplicate
	}
	s.codes[c.ID] = c
	return c, nil
}

func (s orphans) CreateDeviceAuthorization(_ context.Context, d oauth.DeviceAuthorization) (oauth.DeviceAuthorization, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, taken := s.devices[d.ID]; taken {
		return oauth.DeviceAuthorization{}, oauth.ErrIDTaken
	}
	if s.deviceHashTaken(d.DeviceCodeHash) || s.userCodeTaken(d.UserCode) {
		return oauth.DeviceAuthorization{}, errDuplicate
	}
	s.devices[d.ID] = d
	return d, nil
}

func (s orphans) CreateRefreshToken(_ context.Context, r oauth.RefreshToken) (oauth.RefreshToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, taken := s.refresh[r.ID]; taken {
		return oauth.RefreshToken{}, oauth.ErrIDTaken
	}
	if s.refreshHashTaken(r.TokenHash) {
		return oauth.RefreshToken{}, errDuplicate
	}
	s.refresh[r.ID] = r
	return r, nil
}

// silentNotFound answers every miss with a zero record and a nil error — on
// the plain lookups and on the two compare-and-sets, where a silent miss
// reads exactly like a lost race.
type silentNotFound struct{ *refStore }

func (s silentNotFound) FindClient(ctx context.Context, id string) (oauth.Client, error) {
	c, err := s.refStore.FindClient(ctx, id)
	if errors.Is(err, oauth.ErrClientNotFound) {
		return oauth.Client{}, nil
	}
	return c, err
}

func (s silentNotFound) FindGrant(ctx context.Context, id string) (oauth.Grant, error) {
	g, err := s.refStore.FindGrant(ctx, id)
	if errors.Is(err, oauth.ErrGrantNotFound) {
		return oauth.Grant{}, nil
	}
	return g, err
}

func (s silentNotFound) FindDeviceByCodeHash(ctx context.Context, h string) (oauth.DeviceAuthorization, error) {
	d, err := s.refStore.FindDeviceByCodeHash(ctx, h)
	if errors.Is(err, oauth.ErrDeviceNotFound) {
		return oauth.DeviceAuthorization{}, nil
	}
	return d, err
}

func (s silentNotFound) FindDeviceByUserCode(ctx context.Context, u string) (oauth.DeviceAuthorization, error) {
	d, err := s.refStore.FindDeviceByUserCode(ctx, u)
	if errors.Is(err, oauth.ErrDeviceNotFound) {
		return oauth.DeviceAuthorization{}, nil
	}
	return d, err
}

func (s silentNotFound) FindRefreshTokenByHash(ctx context.Context, h string) (oauth.RefreshToken, error) {
	r, err := s.refStore.FindRefreshTokenByHash(ctx, h)
	if errors.Is(err, oauth.ErrRefreshNotFound) {
		return oauth.RefreshToken{}, nil
	}
	return r, err
}

func (s silentNotFound) RedeemCode(ctx context.Context, h string, now time.Time) (oauth.AuthorizationCode, bool, error) {
	c, won, err := s.refStore.RedeemCode(ctx, h, now)
	if errors.Is(err, oauth.ErrCodeNotFound) {
		return oauth.AuthorizationCode{}, false, nil
	}
	return c, won, err
}

func (s silentNotFound) MarkRefreshRotated(ctx context.Context, h string, now time.Time) (oauth.RefreshToken, bool, error) {
	r, won, err := s.refStore.MarkRefreshRotated(ctx, h, now)
	if errors.Is(err, oauth.ErrRefreshNotFound) {
		return oauth.RefreshToken{}, false, nil
	}
	return r, won, err
}

func (s silentNotFound) SetDeviceStatus(ctx context.Context, id string, from, to oauth.DeviceStatus, grantID string, now time.Time) (bool, error) {
	won, err := s.refStore.SetDeviceStatus(ctx, id, from, to, grantID, now)
	if errors.Is(err, oauth.ErrDeviceNotFound) {
		return false, nil
	}
	return won, err
}

// silentMutations answer nil to an update, revoke, touch or delete that
// matched no row — the rows-affected gate removed from every one of them.
type silentMutations struct{ *refStore }

func (s silentMutations) UpdateClient(ctx context.Context, c oauth.Client) error {
	return swallow(s.refStore.UpdateClient(ctx, c), oauth.ErrClientNotFound)
}

func (s silentMutations) DeleteClient(ctx context.Context, id string) error {
	return swallow(s.refStore.DeleteClient(ctx, id), oauth.ErrClientNotFound)
}

func (s silentMutations) RevokeGrant(ctx context.Context, id string, now time.Time) error {
	return swallow(s.refStore.RevokeGrant(ctx, id, now), oauth.ErrGrantNotFound)
}

func (s silentMutations) TouchGrant(ctx context.Context, id string, now time.Time) error {
	return swallow(s.refStore.TouchGrant(ctx, id, now), oauth.ErrGrantNotFound)
}

func (s silentMutations) TouchDevicePoll(ctx context.Context, id string, now time.Time) error {
	return swallow(s.refStore.TouchDevicePoll(ctx, id, now), oauth.ErrDeviceNotFound)
}

func swallow(err, notFound error) error {
	if err != nil && !errors.Is(err, notFound) {
		return err
	}
	return nil
}

// listsIgnoreTheScope returns every row whatever container or user was
// asked for — a cross-tenant leak for clients, a cross-user leak for grants.
type listsIgnoreTheScope struct{ *refStore }

func (s listsIgnoreTheScope) ListClients(context.Context, string) ([]oauth.Client, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []oauth.Client
	for _, c := range s.clients {
		out = append(out, c)
	}
	return out, nil
}

func (s listsIgnoreTheScope) ListGrantsByUser(context.Context, string) ([]oauth.Grant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []oauth.Grant
	for _, g := range s.grants {
		out = append(out, g)
	}
	return out, nil
}

// listsFilterForTheCaller hides disabled clients, revoked or expired
// grants, and rotated or expired refresh tokens, doing the filtering the
// port leaves to the caller.
type listsFilterForTheCaller struct{ *refStore }

func (s listsFilterForTheCaller) ListClients(ctx context.Context, containerID string) ([]oauth.Client, error) {
	all, err := s.refStore.ListClients(ctx, containerID)
	var out []oauth.Client
	for _, c := range all {
		if c.DisabledAt == nil {
			out = append(out, c)
		}
	}
	return out, err
}

func (s listsFilterForTheCaller) ListGrantsByUser(ctx context.Context, userID string) ([]oauth.Grant, error) {
	all, err := s.refStore.ListGrantsByUser(ctx, userID)
	now := time.Now().UTC()
	var out []oauth.Grant
	for _, g := range all {
		if g.RevokedAt != nil || (g.ExpiresAt != nil && !now.Before(*g.ExpiresAt)) {
			continue
		}
		out = append(out, g)
	}
	return out, err
}

func (s listsFilterForTheCaller) FindRefreshTokenByHash(ctx context.Context, h string) (oauth.RefreshToken, error) {
	r, err := s.refStore.FindRefreshTokenByHash(ctx, h)
	if err != nil {
		return oauth.RefreshToken{}, err
	}
	if r.RotatedAt != nil || !time.Now().UTC().Before(r.ExpiresAt) {
		return oauth.RefreshToken{}, oauth.ErrRefreshNotFound
	}
	return r, nil
}

// emptyListIsAnError reports an empty result as a not-found error, and an
// empty family deletion the same way.
type emptyListIsAnError struct{ *refStore }

func (s emptyListIsAnError) ListClients(ctx context.Context, containerID string) ([]oauth.Client, error) {
	out, err := s.refStore.ListClients(ctx, containerID)
	if err == nil && len(out) == 0 {
		return nil, oauth.ErrClientNotFound
	}
	return out, err
}

func (s emptyListIsAnError) ListGrantsByUser(ctx context.Context, userID string) ([]oauth.Grant, error) {
	out, err := s.refStore.ListGrantsByUser(ctx, userID)
	if err == nil && len(out) == 0 {
		return nil, oauth.ErrGrantNotFound
	}
	return out, err
}

func (s emptyListIsAnError) DeleteRefreshFamily(_ context.Context, familyID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for id, r := range s.refresh {
		if r.FamilyID == familyID {
			delete(s.refresh, id)
			n++
		}
	}
	if n == 0 {
		return oauth.ErrRefreshNotFound
	}
	return nil
}

// updateReplacesTheWholeRow writes the immutable fields too.
type updateReplacesTheWholeRow struct{ *refStore }

func (s updateReplacesTheWholeRow) UpdateClient(_ context.Context, c oauth.Client) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.clients[c.ID]; !ok {
		return oauth.ErrClientNotFound
	}
	s.clients[c.ID] = c
	return nil
}

// deleteClientKeepsGrants removes the client and nothing else — the
// cascade MUST dropped entirely.
type deleteClientKeepsGrants struct{ *refStore }

func (s deleteClientKeepsGrants) DeleteClient(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.clients[id]; !ok {
		return oauth.ErrClientNotFound
	}
	delete(s.clients, id)
	return nil
}

// overbroadDeleteClient cascades to every client in the deleted one's
// CONTAINER rather than to the one client.
type overbroadDeleteClient struct{ *refStore }

func (s overbroadDeleteClient) DeleteClient(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	target, ok := s.clients[id]
	if !ok {
		return oauth.ErrClientNotFound
	}
	for cid, c := range s.clients {
		if c.ContainerID == target.ContainerID {
			s.cascadeClient(cid)
			delete(s.clients, cid)
		}
	}
	return nil
}

// revokeGrantKeepsTokens stamps the grant and leaves its refresh tokens —
// the cascade MUST on RevokeGrant dropped.
type revokeGrantKeepsTokens struct{ *refStore }

func (s revokeGrantKeepsTokens) RevokeGrant(_ context.Context, id string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.grants[id]
	if !ok {
		return oauth.ErrGrantNotFound
	}
	g.RevokedAt = &now
	s.grants[id] = g
	return nil
}

// overbroadRevokeGrant deletes every refresh token of the grant's CLIENT.
type overbroadRevokeGrant struct{ *refStore }

func (s overbroadRevokeGrant) RevokeGrant(_ context.Context, id string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.grants[id]
	if !ok {
		return oauth.ErrGrantNotFound
	}
	for k, r := range s.refresh {
		if r.ClientID == g.ClientID {
			delete(s.refresh, k)
		}
	}
	g.RevokedAt = &now
	s.grants[id] = g
	return nil
}

// revokeRefusesASecondTime treats an already-revoked grant as an error.
type revokeRefusesASecondTime struct{ *refStore }

func (s revokeRefusesASecondTime) RevokeGrant(ctx context.Context, id string, now time.Time) error {
	s.mu.Lock()
	g, ok := s.grants[id]
	s.mu.Unlock()
	if ok && g.RevokedAt != nil {
		return oauth.ErrGrantRevoked
	}
	return s.refStore.RevokeGrant(ctx, id, now)
}

// touchesDoNotStamp report success without writing LastUsedAt or
// LastPolledAt.
type touchesDoNotStamp struct{ *refStore }

func (s touchesDoNotStamp) TouchGrant(_ context.Context, id string, _ time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.grants[id]; !ok {
		return oauth.ErrGrantNotFound
	}
	return nil
}

func (s touchesDoNotStamp) TouchDevicePoll(_ context.Context, id string, _ time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.devices[id]; !ok {
		return oauth.ErrDeviceNotFound
	}
	return nil
}

// casDoesNotStamp reports a win from each compare-and-set without writing
// anything: every caller wins, nothing is ever redeemed, rotated or moved.
type casDoesNotStamp struct{ *refStore }

func (s casDoesNotStamp) RedeemCode(_ context.Context, h string, _ time.Time) (oauth.AuthorizationCode, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.codes {
		if c.CodeHash == h {
			return c, true, nil
		}
	}
	return oauth.AuthorizationCode{}, false, oauth.ErrCodeNotFound
}

func (s casDoesNotStamp) MarkRefreshRotated(_ context.Context, h string, _ time.Time) (oauth.RefreshToken, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.refresh {
		if r.TokenHash == h {
			return r, true, nil
		}
	}
	return oauth.RefreshToken{}, false, oauth.ErrRefreshNotFound
}

func (s casDoesNotStamp) SetDeviceStatus(_ context.Context, id string, _, _ oauth.DeviceStatus, _ string, _ time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.devices[id]; !ok {
		return false, oauth.ErrDeviceNotFound
	}
	return true, nil
}

// casAlwaysWins writes on every call and reports a win on every call — the
// compare dropped from each compare-and-set.
type casAlwaysWins struct{ *refStore }

func (s casAlwaysWins) RedeemCode(_ context.Context, h string, now time.Time) (oauth.AuthorizationCode, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, c := range s.codes {
		if c.CodeHash == h {
			c.RedeemedAt = &now
			s.codes[id] = c
			return c, true, nil
		}
	}
	return oauth.AuthorizationCode{}, false, oauth.ErrCodeNotFound
}

func (s casAlwaysWins) MarkRefreshRotated(_ context.Context, h string, now time.Time) (oauth.RefreshToken, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, r := range s.refresh {
		if r.TokenHash == h {
			r.RotatedAt = &now
			s.refresh[id] = r
			return r, true, nil
		}
	}
	return oauth.RefreshToken{}, false, oauth.ErrRefreshNotFound
}

func (s casAlwaysWins) SetDeviceStatus(_ context.Context, id string, _, to oauth.DeviceStatus, grantID string, _ time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.devices[id]
	if !ok {
		return false, oauth.ErrDeviceNotFound
	}
	d.Status = to
	if to == oauth.DeviceStatusApproved {
		d.GrantID = grantID
	}
	s.devices[id] = d
	return true, nil
}

// casChecksExpiry folds an expiry test into the compare-and-set predicate,
// so an expired code or token is never consumed and a replay of it never
// detected.
type casChecksExpiry struct{ *refStore }

func (s casChecksExpiry) RedeemCode(ctx context.Context, h string, now time.Time) (oauth.AuthorizationCode, bool, error) {
	s.mu.Lock()
	for _, c := range s.codes {
		if c.CodeHash == h && !now.Before(c.ExpiresAt) {
			s.mu.Unlock()
			return c, false, nil
		}
	}
	s.mu.Unlock()
	return s.refStore.RedeemCode(ctx, h, now)
}

func (s casChecksExpiry) MarkRefreshRotated(ctx context.Context, h string, now time.Time) (oauth.RefreshToken, bool, error) {
	s.mu.Lock()
	for _, r := range s.refresh {
		if r.TokenHash == h && !now.Before(r.ExpiresAt) {
			s.mu.Unlock()
			return r, false, nil
		}
	}
	s.mu.Unlock()
	return s.refStore.MarkRefreshRotated(ctx, h, now)
}

// setStatusAlwaysWritesGrant attaches grantID on every transition, a denial
// included.
type setStatusAlwaysWritesGrant struct{ *refStore }

func (s setStatusAlwaysWritesGrant) SetDeviceStatus(_ context.Context, id string, from, to oauth.DeviceStatus, grantID string, _ time.Time) (bool, error) {
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
	d.GrantID = grantID
	s.devices[id] = d
	return true, nil
}

// deleteFamilyKeepsRotated deletes only the CURRENT token of a family,
// leaving the rotated ones — which is exactly what a reuse detector would
// then keep matching against.
type deleteFamilyKeepsRotated struct{ *refStore }

func (s deleteFamilyKeepsRotated) DeleteRefreshFamily(_ context.Context, familyID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, r := range s.refresh {
		if r.FamilyID == familyID && r.RotatedAt == nil {
			delete(s.refresh, id)
		}
	}
	return nil
}

// overbroadDeleteFamily deletes every token of the family's GRANT.
type overbroadDeleteFamily struct{ *refStore }

func (s overbroadDeleteFamily) DeleteRefreshFamily(_ context.Context, familyID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var grantID string
	for _, r := range s.refresh {
		if r.FamilyID == familyID {
			grantID = r.GrantID
		}
	}
	for id, r := range s.refresh {
		if r.GrantID == grantID {
			delete(s.refresh, id)
		}
	}
	return nil
}

// purgeInclusiveExpiry purges a row expiring exactly AT the cutoff.
type purgeInclusiveExpiry struct{ *refStore }

func (s purgeInclusiveExpiry) PurgeExpired(ctx context.Context, before time.Time) (int, error) {
	return s.refStore.PurgeExpired(ctx, before.Add(time.Nanosecond))
}

// purgeIgnoresGrants purges the three expiring kinds and never a grant.
type purgeIgnoresGrants struct{ *refStore }

func (s purgeIgnoresGrants) PurgeExpired(_ context.Context, before time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for id, c := range s.codes {
		if c.ExpiresAt.Before(before) {
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
		if r.ExpiresAt.Before(before) {
			delete(s.refresh, id)
			n++
		}
	}
	return n, nil
}

// purgeEverything treats a nil grant expiry as "expired at the dawn of
// time".
type purgeEverything struct{ *refStore }

func (s purgeEverything) PurgeExpired(ctx context.Context, before time.Time) (int, error) {
	s.mu.Lock()
	n := 0
	for id, g := range s.grants {
		if g.ExpiresAt == nil {
			delete(s.grants, id)
			n++
		}
	}
	s.mu.Unlock()
	m, err := s.refStore.PurgeExpired(ctx, before)
	return n + m, err
}

// purgeMiscounts reports one row more than it removed.
type purgeMiscounts struct{ *refStore }

func (s purgeMiscounts) PurgeExpired(ctx context.Context, before time.Time) (int, error) {
	n, err := s.refStore.PurgeExpired(ctx, before)
	return n + 1, err
}

// splitCAS decides each compare-and-set under one lock acquisition and
// writes under a second, with a gap between — the non-atomic shape the
// concurrent single-winner races exist to catch.
type splitCAS struct{ *refStore }

func (s splitCAS) RedeemCode(_ context.Context, h string, now time.Time) (oauth.AuthorizationCode, bool, error) {
	s.mu.Lock()
	var found *oauth.AuthorizationCode
	for _, c := range s.codes {
		if c.CodeHash == h {
			cc := c
			found = &cc
		}
	}
	s.mu.Unlock()
	if found == nil {
		return oauth.AuthorizationCode{}, false, oauth.ErrCodeNotFound
	}
	if found.RedeemedAt != nil {
		return *found, false, nil
	}
	time.Sleep(gap)
	s.mu.Lock()
	found.RedeemedAt = &now
	s.codes[found.ID] = *found
	s.mu.Unlock()
	return *found, true, nil
}

func (s splitCAS) MarkRefreshRotated(_ context.Context, h string, now time.Time) (oauth.RefreshToken, bool, error) {
	s.mu.Lock()
	var found *oauth.RefreshToken
	for _, r := range s.refresh {
		if r.TokenHash == h {
			rr := r
			found = &rr
		}
	}
	s.mu.Unlock()
	if found == nil {
		return oauth.RefreshToken{}, false, oauth.ErrRefreshNotFound
	}
	if found.RotatedAt != nil {
		return *found, false, nil
	}
	time.Sleep(gap)
	s.mu.Lock()
	found.RotatedAt = &now
	s.refresh[found.ID] = *found
	s.mu.Unlock()
	return *found, true, nil
}

func (s splitCAS) SetDeviceStatus(_ context.Context, id string, from, to oauth.DeviceStatus, grantID string, _ time.Time) (bool, error) {
	s.mu.Lock()
	d, ok := s.devices[id]
	s.mu.Unlock()
	if !ok {
		return false, oauth.ErrDeviceNotFound
	}
	if d.Status != from {
		return false, nil
	}
	time.Sleep(gap)
	s.mu.Lock()
	d.Status = to
	if to == oauth.DeviceStatusApproved {
		d.GrantID = grantID
	}
	s.devices[id] = d
	s.mu.Unlock()
	return true, nil
}

// splitUniqueChecks check each uniqueness constraint under one lock and
// write under another.
type splitUniqueChecks struct{ *refStore }

func (s splitUniqueChecks) CreateCode(_ context.Context, c oauth.AuthorizationCode) (oauth.AuthorizationCode, error) {
	s.mu.Lock()
	_, idTaken := s.codes[c.ID]
	_, hasGrant := s.grants[c.GrantID]
	hashTaken := s.codeHashTaken(c.CodeHash)
	s.mu.Unlock()
	switch {
	case idTaken:
		return oauth.AuthorizationCode{}, oauth.ErrIDTaken
	case !hasGrant:
		return oauth.AuthorizationCode{}, oauth.ErrGrantNotFound
	case hashTaken:
		return oauth.AuthorizationCode{}, errDuplicate
	}
	time.Sleep(gap)
	s.mu.Lock()
	s.codes[c.ID] = c
	s.mu.Unlock()
	return c, nil
}

func (s splitUniqueChecks) CreateRefreshToken(_ context.Context, r oauth.RefreshToken) (oauth.RefreshToken, error) {
	s.mu.Lock()
	_, idTaken := s.refresh[r.ID]
	_, hasGrant := s.grants[r.GrantID]
	hashTaken := s.refreshHashTaken(r.TokenHash)
	s.mu.Unlock()
	switch {
	case idTaken:
		return oauth.RefreshToken{}, oauth.ErrIDTaken
	case !hasGrant:
		return oauth.RefreshToken{}, oauth.ErrGrantNotFound
	case hashTaken:
		return oauth.RefreshToken{}, errDuplicate
	}
	time.Sleep(gap)
	s.mu.Lock()
	s.refresh[r.ID] = r
	s.mu.Unlock()
	return r, nil
}

func (s splitUniqueChecks) CreateDeviceAuthorization(_ context.Context, d oauth.DeviceAuthorization) (oauth.DeviceAuthorization, error) {
	s.mu.Lock()
	_, idTaken := s.devices[d.ID]
	_, hasClient := s.clients[d.ClientID]
	taken := s.deviceHashTaken(d.DeviceCodeHash) || s.userCodeTaken(d.UserCode)
	s.mu.Unlock()
	switch {
	case idTaken:
		return oauth.DeviceAuthorization{}, oauth.ErrIDTaken
	case !hasClient:
		return oauth.DeviceAuthorization{}, oauth.ErrClientNotFound
	case taken:
		return oauth.DeviceAuthorization{}, errDuplicate
	}
	time.Sleep(gap)
	s.mu.Lock()
	s.devices[d.ID] = d
	s.mu.Unlock()
	return d, nil
}

// splitDeleteClient decides "the row exists" under one lock and deletes
// under another, so every concurrent caller is told it won.
type splitDeleteClient struct{ *refStore }

func (s splitDeleteClient) DeleteClient(_ context.Context, id string) error {
	s.mu.Lock()
	_, ok := s.clients[id]
	s.mu.Unlock()
	if !ok {
		return oauth.ErrClientNotFound
	}
	time.Sleep(gap)
	s.mu.Lock()
	s.cascadeClient(id)
	delete(s.clients, id)
	s.mu.Unlock()
	return nil
}

// nonAtomicCascade deletes the dependent rows, releases the lock, then
// deletes the client: a CreateGrant landing in the gap is written against a
// client that still exists and outlives it.
type nonAtomicCascade struct{ *refStore }

func (s nonAtomicCascade) DeleteClient(_ context.Context, id string) error {
	s.mu.Lock()
	if _, ok := s.clients[id]; !ok {
		s.mu.Unlock()
		return oauth.ErrClientNotFound
	}
	s.cascadeClient(id)
	s.mu.Unlock()
	time.Sleep(gap)
	s.mu.Lock()
	delete(s.clients, id)
	s.mu.Unlock()
	return nil
}

// ── Driving a check and capturing its verdict ──────────────────────────

// recorder is a [tb] that records failures instead of reporting them to the
// test framework, so a check can be run against a store that is SUPPOSED to
// fail it. Fatalf calls runtime.Goexit, exactly as testing.T.Fatalf does.
type recorder struct {
	mu       sync.Mutex
	failures []string
}

func (r *recorder) Helper()                           {}
func (r *recorder) Logf(string, ...any)               {}
func (r *recorder) Errorf(format string, args ...any) { r.record(format, args) }

func (r *recorder) Fatalf(format string, args ...any) {
	r.record(format, args)
	runtime.Goexit()
}

func (r *recorder) record(format string, args []any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.failures = append(r.failures, fmt.Sprintf(format, args...))
}

// runCheck runs one check against st and reports what it complained about.
// The check runs in its own goroutine so the recorder's Fatalf can end it
// with runtime.Goexit the way testing.T.Fatalf would.
func runCheck(c check, st oauth.Store) []string {
	r := &recorder{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		c.fn(r, st)
	}()
	<-done
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.failures...)
}

func findCheck(t *testing.T, name string) check {
	t.Helper()
	for _, c := range storeContractChecks() {
		if c.name == name {
			return c
		}
	}
	t.Fatalf("no check named %q — the negative-control table names a check that does not exist", name)
	return check{}
}

// TestTheReferenceStorePassesTheContract is the control on the controls
// below. [refStore] is a correct store, so [RunStoreContract] must pass it
// end to end; if it did not, a non-compliant double failing a check would
// prove nothing about the defect injected into it.
func TestTheReferenceStorePassesTheContract(t *testing.T) {
	RunStoreContract(t, func(*testing.T) oauth.Store { return newRefStore() })
}

// TestEveryContractCheckHasANegativeControl fails if a check is added to the
// suite without a row in the table below. A check nothing is known to fail
// is a check that might assert nothing at all, and that is invisible from a
// green run.
func TestEveryContractCheckHasANegativeControl(t *testing.T) {
	covered := map[string]bool{}
	for _, tc := range negativeControls() {
		covered[tc.check] = true
	}
	for _, c := range storeContractChecks() {
		if !covered[c.name] {
			t.Errorf("check %q has no negative control — add a store that fails it to negativeControls()", c.name)
		}
	}
}

// negativeControl pairs a deliberately broken store with the one check that
// must catch its defect.
type negativeControl struct {
	defect   string
	check    string
	newStore func() oauth.Store
}

func negativeControls() []negativeControl {
	ref := func(wrap func(*refStore) oauth.Store) func() oauth.Store {
		return func() oauth.Store { return wrap(newRefStore()) }
	}
	return []negativeControl{
		{"CreateClient drops the redirect URIs", "CreateClient/RoundTrip", ref(func(r *refStore) oauth.Store { return droppedFields{r} })},
		{"a second client may take a taken id", "CreateClient/IDIsUnique", ref(func(r *refStore) oauth.Store { return overwritingIDs{r} })},
		{"FindClient answers a miss with a zero record and no error", "FindClient/UnknownIDReturnsErrClientNotFound", ref(func(r *refStore) oauth.Store { return silentNotFound{r} })},
		{"ListClients ignores the container", "ListClients/ScopesToTheContainer", ref(func(r *refStore) oauth.Store { return listsIgnoreTheScope{r} })},
		{"ListClients hides disabled clients", "ListClients/ReturnsDisabledRowsToo", ref(func(r *refStore) oauth.Store { return listsFilterForTheCaller{r} })},
		{"ListClients reports an empty container as an error", "ListClients/EmptyContainerIsNotAnError", ref(func(r *refStore) oauth.Store { return emptyListIsAnError{r} })},
		{"UpdateClient replaces the immutable fields too", "UpdateClient/ReplacesTheMutableFieldsOnly", ref(func(r *refStore) oauth.Store { return updateReplacesTheWholeRow{r} })},
		{"UpdateClient answers nil when no row matched", "UpdateClient/UnknownIDReturnsErrClientNotFound", ref(func(r *refStore) oauth.Store { return silentMutations{r} })},
		{"DeleteClient leaves the client's rows behind", "DeleteClient/RemovesTheClientAndEverythingOfIt", ref(func(r *refStore) oauth.Store { return deleteClientKeepsGrants{r} })},
		{"DeleteClient cascades to the whole container", "DeleteClient/LeavesOtherClientsAlone", ref(func(r *refStore) oauth.Store { return overbroadDeleteClient{r} })},
		{"DeleteClient answers nil when no row matched", "DeleteClient/UnknownIDReturnsErrClientNotFound", ref(func(r *refStore) oauth.Store { return silentMutations{r} })},
		{"CreateGrant drops the Permissions", "CreateGrant/RoundTrip", ref(func(r *refStore) oauth.Store { return droppedFields{r} })},
		{"a second grant may take a taken id", "CreateGrant/IDIsUnique", ref(func(r *refStore) oauth.Store { return overwritingIDs{r} })},
		{"CreateGrant writes a grant for a client that does not exist", "CreateGrant/UnknownClientIsRefused", ref(func(r *refStore) oauth.Store { return orphans{r} })},
		{"FindGrant answers a miss with a zero record and no error", "FindGrant/UnknownIDReturnsErrGrantNotFound", ref(func(r *refStore) oauth.Store { return silentNotFound{r} })},
		{"ListGrantsByUser ignores the user", "ListGrantsByUser/ScopesToTheUser", ref(func(r *refStore) oauth.Store { return listsIgnoreTheScope{r} })},
		{"ListGrantsByUser hides revoked and expired grants", "ListGrantsByUser/ReturnsRevokedAndExpiredRowsToo", ref(func(r *refStore) oauth.Store { return listsFilterForTheCaller{r} })},
		{"ListGrantsByUser reports a user with none as an error", "ListGrantsByUser/EmptyUserIsNotAnError", ref(func(r *refStore) oauth.Store { return emptyListIsAnError{r} })},
		{"RevokeGrant leaves the grant's refresh tokens behind", "RevokeGrant/StampsRevokedAtAndDeletesItsRefreshTokens", ref(func(r *refStore) oauth.Store { return revokeGrantKeepsTokens{r} })},
		{"RevokeGrant deletes every refresh token of the client", "RevokeGrant/LeavesOtherGrantsAlone", ref(func(r *refStore) oauth.Store { return overbroadRevokeGrant{r} })},
		{"RevokeGrant refuses a second revocation", "RevokeGrant/IsIdempotent", ref(func(r *refStore) oauth.Store { return revokeRefusesASecondTime{r} })},
		{"RevokeGrant answers nil when no row matched", "RevokeGrant/UnknownIDReturnsErrGrantNotFound", ref(func(r *refStore) oauth.Store { return silentMutations{r} })},
		{"TouchGrant writes nothing", "TouchGrant/StampsLastUsedAt", ref(func(r *refStore) oauth.Store { return touchesDoNotStamp{r} })},
		{"TouchGrant answers nil when no row matched", "TouchGrant/UnknownIDReturnsErrGrantNotFound", ref(func(r *refStore) oauth.Store { return silentMutations{r} })},
		{"CreateCode drops the code challenge", "CreateCode/RoundTrip", ref(func(r *refStore) oauth.Store { return droppedFields{r} })},
		{"a second code may take a taken id", "CreateCode/IDIsUnique", ref(func(r *refStore) oauth.Store { return overwritingIDs{r} })},
		{"two codes may share one code hash", "CreateCode/CodeHashIsUnique", ref(func(r *refStore) oauth.Store { return sharedHashes{r} })},
		{"CreateCode writes a code for a grant that does not exist", "CreateCode/UnknownGrantIsRefused", ref(func(r *refStore) oauth.Store { return orphans{r} })},
		{"RedeemCode reports a win without stamping RedeemedAt", "RedeemCode/FirstCallWinsAndStampsRedeemedAt", ref(func(r *refStore) oauth.Store { return casDoesNotStamp{r} })},
		{"RedeemCode wins on every call", "RedeemCode/SecondCallLosesWithoutError", ref(func(r *refStore) oauth.Store { return casAlwaysWins{r} })},
		{"RedeemCode folds expiry into its predicate", "RedeemCode/ExpiryIsNotPartOfThePredicate", ref(func(r *refStore) oauth.Store { return casChecksExpiry{r} })},
		{"RedeemCode answers a miss with (zero, false, nil)", "RedeemCode/UnknownHashReturnsErrCodeNotFound", ref(func(r *refStore) oauth.Store { return silentNotFound{r} })},
		{"CreateDeviceAuthorization drops the grant id", "CreateDeviceAuthorization/RoundTrip", ref(func(r *refStore) oauth.Store { return droppedFields{r} })},
		{"a second device authorization may take a taken id", "CreateDeviceAuthorization/IDIsUnique", ref(func(r *refStore) oauth.Store { return overwritingIDs{r} })},
		{"two device authorizations may share one device code hash", "CreateDeviceAuthorization/DeviceCodeHashIsUnique", ref(func(r *refStore) oauth.Store { return sharedHashes{r} })},
		{"two device authorizations may share one user code", "CreateDeviceAuthorization/UserCodeIsUnique", ref(func(r *refStore) oauth.Store { return sharedUserCodes{r} })},
		{"CreateDeviceAuthorization writes a row for a client that does not exist", "CreateDeviceAuthorization/UnknownClientIsRefused", ref(func(r *refStore) oauth.Store { return orphans{r} })},
		{"FindDeviceByCodeHash answers a miss with a zero record and no error", "FindDeviceByCodeHash/UnknownHashReturnsErrDeviceNotFound", ref(func(r *refStore) oauth.Store { return silentNotFound{r} })},
		{"FindDeviceByUserCode answers a miss with a zero record and no error", "FindDeviceByUserCode/UnknownCodeReturnsErrDeviceNotFound", ref(func(r *refStore) oauth.Store { return silentNotFound{r} })},
		{"SetDeviceStatus reports a win without writing", "SetDeviceStatus/TransitionsWhenTheStatusMatches", ref(func(r *refStore) oauth.Store { return casDoesNotStamp{r} })},
		{"SetDeviceStatus ignores from", "SetDeviceStatus/RefusesWhenTheStatusDiffers", ref(func(r *refStore) oauth.Store { return casAlwaysWins{r} })},
		{"SetDeviceStatus writes the grant id on a denial", "SetDeviceStatus/WritesTheGrantOnlyOnApproval", ref(func(r *refStore) oauth.Store { return setStatusAlwaysWritesGrant{r} })},
		{"SetDeviceStatus answers a miss with (false, nil)", "SetDeviceStatus/UnknownIDReturnsErrDeviceNotFound", ref(func(r *refStore) oauth.Store { return silentNotFound{r} })},
		{"TouchDevicePoll writes nothing", "TouchDevicePoll/StampsLastPolledAt", ref(func(r *refStore) oauth.Store { return touchesDoNotStamp{r} })},
		{"TouchDevicePoll answers nil when no row matched", "TouchDevicePoll/UnknownIDReturnsErrDeviceNotFound", ref(func(r *refStore) oauth.Store { return silentMutations{r} })},
		{"CreateRefreshToken drops RotatedAt", "CreateRefreshToken/RoundTrip", ref(func(r *refStore) oauth.Store { return droppedFields{r} })},
		{"a second refresh token may take a taken id", "CreateRefreshToken/IDIsUnique", ref(func(r *refStore) oauth.Store { return overwritingIDs{r} })},
		{"two refresh tokens may share one hash", "CreateRefreshToken/TokenHashIsUnique", ref(func(r *refStore) oauth.Store { return sharedHashes{r} })},
		{"CreateRefreshToken writes a token for a grant that does not exist", "CreateRefreshToken/UnknownGrantIsRefused", ref(func(r *refStore) oauth.Store { return orphans{r} })},
		{"FindRefreshTokenByHash answers a miss with a zero record and no error", "FindRefreshTokenByHash/UnknownHashReturnsErrRefreshNotFound", ref(func(r *refStore) oauth.Store { return silentNotFound{r} })},
		{"FindRefreshTokenByHash hides rotated and expired tokens", "FindRefreshTokenByHash/ReturnsRotatedAndExpiredRowsToo", ref(func(r *refStore) oauth.Store { return listsFilterForTheCaller{r} })},
		{"MarkRefreshRotated reports a win without stamping RotatedAt", "MarkRefreshRotated/FirstCallWinsAndStampsRotatedAt", ref(func(r *refStore) oauth.Store { return casDoesNotStamp{r} })},
		{"MarkRefreshRotated wins on every call", "MarkRefreshRotated/SecondCallLosesWithoutError", ref(func(r *refStore) oauth.Store { return casAlwaysWins{r} })},
		{"MarkRefreshRotated folds expiry into its predicate", "MarkRefreshRotated/ExpiryIsNotPartOfThePredicate", ref(func(r *refStore) oauth.Store { return casChecksExpiry{r} })},
		{"MarkRefreshRotated answers a miss with (zero, false, nil)", "MarkRefreshRotated/UnknownHashReturnsErrRefreshNotFound", ref(func(r *refStore) oauth.Store { return silentNotFound{r} })},
		{"DeleteRefreshFamily leaves the rotated tokens", "DeleteRefreshFamily/RemovesEveryTokenOfTheFamily", ref(func(r *refStore) oauth.Store { return deleteFamilyKeepsRotated{r} })},
		{"DeleteRefreshFamily deletes every family of the grant", "DeleteRefreshFamily/LeavesOtherFamiliesAlone", ref(func(r *refStore) oauth.Store { return overbroadDeleteFamily{r} })},
		{"DeleteRefreshFamily reports an empty family as an error", "DeleteRefreshFamily/EmptyFamilyIsNotAnError", ref(func(r *refStore) oauth.Store { return emptyListIsAnError{r} })},
		{"PurgeExpired purges a row expiring exactly at the cutoff", "PurgeExpired/CutoffIsStrictOnCodesDevicesAndRefreshTokens", ref(func(r *refStore) oauth.Store { return purgeInclusiveExpiry{r} })},
		{"PurgeExpired never purges a grant", "PurgeExpired/RemovesRevokedAndExpiredGrantsWithWhatHangsOffThem", ref(func(r *refStore) oauth.Store { return purgeIgnoresGrants{r} })},
		{"PurgeExpired purges live grants with no expiry", "PurgeExpired/LeavesLiveRowsAndEveryClientAlone", ref(func(r *refStore) oauth.Store { return purgeEverything{r} })},
		{"PurgeExpired miscounts", "PurgeExpired/NothingToPurgeReturnsZero", ref(func(r *refStore) oauth.Store { return purgeMiscounts{r} })},
		{"RedeemCode checks under one lock and writes under another", "RedeemCode/ConcurrentCallersAdmitExactlyOneWinner", ref(func(r *refStore) oauth.Store { return splitCAS{r} })},
		{"SetDeviceStatus checks under one lock and writes under another", "SetDeviceStatus/ConcurrentCallersAdmitExactlyOneWinner", ref(func(r *refStore) oauth.Store { return splitCAS{r} })},
		{"MarkRefreshRotated checks under one lock and writes under another", "MarkRefreshRotated/ConcurrentCallersAdmitExactlyOneWinner", ref(func(r *refStore) oauth.Store { return splitCAS{r} })},
		{"CreateCode checks the hash under one lock and writes under another", "CreateCode/ConcurrentCreatesOfOneHashAdmitExactlyOne", ref(func(r *refStore) oauth.Store { return splitUniqueChecks{r} })},
		{"CreateRefreshToken checks the hash under one lock and writes under another", "CreateRefreshToken/ConcurrentCreatesOfOneHashAdmitExactlyOne", ref(func(r *refStore) oauth.Store { return splitUniqueChecks{r} })},
		{"CreateDeviceAuthorization checks the user code under one lock and writes under another", "CreateDeviceAuthorization/ConcurrentCreatesOfOneUserCodeAdmitExactlyOne", ref(func(r *refStore) oauth.Store { return splitUniqueChecks{r} })},
		{"DeleteClient decides under one lock and deletes under another", "DeleteClient/ConcurrentDeletesAdmitExactlyOneWinner", ref(func(r *refStore) oauth.Store { return splitDeleteClient{r} })},
		{"DeleteClient deletes the dependents, releases the lock, then the client", "DeleteClient/NoGrantOutlivesItsClient", ref(func(r *refStore) oauth.Store { return nonAtomicCascade{r} })},
	}
}

// TestTheContractRejectsNonCompliantStores runs the whole suite against each
// double, requires the named check to have failed, and logs every check
// that failed so the blast radius of each defect is on the record.
func TestTheContractRejectsNonCompliantStores(t *testing.T) {
	for _, tc := range negativeControls() {
		t.Run(tc.defect, func(t *testing.T) {
			want := findCheck(t, tc.check)

			var caught []string
			var firstMessage string
			for _, c := range storeContractChecks() {
				failures := runCheck(c, tc.newStore())
				if len(failures) == 0 {
					continue
				}
				caught = append(caught, c.name)
				if c.name == want.name {
					firstMessage = failures[0]
				}
			}
			sort.Strings(caught)

			if firstMessage == "" {
				t.Fatalf("%s PASSED %s — the check does not catch this defect. Checks that did fail: %v", tc.defect, tc.check, caught)
			}
			t.Logf("%s\n  caught by %s: %s\n  all checks that failed: %v", tc.defect, tc.check, firstMessage, caught)
		})
	}
}
