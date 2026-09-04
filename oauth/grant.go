package oauth

import (
	"context"
	"time"

	"github.com/bernardoforcillo/authlayer/scope"
)

// ListGrants is the "connected apps" view: every live delegation the ctx
// subject has made, across every client and every container — revoked
// ones are left out, expired ones are returned with ExpiresAt set so the
// screen can say so. It reads the subject alone (scope.WithSubject;
// scope.ErrSubjectMissing otherwise) and needs no container, since a
// person's connected apps span their organizations. Order is whatever the
// Store returns.
func (s *Service) ListGrants(ctx context.Context) ([]Grant, error) {
	user, ok := scope.SubjectFrom(ctx)
	if !ok {
		return nil, scope.ErrSubjectMissing
	}
	all, err := s.st.ListGrantsByUser(ctx, user)
	if err != nil {
		return nil, err
	}
	live := make([]Grant, 0, len(all))
	for _, g := range all {
		if g.RevokedAt == nil {
			live = append(live, g)
		}
	}
	return live, nil
}

// RevokeGrant disconnects an app: it stamps the grant's RevokedAt and
// deletes its refresh tokens, atomically ([Store.RevokeGrant]), so the
// client can never refresh again; its access tokens live out their TTL
// unless [Service.Authenticate] verifies online, in which case they are
// refused from now. Only the grantor may revoke — a grant belonging to
// another user is scope.ErrForbidden, whatever the caller's role: a
// delegation is the user's consent, not an administrator's resource. An
// administrator revokes every grant of a client by deleting or disabling
// the client. An unknown id is [ErrGrantNotFound]; revoking a revoked
// grant is not an error.
func (s *Service) RevokeGrant(ctx context.Context, grantID string) error {
	user, ok := scope.SubjectFrom(ctx)
	if !ok {
		return scope.ErrSubjectMissing
	}
	g, err := s.st.FindGrant(ctx, grantID)
	if err != nil {
		return err
	}
	if g.UserID != user {
		return scope.ErrForbidden
	}
	now := s.cfg.clock()
	if err := s.st.RevokeGrant(ctx, grantID, now); err != nil {
		return err
	}
	return s.emit(ctx, Event{
		Kind: GrantRevoked, ContainerID: g.ContainerID, ActorID: user,
		ClientID: g.ClientID, GrantID: g.ID, Detail: DetailUserRevoked, At: now,
	})
}

// PurgeExpired deletes every code, device authorization and refresh token
// expired strictly before `before`, and every grant revoked or expired
// strictly before it with what hangs off it, and returns how many rows
// went. It performs NO authorization check and reads neither a subject nor
// a container — one call spans every container — so call it from a cron
// job or a trusted maintenance path, never from a handler wired to caller
// input: an unauthenticated caller who could trigger it at will gets a
// cross-tenant denial-of-service knob even though it cannot itself grant
// access. Clients are never purged. Choose `before` at least one refresh
// lifetime in the past if replay detection on long-idle tokens matters to
// you: a rotated token that is purged can no longer be recognised as a
// replay, only as unknown.
func (s *Service) PurgeExpired(ctx context.Context, before time.Time) (int, error) {
	return s.st.PurgeExpired(ctx, before)
}
