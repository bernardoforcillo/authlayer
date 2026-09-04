package apikey

import (
	"context"
	"time"

	"github.com/bernardoforcillo/authlayer/access"
	"github.com/bernardoforcillo/authlayer/scope"
)

// Kind says what sort of principal authenticated. It is a string so a log
// line or a feature flag can carry it as-is, and so the oauth package can
// declare further kinds without this package changing.
type Kind string

// The kinds. [Service.Authenticate] produces KindServiceAccount only; the
// other two are declared here so every package that reads a [Principal]
// agrees on the vocabulary, and are populated by the oauth package.
const (
	// KindUser is a person acting through their own session — the shape an
	// OAuth authorization-code grant produces. Never returned by this
	// package.
	KindUser Kind = "user"
	// KindServiceAccount is a service account acting through one of its
	// API keys (this package) or through an OAuth client-credentials grant
	// (the oauth package).
	KindServiceAccount Kind = "service_account"
	// KindDelegated is one party acting on behalf of another — RFC 8693's
	// "act" claim. Never returned by this package.
	KindDelegated Kind = "delegated"
)

// Principal is who [Service.Authenticate] decided a presented key is, in the
// terms the RBAC engine needs: a subject, a container, and an optional cap.
// It is a value to hand to [WithPrincipal], to log, and to read back with
// [PrincipalFrom]; it carries no secret.
type Principal struct {
	// Kind is the sort of principal — KindServiceAccount from this package.
	Kind Kind
	// ID is the subject id: the service account's id, which is what
	// scope.WithSubject receives and what the account's membership is keyed
	// by.
	ID string
	// ContainerID is the scope the principal acts in — the account's
	// container, read off the key.
	ContainerID string
	// KeyID is the key that authenticated, for audit and for
	// [Service.RevokeKey]. Empty for principals the oauth package builds
	// from a token rather than a key.
	KeyID string
	// ClientID is the OAuth client acting, set by the oauth package. Empty
	// for API-key principals.
	ClientID string
	// GrantID is the delegation grant this principal acts under, set by the
	// oauth package. Empty for API-key principals.
	GrantID string
	// Permissions is the key's restricted permission set, decoded against
	// the scope's statements, or nil for a key with no restriction. When
	// set, [WithPrincipal] installs it as the context's permission cap
	// ([scope.WithPermissionCap]), so the effective standing is role ∩
	// Permissions.
	Permissions *access.Permission
	// AuthenticatedAt is the Service clock's now at authentication.
	AuthenticatedAt time.Time
}

// principalKey is the private context key a Principal travels under, so only
// [WithPrincipal] can put one on a context and only [PrincipalFrom] read it.
type principalKey struct{}

// WithPrincipal returns ctx annotated for the RBAC engine as p: the subject
// is p.ID ([scope.WithSubject]), the active container p.ContainerID
// ([scope.WithScope]), and — when p.Permissions is non-nil — the permission
// cap *p.Permissions ([scope.WithPermissionCap]). The Principal itself rides
// along too, retrievable with [PrincipalFrom], so a handler can tell a key
// from a session and log which key acted.
//
// After this, [scope.Service.Can], [scope.Service.Authorize], every
// management call in scope and invite, and a mounted
// [scope.Service.PermissionGuard] all work for the key exactly as they do
// for a logged-in user — capped, when the key is restricted.
//
// Apply it to a request-fresh context. A context value cannot be removed,
// so a ctx that already carries a cap from an earlier principal keeps it
// when p.Permissions is nil, and the two subjects' restrictions would
// compound in a way nobody asked for.
func WithPrincipal(ctx context.Context, p Principal) context.Context {
	ctx = scope.WithSubject(ctx, p.ID)
	ctx = scope.WithScope(ctx, p.ContainerID)
	if p.Permissions != nil {
		ctx = scope.WithPermissionCap(ctx, *p.Permissions)
	}
	return context.WithValue(ctx, principalKey{}, p)
}

// PrincipalFrom returns the Principal [WithPrincipal] put on ctx and ok=false
// when there is none — which is the ordinary case for a request made by a
// person through a session.
func PrincipalFrom(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(principalKey{}).(Principal)
	return p, ok
}
