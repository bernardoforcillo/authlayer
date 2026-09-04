package scope

import (
	"context"

	"github.com/bernardoforcillo/drops/pg"

	"github.com/bernardoforcillo/authlayer/access"
)

// The acting subject and the active container travel on the context, reusing
// drops' own keys (pg.WithSubject / pg.WithTenant) so one ctx drives both the
// in-memory decision and drops' query guards / tenant scoping. The optional
// permission cap ([WithPermissionCap]) travels under a key of this package's
// own, since drops has no notion of it.

// WithSubject annotates ctx with the acting user's id.
func WithSubject(ctx context.Context, userID string) context.Context {
	return pg.WithSubject(ctx, userID)
}

// SubjectFrom returns the acting user's id and ok=false when unset.
func SubjectFrom(ctx context.Context) (string, bool) {
	v, ok := pg.SubjectFrom(ctx)
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}

// WithScope annotates ctx with the active container's id.
func WithScope(ctx context.Context, containerID string) context.Context {
	return pg.WithTenant(ctx, containerID)
}

// ScopeFrom returns the active container's id and ok=false when unset.
func ScopeFrom(ctx context.Context) (string, bool) {
	v, ok := pg.TenantFrom(ctx)
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}

// ctxActor extracts the acting subject and active container from ctx.
func ctxActor(ctx context.Context) (subject, containerID string, err error) {
	subject, ok := SubjectFrom(ctx)
	if !ok {
		return "", "", ErrSubjectMissing
	}
	containerID, ok = ScopeFrom(ctx)
	if !ok {
		return "", "", ErrScopeMissing
	}
	return subject, containerID, nil
}

// capKey is the private context key the permission cap travels under. It is
// scope's own rather than one of drops' — drops has no notion of a cap, and
// a key of a package-private type cannot be forged or read by any other
// package, so the only way to put a cap on a context is [WithPermissionCap].
type capKey struct{}

// WithPermissionCap caps every standing the engine resolves for ctx's
// SUBJECT to cap: the effective permission set becomes role permissions ∩
// cap ([access.Permission.Intersect]), and the subject is never treated as
// elevated unless cap itself is Full. It is how an API key minted with
// restricted permissions, or a delegated (on-behalf-of) token, acts as a
// principal that can do strictly less than the account behind it — the
// apikey package's WithPrincipal puts one here.
//
// # It can only remove, never add
//
// The cap is applied AFTER the whole resolution [Service] documents — owner
// bypass, inherited standing, role lookup — so a cap naming a grant the role
// does not hold confers nothing: it is intersected with what the subject
// already has. A capped OWNER is not elevated and stands on Full ∩ cap, so
// even the one principal that normally bypasses every fine-grained check is
// bounded by it. And because [access.Permission.Intersect] fails closed, a
// cap compiled against a different Statements than this scope's — a key
// minted for one scope presented against another — yields an empty
// standing rather than a reinterpreted one.
//
// # Which paths honour it
//
// Every path that resolves the CONTEXT subject: [Service.Can],
// [Service.Authorize], the privilege-escalation guard inside AddMember,
// ChangeMemberRole, RemoveMember, CreateRole and UpdateRole (so a restricted
// key cannot grant, mint or remove more than the key allows),
// [Service.PermissionGuard], and the standing checks in ListMembers and
// ListRoles. [Service.CreateContainer] on a NESTED scope — which resolves
// the subject in the PARENT, whose statements the cap was not compiled
// against — refuses a capped subject outright unless the cap is Full, since
// there is no honest way to project the cap there.
//
// The explicit-user-id methods — [Service.HasPermission],
// [Service.Standing], [Service.RolePermissions], [Service.ContainersWith],
// [Service.Container] — read NOTHING from the context by contract, and that
// includes the cap: they answer about the user they are handed, as that user
// actually stands, whoever is asking. That is the right answer for the admin
// tooling and background jobs they exist for, and it is why none of them may
// be exposed directly to end users. A caller that needs a capped answer from
// one of them applies [Service.CapStanding] itself, which is exactly what the invite
// and apikey packages do around Standing.
//
// A nil or zero cap — one with no statements — is stored as given and
// intersects to nothing, so a subject carrying it can do nothing at all.
// That is deliberate: a cap the caller failed to build is not the same as no
// cap, and silently ignoring it would be the fail-open reading.
func WithPermissionCap(ctx context.Context, cap access.Permission) context.Context {
	return context.WithValue(ctx, capKey{}, cap)
}

// PermissionCapFrom returns the cap [WithPermissionCap] put on ctx and
// ok=false when there is none. A context with no cap is the ordinary case:
// the subject stands on their role alone.
func PermissionCapFrom(ctx context.Context) (access.Permission, bool) {
	cap, ok := ctx.Value(capKey{}).(access.Permission)
	return cap, ok
}
