package scope

import (
	"context"

	"github.com/bernardoforcillo/drops/pg"
)

// The acting subject and the active container travel on the context, reusing
// drops' own keys (pg.WithSubject / pg.WithTenant) so one ctx drives both the
// in-memory decision and drops' query guards / tenant scoping.

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
