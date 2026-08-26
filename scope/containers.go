package scope

import (
	"context"
	"errors"

	"github.com/bernardoforcillo/authlayer/access"
)

// ContainersWith returns the ids of the containers in which userID may perform
// every action on resource.
//
// It works from the subject's membership rows rather than through
// [Service.Can], re-resolving each one by the same steps — owner bypass, then a
// code-defined default role, then a custom role from the store — so the two
// agree for every container where the subject holds a membership whose role key
// resolves. Where they diverge, this side denies: a guard built on it shows
// fewer rows, never more. Examples, not a closed list: a role key that resolves
// to nothing drops its own container here while Can returns ErrRoleNotFound; a
// membership whose container row is gone is omitted here while Can returns
// ErrContainerNotFound; an owner with no membership row of their own —
// reachable by provisioning through the [Store] port, or with LastOwnerLocked
// disabled — is omitted here while Can still lets them in under OwnerBypass.
//
// # It does not consult a parent scope
//
// This resolves membership-based standing only. It does not walk the parent
// rung that [Service.Can] applies in a nested scope ([WithParent]), so inherited
// standing is invisible to it: an organization administrator who may administer
// a team purely through inheritance, holding no membership row of their own in
// that team, gets no row for it here and no rows from a
// [Service.PermissionGuard] built over it — even though Can, Authorize and
// [Service.Standing] all admit them in that same container.
//
// That is a known gap rather than a deliberate rule, and it is the one place
// where "fewer rows, never more" costs a legitimate user something they can see.
// Closing it means consulting the parent once per candidate container, which is
// an N+1 unless the parent's standings are batched, so it is deferred rather
// than papered over. Until then, do not build a nested scope's row-level
// filtering on the assumption that it mirrors Can.
//
// A store failure is never one of those divergences: it aborts the call, since
// a database error must not be narrowed into "you may see nothing". Zero
// actions returns an empty slice: there is nothing to authorize, which is the
// same rule [access.Permission.Allows] applies.
//
// Cost is one store round trip for the standings, plus one role lookup per
// distinct (container, role key) pair that names a custom role; default roles
// resolve in memory. A user with no qualifying containers gets an empty slice
// and no error — that is an answer, not a failure.
//
// This is the out-of-band form, taking the user id explicitly, so it needs no
// subject on the context. Like [Service.HasPermission], it performs no check
// that the *caller* is entitled to ask about userID, and its answer enumerates
// that user's memberships and how privileged they are in each. Do not expose it
// directly to end users. [Service.PermissionGuard] is the context-driven form,
// and the safe one: it takes the subject from the context rather than an
// argument, so a caller cannot ask about somebody else.
func (s *Service[C, M, PC, PM]) ContainersWith(
	ctx context.Context, userID, resource string, actions ...access.Action,
) ([]string, error) {
	if len(actions) == 0 {
		return nil, nil
	}
	standings, err := s.store.ListUserStandings(ctx, userID)
	if err != nil {
		return nil, err
	}

	// Cache by (container, role key): a custom role is per-container, so the
	// container id must be part of the key.
	type roleKey struct{ container, role string }
	resolved := make(map[roleKey]access.Permission, len(standings))

	var out []string
	for _, st := range standings {
		if s.cfg.policy.OwnerBypass && st.OwnerID == userID {
			out = append(out, st.ContainerID)
			continue
		}
		k := roleKey{st.ContainerID, st.RoleKey}
		perms, ok := resolved[k]
		if !ok {
			p, err := s.resolveRole(ctx, st.ContainerID, st.RoleKey)
			switch {
			case errors.Is(err, ErrRoleNotFound):
				// The key names nothing, so the standing grants nothing:
				// deny this container and carry on. Aborting here would let
				// one bad membership row deny every container the user is in,
				// including those in other tenants.
				continue
			case err != nil:
				// Anything else is the store failing to answer, not an answer.
				// Skipping would narrow the result silently, which a guard
				// renders as "you may see nothing".
				return nil, err
			}
			perms = p
			resolved[k] = perms
		}
		if perms.IsFull() || perms.Allows(resource, actions...) {
			out = append(out, st.ContainerID)
		}
	}
	return out, nil
}
