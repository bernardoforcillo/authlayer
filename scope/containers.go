package scope

import (
	"context"

	"github.com/bernardoforcillo/authlayer/access"
)

// ContainersWith returns the ids of the containers in which userID may perform
// every action on resource.
//
// It resolves each membership through the same ladder [Service.Can] uses —
// owner bypass, then a code-defined default role, then a custom role from the
// store — so the two agree for every container where the subject holds a
// membership row. The one exception is an owner whose own membership row has
// been removed, reachable only with LastOwnerLocked disabled: ContainersWith
// omits that container, so a guard built on it fails closed there rather than
// leaking access. Zero actions returns an empty slice: there is nothing to
// authorize, which is the same rule [access.Permission.Allows] applies.
//
// Cost is one store round trip for the standings, plus one role lookup per
// distinct (container, role key) pair that names a custom role; default roles
// resolve in memory. A user with no qualifying containers gets an empty slice
// and no error — that is an answer, not a failure.
//
// This is the out-of-band form, taking the user id explicitly, so it needs no
// subject on the context. [Service.PermissionGuard] is the context-driven form.
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
			perms, err = s.resolveRole(ctx, st.ContainerID, st.RoleKey)
			if err != nil {
				return nil, err
			}
			resolved[k] = perms
		}
		if perms.IsFull() || perms.Allows(resource, actions...) {
			out = append(out, st.ContainerID)
		}
	}
	return out, nil
}
