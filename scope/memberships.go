package scope

import "context"

// Membership is one container a user belongs to, with the standing they hold
// in it.
type Membership struct {
	// ContainerID is the container.
	ContainerID string
	// RoleKey is the user's role there.
	RoleKey string
	// Owner is true when the user owns the container.
	Owner bool
}

// Memberships returns every container userID belongs to, in this Service's
// store, with their role in each — the scope half of a data-subject access
// request (GDPR Art. 15). It is the out-of-band form like [Service.ContainersWith]:
// it takes the user id explicitly, checks nothing about the caller, and its
// answer enumerates the user's memberships, so do not expose it directly to
// end users. A user with no memberships gets an empty slice and no error.
func (s *Service[C, M, PC, PM]) Memberships(ctx context.Context, userID string) ([]Membership, error) {
	standings, err := s.store.ListUserStandings(ctx, userID)
	if err != nil {
		return nil, err
	}
	out := make([]Membership, 0, len(standings))
	for _, st := range standings {
		out = append(out, Membership{ContainerID: st.ContainerID, RoleKey: st.RoleKey, Owner: st.OwnerID == userID})
	}
	return out, nil
}
