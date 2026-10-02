package scope

import (
	"context"
	"errors"
)

// Mutation describes a membership or ownership change the engine is about to
// make, after authorization has already passed.
type Mutation struct {
	// Kind is the [EventKind] the change will emit once it succeeds:
	// ContainerCreated, MemberAdded, MemberRoleChanged, MemberRemoved or
	// OwnershipTransferred.
	Kind        EventKind
	ContainerID string
	// ActorID is who is acting; TargetID who is affected (the new owner for
	// a transfer, the new member for an add). RoleKey is the role being
	// granted, when there is one.
	ActorID  string
	TargetID string
	RoleKey  string
}

// Decider is the application's veto over mutations. It runs after the
// engine's own authorization and invariants (permissions, escalation guard,
// last-owner lock, parent membership) have passed and BEFORE anything is
// written, so a refusal changes nothing. Use it for rules the engine cannot
// know: a frozen tenant, a billing seat limit, "only billing admins may
// transfer ownership".
//
// A Decider can only restrict: it runs in addition to the engine's checks,
// never instead of them. A non-nil error is returned to the caller unchanged.
// It is not consulted by [Service.RemoveUser], which is a system operation
// driven by account removal rather than an actor's request.
type Decider interface {
	Decide(ctx context.Context, m Mutation) error
}

// DeciderFunc adapts a function to [Decider].
type DeciderFunc func(ctx context.Context, m Mutation) error

// Decide implements [Decider].
func (f DeciderFunc) Decide(ctx context.Context, m Mutation) error { return f(ctx, m) }

// WithDecider installs a [Decider]. nil restores the default (no veto).
func WithDecider(d Decider) Option {
	return func(c *config) { c.decider = d }
}

func (s *Service[C, M, PC, PM]) decide(ctx context.Context, m Mutation) error {
	if s.cfg.decider == nil {
		return nil
	}
	return s.cfg.decider.Decide(ctx, m)
}

// ErrOwnsContainer: the user owns at least one container and no
// [OrphanPolicy] says what should happen to it. Removal is refused before
// anything is changed.
var ErrOwnsContainer = errors.New("authlayer/scope: user owns a container; transfer ownership first")

// ErrBadSuccessor: an [OrphanPolicy] named a successor who is not a member
// of the container, or is the user being removed.
var ErrBadSuccessor = errors.New("authlayer/scope: successor must be another member of the container")

// Resolution is an [OrphanPolicy]'s answer for one owned container.
type Resolution struct {
	// Successor becomes the owner. It must be another current member.
	Successor string
	// Abandon leaves the container's owner id as it is and only removes the
	// membership. The container is then owned by an id that no longer signs
	// in; choose it only when the owning account row is being kept (an
	// anonymized account) or the container is to be cleaned up elsewhere.
	Abandon bool
}

// OrphanPolicy decides what happens to a container whose owner is being
// removed. others lists the container's other members' user ids, oldest
// first as the store returns them. Return a [Resolution], or an error to
// refuse the whole removal.
type OrphanPolicy func(ctx context.Context, containerID string, others []string) (Resolution, error)

// SuccessorFirstMember is an [OrphanPolicy] that hands each owned container
// to its first other member, and refuses ([ErrOwnsContainer]) when there is
// none. A convenient default for products where ownership may pass silently;
// do not use it where it must not.
func SuccessorFirstMember(_ context.Context, _ string, others []string) (Resolution, error) {
	if len(others) == 0 {
		return Resolution{}, ErrOwnsContainer
	}
	return Resolution{Successor: others[0]}, nil
}

// WithOrphanPolicy installs the [OrphanPolicy] [Service.RemoveUser] consults
// for containers the removed user owns. The default (nil) refuses with
// [ErrOwnsContainer].
func WithOrphanPolicy(p OrphanPolicy) Option {
	return func(c *config) { c.orphan = p }
}

// RemoveUser removes userID from every container in this Service — the
// scope half of deleting or anonymizing an account. It is all or nothing:
// every owned container is resolved by the [OrphanPolicy] first (an error or
// [ErrOwnsContainer] aborts before any write), then ownership transfers and
// membership removals are applied in one store transaction, and a
// [MemberRemoved] event is emitted for each membership only after the
// transaction commits.
//
// It acts as the system, not as a user: no permission is checked and the
// [Decider] is not consulted, because the account is going away whatever a
// container's rules would say. Its events carry ActorID "" to say so.
func (s *Service[C, M, PC, PM]) RemoveUser(ctx context.Context, userID string) error {
	return s.removeUser(ctx, userID, false)
}

func (s *Service[C, M, PC, PM]) removeUser(ctx context.Context, userID string, anonymize bool) error {
	containers, err := s.store.ListUserContainers(ctx, userID)
	if err != nil {
		return err
	}

	type step struct {
		containerID string
		successor   string // non-empty: transfer ownership first
	}
	steps := make([]step, 0, len(containers))
	for _, c := range containers {
		st := step{containerID: c.ContainerID()}
		if c.ContainerOwner() == userID {
			members, err := s.store.ListMembers(ctx, st.containerID)
			if err != nil {
				return err
			}
			others := make([]string, 0, len(members))
			for _, m := range members {
				if m.MemberUser() != userID {
					others = append(others, m.MemberUser())
				}
			}
			if s.cfg.orphan == nil {
				return ErrOwnsContainer
			}
			res, err := s.cfg.orphan(ctx, st.containerID, others)
			if err != nil {
				return err
			}
			if !res.Abandon {
				ok := false
				for _, o := range others {
					if o == res.Successor {
						ok = true
					}
				}
				if !ok {
					return ErrBadSuccessor
				}
				st.successor = res.Successor
			}
		}
		steps = append(steps, st)
	}

	for _, st := range steps {
		if err := s.depart(ctx, st.containerID, userID, DepartedAccount, anonymize); err != nil {
			return err
		}
	}

	if err := s.store.WithTx(ctx, func(tx Store[C, M]) error {
		for _, st := range steps {
			if st.successor != "" {
				if err := tx.UpdateContainerOwner(ctx, st.containerID, st.successor); err != nil {
					return err
				}
			}
			if err := tx.RemoveMember(ctx, st.containerID, userID); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return err
	}

	for _, st := range steps {
		if st.successor != "" {
			if err := s.emit(ctx, Event{Kind: OwnershipTransferred, ContainerID: st.containerID, TargetID: st.successor}); err != nil {
				return err
			}
		}
		if err := s.emit(ctx, Event{Kind: MemberRemoved, ContainerID: st.containerID, TargetID: userID, Anonymized: anonymize}); err != nil {
			return err
		}
	}
	return nil
}
