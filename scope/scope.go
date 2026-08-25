package scope

import (
	"context"
	"errors"

	"github.com/bernardoforcillo/authlayer/access"
)

// Service is the generic scope RBAC engine. C is the container type (embed
// [ContainerBase]), M the member type (embed [MemberBase]); PC/PM are their
// pointer types, inferred by the compiler and used only to stamp base fields on
// create.
//
// # How a decision is made
//
// Every check resolves the actor's *standing* in a container, in this order:
//
//  1. Load the container. Not found → ErrContainerNotFound.
//  2. If OwnerBypass is on and the actor owns it → elevated, full permissions.
//     No membership lookup, no role resolution.
//  3. Load the membership. Not a member → ErrNotMember.
//  4. Resolve the membership's role key: a code-defined default if the Access
//     registry knows it, otherwise a custom role loaded from the store and
//     decoded. Unknown key → ErrRoleNotFound.
//  5. The actor is elevated if the resolved permission set is full.
//
// An elevated actor passes every fine-grained check naming at least one action,
// and the privilege-escalation guard. Everyone else must hold every requested
// (resource, action) pair, or the check returns ErrForbidden. A check naming no
// actions denies everyone, elevated included: there is nothing to authorize.
//
// # Context, not arguments
//
// The acting subject and active container are read from the context
// ([WithSubject], [WithScope]) rather than passed per call, so the same context
// drives in-memory decisions and drops' query guards. A missing subject or
// container is ErrSubjectMissing / ErrScopeMissing — never a silent allow.
//
// # Concurrency and caching
//
// A Service is safe for concurrent use if its Store is. It caches nothing:
// every check hits the store for the container, the membership, and (for custom
// roles) the role record, so a permission change takes effect immediately and
// there is no invalidation to get wrong. Applications that need fewer round
// trips should wrap the Store, not the Service.
type Service[C Container, M Member,
	PC interface {
		*C
		MutableContainer
	},
	PM interface {
		*M
		MutableMember
	}] struct {
	ac    *access.Access
	store Store[C, M]
	cfg   config
}

// New wires an access engine, a Store and options into a Service. The pointer
// type parameters are inferred, so callers write New[C, M](ac, store).
func New[C Container, M Member,
	PC interface {
		*C
		MutableContainer
	},
	PM interface {
		*M
		MutableMember
	}](ac *access.Access, store Store[C, M], opts ...Option) *Service[C, M, PC, PM] {
	cfg := defaultConfig()
	for _, o := range opts {
		o(&cfg)
	}
	return &Service[C, M, PC, PM]{ac: ac, store: store, cfg: cfg}
}

// authz is a subject's resolved standing within a container.
type authz struct {
	perms    access.Permission
	elevated bool
	ownerID  string
}

func (s *Service[C, M, PC, PM]) newMember(containerID, userID, roleKey string) M {
	var m M
	pm := PM(&m)
	pm.SetKeys(containerID, userID, roleKey)
	pm.SetJoined(s.cfg.clock())
	return m
}

func (s *Service[C, M, PC, PM]) emit(ctx context.Context, e Event) error {
	if e.At.IsZero() {
		e.At = s.cfg.clock()
	}
	for _, h := range s.cfg.hooks {
		if err := h.On(ctx, e); err != nil {
			return err
		}
	}
	return nil
}

// CreateContainer stamps the container's base fields (id from the id generator,
// owner from the ctx subject, timestamps from the clock), persists it, and
// seeds the owner's membership — atomically.
//
// Pass a value carrying only your own fields; the base fields are overwritten,
// so setting them beforehand has no effect. The container and the owner's
// membership are written in one Store transaction together with the
// ContainerCreated hook, so a failing hook rolls back both and a container can
// never be left without its owner-member row.
//
// This is the one mutation that does not require a container on the context —
// there is no container yet — and the one that runs no permission check:
// anyone with a subject may create a container, and becomes its owner. Gate it
// upstream if your application restricts who may create containers.
//
// A unique-constraint violation on one of your own fields (a slug, say) is
// reported by the Store as ErrConflict.
func (s *Service[C, M, PC, PM]) CreateContainer(ctx context.Context, c C) (C, error) {
	subject, ok := SubjectFrom(ctx)
	if !ok {
		var zero C
		return zero, ErrSubjectMissing
	}
	pc := PC(&c)
	pc.SetID(s.cfg.idgen())
	pc.SetOwner(subject)
	now := s.cfg.clock()
	pc.SetTimes(now, now)

	err := s.store.WithTx(ctx, func(st Store[C, M]) error {
		created, err := st.CreateContainer(ctx, c)
		if err != nil {
			return err
		}
		c = created
		if _, err := st.AddMember(ctx, s.newMember(created.ContainerID(), subject, RoleOwner)); err != nil {
			return err
		}
		return s.emit(ctx, Event{Kind: ContainerCreated, ContainerID: created.ContainerID(), ActorID: subject})
	})
	if err != nil {
		var zero C
		return zero, err
	}
	return c, nil
}

// Authorize returns nil when the ctx subject may perform every action on
// resource within the ctx container, else a sentinel error.
//
// All actions must be granted — the check is an AND, not an OR — and calling it
// with no actions denies, since there is nothing to authorize. An undeclared
// resource or action also denies, so a typo fails closed.
//
// Use Authorize at the top of a handler when you want the distinction between
// "denied" (ErrForbidden), "not a member" (ErrNotMember) and "no such
// container" (ErrContainerNotFound) — typically to map them to 403, 403 and 404.
// Use [Service.Can] when you only need a boolean, e.g. to decide what to render.
//
//	if err := svc.Authorize(ctx, "project", org.ActionDelete); err != nil {
//	    return err
//	}
func (s *Service[C, M, PC, PM]) Authorize(ctx context.Context, resource string, actions ...access.Action) error {
	subject, containerID, err := ctxActor(ctx)
	if err != nil {
		return err
	}
	_, err = s.authorize(ctx, containerID, subject, resource, actions...)
	return err
}

// Can is the boolean form of [Service.Authorize]: it folds ErrForbidden and
// ErrNotMember into (false, nil), because "this user may not do that" is an
// answer rather than a failure.
//
// Everything else still surfaces as an error — a missing subject or container
// on the context, a store failure, an unresolvable role — so a non-nil error
// means the question could not be answered and must not be read as a denial.
// Always check err before trusting the bool.
func (s *Service[C, M, PC, PM]) Can(ctx context.Context, resource string, actions ...access.Action) (bool, error) {
	err := s.Authorize(ctx, resource, actions...)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, ErrForbidden), errors.Is(err, ErrNotMember):
		return false, nil
	default:
		return false, err
	}
}

// HasPermission reports whether userID may perform every action in req within
// containerID, independent of the ctx subject and the ctx container.
//
// This is the out-of-band form of [Service.Can], for the cases where the user
// being asked about is not the user making the request: admin tooling, batch
// jobs, "what can this member do?" screens, and background workers that have no
// request context. It takes ids explicitly and reads nothing from the context,
// so it needs no [WithSubject] / [WithScope].
//
// req is checked as a conjunction across resources: every action of every
// resource must be granted. An empty req therefore returns true for any member
// — it asks nothing. Non-membership is (false, nil), matching Can.
//
// Because it bypasses the ctx subject entirely, HasPermission performs no check
// that the *caller* is entitled to ask. Do not expose it directly to end users.
func (s *Service[C, M, PC, PM]) HasPermission(ctx context.Context, containerID, userID string, req map[string][]access.Action) (bool, error) {
	a, err := s.standing(ctx, containerID, userID)
	if err != nil {
		if errors.Is(err, ErrNotMember) {
			return false, nil
		}
		return false, err
	}
	if a.elevated {
		return true, nil
	}
	for resource, actions := range req {
		if !a.perms.Allows(resource, actions...) {
			return false, nil
		}
	}
	return true, nil
}

// Standing resolves userID's permissions within containerID and reports whether
// they are elevated there — the same resolution [Service.Can] performs, exposed
// so a nested scope can consult its parent through [ParentScope].
//
// It reads nothing from the context and performs no check that the caller is
// entitled to ask, exactly like [Service.HasPermission]. Do not expose it
// directly to end users.
func (s *Service[C, M, PC, PM]) Standing(
	ctx context.Context, containerID, userID string,
) (access.Permission, bool, error) {
	a, err := s.standing(ctx, containerID, userID)
	if err != nil {
		return access.Permission{}, false, err
	}
	return a.perms, a.elevated, nil
}

func (s *Service[C, M, PC, PM]) standing(ctx context.Context, containerID, userID string) (authz, error) {
	c, err := s.store.FindContainer(ctx, containerID)
	if err != nil {
		return authz{}, err
	}
	owner := c.ContainerOwner()
	if s.cfg.policy.OwnerBypass && owner == userID {
		return authz{perms: s.ac.Full(), elevated: true, ownerID: owner}, nil
	}
	m, err := s.store.FindMember(ctx, containerID, userID)
	if err != nil {
		return authz{}, err
	}
	perms, err := s.resolveRole(ctx, containerID, m.MemberRole())
	if err != nil {
		return authz{}, err
	}
	return authz{perms: perms, elevated: perms.IsFull(), ownerID: owner}, nil
}

func (s *Service[C, M, PC, PM]) authorize(ctx context.Context, containerID, userID, resource string, actions ...access.Action) (authz, error) {
	a, err := s.standing(ctx, containerID, userID)
	if err != nil {
		return authz{}, err
	}
	// Zero actions denies even for an elevated actor — there is nothing to
	// authorize, the same rule access.Permission.Allows applies on its own.
	// The elevated short-circuit below is only for the normal, non-empty case.
	if len(actions) == 0 {
		return authz{}, ErrForbidden
	}
	if !a.elevated && !a.perms.Allows(resource, actions...) {
		return authz{}, ErrForbidden
	}
	return a, nil
}

func (s *Service[C, M, PC, PM]) guardEscalation(ctx context.Context, a authz, containerID, roleKey string) error {
	if a.elevated || s.cfg.policy.Escalation == EscalationOff {
		return nil
	}
	grant, err := s.resolveRole(ctx, containerID, roleKey)
	if err != nil {
		return err
	}
	if !grant.SubsetOf(a.perms) {
		return ErrPrivilegeEscalation
	}
	return nil
}

func (s *Service[C, M, PC, PM]) resolveRole(ctx context.Context, containerID, roleKey string) (access.Permission, error) {
	if r, ok := s.ac.Role(roleKey); ok {
		return r.Permissions, nil
	}
	rec, err := s.store.FindRole(ctx, containerID, roleKey)
	if err != nil {
		return access.Permission{}, err
	}
	return s.ac.Decode(rec.Permissions)
}

func (s *Service[C, M, PC, PM]) requireOwner(ctx context.Context, containerID, userID string) (C, error) {
	c, err := s.store.FindContainer(ctx, containerID)
	if err != nil {
		var zero C
		return zero, err
	}
	if c.ContainerOwner() != userID {
		var zero C
		return zero, ErrOwnerOnly
	}
	return c, nil
}

// AddMember adds userID to the ctx container holding roleKey.
//
// The actor needs member:create, and unless elevated may only grant a role
// whose permissions are a subset of their own (ErrPrivilegeEscalation). roleKey
// may name a default role or a custom role of this container; an unknown key is
// ErrRoleNotFound. Adding someone who is already a member is ErrAlreadyMember.
//
// authlayer stores no user records — userID is an opaque id from your own user
// table, and no existence check is performed on it.
func (s *Service[C, M, PC, PM]) AddMember(ctx context.Context, userID, roleKey string) (M, error) {
	var zero M
	actor, containerID, err := ctxActor(ctx)
	if err != nil {
		return zero, err
	}
	a, err := s.authorize(ctx, containerID, actor, ResourceMember, ActionCreate)
	if err != nil {
		return zero, err
	}
	if err := s.guardEscalation(ctx, a, containerID, roleKey); err != nil {
		return zero, err
	}
	m, err := s.store.AddMember(ctx, s.newMember(containerID, userID, roleKey))
	if err != nil {
		return zero, err
	}
	if err := s.emit(ctx, Event{Kind: MemberAdded, ContainerID: containerID, ActorID: actor, TargetID: userID, RoleKey: roleKey}); err != nil {
		return zero, err
	}
	return m, nil
}

// ChangeMemberRole reassigns targetUserID to roleKey.
//
// The actor needs member:update. Under LastOwnerLocked the owner cannot be
// demoted by anyone, including themselves (ErrLastOwner) — move ownership with
// [Service.TransferOwnership] instead. Unless elevated, the actor may not grant
// a role exceeding their own permissions (ErrPrivilegeEscalation).
//
// The guard constrains the role being granted, not the role being replaced: an
// actor who can reach this call may lower a peer's privileges. Combine with
// your own rules if that is not what you want.
func (s *Service[C, M, PC, PM]) ChangeMemberRole(ctx context.Context, targetUserID, roleKey string) error {
	actor, containerID, err := ctxActor(ctx)
	if err != nil {
		return err
	}
	a, err := s.authorize(ctx, containerID, actor, ResourceMember, ActionUpdate)
	if err != nil {
		return err
	}
	if s.cfg.policy.LastOwnerLocked && targetUserID == a.ownerID {
		return ErrLastOwner
	}
	if err := s.guardEscalation(ctx, a, containerID, roleKey); err != nil {
		return err
	}
	if _, err := s.store.FindMember(ctx, containerID, targetUserID); err != nil {
		return err
	}
	if err := s.store.UpdateMemberRole(ctx, containerID, targetUserID, roleKey); err != nil {
		return err
	}
	return s.emit(ctx, Event{Kind: MemberRoleChanged, ContainerID: containerID, ActorID: actor, TargetID: targetUserID, RoleKey: roleKey})
}

// RemoveMember removes targetUserID from the ctx container.
//
// The actor needs member:delete; under LastOwnerLocked the owner cannot be
// removed (ErrLastOwner). Here the escalation guard is applied to the *target's*
// role rather than a granted one: unless elevated, an actor may not remove a
// member whose permissions are not a subset of their own, so two admins cannot
// evict each other and a moderator cannot evict an admin.
//
// A member removing themselves is better expressed as [Service.LeaveContainer],
// which needs no member:delete grant.
func (s *Service[C, M, PC, PM]) RemoveMember(ctx context.Context, targetUserID string) error {
	actor, containerID, err := ctxActor(ctx)
	if err != nil {
		return err
	}
	a, err := s.authorize(ctx, containerID, actor, ResourceMember, ActionDelete)
	if err != nil {
		return err
	}
	if s.cfg.policy.LastOwnerLocked && targetUserID == a.ownerID {
		return ErrLastOwner
	}
	target, err := s.store.FindMember(ctx, containerID, targetUserID)
	if err != nil {
		return err
	}
	if !a.elevated && s.cfg.policy.Escalation != EscalationOff {
		tperms, err := s.resolveRole(ctx, containerID, target.MemberRole())
		if err != nil {
			return err
		}
		if !tperms.SubsetOf(a.perms) {
			return ErrPrivilegeEscalation
		}
	}
	if err := s.store.RemoveMember(ctx, containerID, targetUserID); err != nil {
		return err
	}
	return s.emit(ctx, Event{Kind: MemberRemoved, ContainerID: containerID, ActorID: actor, TargetID: targetUserID})
}

// TransferOwnership hands the ctx container to newOwnerUserID.
//
// Only the current owner may call it (ErrOwnerOnly) — no permission grant
// substitutes for ownership, not even a full one — and the recipient must
// already be a member (ErrNotMember). Add them first if they are not.
//
// Only the container's owner_id moves. Neither membership's role key changes,
// so the outgoing owner keeps whatever role they were stored with (typically
// "owner", which is a full role) and the incoming owner gains elevated standing
// from ownership itself under OwnerBypass. If you want the outgoing owner
// demoted, follow up with [Service.ChangeMemberRole] as the new owner.
func (s *Service[C, M, PC, PM]) TransferOwnership(ctx context.Context, newOwnerUserID string) error {
	actor, containerID, err := ctxActor(ctx)
	if err != nil {
		return err
	}
	if _, err := s.requireOwner(ctx, containerID, actor); err != nil {
		return err
	}
	if _, err := s.store.FindMember(ctx, containerID, newOwnerUserID); err != nil {
		return err
	}
	if err := s.store.UpdateContainerOwner(ctx, containerID, newOwnerUserID); err != nil {
		return err
	}
	return s.emit(ctx, Event{Kind: OwnershipTransferred, ContainerID: containerID, ActorID: actor, TargetID: newOwnerUserID})
}

// LeaveContainer removes the ctx subject's own membership.
//
// It needs no permission grant — leaving is always the member's own call — but
// under LastOwnerLocked the owner cannot leave (ErrLastOwner) and must transfer
// ownership first. Leaving emits MemberRemoved with TargetID equal to ActorID.
func (s *Service[C, M, PC, PM]) LeaveContainer(ctx context.Context) error {
	actor, containerID, err := ctxActor(ctx)
	if err != nil {
		return err
	}
	c, err := s.store.FindContainer(ctx, containerID)
	if err != nil {
		return err
	}
	if s.cfg.policy.LastOwnerLocked && c.ContainerOwner() == actor {
		return ErrLastOwner
	}
	if err := s.store.RemoveMember(ctx, containerID, actor); err != nil {
		return err
	}
	return s.emit(ctx, Event{Kind: MemberRemoved, ContainerID: containerID, ActorID: actor, TargetID: actor})
}

// ListMembers returns the members of the ctx container.
//
// Any member may list — standing is the only requirement, so no member:*
// grant is needed — and a non-member gets ErrNotMember rather than an empty
// slice, which keeps a container's roster from leaking. Order is whatever the
// Store returns; the in-memory store's is unspecified.
func (s *Service[C, M, PC, PM]) ListMembers(ctx context.Context) ([]M, error) {
	actor, containerID, err := ctxActor(ctx)
	if err != nil {
		return nil, err
	}
	if _, err := s.standing(ctx, containerID, actor); err != nil {
		return nil, err
	}
	return s.store.ListMembers(ctx, containerID)
}
