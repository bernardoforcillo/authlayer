package scope

import (
	"context"

	"github.com/bernardoforcillo/authlayer/access"
)

// CreateRole defines a custom role in the ctx container.
//
// The actor needs role:create. key must not collide with a default role
// (ErrRoleKeyTaken) nor with an existing custom role of this container (the
// Store reports ErrRoleKeyTaken), and every grant must name a declared
// (resource, action) pair — an undeclared one is an error from the access
// engine, not a silent no-op. Unless elevated, the actor may not mint a role
// exceeding their own permissions (ErrPrivilegeEscalation), which is what stops
// an admin from manufacturing a role more powerful than themselves and then
// assigning it.
//
// name is a human label for display only; key is what gets stored on
// memberships and what [Service.AddMember] and [Service.ChangeMemberRole] take.
//
//	_, err := svc.CreateRole(ctx, "editor", "Editor", map[string][]access.Action{
//	    "project": {"create", "update"},
//	})
func (s *Service[C, M, PC, PM]) CreateRole(ctx context.Context, key, name string, grants map[string][]access.Action) (RoleView, error) {
	actor, containerID, err := ctxActor(ctx)
	if err != nil {
		return RoleView{}, err
	}
	a, err := s.authorize(ctx, containerID, actor, ResourceRole, ActionCreate)
	if err != nil {
		return RoleView{}, err
	}
	if _, isDefault := s.ac.Role(key); isDefault {
		return RoleView{}, ErrRoleKeyTaken
	}
	perm, err := s.ac.Permission(grants)
	if err != nil {
		return RoleView{}, err
	}
	if !a.elevated && s.cfg.policy.Escalation != EscalationOff && !perm.SubsetOf(a.perms) {
		return RoleView{}, ErrPrivilegeEscalation
	}
	rec, err := s.store.CreateRole(ctx, RoleRecord{
		ID:          s.cfg.idgen(),
		ContainerID: containerID,
		Key:         key,
		Name:        name,
		Permissions: perm.Encode(),
		CreatedAt:   s.cfg.clock(),
	})
	if err != nil {
		return RoleView{}, err
	}
	if err := s.emit(ctx, Event{Kind: RoleCreated, ContainerID: containerID, ActorID: actor, RoleKey: key}); err != nil {
		return RoleView{}, err
	}
	return RoleView{Key: rec.Key, Name: rec.Name, Permissions: perm}, nil
}

// UpdateRole replaces a custom role's name and permissions.
//
// The actor needs role:update. Default roles are immutable (ErrDefaultRole) —
// they are code, so change them in code — and the role must already exist in
// this container (ErrRoleNotFound). The same escalation guard as
// [Service.CreateRole] applies.
//
// grants replace the role's permissions wholesale rather than merging, so pass
// the complete intended set. The change takes effect immediately for every
// member already holding the role: permissions are resolved per check, never
// copied onto the membership.
func (s *Service[C, M, PC, PM]) UpdateRole(ctx context.Context, key, name string, grants map[string][]access.Action) (RoleView, error) {
	actor, containerID, err := ctxActor(ctx)
	if err != nil {
		return RoleView{}, err
	}
	a, err := s.authorize(ctx, containerID, actor, ResourceRole, ActionUpdate)
	if err != nil {
		return RoleView{}, err
	}
	if _, isDefault := s.ac.Role(key); isDefault {
		return RoleView{}, ErrDefaultRole
	}
	if _, err := s.store.FindRole(ctx, containerID, key); err != nil {
		return RoleView{}, err
	}
	perm, err := s.ac.Permission(grants)
	if err != nil {
		return RoleView{}, err
	}
	if !a.elevated && s.cfg.policy.Escalation != EscalationOff && !perm.SubsetOf(a.perms) {
		return RoleView{}, ErrPrivilegeEscalation
	}
	if err := s.store.UpdateRole(ctx, containerID, key, name, perm.Encode()); err != nil {
		return RoleView{}, err
	}
	if err := s.emit(ctx, Event{Kind: RoleUpdated, ContainerID: containerID, ActorID: actor, RoleKey: key}); err != nil {
		return RoleView{}, err
	}
	return RoleView{Key: key, Name: name, Permissions: perm}, nil
}

// DeleteRole removes a custom role from the ctx container.
//
// The actor needs role:delete. Default roles cannot be deleted (ErrDefaultRole),
// and a role still assigned to at least one member is refused (ErrRoleInUse)
// rather than cascading — that would silently strip or orphan those
// memberships. Reassign the members first, then delete.
func (s *Service[C, M, PC, PM]) DeleteRole(ctx context.Context, key string) error {
	actor, containerID, err := ctxActor(ctx)
	if err != nil {
		return err
	}
	if _, err := s.authorize(ctx, containerID, actor, ResourceRole, ActionDelete); err != nil {
		return err
	}
	if _, isDefault := s.ac.Role(key); isDefault {
		return ErrDefaultRole
	}
	if _, err := s.store.FindRole(ctx, containerID, key); err != nil {
		return err
	}
	n, err := s.store.CountMembersWithRole(ctx, containerID, key)
	if err != nil {
		return err
	}
	if n > 0 {
		return ErrRoleInUse
	}
	if err := s.store.DeleteRole(ctx, containerID, key); err != nil {
		return err
	}
	return s.emit(ctx, Event{Kind: RoleDeleted, ContainerID: containerID, ActorID: actor, RoleKey: key})
}

// ListRoles returns the three code-defined defaults (IsDefault true) in owner,
// admin, member order, followed by the ctx container's custom roles in Store
// order.
//
// That is not necessarily every role assignable in the container. A role an
// application registers in code with [access.Access.NewRole] — a "viewer",
// say — is fully assignable: [Service.AddMember] and
// [Service.GrantMembership] resolve it through [Service.RolePermissions],
// which consults the registry before the store. ListRoles does not enumerate
// it. So treat this as "the defaults plus what this container stored", and
// use RolePermissions when you need the engine's real answer for a given key
// rather than a list to display. Widening ListRoles to cover app-registered
// roles is deferred: it would change what every existing role editor renders.
//
// Any member may list; a non-member gets ErrNotMember. Each [RoleView] carries
// a resolved [access.Permission], so a role editor can show exactly what a role
// grants without a second lookup. This is the call to drive a "change role"
// dropdown — note that it does not filter by what the *actor* may grant, so
// pair it with the escalation rule if you want to hide roles the actor could
// not assign anyway.
func (s *Service[C, M, PC, PM]) ListRoles(ctx context.Context) ([]RoleView, error) {
	actor, containerID, err := ctxActor(ctx)
	if err != nil {
		return nil, err
	}
	if _, err := s.standing(ctx, containerID, actor); err != nil {
		return nil, err
	}

	views := make([]RoleView, 0, 4)
	for _, key := range []string{RoleOwner, RoleAdmin, RoleMember} {
		if r, ok := s.ac.Role(key); ok {
			views = append(views, RoleView{Key: r.Key, Name: r.Key, Permissions: r.Permissions, IsDefault: true})
		}
	}
	recs, err := s.store.ListRoles(ctx, containerID)
	if err != nil {
		return nil, err
	}
	for _, rec := range recs {
		perm, err := s.ac.Decode(rec.Permissions)
		if err != nil {
			return nil, err
		}
		views = append(views, RoleView{Key: rec.Key, Name: rec.Name, Permissions: perm, IsDefault: false})
	}
	return views, nil
}
