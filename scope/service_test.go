package scope

import (
	"context"
	"errors"
	"testing"

	"github.com/bernardoforcillo/authlayer/access"
)

const resOrg = "organization"

func newTestService(opts ...Option) *Service[testContainer, testMember, *testContainer, *testMember] {
	ac := NewAccess(resOrg, nil)
	return New(ac, newMemStore[testContainer, testMember](), opts...)
}

func ownerCtx(t *testing.T, svc *Service[testContainer, testMember, *testContainer, *testMember], ownerID string) (context.Context, testContainer) {
	t.Helper()
	ctx := WithSubject(context.Background(), ownerID)
	c, err := svc.CreateContainer(ctx, testContainer{Name: "Acme"})
	if err != nil {
		t.Fatalf("CreateContainer: %v", err)
	}
	return WithScope(ctx, c.ContainerID()), c
}

func TestCreateContainerMakesSubjectOwner(t *testing.T) {
	svc := newTestService()
	ctx := WithSubject(context.Background(), "alice")

	c, err := svc.CreateContainer(ctx, testContainer{Name: "Acme"})
	if err != nil {
		t.Fatalf("CreateContainer: %v", err)
	}
	if c.ContainerOwner() != "alice" || c.ContainerID() == "" {
		t.Fatalf("container = %+v", c.ContainerBase)
	}

	octx := WithScope(ctx, c.ContainerID())
	if ok, err := svc.Can(octx, resOrg, ActionDelete); err != nil || !ok {
		t.Fatalf("owner org:delete = %v,%v; want true,nil", ok, err)
	}
}

func TestCanWithZeroActionsDeniesEvenForOwner(t *testing.T) {
	svc := newTestService()
	octx, _ := ownerCtx(t, svc, "alice")

	// The owner is elevated and would pass any fine-grained check, but zero
	// actions has nothing to authorize — that must deny regardless of
	// elevation, matching access.Permission.Allows' own rule.
	if ok, err := svc.Can(octx, resOrg); err != nil || ok {
		t.Fatalf("owner with zero actions = %v,%v; want false,nil", ok, err)
	}
}

func TestCreateContainerRequiresSubject(t *testing.T) {
	svc := newTestService()
	if _, err := svc.CreateContainer(context.Background(), testContainer{}); !errors.Is(err, ErrSubjectMissing) {
		t.Fatalf("err = %v, want ErrSubjectMissing", err)
	}
}

func TestCanIsFalseForNonMember(t *testing.T) {
	svc := newTestService()
	_, c := ownerCtx(t, svc, "alice")
	bob := WithScope(WithSubject(context.Background(), "bob"), c.ContainerID())
	if ok, err := svc.Can(bob, ResourceMember, ActionCreate); err != nil || ok {
		t.Fatalf("non-member = %v,%v; want false,nil", ok, err)
	}
}

func TestAddMemberAndEscalation(t *testing.T) {
	svc := newTestService()
	octx, c := ownerCtx(t, svc, "alice")

	if _, err := svc.AddMember(octx, "bob", RoleAdmin); err != nil {
		t.Fatalf("AddMember: %v", err)
	}
	bob := WithScope(WithSubject(context.Background(), "bob"), c.ContainerID())
	if ok, _ := svc.Can(bob, ResourceMember, ActionCreate); !ok {
		t.Fatal("admin bob should manage members")
	}
	if ok, _ := svc.Can(bob, resOrg, ActionDelete); ok {
		t.Fatal("admin bob must not delete the org")
	}

	// admin cannot grant the full owner role.
	if _, err := svc.AddMember(bob, "carol", RoleOwner); !errors.Is(err, ErrPrivilegeEscalation) {
		t.Fatalf("escalation err = %v, want ErrPrivilegeEscalation", err)
	}
	// but can grant within his powers.
	if _, err := svc.AddMember(bob, "carol", RoleAdmin); err != nil {
		t.Fatalf("admin granting admin: %v", err)
	}
}

func TestAddMemberForbiddenForPlainMember(t *testing.T) {
	svc := newTestService()
	octx, c := ownerCtx(t, svc, "alice")
	if _, err := svc.AddMember(octx, "dave", RoleMember); err != nil {
		t.Fatalf("seed: %v", err)
	}
	dave := WithScope(WithSubject(context.Background(), "dave"), c.ContainerID())
	if _, err := svc.AddMember(dave, "erin", RoleMember); !errors.Is(err, ErrForbidden) {
		t.Fatalf("err = %v, want ErrForbidden", err)
	}
}

func TestChangeMemberRoleOwnerProtectionAndEscalation(t *testing.T) {
	svc := newTestService()
	octx, c := ownerCtx(t, svc, "alice")
	if _, err := svc.AddMember(octx, "bob", RoleAdmin); err != nil {
		t.Fatalf("seed admin: %v", err)
	}
	if _, err := svc.AddMember(octx, "carol", RoleMember); err != nil {
		t.Fatalf("seed member: %v", err)
	}

	if err := svc.ChangeMemberRole(octx, "carol", RoleAdmin); err != nil {
		t.Fatalf("ChangeMemberRole: %v", err)
	}
	if err := svc.ChangeMemberRole(octx, "alice", RoleMember); !errors.Is(err, ErrLastOwner) {
		t.Fatalf("owner-target err = %v, want ErrLastOwner", err)
	}
	bob := WithScope(WithSubject(context.Background(), "bob"), c.ContainerID())
	if err := svc.ChangeMemberRole(bob, "carol", RoleOwner); !errors.Is(err, ErrPrivilegeEscalation) {
		t.Fatalf("escalation err = %v, want ErrPrivilegeEscalation", err)
	}
}

func TestRemoveMemberProtections(t *testing.T) {
	svc := newTestService()
	octx, c := ownerCtx(t, svc, "alice")
	if _, err := svc.AddMember(octx, "bob", RoleAdmin); err != nil {
		t.Fatalf("seed admin: %v", err)
	}
	if _, err := svc.AddMember(octx, "carol", RoleOwner); err != nil {
		t.Fatalf("seed full: %v", err)
	}

	if err := svc.RemoveMember(octx, "alice"); !errors.Is(err, ErrLastOwner) {
		t.Fatalf("owner-target err = %v, want ErrLastOwner", err)
	}
	bob := WithScope(WithSubject(context.Background(), "bob"), c.ContainerID())
	if err := svc.RemoveMember(bob, "carol"); !errors.Is(err, ErrPrivilegeEscalation) {
		t.Fatalf("more-powerful err = %v, want ErrPrivilegeEscalation", err)
	}
	if err := svc.RemoveMember(octx, "bob"); err != nil {
		t.Fatalf("RemoveMember: %v", err)
	}
}

func TestCustomRoleLifecycle(t *testing.T) {
	svc := newTestService()
	octx, c := ownerCtx(t, svc, "alice")

	if _, err := svc.CreateRole(octx, "editor", "Editor", map[string][]access.Action{
		ResourceMember: {ActionCreate},
	}); err != nil {
		t.Fatalf("CreateRole: %v", err)
	}
	if _, err := svc.CreateRole(octx, RoleAdmin, "x", map[string][]access.Action{ResourceMember: {ActionCreate}}); !errors.Is(err, ErrRoleKeyTaken) {
		t.Fatalf("collision err = %v, want ErrRoleKeyTaken", err)
	}
	if _, err := svc.CreateRole(octx, "weird", "W", map[string][]access.Action{ResourceMember: {"obliterate"}}); err == nil {
		t.Fatal("expected error for undeclared grant")
	}

	if _, err := svc.AddMember(octx, "bob", "editor"); err != nil {
		t.Fatalf("assign editor: %v", err)
	}
	bob := WithScope(WithSubject(context.Background(), "bob"), c.ContainerID())
	if ok, _ := svc.Can(bob, ResourceMember, ActionCreate); !ok {
		t.Fatal("editor bob should member:create")
	}

	if _, err := svc.UpdateRole(octx, RoleAdmin, "x", map[string][]access.Action{ResourceMember: {ActionCreate}}); !errors.Is(err, ErrDefaultRole) {
		t.Fatalf("update default err = %v, want ErrDefaultRole", err)
	}
	if err := svc.DeleteRole(octx, "editor"); !errors.Is(err, ErrRoleInUse) {
		t.Fatalf("delete-in-use err = %v, want ErrRoleInUse", err)
	}
	if err := svc.RemoveMember(octx, "bob"); err != nil {
		t.Fatalf("RemoveMember: %v", err)
	}
	if err := svc.DeleteRole(octx, "editor"); err != nil {
		t.Fatalf("DeleteRole: %v", err)
	}
}

func TestCreateRoleEscalation(t *testing.T) {
	svc := newTestService()
	octx, c := ownerCtx(t, svc, "alice")
	if _, err := svc.AddMember(octx, "bob", RoleAdmin); err != nil {
		t.Fatalf("seed admin: %v", err)
	}
	bob := WithScope(WithSubject(context.Background(), "bob"), c.ContainerID())
	if _, err := svc.CreateRole(bob, "super", "S", map[string][]access.Action{resOrg: {ActionDelete}}); !errors.Is(err, ErrPrivilegeEscalation) {
		t.Fatalf("err = %v, want ErrPrivilegeEscalation", err)
	}
}

func TestTransferOwnershipAndLeave(t *testing.T) {
	svc := newTestService()
	octx, c := ownerCtx(t, svc, "alice")
	if _, err := svc.AddMember(octx, "bob", RoleMember); err != nil {
		t.Fatalf("seed: %v", err)
	}

	if err := svc.TransferOwnership(octx, "stranger"); !errors.Is(err, ErrNotMember) {
		t.Fatalf("non-member target err = %v, want ErrNotMember", err)
	}
	bobAdminless := WithScope(WithSubject(context.Background(), "bob"), c.ContainerID())
	if err := svc.TransferOwnership(bobAdminless, "bob"); !errors.Is(err, ErrOwnerOnly) {
		t.Fatalf("non-owner err = %v, want ErrOwnerOnly", err)
	}
	if err := svc.TransferOwnership(octx, "bob"); err != nil {
		t.Fatalf("TransferOwnership: %v", err)
	}
	if ok, _ := svc.Can(bobAdminless, resOrg, ActionDelete); !ok {
		t.Fatal("new owner bob should org:delete")
	}

	// original owner alice is now a plain member and may leave.
	if err := svc.LeaveContainer(octx); err != nil {
		t.Fatalf("LeaveContainer: %v", err)
	}
	// new owner bob cannot leave.
	if err := svc.LeaveContainer(bobAdminless); !errors.Is(err, ErrLastOwner) {
		t.Fatalf("owner leave err = %v, want ErrLastOwner", err)
	}
}

func TestListMembersAndRoles(t *testing.T) {
	svc := newTestService()
	octx, _ := ownerCtx(t, svc, "alice")
	if _, err := svc.AddMember(octx, "bob", RoleMember); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := svc.CreateRole(octx, "editor", "Editor", map[string][]access.Action{ResourceMember: {ActionCreate}}); err != nil {
		t.Fatalf("seed role: %v", err)
	}

	members, err := svc.ListMembers(octx)
	if err != nil || len(members) != 2 {
		t.Fatalf("ListMembers = %d, %v; want 2", len(members), err)
	}
	roles, err := svc.ListRoles(octx)
	if err != nil {
		t.Fatalf("ListRoles: %v", err)
	}
	keys := map[string]bool{}
	for _, r := range roles {
		keys[r.Key] = true
	}
	for _, want := range []string{RoleOwner, RoleAdmin, RoleMember, "editor"} {
		if !keys[want] {
			t.Fatalf("ListRoles missing %q; got %v", want, keys)
		}
	}
}

func TestStandingReportsPermissionsAndElevation(t *testing.T) {
	svc := newTestService()
	ctx := WithSubject(context.Background(), "alice")
	c, err := svc.CreateContainer(ctx, testContainer{})
	if err != nil {
		t.Fatalf("CreateContainer: %v", err)
	}

	perms, elevated, err := svc.Standing(context.Background(), c.ContainerID(), "alice")
	if err != nil {
		t.Fatalf("Standing: %v", err)
	}
	if !elevated {
		t.Fatal("the owner is not reported as elevated")
	}
	if !perms.IsFull() {
		t.Fatal("the owner's permissions are not full")
	}

	if _, _, err := svc.Standing(context.Background(), c.ContainerID(), "stranger"); !errors.Is(err, ErrNotMember) {
		t.Fatalf("Standing for a non-member = %v, want ErrNotMember", err)
	}
	if _, _, err := svc.Standing(context.Background(), "nope", "alice"); !errors.Is(err, ErrContainerNotFound) {
		t.Fatalf("Standing in a missing container = %v, want ErrContainerNotFound", err)
	}
}

// *Service must satisfy the bridge interface, or nesting cannot be wired.
func TestServiceSatisfiesParentScope(t *testing.T) {
	var _ ParentScope = (*Service[testContainer, testMember, *testContainer, *testMember])(nil)
}

// GrantMembership is the invitation-acceptance admission path: it performs no
// actor resolution at all, so calling it with a bare context.Background() —
// no [WithSubject], no [WithScope] — must still succeed. If it read the ctx
// actor the way AddMember does, this call would fail with ErrSubjectMissing
// before it ever reached the store. Granting RoleOwner (the most powerful
// role there is) with no actor on the context also proves the
// privilege-escalation guard never runs here: there is no actor's permission
// set to compare against.
func TestGrantMembershipAdmitsWithoutAnActorCheck(t *testing.T) {
	svc := newTestService()
	_, c := ownerCtx(t, svc, "alice")

	m, err := svc.GrantMembership(context.Background(), c.ContainerID(), "bob", RoleOwner)
	if err != nil {
		t.Fatalf("GrantMembership: %v", err)
	}
	if m.MemberUser() != "bob" || m.MemberRole() != RoleOwner {
		t.Fatalf("member = %+v, want user=bob role=%s", m.MemberBase, RoleOwner)
	}

	// The membership actually landed in the store and resolves to elevated
	// standing, not just a returned value with nothing behind it.
	perms, elevated, err := svc.Standing(context.Background(), c.ContainerID(), "bob")
	if err != nil {
		t.Fatalf("Standing: %v", err)
	}
	if !elevated || !perms.IsFull() {
		t.Fatalf("bob's standing after GrantMembership(..., RoleOwner) = %+v, elevated=%v; want full and elevated", perms, elevated)
	}
}

// Rules that are not about the actor still apply. A duplicate grant is
// ErrAlreadyMember, matching AddMember's own store-level invariant.
func TestGrantMembershipStillRejectsADuplicate(t *testing.T) {
	svc := newTestService()
	_, c := ownerCtx(t, svc, "alice")

	if _, err := svc.GrantMembership(context.Background(), c.ContainerID(), "bob", RoleMember); err != nil {
		t.Fatalf("first GrantMembership: %v", err)
	}
	if _, err := svc.GrantMembership(context.Background(), c.ContainerID(), "bob", RoleMember); !errors.Is(err, ErrAlreadyMember) {
		t.Fatalf("second GrantMembership err = %v, want ErrAlreadyMember", err)
	}
}

// An unresolvable role key is ErrRoleNotFound, and the rejection leaves no
// partial write behind: a malformed invitation must not be able to mint a
// membership whose role never resolves.
func TestGrantMembershipStillRejectsAnUnknownRole(t *testing.T) {
	svc := newTestService()
	_, c := ownerCtx(t, svc, "alice")

	if _, err := svc.GrantMembership(context.Background(), c.ContainerID(), "bob", "nonesuch"); !errors.Is(err, ErrRoleNotFound) {
		t.Fatalf("GrantMembership err = %v, want ErrRoleNotFound", err)
	}
	if _, _, err := svc.Standing(context.Background(), c.ContainerID(), "bob"); !errors.Is(err, ErrNotMember) {
		t.Fatalf("bob was written to the store despite the unknown role: Standing err = %v, want ErrNotMember", err)
	}
}

// Under MembersFromParent (the default), GrantMembership still requires the
// invitee to already hold standing in the parent scope — you cannot accept an
// invitation onto a team without being in the organization that owns it —
// even though no actor is being checked. This is the "not about the actor"
// half of the rule set, proven with the two-scope fixture from
// nested_test.go.
func TestGrantMembershipHonoursMembersFromParent(t *testing.T) {
	parent := newParentScope()
	octx, orgC := ownerCtx(t, parent, "alice")
	if _, err := parent.AddMember(octx, "bob", RoleMember); err != nil {
		t.Fatalf("seed org member: %v", err)
	}

	child, st := newChildScope(parent, InheritElevation)
	team := createTeam(t, child, orgC.ContainerID(), "alice")

	// bob belongs to the organization, so GrantMembership admits him with no
	// actor on the context at all.
	if _, err := child.GrantMembership(context.Background(), team.ContainerID(), "bob", RoleMember); err != nil {
		t.Fatalf("granting membership to an org member: %v", err)
	}

	// zoe never joined the organization, so the parent rung refuses her.
	if _, err := child.GrantMembership(context.Background(), team.ContainerID(), "zoe", RoleMember); !errors.Is(err, ErrNotParentMember) {
		t.Fatalf("GrantMembership err = %v, want ErrNotParentMember", err)
	}
	// The refusal is a refusal, not a partial write.
	if _, err := st.FindMember(context.Background(), team.ContainerID(), "zoe"); !errors.Is(err, ErrNotMember) {
		t.Fatalf("zoe was written to the team anyway: %v", err)
	}
}

// With MembersFromParent turned off, GrantMembership admits an invitee who
// holds no standing in the parent scope. The invariant is enforced only when
// the policy says so — matching the doc comment's "under MembersFromParent"
// — not unconditionally whenever a parent link exists, which is what the same
// rows refused under the default policy in
// TestGrantMembershipHonoursMembersFromParent above.
func TestGrantMembershipWithMembersFromParentOffAdmitsAnyone(t *testing.T) {
	parent := newParentScope()
	_, orgC := ownerCtx(t, parent, "alice")

	child, st := newChildScope(parent, InheritElevation)
	team := createTeam(t, child, orgC.ContainerID(), "alice")

	policy := defaultPolicy()
	policy.MembersFromParent = false
	open := newChildScopeOn(st, parent, InheritElevation, WithPolicy(policy))

	// zoe never joined the organization. Under the default policy this is
	// ErrNotParentMember; with the flag cleared, the same call over the same
	// rows must succeed.
	if _, err := open.GrantMembership(context.Background(), team.ContainerID(), "zoe", RoleMember); err != nil {
		t.Fatalf("with MembersFromParent cleared, zoe should be admitted: %v", err)
	}
}

// On an unparented Service — built with no WithParent — whose container type
// still embeds NestedBase and carries a non-empty ParentID (because the same
// store also backs a parented Service, the shared-store pattern
// TestNestedWithoutWithParentDeniesTheSameActor uses for other methods),
// GrantMembership must succeed rather than dereferencing a nil ParentScope.
// s.cfg.parent == nil is what has to close the gate: ParentID being non-empty
// on the row proves nothing about whether THIS Service has a parent to ask.
func TestGrantMembershipOnUnparentedServiceDoesNotPanic(t *testing.T) {
	parent := newParentScope()
	_, orgC := ownerCtx(t, parent, "alice")
	child, st := newChildScope(parent, InheritElevation)
	team := createTeam(t, child, orgC.ContainerID(), "alice")
	if team.ContainerParent() == "" {
		t.Fatal("fixture: the team has no parent link to be dangerous with")
	}

	unparented := New(NewAccess(resTeam, map[string][]access.Action{
		resDoc: {actionRead, actionWrite},
	}), st)

	if _, err := unparented.GrantMembership(context.Background(), team.ContainerID(), "quinn", RoleMember); err != nil {
		t.Fatalf("GrantMembership on an unparented Service: %v", err)
	}
}

// Container is the plain loader Task 6 (invitation acceptance) needs:
// GrantMembership hands back only the new membership, not the container the
// invitee was just admitted to, and nothing else exported took an id and
// returned C. It must round-trip what CreateContainer stored.
func TestContainerLoadsByID(t *testing.T) {
	svc := newTestService()
	_, c := ownerCtx(t, svc, "alice")

	got, err := svc.Container(context.Background(), c.ContainerID())
	if err != nil {
		t.Fatalf("Container: %v", err)
	}
	if got.ContainerID() != c.ContainerID() || got.ContainerOwner() != "alice" {
		t.Fatalf("Container = %+v, want id=%s owner=alice", got.ContainerBase, c.ContainerID())
	}
}

// An unknown id is ErrContainerNotFound, matching every other lookup by
// container id in this package.
func TestContainerUnknownIDIsErrContainerNotFound(t *testing.T) {
	svc := newTestService()
	if _, err := svc.Container(context.Background(), "nope"); !errors.Is(err, ErrContainerNotFound) {
		t.Fatalf("err = %v, want ErrContainerNotFound", err)
	}
}

// RolePermissions is the engine's own role resolution, newly exported so
// another package — invite — can ask the real question instead of
// approximating it from ListRoles. Both privilege-escalation rounds on the
// invitations branch came from that approximation, so its two contract
// points are pinned here directly rather than only end-to-end through
// invite: the code-defined registry is consulted BEFORE the store, and a key
// resolving through neither path is ErrRoleNotFound.
//
// The shadowing row is seeded straight against the Store because that is the
// only way to reach the state: CreateRole refuses a key already registered in
// the Access (ErrRoleKeyTaken). But the RoleStore port does not forbid it and
// no shipped store rejects it independently, so a backend that does not
// defend against it can hold such a row, and resolution must be inert to it.
func TestRolePermissionsPrefersTheRegistryOverAShadowingStoreRow(t *testing.T) {
	ac := NewAccess(resOrg, map[string][]access.Action{"project": {"read", "write"}})
	ac.NewRole("viewer", map[string][]access.Action{"project": {"read"}})
	st := newMemStore[testContainer, testMember]()
	svc := New(ac, st)

	c, err := svc.CreateContainer(WithSubject(context.Background(), "alice"), testContainer{Name: "Acme"})
	if err != nil {
		t.Fatalf("CreateContainer: %v", err)
	}

	// A stored row keyed "viewer" granting nothing at all. If the store won,
	// the resolved permission would be empty — which is vacuously a SubsetOf
	// anything, and so exactly the shape that let an escalation through.
	empty, err := ac.Permission(map[string][]access.Action{})
	if err != nil {
		t.Fatalf("ac.Permission: %v", err)
	}
	if _, err := st.CreateRole(context.Background(), RoleRecord{
		ID: "shadow-viewer", ContainerID: c.ContainerID(), Key: "viewer",
		Name: "Fake Viewer", Permissions: empty.Encode(),
	}); err != nil {
		t.Fatalf("seed shadowing role row: %v", err)
	}

	got, err := svc.RolePermissions(context.Background(), c.ContainerID(), "viewer")
	if err != nil {
		t.Fatalf("RolePermissions: %v", err)
	}
	if !got.Allows("project", "read") {
		t.Fatal("resolved permission does not grant project:read — the shadowing store row won")
	}
	// And it is the real registry role, not something broader: viewer grants
	// read only.
	if got.Allows("project", "write") {
		t.Fatal("resolved permission grants project:write — that is not the registered viewer role")
	}
}

// A key registered nowhere — neither the access registry nor the container's
// stored roles — is ErrRoleNotFound, matching what AddMember and
// GrantMembership report for the same key.
func TestRolePermissionsUnknownKeyIsErrRoleNotFound(t *testing.T) {
	svc := newTestService()
	_, c := ownerCtx(t, svc, "alice")

	if _, err := svc.RolePermissions(context.Background(), c.ContainerID(), "no-such-role"); !errors.Is(err, ErrRoleNotFound) {
		t.Fatalf("err = %v, want ErrRoleNotFound", err)
	}
}

// Adding invite:* to the control statements widens the built-in admin role,
// which is derived from the merged surface. That widening is intended — it is
// exactly why the invite package's ListLinks redaction exists — so it is
// asserted here rather than left implicit. The member default must stay at
// no grants at all.
func TestInviteControlStatementsAreDeclared(t *testing.T) {
	ac := NewAccess(resOrg, nil)

	admin, ok := ac.Role(RoleAdmin)
	if !ok {
		t.Fatal("default admin role is not registered")
	}
	for _, action := range []access.Action{ActionCreate, ActionRead, ActionDelete} {
		if !admin.Permissions.Allows(ResourceInvite, action) {
			t.Fatalf("admin does not hold invite:%s", action)
		}
	}

	member, ok := ac.Role(RoleMember)
	if !ok {
		t.Fatal("default member role is not registered")
	}
	for _, action := range []access.Action{ActionCreate, ActionRead, ActionDelete} {
		if member.Permissions.Allows(ResourceInvite, action) {
			t.Fatalf("member holds invite:%s, want none", action)
		}
	}
}
