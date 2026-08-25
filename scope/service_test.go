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
