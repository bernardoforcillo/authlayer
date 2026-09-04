package scope

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/bernardoforcillo/drops/pg"

	"github.com/bernardoforcillo/authlayer/access"
)

// mustCap compiles grants against svc's own statements — the only space a cap
// can meaningfully be built in (see access.Permission.Intersect).
func mustCap(t *testing.T, svc *Service[testContainer, testMember, *testContainer, *testMember], grants map[string][]access.Action) access.Permission {
	t.Helper()
	p, err := svc.Access().Permission(grants)
	if err != nil {
		t.Fatalf("build cap %v: %v", grants, err)
	}
	return p
}

// A cap intersects: what the role does not grant, the cap cannot add, and
// what the cap does not name, the role no longer confers.
func TestPermissionCapRemovesButNeverAdds(t *testing.T) {
	svc := newTestService()
	octx, c := ownerCtx(t, svc, "alice")
	if _, err := svc.AddMember(octx, "bob", RoleAdmin); err != nil {
		t.Fatalf("AddMember: %v", err)
	}
	bob := WithScope(WithSubject(context.Background(), "bob"), c.ContainerID())

	// Uncapped, an admin holds member:create and member:delete.
	for _, a := range []access.Action{ActionCreate, ActionDelete} {
		if ok, err := svc.Can(bob, ResourceMember, a); err != nil || !ok {
			t.Fatalf("uncapped admin member:%s = %v,%v; want true,nil", a, ok, err)
		}
	}

	// Capped to member:create — delete is removed.
	capped := WithPermissionCap(bob, mustCap(t, svc, map[string][]access.Action{ResourceMember: {ActionCreate}}))
	if ok, err := svc.Can(capped, ResourceMember, ActionCreate); err != nil || !ok {
		t.Fatalf("capped admin member:create = %v,%v; want true,nil", ok, err)
	}
	if ok, err := svc.Can(capped, ResourceMember, ActionDelete); err != nil || ok {
		t.Fatalf("capped admin member:delete = %v,%v; want false,nil — the cap must remove it", ok, err)
	}
	if err := svc.Authorize(capped, ResourceMember, ActionDelete); !errors.Is(err, ErrForbidden) {
		t.Fatalf("Authorize under the cap = %v, want ErrForbidden", err)
	}

	// Capped to organization:delete, which an admin does NOT hold — the cap
	// adds nothing: role ∩ cap is empty.
	overreach := WithPermissionCap(bob, mustCap(t, svc, map[string][]access.Action{resOrg: {ActionDelete}}))
	if ok, err := svc.Can(overreach, resOrg, ActionDelete); err != nil || ok {
		t.Fatalf("cap naming a grant the role lacks = %v,%v; want false,nil — a cap can never add", ok, err)
	}
	if ok, err := svc.Can(overreach, ResourceMember, ActionCreate); err != nil || ok {
		t.Fatalf("grant outside the cap = %v,%v; want false,nil", ok, err)
	}
}

// OwnerBypass hands the owner Full and elevation. Under a cap the owner stands
// on Full ∩ cap = cap, and is not elevated unless the cap is Full — so the one
// principal who normally bypasses every check is bounded by a restricted key.
func TestCappedOwnerIsNotElevated(t *testing.T) {
	svc := newTestService()
	octx, _ := ownerCtx(t, svc, "alice")

	ceiling := mustCap(t, svc, map[string][]access.Action{ResourceMember: {ActionCreate}})
	capped := WithPermissionCap(octx, ceiling)

	// The owner's own organization:delete is gone under the cap.
	if ok, err := svc.Can(capped, resOrg, ActionDelete); err != nil || ok {
		t.Fatalf("capped owner organization:delete = %v,%v; want false,nil", ok, err)
	}
	if ok, err := svc.Can(capped, ResourceMember, ActionCreate); err != nil || !ok {
		t.Fatalf("capped owner member:create = %v,%v; want true,nil", ok, err)
	}

	// Not elevated: the escalation guard applies, so the capped owner cannot
	// mint an admin — admin grants more than member:create.
	if _, err := svc.AddMember(capped, "bob", RoleAdmin); !errors.Is(err, ErrPrivilegeEscalation) {
		t.Fatalf("capped owner adding an admin = %v, want ErrPrivilegeEscalation", err)
	}
	// A role within the cap is fine. member grants nothing, so it is ⊆ anything.
	if _, err := svc.AddMember(capped, "bob", RoleMember); err != nil {
		t.Fatalf("capped owner adding a member: %v", err)
	}
	// The uncapped owner is unchanged: the cap lives on the context it was
	// put on, not on the owner.
	if ok, err := svc.Can(octx, resOrg, ActionDelete); err != nil || !ok {
		t.Fatalf("uncapped owner organization:delete = %v,%v; want true,nil", ok, err)
	}
}

// The escalation guard compares the granted role against the actor's CAPPED
// standing, so a restricted key cannot grant, mint or remove more than the
// key allows — even though the account behind it could.
func TestEscalationGuardUsesTheCappedStanding(t *testing.T) {
	svc := newTestService()
	octx, c := ownerCtx(t, svc, "alice")
	if _, err := svc.AddMember(octx, "bob", RoleAdmin); err != nil {
		t.Fatalf("AddMember bob: %v", err)
	}
	if _, err := svc.AddMember(octx, "dave", RoleAdmin); err != nil {
		t.Fatalf("AddMember dave: %v", err)
	}
	bob := WithScope(WithSubject(context.Background(), "bob"), c.ContainerID())

	// Uncapped, admin bob may add another admin.
	if _, err := svc.AddMember(bob, "carol", RoleAdmin); err != nil {
		t.Fatalf("uncapped admin adding an admin: %v", err)
	}
	if err := svc.RemoveMember(bob, "carol"); err != nil {
		t.Fatalf("cleanup: %v", err)
	}

	capped := WithPermissionCap(bob, mustCap(t, svc, map[string][]access.Action{
		ResourceMember: {ActionCreate, ActionUpdate, ActionDelete},
		ResourceRole:   {ActionCreate, ActionUpdate},
	}))

	// AddMember: admin exceeds the cap.
	if _, err := svc.AddMember(capped, "carol", RoleAdmin); !errors.Is(err, ErrPrivilegeEscalation) {
		t.Fatalf("capped AddMember(admin) = %v, want ErrPrivilegeEscalation", err)
	}
	if _, err := svc.AddMember(capped, "carol", RoleMember); err != nil {
		t.Fatalf("capped AddMember(member): %v", err)
	}
	// ChangeMemberRole: same guard, same answer.
	if err := svc.ChangeMemberRole(capped, "carol", RoleAdmin); !errors.Is(err, ErrPrivilegeEscalation) {
		t.Fatalf("capped ChangeMemberRole(admin) = %v, want ErrPrivilegeEscalation", err)
	}
	// CreateRole: a role within the cap is fine, one beyond it is not.
	if _, err := svc.CreateRole(capped, "adder", "Adder", map[string][]access.Action{
		ResourceMember: {ActionCreate},
	}); err != nil {
		t.Fatalf("capped CreateRole within the cap: %v", err)
	}
	if _, err := svc.CreateRole(capped, "inviter", "Inviter", map[string][]access.Action{
		ResourceInvite: {ActionCreate},
	}); !errors.Is(err, ErrPrivilegeEscalation) {
		t.Fatalf("capped CreateRole beyond the cap = %v, want ErrPrivilegeEscalation", err)
	}
	// RemoveMember guards on the TARGET's rank: dave is an admin, and admin
	// is not ⊆ the cap, so the capped bob cannot evict him — though the
	// uncapped bob, an equal, could.
	if err := svc.RemoveMember(capped, "dave"); !errors.Is(err, ErrPrivilegeEscalation) {
		t.Fatalf("capped RemoveMember(admin) = %v, want ErrPrivilegeEscalation", err)
	}
	if err := svc.RemoveMember(capped, "carol"); err != nil {
		t.Fatalf("capped RemoveMember(member): %v", err)
	}
}

// HasPermission and Standing take an explicit user id and read nothing from
// the context — the cap included. They answer about the user as they really
// stand; the same context asked through Can answers about the principal.
func TestHasPermissionAndStandingIgnoreTheCap(t *testing.T) {
	svc := newTestService()
	octx, c := ownerCtx(t, svc, "alice")
	if _, err := svc.AddMember(octx, "bob", RoleAdmin); err != nil {
		t.Fatalf("AddMember: %v", err)
	}
	bob := WithScope(WithSubject(context.Background(), "bob"), c.ContainerID())
	capped := WithPermissionCap(bob, mustCap(t, svc, map[string][]access.Action{ResourceMember: {ActionCreate}}))

	ok, err := svc.HasPermission(capped, c.ContainerID(), "bob", map[string][]access.Action{ResourceMember: {ActionDelete}})
	if err != nil || !ok {
		t.Fatalf("HasPermission under a cap = %v,%v; want true,nil — it reads no cap", ok, err)
	}
	perms, elevated, err := svc.Standing(capped, c.ContainerID(), "bob")
	if err != nil {
		t.Fatalf("Standing: %v", err)
	}
	if !perms.Allows(ResourceMember, ActionDelete) || elevated {
		t.Fatalf("Standing under a cap = allows delete %v, elevated %v; want the uncapped admin standing", perms.Allows(ResourceMember, ActionDelete), elevated)
	}
	// The owner, asked about explicitly, is still elevated whatever cap the
	// asking context carries.
	if _, elevated, err := svc.Standing(capped, c.ContainerID(), "alice"); err != nil || !elevated {
		t.Fatalf("Standing(owner) under a cap = elevated %v, %v; want true", elevated, err)
	}
	// And the same context through Can sees the cap.
	if ok, err := svc.Can(capped, ResourceMember, ActionDelete); err != nil || ok {
		t.Fatalf("Can under the same cap = %v,%v; want false,nil", ok, err)
	}
	// CapStanding is the exported form of the rule Can applied.
	cp, ce := svc.CapStanding(capped, perms, elevated)
	if cp.Allows(ResourceMember, ActionDelete) || !cp.Allows(ResourceMember, ActionCreate) || ce {
		t.Fatal("CapStanding did not apply role ∩ cap")
	}
	if p2, e2 := svc.CapStanding(bob, perms, elevated); !p2.SubsetOf(perms) || !perms.SubsetOf(p2) || e2 != elevated {
		t.Fatal("CapStanding with no cap on ctx must return its inputs unchanged")
	}
}

// A Full cap caps nothing: role ∩ Full = role, and elevation survives. This is
// what an unrestricted key looks like, and it must be indistinguishable from
// no cap at all.
func TestCanWithAFullCapBehavesAsBefore(t *testing.T) {
	svc := newTestService()
	octx, c := ownerCtx(t, svc, "alice")
	if _, err := svc.AddMember(octx, "bob", RoleAdmin); err != nil {
		t.Fatalf("AddMember: %v", err)
	}
	full := svc.Access().Full()

	owner := WithPermissionCap(octx, full)
	if ok, err := svc.Can(owner, resOrg, ActionDelete); err != nil || !ok {
		t.Fatalf("owner under a Full cap organization:delete = %v,%v; want true,nil", ok, err)
	}
	// Still elevated: may mint an admin.
	if _, err := svc.AddMember(owner, "carol", RoleAdmin); err != nil {
		t.Fatalf("owner under a Full cap adding an admin: %v", err)
	}

	bob := WithScope(WithSubject(context.Background(), "bob"), c.ContainerID())
	fullBob := WithPermissionCap(bob, full)
	for _, tc := range []struct {
		resource string
		action   access.Action
	}{{ResourceMember, ActionCreate}, {ResourceMember, ActionDelete}, {resOrg, ActionDelete}} {
		plain, err1 := svc.Can(bob, tc.resource, tc.action)
		capped, err2 := svc.Can(fullBob, tc.resource, tc.action)
		if err1 != nil || err2 != nil || plain != capped {
			t.Fatalf("%s:%s: uncapped %v,%v vs Full-capped %v,%v — must agree", tc.resource, tc.action, plain, err1, capped, err2)
		}
	}
}

// A cap compiled against another scope's statements — a key minted for one
// scope presented against another — has bits that mean nothing here.
// Intersect fails closed, so the subject can do nothing rather than something
// unintended. The foreign space here declares exactly ONE pair and the cap
// grants it, so the cap reports IsFull() in its own space: a rule that judged
// fullness by cap.IsFull() alone would keep the owner elevated, and this test
// is what caught that.
func TestForeignCapDeniesEverything(t *testing.T) {
	svc := newTestService()
	octx, _ := ownerCtx(t, svc, "alice")

	other := access.New(access.NewStatements(map[string][]access.Action{"doc": {"read"}}))
	foreign, err := other.Permission(map[string][]access.Action{"doc": {"read"}})
	if err != nil {
		t.Fatalf("build foreign: %v", err)
	}
	capped := WithPermissionCap(octx, foreign)
	if ok, err := svc.Can(capped, ResourceMember, ActionCreate); err != nil || ok {
		t.Fatalf("owner under a foreign cap = %v,%v; want false,nil", ok, err)
	}
	if ok, err := svc.Can(capped, resOrg, ActionDelete); err != nil || ok {
		t.Fatalf("owner under a foreign cap = %v,%v; want false,nil", ok, err)
	}
	if _, err := svc.AddMember(capped, "bob", RoleMember); !errors.Is(err, ErrForbidden) {
		t.Fatalf("owner under a foreign cap adding a member = %v, want ErrForbidden — not elevated, nothing granted", err)
	}
	perms, elevated := svc.CapStanding(capped, svc.Access().Full(), true)
	if elevated || !perms.IsZero() {
		t.Fatalf("CapStanding with a foreign Full-in-its-own-space cap = elevated %v, zero %v; want false, true", elevated, perms.IsZero())
	}
}

// PermissionGuard is the row-level form of Can, and it honours the cap the
// same way: a cap that refuses the actions yields the false predicate — no
// rows, owner bypass included — while a cap that allows them changes nothing.
func TestPermissionGuardHonoursTheCap(t *testing.T) {
	svc, _ := containersWithFixture(t)
	tbl := pg.NewTable("projects")
	col := pg.Add(tbl, pg.Text("organization_id"))
	g := svc.PermissionGuard(col.Column, "project", "delete")
	alice := WithSubject(context.Background(), "alice")

	boundIDs := func(t *testing.T, ctx context.Context) []string {
		t.Helper()
		expr, err := g.Predicate(ctx)
		if err != nil {
			t.Fatalf("Predicate: %v", err)
		}
		_, args := renderExpr(t, expr)
		ids := make([]string, 0, len(args))
		for _, a := range args {
			ids = append(ids, a.(string))
		}
		slices.Sort(ids)
		return ids
	}

	// Uncapped: the owned container (bypass) and the admin one.
	if got := boundIDs(t, alice); !slices.Equal(got, []string{"admin", "owned"}) {
		t.Fatalf("uncapped guard bound %v, want [admin owned]", got)
	}
	// A cap without project:delete: nothing, not even the owned container.
	readOnly, err := svc.Access().Permission(map[string][]access.Action{"project": {"read"}})
	if err != nil {
		t.Fatalf("build cap: %v", err)
	}
	expr, err := g.Predicate(WithPermissionCap(alice, readOnly))
	if err != nil {
		t.Fatalf("Predicate under a refusing cap: %v", err)
	}
	if sql, args := renderExpr(t, expr); len(args) != 0 {
		t.Fatalf("refusing cap bound %v (%s); want the false predicate with no ids", args, sql)
	}
	// A cap with project:delete: the same set as uncapped — a cap adds nothing.
	deleter, err := svc.Access().Permission(map[string][]access.Action{"project": {"delete"}})
	if err != nil {
		t.Fatalf("build cap: %v", err)
	}
	if got := boundIDs(t, WithPermissionCap(alice, deleter)); !slices.Equal(got, []string{"admin", "owned"}) {
		t.Fatalf("allowing cap bound %v, want [admin owned]", got)
	}
}

// The parented CreateContainer resolves the subject in the PARENT, whose
// statements a cap was not compiled against, so a non-Full cap is refused
// rather than silently ignored. A Full cap caps nothing and passes.
func TestNestedCreateContainerRefusesACappedSubject(t *testing.T) {
	parent := newParentScope()
	octx, orgC := ownerCtx(t, parent, "alice")
	child, _ := newChildScope(parent, InheritElevation)

	docReader, err := child.Access().Permission(map[string][]access.Action{resDoc: {actionRead}})
	if err != nil {
		t.Fatalf("build cap: %v", err)
	}
	capped := WithPermissionCap(actorCtx("alice", orgC.ContainerID()), docReader)
	if _, err := child.CreateContainer(capped, nestedContainer{Name: "Nope"}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("capped owner creating a team = %v, want ErrForbidden", err)
	}
	full := WithPermissionCap(actorCtx("alice", orgC.ContainerID()), child.Access().Full())
	if _, err := child.CreateContainer(full, nestedContainer{Name: "Platform"}); err != nil {
		t.Fatalf("owner under a Full cap creating a team: %v", err)
	}
	_ = octx
}

func TestPermissionCapFromReportsAbsence(t *testing.T) {
	if _, ok := PermissionCapFrom(context.Background()); ok {
		t.Fatal("a bare context reports a cap")
	}
	svc := newTestService()
	ceiling := svc.Access().Full()
	got, ok := PermissionCapFrom(WithPermissionCap(context.Background(), ceiling))
	if !ok || !got.IsFull() {
		t.Fatalf("PermissionCapFrom = %v, %v; want the Full cap back", got.IsFull(), ok)
	}
}

// Adding service_account:* to the control statements widens the built-in
// admin role, exactly as invite:* did — asserted so the widening is a
// decision on the record rather than a side effect. member stays at nothing.
func TestServiceAccountControlStatementsAreDeclared(t *testing.T) {
	ac := NewAccess(resOrg, nil)

	admin, ok := ac.Role(RoleAdmin)
	if !ok {
		t.Fatal("default admin role is not registered")
	}
	for _, action := range []access.Action{ActionCreate, ActionRead, ActionUpdate, ActionDelete} {
		if !admin.Permissions.Allows(ResourceServiceAccount, action) {
			t.Fatalf("admin does not hold service_account:%s", action)
		}
	}

	member, ok := ac.Role(RoleMember)
	if !ok {
		t.Fatal("default member role is not registered")
	}
	for _, action := range []access.Action{ActionCreate, ActionRead, ActionUpdate, ActionDelete} {
		if member.Permissions.Allows(ResourceServiceAccount, action) {
			t.Fatalf("member holds service_account:%s, want none", action)
		}
	}
	if got := ControlStatements(resOrg)[ResourceServiceAccount]; len(got) != 4 {
		t.Fatalf("ControlStatements declares service_account: %v, want create/read/update/delete", got)
	}
}

func TestAccessReturnsTheEngineItWasBuiltWith(t *testing.T) {
	ac := NewAccess(resOrg, nil)
	svc := New(ac, newMemStore[testContainer, testMember]())
	if svc.Access() != ac {
		t.Fatal("Access() must return the very *access.Access the Service was built with")
	}
}
