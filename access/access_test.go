package access

import "testing"

func TestPermissionAllowsGrantedActionOnly(t *testing.T) {
	s := NewStatements(map[string][]Action{
		"member": {"create", "delete"},
	})
	ac := New(s)

	p, err := ac.Permission(map[string][]Action{
		"member": {"create"},
	})
	if err != nil {
		t.Fatalf("Permission: %v", err)
	}
	if !p.Allows("member", "create") {
		t.Fatal("expected member:create to be allowed")
	}
	if p.Allows("member", "delete") {
		t.Fatal("did not expect member:delete to be allowed")
	}
}

func TestPermissionAllowsRequiresAllActions(t *testing.T) {
	s := NewStatements(map[string][]Action{"member": {"create", "delete"}})
	ac := New(s)

	p, _ := ac.Permission(map[string][]Action{"member": {"create"}})

	if p.Allows("member", "create", "delete") {
		t.Fatal("Allows must require every listed action, not just one")
	}
	if p.Allows("member") {
		t.Fatal("Allows with no actions must be false (nothing to authorize)")
	}
}

func TestPermissionUndeclaredGrantIsRejected(t *testing.T) {
	s := NewStatements(map[string][]Action{"member": {"create"}})
	ac := New(s)

	if _, err := ac.Permission(map[string][]Action{"member": {"banish"}}); err == nil {
		t.Fatal("expected error for undeclared action member:banish")
	}
	if _, err := ac.Permission(map[string][]Action{"ghost": {"create"}}); err == nil {
		t.Fatal("expected error for undeclared resource ghost")
	}
}

func TestPermissionSubsetOf(t *testing.T) {
	s := NewStatements(map[string][]Action{
		"member": {"create", "delete"},
		"role":   {"update"},
	})
	ac := New(s)

	viewer, _ := ac.Permission(map[string][]Action{"member": {"create"}})
	manager, _ := ac.Permission(map[string][]Action{
		"member": {"create", "delete"},
		"role":   {"update"},
	})

	if !viewer.SubsetOf(manager) {
		t.Fatal("viewer grants should be a subset of manager grants")
	}
	if manager.SubsetOf(viewer) {
		t.Fatal("manager grants should not be a subset of viewer grants")
	}
	if !viewer.SubsetOf(viewer) {
		t.Fatal("a permission is a subset of itself")
	}
}

func TestFullPermissionAllowsEverythingAndIsFull(t *testing.T) {
	s := NewStatements(map[string][]Action{
		"member": {"create", "delete"},
		"role":   {"update"},
	})
	ac := New(s)

	full := ac.Full()
	if !full.Allows("member", "create", "delete") || !full.Allows("role", "update") {
		t.Fatal("Full() must allow every declared action")
	}
	if !full.IsFull() {
		t.Fatal("Full() must report IsFull() == true")
	}

	partial, _ := ac.Permission(map[string][]Action{"member": {"create"}})
	if partial.IsFull() {
		t.Fatal("a partial permission must not be IsFull()")
	}
	if !partial.SubsetOf(full) {
		t.Fatal("every permission is a subset of Full()")
	}
}

func TestNewRoleRegistersCodeDefinedRole(t *testing.T) {
	s := NewStatements(map[string][]Action{
		"member": {"create", "delete"},
		"role":   {"create", "update", "delete"},
	})
	ac := New(s)

	admin := ac.NewRole("admin", map[string][]Action{
		"member": {"create", "delete"},
		"role":   {"create", "update", "delete"},
	})

	if admin.Key != "admin" {
		t.Fatalf("role key = %q, want admin", admin.Key)
	}
	if !admin.Permissions.Allows("member", "create", "delete") {
		t.Fatal("admin role must allow member:create,delete")
	}

	got, ok := ac.Role("admin")
	if !ok {
		t.Fatal("Role(admin) should be found after NewRole")
	}
	if !got.Permissions.SubsetOf(admin.Permissions) || !admin.Permissions.SubsetOf(got.Permissions) {
		t.Fatal("retrieved role must equal the registered role")
	}
	if _, ok := ac.Role("nope"); ok {
		t.Fatal("Role(nope) should not be found")
	}
}

func TestNewRolePanicsOnUndeclaredGrant(t *testing.T) {
	s := NewStatements(map[string][]Action{"member": {"create"}})
	ac := New(s)
	defer func() {
		if recover() == nil {
			t.Fatal("NewRole with an undeclared grant must panic (startup misconfig)")
		}
	}()
	ac.NewRole("bad", map[string][]Action{"member": {"obliterate"}})
}

func mustPerm(t *testing.T, ac *Access, grants map[string][]Action) Permission {
	t.Helper()
	p, err := ac.Permission(grants)
	if err != nil {
		t.Fatalf("Permission%v: %v", grants, err)
	}
	return p
}

func TestPermissionEncodeDecodeRoundTrip(t *testing.T) {
	s := NewStatements(map[string][]Action{
		"member": {"create", "delete"},
		"role":   {"update"},
	})
	ac := New(s)

	orig := mustPerm(t, ac, map[string][]Action{
		"member": {"create"},
		"role":   {"update"},
	})

	got, err := ac.Decode(orig.Encode())
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !got.SubsetOf(orig) || !orig.SubsetOf(got) {
		t.Fatal("decoded permission must equal the original")
	}
}

// Encoding stores grant NAMES, so adding new statements later never shifts or
// corrupts a previously stored permission — the "role saved last month still
// means the same thing" guarantee that raw bit indices cannot give.
func TestDecodeIsStableAcrossStatementEvolution(t *testing.T) {
	old := New(NewStatements(map[string][]Action{
		"member": {"create", "delete"},
	}))
	stored := mustPerm(t, old, map[string][]Action{"member": {"delete"}}).Encode()

	// A later version of the app adds a resource (new bit space).
	evolved := New(NewStatements(map[string][]Action{
		"billing": {"manage"},
		"member":  {"create", "delete"},
	}))
	got, err := evolved.Decode(stored)
	if err != nil {
		t.Fatalf("Decode after evolution: %v", err)
	}
	if !got.Allows("member", "delete") {
		t.Fatal("member:delete must survive adding an unrelated resource")
	}
	if got.Allows("member", "create") {
		t.Fatal("decoded permission must not gain grants it never had")
	}
}

func TestDecodeDropsRemovedCapabilities(t *testing.T) {
	old := New(NewStatements(map[string][]Action{
		"member": {"create"},
		"legacy": {"do"},
	}))
	stored := mustPerm(t, old, map[string][]Action{
		"member": {"create"},
		"legacy": {"do"},
	}).Encode()

	// "legacy" resource removed in the new version.
	newAc := New(NewStatements(map[string][]Action{"member": {"create"}}))
	got, err := newAc.Decode(stored)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !got.Allows("member", "create") {
		t.Fatal("member:create must survive; legacy:do is simply dropped")
	}
}

func TestUnionCombinesGrants(t *testing.T) {
	ac := New(NewStatements(map[string][]Action{
		"doc": {"read", "write"}, "billing": {"read"},
	}))
	a, err := ac.Permission(map[string][]Action{"doc": {"read"}})
	if err != nil {
		t.Fatalf("build a: %v", err)
	}
	b, err := ac.Permission(map[string][]Action{"billing": {"read"}})
	if err != nil {
		t.Fatalf("build b: %v", err)
	}

	u, err := ac.Union(a, b)
	if err != nil {
		t.Fatalf("Union: %v", err)
	}
	if !u.Allows("doc", "read") || !u.Allows("billing", "read") {
		t.Fatal("union does not grant both inputs' grants")
	}
	if u.Allows("doc", "write") {
		t.Fatal("union invented a grant neither input held")
	}
	// Inputs are immutable.
	if a.Allows("billing", "read") {
		t.Fatal("Union mutated its first argument")
	}
}

func TestUnionOfNoneGrantsNothing(t *testing.T) {
	ac := New(NewStatements(map[string][]Action{"doc": {"read"}}))
	u, err := ac.Union()
	if err != nil {
		t.Fatalf("Union: %v", err)
	}
	if u.Allows("doc", "read") {
		t.Fatal("empty union grants something")
	}
}

// The point of the method: a permission from another Statements space has
// meaningless bits here and must be refused, not silently reinterpreted.
func TestUnionRejectsAForeignPermission(t *testing.T) {
	parent := New(NewStatements(map[string][]Action{"org": {"admin"}}))
	child := New(NewStatements(map[string][]Action{"team": {"read"}}))

	foreign, err := parent.Permission(map[string][]Action{"org": {"admin"}})
	if err != nil {
		t.Fatalf("build foreign: %v", err)
	}
	if _, err := child.Union(foreign); err == nil {
		t.Fatal("Union accepted a permission built from a different Statements — bits would be reinterpreted")
	}
}

func TestUnionAcceptsTheZeroPermission(t *testing.T) {
	ac := New(NewStatements(map[string][]Action{"doc": {"read"}}))
	granted, err := ac.Permission(map[string][]Action{"doc": {"read"}})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	// The zero Permission has no statements and grants nothing; unioning it
	// must be a no-op rather than an error, so callers need not special-case
	// "no inherited grants".
	u, err := ac.Union(granted, Permission{})
	if err != nil {
		t.Fatalf("Union with the zero permission: %v", err)
	}
	if !u.Allows("doc", "read") {
		t.Fatal("unioning the zero permission dropped a grant")
	}
}
