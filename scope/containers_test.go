package scope

import (
	"context"
	"slices"
	"testing"

	"github.com/bernardoforcillo/authlayer/access"
)

// cwStore names the concrete in-package test double these fixtures build
// against, so call sites below don't repeat the full generic instantiation.
type cwStore = *memStore[testContainer, testMember, *testContainer, *testMember]

func newCWStore() cwStore {
	return newMemStore[testContainer, testMember]()
}

// seedContainer writes a container straight to the store with id and owner
// already set, bypassing Service.CreateContainer (and the authorized actor it
// would require) since these fixtures need containers under several different
// owners that no single actor could all legitimately create.
func seedContainer(t *testing.T, st cwStore, id, owner string) {
	t.Helper()
	c := testContainer{ContainerBase: ContainerBase{ID: id, OwnerID: owner}}
	if _, err := st.CreateContainer(context.Background(), c); err != nil {
		t.Fatalf("seed container %q: %v", id, err)
	}
}

// seedMember writes a membership straight to the store, bypassing
// Service.AddMember's authorization and escalation checks.
func seedMember(t *testing.T, st cwStore, containerID, userID, roleKey string) {
	t.Helper()
	m := testMember{MemberBase: MemberBase{ContainerID: containerID, UserID: userID, RoleKey: roleKey}}
	if _, err := st.AddMember(context.Background(), m); err != nil {
		t.Fatalf("seed member %q in %q: %v", userID, containerID, err)
	}
}

// seedRole writes a custom role record straight to the store.
func seedRole(t *testing.T, st cwStore, containerID, key string, perms access.Permission) {
	t.Helper()
	rec := RoleRecord{ContainerID: containerID, Key: key, Permissions: perms.Encode()}
	if _, err := st.CreateRole(context.Background(), rec); err != nil {
		t.Fatalf("seed role %q in %q: %v", key, containerID, err)
	}
}

// containersWithFixture builds a service whose subject "alice" has three
// different kinds of standing, so one call exercises every branch of the
// resolution ladder.
func containersWithFixture(t *testing.T) *Service[testContainer, testMember, *testContainer, *testMember] {
	t.Helper()
	ac := NewAccess("organization", map[string][]access.Action{
		"project": {"create", "read", "delete"},
	})
	st := newCWStore()
	svc := New[testContainer, testMember](ac, st)

	// owned: alice owns it but holds the weakest role — OwnerBypass must win.
	seedContainer(t, st, "owned", "alice")
	seedMember(t, st, "owned", "alice", RoleMember)
	// admin: alice is an admin, which grants project:delete.
	seedContainer(t, st, "admin", "bob")
	seedMember(t, st, "admin", "alice", RoleAdmin)
	// plain: alice is a bare member, which grants nothing.
	seedContainer(t, st, "plain", "bob")
	seedMember(t, st, "plain", "alice", RoleMember)
	// absent: alice is not a member at all.
	seedContainer(t, st, "absent", "bob")

	return svc
}

func TestContainersWithAppliesTheSameLadderAsCan(t *testing.T) {
	svc := containersWithFixture(t)

	got, err := svc.ContainersWith(context.Background(), "alice", "project", "delete")
	if err != nil {
		t.Fatalf("ContainersWith: %v", err)
	}
	slices.Sort(got)
	want := []string{"admin", "owned"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v, want %v — owned via OwnerBypass, admin via its role", got, want)
	}
}

func TestContainersWithZeroActionsDenies(t *testing.T) {
	svc := containersWithFixture(t)

	got, err := svc.ContainersWith(context.Background(), "alice", "project")
	if err != nil {
		t.Fatalf("ContainersWith: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("got %v, want none — zero actions has nothing to authorize", got)
	}
}

func TestContainersWithUndeclaredResourceDenies(t *testing.T) {
	svc := containersWithFixture(t)

	got, err := svc.ContainersWith(context.Background(), "alice", "typo", "delete")
	if err != nil {
		t.Fatalf("ContainersWith: %v", err)
	}
	// The owner is elevated and passes every check, including on an undeclared
	// resource; nobody else may.
	slices.Sort(got)
	if !slices.Equal(got, []string{"owned"}) {
		t.Fatalf("got %v, want only the owned container", got)
	}
}

func TestContainersWithUnknownUserIsEmpty(t *testing.T) {
	svc := containersWithFixture(t)

	got, err := svc.ContainersWith(context.Background(), "nobody", "project", "read")
	if err != nil {
		t.Fatalf("ContainersWith: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("got %v, want none", got)
	}
}

// A custom role must be fetched once per (container, roleKey), not once per
// role name alone. All three containers here define a role keyed "editor", so
// a cache keyed by role name alone would conflate them — and because their
// permissions differ (c2's editor grants project:write but not project:read),
// a wrongly-scoped cache does not just miscount lookups, it changes who gets
// access: whichever container resolves "editor" first would leak its
// permissions into the other two, regardless of store iteration order.
func TestContainersWithMemoizesCustomRoleLookups(t *testing.T) {
	ac := NewAccess("organization", map[string][]access.Action{"project": {"read", "write"}})
	st := newCWStore()
	svc := New[testContainer, testMember](ac, st)

	readPerm, err := ac.Permission(map[string][]access.Action{"project": {"read"}})
	if err != nil {
		t.Fatalf("build read permission: %v", err)
	}
	writeOnlyPerm, err := ac.Permission(map[string][]access.Action{"project": {"write"}})
	if err != nil {
		t.Fatalf("build write-only permission: %v", err)
	}

	seedContainer(t, st, "c1", "bob")
	seedMember(t, st, "c1", "alice", "editor")
	seedRole(t, st, "c1", "editor", readPerm)

	seedContainer(t, st, "c2", "bob")
	seedMember(t, st, "c2", "alice", "editor")
	seedRole(t, st, "c2", "editor", writeOnlyPerm)

	seedContainer(t, st, "c3", "bob")
	seedMember(t, st, "c3", "alice", "editor")
	seedRole(t, st, "c3", "editor", readPerm)

	st.resetRoleLookups()
	got, err := svc.ContainersWith(context.Background(), "alice", "project", "read")
	if err != nil {
		t.Fatalf("ContainersWith: %v", err)
	}
	slices.Sort(got)
	want := []string{"c1", "c3"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v, want %v — c2's editor grants write, not read", got, want)
	}
	// Three distinct (container, role) pairs, so three lookups is correct here;
	// what must not happen is a cache keyed by role name alone short-circuiting
	// after the first lookup and reusing its permissions for the other two.
	if n := st.roleLookups(); n != 3 {
		t.Fatalf("made %d role lookups for 3 distinct (container, role) pairs, want 3", n)
	}
}
