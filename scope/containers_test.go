package scope

import (
	"context"
	"errors"
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
// resolution ladder. It returns the store too, so a test can iterate the
// fixture's containers or extend it, and takes options so the same fixture can
// be rebuilt under a different [Policy].
func containersWithFixture(t *testing.T, opts ...Option) (*Service[testContainer, testMember, *testContainer, *testMember], cwStore) {
	t.Helper()
	ac := NewAccess("organization", map[string][]access.Action{
		"project": {"create", "read", "delete"},
	})
	st := newCWStore()
	svc := New[testContainer, testMember](ac, st, opts...)

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

	return svc, st
}

// fixtureContainerIDs lists every container the fixture holds, sorted. Tests
// that must cover the whole fixture read it from the store rather than from a
// hardcoded list, so they keep covering it as the fixture grows.
func fixtureContainerIDs(st cwStore) []string {
	ids := make([]string, 0, len(st.containers))
	for id := range st.containers {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	return ids
}

// strictNoBypass is the default policy with the one deviation that matters to
// ContainersWith: the container owner is an ordinary member, subject to the
// role key on their own membership row.
func strictNoBypass() Policy {
	return Policy{
		Escalation:      EscalationStrict,
		LastOwnerLocked: true,
		OwnerBypass:     false,
	}
}

func TestContainersWithAppliesTheSameLadderAsCan(t *testing.T) {
	svc, _ := containersWithFixture(t)

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

// The feature exists because the container set must not be able to disagree
// with the in-memory check, so the assertion here is that comparison itself
// rather than a hardcoded set: for every container in the fixture, membership
// of ContainersWith's result must match what Can answers for the same subject,
// resource and actions. It runs under both owner policies, because the one
// direction in which a disagreement leaks access — an owner treated as elevated
// when the policy says they are not — is reachable only with OwnerBypass off.
func TestContainersWithAgreesWithCanAcrossTheFixture(t *testing.T) {
	policies := map[string][]Option{
		"default policy":   nil,
		"owner bypass off": {WithPolicy(strictNoBypass())},
	}
	requests := [][]access.Action{{"delete"}, {"read"}, {"read", "delete"}}

	for name, opts := range policies {
		t.Run(name, func(t *testing.T) {
			svc, st := containersWithFixture(t, opts...)
			ids := fixtureContainerIDs(st)
			for _, actions := range requests {
				got, err := svc.ContainersWith(context.Background(), "alice", "project", actions...)
				if err != nil {
					t.Fatalf("ContainersWith(project, %v): %v", actions, err)
				}
				for _, id := range ids {
					ctx := WithScope(WithSubject(context.Background(), "alice"), id)
					can, err := svc.Can(ctx, "project", actions...)
					if err != nil {
						t.Fatalf("Can(%q, project, %v): %v", id, actions, err)
					}
					if listed := slices.Contains(got, id); listed != can {
						t.Fatalf("container %q, project %v: ContainersWith says %t, Can says %t (set %v)",
							id, actions, listed, can, got)
					}
				}
			}
		})
	}
}

// OwnerBypass is the one field whose loss fails open: drop it from the check
// and an owner holding only a bare member role is handed every row the guard
// should deny. With the policy off, Can denies them, so ContainersWith must.
func TestContainersWithoutOwnerBypassDeniesTheBareMemberOwner(t *testing.T) {
	svc, _ := containersWithFixture(t, WithPolicy(strictNoBypass()))

	got, err := svc.ContainersWith(context.Background(), "alice", "project", "delete")
	if err != nil {
		t.Fatalf("ContainersWith: %v", err)
	}
	slices.Sort(got)
	want := []string{"admin"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v, want %v — alice owns %q but holds only the %q role there, and OwnerBypass is off",
			got, want, "owned", RoleMember)
	}

	ctx := WithScope(WithSubject(context.Background(), "alice"), "owned")
	can, err := svc.Can(ctx, "project", "delete")
	if err != nil {
		t.Fatalf("Can: %v", err)
	}
	if can {
		t.Fatal("Can allows project:delete in the owned container with OwnerBypass off; the policy is not reaching the ladder")
	}
}

func TestContainersWithZeroActionsDenies(t *testing.T) {
	svc, _ := containersWithFixture(t)

	got, err := svc.ContainersWith(context.Background(), "alice", "project")
	if err != nil {
		t.Fatalf("ContainersWith: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("got %v, want none — zero actions has nothing to authorize", got)
	}
}

func TestContainersWithUndeclaredResourceDenies(t *testing.T) {
	svc, _ := containersWithFixture(t)

	got, err := svc.ContainersWith(context.Background(), "alice", "typo", "delete")
	if err != nil {
		t.Fatalf("ContainersWith: %v", err)
	}
	// The owner is elevated and passes every fine-grained check on a non-empty
	// action list, including on an undeclared resource; nobody else may.
	slices.Sort(got)
	if !slices.Equal(got, []string{"owned"}) {
		t.Fatalf("got %v, want only the owned container", got)
	}
}

func TestContainersWithUnknownUserIsEmpty(t *testing.T) {
	svc, _ := containersWithFixture(t)

	got, err := svc.ContainersWith(context.Background(), "nobody", "project", "read")
	if err != nil {
		t.Fatalf("ContainersWith: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("got %v, want none", got)
	}
}

// A membership naming a role that resolves to nothing must deny its own
// container and no other. ContainersWith answers across every container the
// user belongs to, so aborting the batch would let one mistyped role key in one
// container blank out the guard everywhere — including in other tenants, whose
// data the mistake never touched. This is a documented divergence from Can,
// which still surfaces the bad key as an error, and it denies rather than leaks.
func TestContainersWithUnresolvableRoleSkipsOnlyThatContainer(t *testing.T) {
	svc, st := containersWithFixture(t)
	seedContainer(t, st, "mistyped", "bob")
	seedMember(t, st, "mistyped", "alice", "edtior")

	got, err := svc.ContainersWith(context.Background(), "alice", "project", "delete")
	if err != nil {
		t.Fatalf("ContainersWith: %v", err)
	}
	slices.Sort(got)
	want := []string{"admin", "owned"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v, want %v — an unresolvable role must deny its own container only", got, want)
	}

	ctx := WithScope(WithSubject(context.Background(), "alice"), "mistyped")
	if _, err := svc.Can(ctx, "project", "delete"); !errors.Is(err, ErrRoleNotFound) {
		t.Fatalf("Can in the container with the bad role key = %v, want ErrRoleNotFound", err)
	}
}

// A store failure is not a denial. Skipping the container it concerns would
// turn a database outage into "you may see nothing", which a guard renders as a
// false predicate — an answer nobody asked for. Only ErrRoleNotFound skips;
// everything else aborts the call.
func TestContainersWithPropagatesStoreErrors(t *testing.T) {
	errBoom := errors.New("store is down")

	t.Run("standings lookup", func(t *testing.T) {
		svc, st := containersWithFixture(t)
		st.failListUserStandings = errBoom

		if _, err := svc.ContainersWith(context.Background(), "alice", "project", "delete"); !errors.Is(err, errBoom) {
			t.Fatalf("err = %v, want the store error", err)
		}
	})

	t.Run("custom role lookup", func(t *testing.T) {
		svc, st := containersWithFixture(t)
		seedContainer(t, st, "custom", "bob")
		seedMember(t, st, "custom", "alice", "editor")
		st.failFindRole = errBoom

		if _, err := svc.ContainersWith(context.Background(), "alice", "project", "delete"); !errors.Is(err, errBoom) {
			t.Fatalf("err = %v, want the store error", err)
		}
	})
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
