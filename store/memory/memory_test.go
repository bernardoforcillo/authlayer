package memory_test

import (
	"context"
	"errors"
	"testing"

	"github.com/bernardoforcillo/authlayer/org"
	"github.com/bernardoforcillo/authlayer/scope"
	"github.com/bernardoforcillo/authlayer/store/memory"
)

// Compile-time proof the memory store satisfies scope.Store.
var _ scope.Store[org.Organization, org.Member] = (*memory.Store[org.Organization, org.Member, *org.Organization, *org.Member])(nil)

func newStore() *memory.Store[org.Organization, org.Member, *org.Organization, *org.Member] {
	return memory.New[org.Organization, org.Member]()
}

func TestWithTxRollsBackOnError(t *testing.T) {
	st := newStore()
	ctx := context.Background()
	sentinel := errors.New("boom")

	err := st.WithTx(ctx, func(tx scope.Store[org.Organization, org.Member]) error {
		var o org.Organization
		(&o).SetID("o1")
		(&o).SetOwner("alice")
		if _, err := tx.CreateContainer(ctx, o); err != nil {
			return err
		}
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("WithTx err = %v, want sentinel", err)
	}
	if _, err := st.FindContainer(ctx, "o1"); !errors.Is(err, scope.ErrContainerNotFound) {
		t.Fatal("rollback failed: container from aborted tx still present")
	}
}

func TestEndToEndThroughEngine(t *testing.T) {
	svc := scope.New[org.Organization, org.Member](scope.NewAccess("organization", nil), newStore())
	ctx := scope.WithSubject(context.Background(), "alice")

	o, err := svc.CreateContainer(ctx, org.Organization{Name: "Acme", Slug: "acme"})
	if err != nil {
		t.Fatalf("CreateContainer: %v", err)
	}
	octx := scope.WithScope(ctx, o.ContainerID())
	if _, err := svc.AddMember(octx, "bob", scope.RoleAdmin); err != nil {
		t.Fatalf("AddMember: %v", err)
	}

	bob := scope.WithScope(scope.WithSubject(context.Background(), "bob"), o.ContainerID())
	if ok, _ := svc.Can(bob, scope.ResourceMember, scope.ActionCreate); !ok {
		t.Fatal("admin bob must be allowed member:create")
	}
	if ok, _ := svc.Can(bob, "organization", scope.ActionDelete); ok {
		t.Fatal("admin bob must not delete the organization")
	}
}

func TestListUserStandingsReturnsOneRowPerMembershipWithOwner(t *testing.T) {
	st := memory.New[org.Organization, org.Member]()
	ctx := context.Background()

	// alice owns acme and is a plain member of globex.
	if _, err := st.CreateContainer(ctx, org.Organization{
		ContainerBase: scope.ContainerBase{ID: "acme", OwnerID: "alice"},
	}); err != nil {
		t.Fatalf("create acme: %v", err)
	}
	if _, err := st.CreateContainer(ctx, org.Organization{
		ContainerBase: scope.ContainerBase{ID: "globex", OwnerID: "bob"},
	}); err != nil {
		t.Fatalf("create globex: %v", err)
	}
	add := func(container, user, role string) {
		t.Helper()
		if _, err := st.AddMember(ctx, org.Member{MemberBase: scope.MemberBase{
			ContainerID: container, UserID: user, RoleKey: role,
		}}); err != nil {
			t.Fatalf("add %s/%s: %v", container, user, err)
		}
	}
	add("acme", "alice", scope.RoleOwner)
	add("globex", "alice", scope.RoleMember)
	add("globex", "bob", scope.RoleOwner)

	got, err := st.ListUserStandings(ctx, "alice")
	if err != nil {
		t.Fatalf("ListUserStandings: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d standings, want 2: %+v", len(got), got)
	}

	byContainer := map[string]scope.MemberStanding{}
	for _, s := range got {
		byContainer[s.ContainerID] = s
	}
	if s := byContainer["acme"]; s.RoleKey != scope.RoleOwner || s.OwnerID != "alice" {
		t.Fatalf("acme standing = %+v, want role=%s owner=alice", s, scope.RoleOwner)
	}
	// The owner id must be the CONTAINER's owner, not the subject: bob owns globex.
	if s := byContainer["globex"]; s.RoleKey != scope.RoleMember || s.OwnerID != "bob" {
		t.Fatalf("globex standing = %+v, want role=%s owner=bob", s, scope.RoleMember)
	}
}

func TestListUserStandingsUnknownUserIsEmptyNotError(t *testing.T) {
	st := memory.New[org.Organization, org.Member]()
	got, err := st.ListUserStandings(context.Background(), "nobody")
	if err != nil {
		t.Fatalf("ListUserStandings: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("got %d standings for an unknown user, want 0", len(got))
	}
}

func TestListUserContainersReturnsTheContainersJoined(t *testing.T) {
	st := memory.New[org.Organization, org.Member]()
	ctx := context.Background()

	for _, o := range []org.Organization{
		{ContainerBase: scope.ContainerBase{ID: "acme", OwnerID: "alice"}, Name: "Acme"},
		{ContainerBase: scope.ContainerBase{ID: "globex", OwnerID: "bob"}, Name: "Globex"},
	} {
		if _, err := st.CreateContainer(ctx, o); err != nil {
			t.Fatalf("create %s: %v", o.ID, err)
		}
	}
	if _, err := st.AddMember(ctx, org.Member{MemberBase: scope.MemberBase{
		ContainerID: "acme", UserID: "alice", RoleKey: scope.RoleOwner,
	}}); err != nil {
		t.Fatalf("add member: %v", err)
	}

	got, err := st.ListUserContainers(ctx, "alice")
	if err != nil {
		t.Fatalf("ListUserContainers: %v", err)
	}
	if len(got) != 1 || got[0].ID != "acme" || got[0].Name != "Acme" {
		t.Fatalf("got %+v, want just Acme — the whole container, not only its id", got)
	}
}
