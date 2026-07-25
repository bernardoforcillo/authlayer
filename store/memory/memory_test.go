package memory

import (
	"context"
	"errors"
	"testing"

	"github.com/bernardoforcillo/authlayer/scope"
)

// Local concrete types embedding the scope bases.
type org struct {
	scope.ContainerBase
	Name string
	Slug string
}

type member struct {
	scope.MemberBase
}

// Compile-time proof the memory store satisfies scope.Store.
var _ scope.Store[org, member] = (*Store[org, member, *org, *member])(nil)

func newStore() *Store[org, member, *org, *member] { return New[org, member]() }

func TestWithTxRollsBackOnError(t *testing.T) {
	st := newStore()
	ctx := context.Background()
	sentinel := errors.New("boom")

	err := st.WithTx(ctx, func(tx scope.Store[org, member]) error {
		var o org
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
	svc := scope.New[org, member](scope.NewAccess("organization", nil), newStore())
	ctx := scope.WithSubject(context.Background(), "alice")

	o, err := svc.CreateContainer(ctx, org{Name: "Acme", Slug: "acme"})
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
