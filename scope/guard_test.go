package scope

import (
	"context"
	"errors"
	"testing"

	"github.com/bernardoforcillo/drops/pg"
)

func TestMembershipGuardWiring(t *testing.T) {
	members := pg.NewTable("organization_members")
	pg.Add(members, pg.Text("user_id").NotNull())
	pg.Add(members, pg.Text("container_id").NotNull())

	invoices := pg.NewTable("invoices")
	pg.Add(invoices, pg.Text("container_id").NotNull())

	g := MembershipGuard(
		members,
		members.Col("user_id"),
		members.Col("container_id"),
		invoices.Col("container_id"),
	)

	// With a subject on the context, the guard yields a predicate.
	ctx := WithSubject(context.Background(), "u1")
	expr, err := g.Predicate(ctx)
	if err != nil || expr == nil {
		t.Fatalf("Predicate with subject = %v, %v; want a predicate and no error", expr, err)
	}

	// Without a subject it fails closed, matching drops' own guards.
	if _, err := g.Predicate(context.Background()); !errors.Is(err, pg.ErrSubjectMissing) {
		t.Fatalf("Predicate without subject err = %v; want pg.ErrSubjectMissing", err)
	}
}
