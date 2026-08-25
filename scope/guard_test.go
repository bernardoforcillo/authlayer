package scope

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/bernardoforcillo/drops"
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

// renderExpr writes expr through a drops.Builder and returns the rendered SQL
// and its bound arguments, so guard tests can assert on generated SQL instead
// of trusting a predicate is merely non-nil.
func renderExpr(t *testing.T, expr drops.Expression) (string, []any) {
	t.Helper()
	b := drops.NewBuilder()
	expr.WriteSQL(b)
	sql, args := b.SQL()
	return sql, args
}

func TestPermissionGuardEmitsTheContainerSet(t *testing.T) {
	svc := containersWithFixture(t)
	tbl := pg.NewTable("projects")
	col := pg.Add(tbl, pg.Text("organization_id"))

	g := svc.PermissionGuard(col.Column, "project", "delete")
	ctx := WithSubject(context.Background(), "alice")

	expr, err := g.Predicate(ctx)
	if err != nil {
		t.Fatalf("Predicate: %v", err)
	}
	sql, args := renderExpr(t, expr)
	if !strings.Contains(sql, `"organization_id" IN`) {
		t.Fatalf("predicate does not filter the column:\n%s", sql)
	}
	if len(args) != 2 {
		t.Fatalf("got %d args (%v), want the 2 qualifying container ids", len(args), args)
	}
}

// The whole point of a guard: no qualifying container must mean no rows, never
// an unfiltered query.
func TestPermissionGuardWithNoContainersDeniesEverything(t *testing.T) {
	svc := containersWithFixture(t)
	tbl := pg.NewTable("projects")
	col := pg.Add(tbl, pg.Text("organization_id"))

	g := svc.PermissionGuard(col.Column, "project", "delete")
	ctx := WithSubject(context.Background(), "nobody")

	expr, err := g.Predicate(ctx)
	if err != nil {
		t.Fatalf("Predicate: %v", err)
	}
	sql, args := renderExpr(t, expr)
	if !strings.Contains(strings.ToLower(sql), "false") {
		t.Fatalf("empty container set did not render as false:\n%s", sql)
	}
	if len(args) != 0 {
		t.Fatalf("got args %v for an empty set, want none", args)
	}
}

func TestPermissionGuardWithoutSubjectFailsClosed(t *testing.T) {
	svc := containersWithFixture(t)
	tbl := pg.NewTable("projects")
	col := pg.Add(tbl, pg.Text("organization_id"))

	g := svc.PermissionGuard(col.Column, "project", "delete")

	if _, err := g.Predicate(context.Background()); !errors.Is(err, pg.ErrSubjectMissing) {
		t.Fatalf("err = %v, want pg.ErrSubjectMissing — a guard with no subject must not render a predicate", err)
	}
}
