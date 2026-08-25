package scope

import (
	"context"
	"errors"
	"slices"
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
	svc, _ := containersWithFixture(t)
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
	// The values matter, not just the count: a guard that bound the containers
	// alice may *not* delete in would emit two args and filter nothing right.
	ids := make([]string, 0, len(args))
	for _, a := range args {
		id, ok := a.(string)
		if !ok {
			t.Fatalf("bound arg %v is %T, want a container id string", a, a)
		}
		ids = append(ids, id)
	}
	slices.Sort(ids)
	if want := []string{"admin", "owned"}; !slices.Equal(ids, want) {
		t.Fatalf("guard bound %v, want %v — the containers granting project:delete", ids, want)
	}
}

// A guard that swallowed a store failure would render as a false predicate and
// silently show the user nothing. It must surface the error instead, which
// drops turns into an aborted query at every guardPredicate call site.
func TestPermissionGuardPropagatesStoreErrors(t *testing.T) {
	svc, st := containersWithFixture(t)
	tbl := pg.NewTable("projects")
	col := pg.Add(tbl, pg.Text("organization_id"))
	errBoom := errors.New("store is down")
	st.failListUserStandings = errBoom

	g := svc.PermissionGuard(col.Column, "project", "delete")
	expr, err := g.Predicate(WithSubject(context.Background(), "alice"))
	if !errors.Is(err, errBoom) {
		t.Fatalf("err = %v, want the store error", err)
	}
	if expr != nil {
		t.Fatalf("got predicate %v alongside the error; a failed guard must render nothing", expr)
	}
}

// The whole point of a guard: no qualifying container must mean no rows, never
// an unfiltered query.
func TestPermissionGuardWithNoContainersDeniesEverything(t *testing.T) {
	svc, _ := containersWithFixture(t)
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
	svc, _ := containersWithFixture(t)
	tbl := pg.NewTable("projects")
	col := pg.Add(tbl, pg.Text("organization_id"))

	g := svc.PermissionGuard(col.Column, "project", "delete")

	if _, err := g.Predicate(context.Background()); !errors.Is(err, pg.ErrSubjectMissing) {
		t.Fatalf("err = %v, want pg.ErrSubjectMissing — a guard with no subject must not render a predicate", err)
	}
}
