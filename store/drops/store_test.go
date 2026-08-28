package dropsstore

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/bernardoforcillo/authlayer/org"
	"github.com/bernardoforcillo/authlayer/scope"
	"github.com/bernardoforcillo/drops"
	"github.com/bernardoforcillo/drops/pg"
)

// Compile-time proof the drops store satisfies the Store port.
var _ org.Store = (*Store[org.Organization, org.Member])(nil)

// ── fake driver ─────────────────────────────────────────────────────────────

type fakeResult struct{ n int64 }

func (r fakeResult) RowsAffected() (int64, error) { return r.n, nil }

type fakeRows struct {
	cols []string
	data [][]any
	i    int
}

func (r *fakeRows) Next() bool                 { r.i++; return r.i <= len(r.data) }
func (r *fakeRows) Columns() ([]string, error) { return r.cols, nil }
func (r *fakeRows) Close() error               { return nil }
func (r *fakeRows) Err() error                 { return nil }
func (r *fakeRows) Scan(dest ...any) error {
	row := r.data[r.i-1]
	for k := range dest {
		reflect.ValueOf(dest[k]).Elem().Set(reflect.ValueOf(row[k]))
	}
	return nil
}

type fakeDriver struct {
	execs, queries []string
	execErr        error
	rows           drops.Rows
	// rowsSeq, when non-empty, is popped one entry per Query call before
	// falling back to rows — needed by auth_test.go's MarkRotated
	// reclassification tests, where the UPDATE...RETURNING query and the
	// follow-up FindSessionByHash query must see two different results
	// (e.g. empty, then one already-rotated row) rather than the single
	// shared rows value every other test in this package needs only once.
	rowsSeq []drops.Rows
	// queryErr, when set, is what Query returns instead of rows — no
	// existing caller of this fake driver needed a Query-level failure
	// (as opposed to a query that legitimately returns zero rows) until
	// MarkRotated's propagated-error test.
	queryErr                   error
	affected                   int64
	begins, commits, rollbacks int
}

func (d *fakeDriver) Exec(_ context.Context, sql string, _ ...any) (drops.Result, error) {
	d.execs = append(d.execs, sql)
	if d.execErr != nil {
		return nil, d.execErr
	}
	return fakeResult{d.affected}, nil
}

func (d *fakeDriver) Query(_ context.Context, sql string, _ ...any) (drops.Rows, error) {
	d.queries = append(d.queries, sql)
	if d.queryErr != nil {
		return nil, d.queryErr
	}
	if len(d.rowsSeq) > 0 {
		r := d.rowsSeq[0]
		d.rowsSeq = d.rowsSeq[1:]
		return r, nil
	}
	if d.rows != nil {
		return d.rows, nil
	}
	return &fakeRows{}, nil
}

func (d *fakeDriver) Begin(context.Context) (drops.Tx, error) {
	d.begins++
	return &fakeTx{d}, nil
}

type fakeTx struct{ *fakeDriver }

func (t *fakeTx) Commit(context.Context) error   { t.commits++; return nil }
func (t *fakeTx) Rollback(context.Context) error { t.rollbacks++; return nil }

func newStore(fd *fakeDriver) *Store[org.Organization, org.Member] {
	return New[org.Organization, org.Member](pg.New(fd))
}

// ── tests ───────────────────────────────────────────────────────────────────

// The engine stamps id/owner/timestamps before calling in; the store persists
// them verbatim and issues a single INSERT.
func TestCreateContainerInsertsStampedOrg(t *testing.T) {
	fd := &fakeDriver{}
	st := newStore(fd)

	now := time.Now().UTC()
	in := org.Organization{
		ContainerBase: scope.ContainerBase{ID: "org1", OwnerID: "alice", CreatedAt: now, UpdatedAt: now},
		Name:          "Acme",
		Slug:          "acme",
	}
	o, err := st.CreateContainer(context.Background(), in)
	if err != nil {
		t.Fatalf("CreateContainer: %v", err)
	}
	if o.ID != "org1" || o.OwnerID != "alice" || o.CreatedAt != now {
		t.Fatalf("store must persist stamped fields verbatim: %+v", o)
	}
	if len(fd.execs) != 1 || !strings.Contains(fd.execs[0], "organizations") || !strings.Contains(fd.execs[0], "INSERT") {
		t.Fatalf("unexpected exec: %v", fd.execs)
	}
}

func TestCreateContainerMapsUniqueViolation(t *testing.T) {
	st := newStore(&fakeDriver{execErr: pg.ErrUniqueViolation})
	in := org.Organization{ContainerBase: scope.ContainerBase{ID: "o"}, Slug: "acme"}
	if _, err := st.CreateContainer(context.Background(), in); !errors.Is(err, org.ErrSlugTaken) {
		t.Fatalf("err = %v, want ErrSlugTaken", err)
	}
}

func TestAddMemberMapsUniqueViolationToAlreadyMember(t *testing.T) {
	st := newStore(&fakeDriver{execErr: pg.ErrUniqueViolation})
	m := org.Member{MemberBase: scope.MemberBase{ContainerID: "o", UserID: "u", RoleKey: "admin"}}
	if _, err := st.AddMember(context.Background(), m); !errors.Is(err, org.ErrAlreadyMember) {
		t.Fatalf("err = %v, want ErrAlreadyMember", err)
	}
}

func TestFindContainerScansRow(t *testing.T) {
	now := time.Now().UTC()
	fd := &fakeDriver{rows: &fakeRows{
		cols: []string{"id", "name", "slug", "owner_id", "created_at", "updated_at"},
		data: [][]any{{"org1", "Acme", "acme", "alice", now, now}},
	}}
	st := newStore(fd)

	o, err := st.FindContainer(context.Background(), "org1")
	if err != nil {
		t.Fatalf("FindContainer: %v", err)
	}
	if o.ID != "org1" || o.Slug != "acme" || o.OwnerID != "alice" {
		t.Fatalf("scanned org = %+v", o)
	}
}

func TestFindContainerNotFound(t *testing.T) {
	st := newStore(&fakeDriver{}) // Query returns empty rows
	if _, err := st.FindContainer(context.Background(), "nope"); !errors.Is(err, org.ErrOrgNotFound) {
		t.Fatalf("err = %v, want ErrOrgNotFound", err)
	}
}

func TestRemoveMemberAffectsRowsOrNotFound(t *testing.T) {
	// No rows affected -> not a member.
	st := newStore(&fakeDriver{affected: 0})
	if err := st.RemoveMember(context.Background(), "o", "u"); !errors.Is(err, org.ErrNotMember) {
		t.Fatalf("err = %v, want ErrNotMember", err)
	}

	// One row affected -> success, and it issues a DELETE on the members table.
	fd := &fakeDriver{affected: 1}
	st = newStore(fd)
	if err := st.RemoveMember(context.Background(), "o", "u"); err != nil {
		t.Fatalf("RemoveMember: %v", err)
	}
	if !strings.Contains(fd.execs[0], "DELETE") || !strings.Contains(fd.execs[0], "organization_members") {
		t.Fatalf("unexpected exec: %v", fd.execs)
	}
}

// drops' CreateTableIfNotExists writes column definitions only, so the composite
// PK and UNIQUE registered on the *pg.Table would never reach the database
// unless CreateSchema emits them itself. Assert the SQL, not the registry: the
// registry is what was already true before the constraints were emitted.
func TestCreateSchemaEmitsCompositeConstraints(t *testing.T) {
	fd := &fakeDriver{}
	st := newStore(fd)
	if err := st.CreateSchema(context.Background()); err != nil {
		t.Fatalf("CreateSchema: %v", err)
	}

	// 3 CREATE TABLE + the members PK + the roles UNIQUE.
	if len(fd.execs) != 5 {
		t.Fatalf("CreateSchema issued %d statements, want 5:\n%s",
			len(fd.execs), strings.Join(fd.execs, "\n--\n"))
	}

	want := []string{
		`ALTER TABLE "organization_members" ADD CONSTRAINT "organization_members_pkey" ` +
			`PRIMARY KEY ("container_id", "user_id");`,
		`ALTER TABLE "organization_roles" ADD CONSTRAINT "organization_roles_container_key" ` +
			`UNIQUE ("container_id", "key");`,
	}
	all := strings.Join(fd.execs, "\n--\n")
	for _, w := range want {
		if !strings.Contains(all, w) {
			t.Fatalf("CreateSchema never emitted:\n%s\ngot:\n%s", w, all)
		}
	}

	// Re-running must be safe, so each ALTER is guarded rather than bare.
	for _, sql := range fd.execs {
		if strings.Contains(sql, "ALTER TABLE") && !strings.Contains(sql, "EXCEPTION") {
			t.Fatalf("unguarded ALTER, so CreateSchema is not re-runnable:\n%s", sql)
		}
	}

	// The containers table declares no composite constraint, so it gets one
	// statement and no ALTER.
	if strings.Contains(all, `ALTER TABLE "organizations"`) {
		t.Fatalf("containers table has no composite constraint but got an ALTER:\n%s", all)
	}
}

// The constraint names follow the configured table names, so a second scope
// instance does not collide with the organization one.
func TestCreateSchemaConstraintNamesFollowCustomNames(t *testing.T) {
	fd := &fakeDriver{}
	st := New[org.Organization, org.Member](pg.New(fd), WithNames(Names{
		Containers: "teams", Members: "team_members", Roles: "team_roles",
	}))
	if err := st.CreateSchema(context.Background()); err != nil {
		t.Fatalf("CreateSchema: %v", err)
	}
	all := strings.Join(fd.execs, "\n--\n")
	for _, w := range []string{`"team_members_pkey"`, `"team_roles_container_key"`} {
		if !strings.Contains(all, w) {
			t.Fatalf("constraint %s missing from:\n%s", w, all)
		}
	}
}

func TestWithTxCommitsAndRollsBack(t *testing.T) {
	fd := &fakeDriver{}
	st := newStore(fd)
	if err := st.WithTx(context.Background(), func(org.Store) error { return nil }); err != nil {
		t.Fatalf("WithTx success: %v", err)
	}
	if fd.begins != 1 || fd.commits != 1 || fd.rollbacks != 0 {
		t.Fatalf("commit path: begins=%d commits=%d rollbacks=%d", fd.begins, fd.commits, fd.rollbacks)
	}

	fd2 := &fakeDriver{}
	st2 := newStore(fd2)
	sentinel := errors.New("boom")
	if err := st2.WithTx(context.Background(), func(org.Store) error { return sentinel }); !errors.Is(err, sentinel) {
		t.Fatalf("WithTx err = %v, want sentinel", err)
	}
	if fd2.begins != 1 || fd2.commits != 0 || fd2.rollbacks != 1 {
		t.Fatalf("rollback path: begins=%d commits=%d rollbacks=%d", fd2.begins, fd2.commits, fd2.rollbacks)
	}
}

// The whole point of deriving columns from tags is that a consumer brings its
// own container type. A named string type — `type Slug string` — is ordinary Go
// domain modelling; it used to build a schema and then panic on the first
// INSERT, in production, on a model the library accepted at startup.
func TestCreateContainerAcceptsNamedStringFields(t *testing.T) {
	fd := &fakeDriver{}
	st := New[slugOrg, org.Member](pg.New(fd))

	now := time.Now().UTC()
	in := slugOrg{
		ContainerBase: scope.ContainerBase{ID: "o1", OwnerID: "u1", CreatedAt: now, UpdatedAt: now},
		Slug:          "acme",
		Seats:         12,
	}
	if _, err := st.CreateContainer(context.Background(), in); err != nil {
		t.Fatalf("CreateContainer: %v", err)
	}
	if len(fd.execs) != 1 || !strings.Contains(fd.execs[0], "INSERT") {
		t.Fatalf("unexpected exec: %v", fd.execs)
	}
}

type slug string

type slugOrg struct {
	scope.ContainerBase
	Slug  slug `drop:"slug"`
	Seats int  `drop:"seats"`
}

// No test in the branch could observe a bound value — the fake driver discards
// its arguments — so assert the shape of the SQL instead: the INSERT's column
// list, and the two-column predicates the members and roles reads key on. A
// mis-declared tag would change these strings.
func TestEmittedSQLNamesTheDerivedColumns(t *testing.T) {
	fd := &fakeDriver{}
	st := newStore(fd)
	ctx := context.Background()

	now := time.Now().UTC()
	if _, err := st.CreateContainer(ctx, org.Organization{
		ContainerBase: scope.ContainerBase{ID: "o1", OwnerID: "u1", CreatedAt: now, UpdatedAt: now},
		Name:          "Acme", Slug: "acme",
	}); err != nil {
		t.Fatalf("CreateContainer: %v", err)
	}
	wantInsert := `INSERT INTO "organizations" ` +
		`("id", "owner_id", "created_at", "updated_at", "name", "slug")`
	if !strings.Contains(fd.execs[0], wantInsert) {
		t.Fatalf("INSERT = %q, want it to name %q", fd.execs[0], wantInsert)
	}

	if _, err := st.FindMember(ctx, "o1", "u1"); !errors.Is(err, org.ErrNotMember) {
		t.Fatalf("FindMember on empty rows = %v, want ErrNotMember", err)
	}
	for _, want := range []string{
		`"organization_members"."container_id" =`,
		`"organization_members"."user_id" =`,
	} {
		if !strings.Contains(fd.queries[0], want) {
			t.Fatalf("FindMember query = %q, want it to key on %q", fd.queries[0], want)
		}
	}

	if _, err := st.FindRole(ctx, "o1", "editor"); !errors.Is(err, org.ErrRoleNotFound) {
		t.Fatalf("FindRole on empty rows = %v, want ErrRoleNotFound", err)
	}
	for _, want := range []string{
		`"organization_roles"."container_id" =`,
		`"organization_roles"."key" =`,
	} {
		if !strings.Contains(fd.queries[1], want) {
			t.Fatalf("FindRole query = %q, want it to key on %q", fd.queries[1], want)
		}
	}
}

func TestListUserStandingsJoinsMembersToContainers(t *testing.T) {
	fd := &fakeDriver{rows: &fakeRows{
		cols: []string{"container_id", "role_key", "owner_id"},
		data: [][]any{{"acme", "owner", "alice"}},
	}}
	st := newStore(fd)

	got, err := st.ListUserStandings(context.Background(), "alice")
	if err != nil {
		t.Fatalf("ListUserStandings: %v", err)
	}
	if len(got) != 1 || got[0] != (scope.MemberStanding{
		ContainerID: "acme", RoleKey: "owner", OwnerID: "alice",
	}) {
		t.Fatalf("got %+v, want one acme/owner/alice standing", got)
	}

	if len(fd.queries) != 1 {
		t.Fatalf("issued %d queries, want exactly 1 — this must be a join, not a query per container", len(fd.queries))
	}
	sql := fd.queries[0]
	// Pin the SELECT list itself, not just that the two table names appear
	// somewhere: owner_id must come from "organizations", not
	// "organization_members" — the equality assertion above can't catch that
	// swap because the fake driver ignores this string and scans positionally
	// off the test's own declared columns.
	wantSelect := `SELECT "organization_members"."container_id", "organization_members"."role_key", "organizations"."owner_id"`
	if !strings.Contains(sql, wantSelect) {
		t.Fatalf("query does not select %q:\n%s", wantSelect, sql)
	}
	// Pin the join condition's exact qualified form, so a reversed or
	// mis-columned join (e.g. onto owner_id, or onto members.user_id) fails
	// here instead of passing every other assertion unchanged.
	wantOn := `ON ("organizations"."id" = "organization_members"."container_id")`
	if !strings.Contains(sql, wantOn) {
		t.Fatalf("query does not join on %q:\n%s", wantOn, sql)
	}
	wantWhere := `WHERE ("organization_members"."user_id" = $1)`
	if !strings.Contains(sql, wantWhere) {
		t.Fatalf("query does not filter %q:\n%s", wantWhere, sql)
	}
}

// A user with no memberships is not an error — same contract as
// store/memory's TestListUserStandingsUnknownUserIsEmptyNotError.
func TestListUserStandingsUnknownUserIsEmptyNotError(t *testing.T) {
	st := newStore(&fakeDriver{}) // Query returns empty rows
	got, err := st.ListUserStandings(context.Background(), "nobody")
	if err != nil {
		t.Fatalf("ListUserStandings: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("got %d standings for an unknown user, want 0", len(got))
	}
}

func TestListUserContainersJoinsThroughMembership(t *testing.T) {
	fd := &fakeDriver{rows: &fakeRows{
		cols: []string{"id", "name", "slug", "owner_id", "created_at", "updated_at"},
		data: [][]any{{"acme", "Acme", "acme", "alice", time.Time{}, time.Time{}}},
	}}
	st := newStore(fd)

	got, err := st.ListUserContainers(context.Background(), "alice")
	if err != nil {
		t.Fatalf("ListUserContainers: %v", err)
	}
	if len(got) != 1 || got[0].ID != "acme" || got[0].Name != "Acme" {
		t.Fatalf("got %+v, want the whole Acme container", got)
	}
	if len(fd.queries) != 1 {
		t.Fatalf("issued %d queries, want exactly 1", len(fd.queries))
	}
	sql := fd.queries[0]
	// Pin the SELECT list to the containers table's own columns, not the
	// join's full column set (which would include organization_members'
	// columns too and break the scan into C).
	wantSelect := `SELECT "organizations"."id", "organizations"."owner_id", ` +
		`"organizations"."created_at", "organizations"."updated_at", ` +
		`"organizations"."name", "organizations"."slug"`
	if !strings.Contains(sql, wantSelect) {
		t.Fatalf("query does not select %q:\n%s", wantSelect, sql)
	}
	wantOn := `ON ("organizations"."id" = "organization_members"."container_id")`
	if !strings.Contains(sql, wantOn) {
		t.Fatalf("query does not join on %q:\n%s", wantOn, sql)
	}
	wantWhere := `WHERE ("organization_members"."user_id" = $1)`
	if !strings.Contains(sql, wantWhere) {
		t.Fatalf("query does not filter %q:\n%s", wantWhere, sql)
	}
}

// A user with no memberships is not an error — same contract as
// store/memory's TestListUserContainersReturnsTheContainersJoined companion.
func TestListUserContainersUnknownUserIsEmptyNotError(t *testing.T) {
	st := newStore(&fakeDriver{}) // Query returns empty rows
	got, err := st.ListUserContainers(context.Background(), "nobody")
	if err != nil {
		t.Fatalf("ListUserContainers: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("got %d containers for an unknown user, want 0", len(got))
	}
}
