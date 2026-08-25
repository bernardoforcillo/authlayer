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
	execs, queries             []string
	execErr                    error
	rows                       drops.Rows
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
