package dropsstore

import (
	"context"
	"errors"
	"time"

	"github.com/bernardoforcillo/authlayer/scope"
	"github.com/bernardoforcillo/drops"
	"github.com/bernardoforcillo/drops/pg"
)

// Store is a drops-backed scope.Store[C, M]. It is pure persistence: the engine
// stamps ids, owners and timestamps before calling in, so the store only writes
// and reads the values it is handed, and authorizes nothing.
type Store[C scope.Container, M scope.Member] struct {
	db *pg.DB
	s  *Schema[C, M]
}

// New returns a Store over db, building a fresh [Schema].
//
//	st := dropsstore.New[org.Organization, org.Member](pg.New(stdlib.New(sqlDB)))
//	svc := org.New(org.NewAccess(appStatements), st)
//
// Use [Store.Schema] to reach the tables (to build a guard, or to generate DDL).
func New[C scope.Container, M scope.Member](db *pg.DB, opts ...Option) *Store[C, M] {
	return &Store[C, M]{db: db, s: NewSchema[C, M](opts...)}
}

// Schema exposes the tables so callers can build query guards, join against
// memberships, or emit their own DDL.
func (st *Store[C, M]) Schema() *Schema[C, M] { return st.s }

// MembershipGuard returns a drops guard restricting a table's rows to the
// context subject's containers, using this store's members table — the
// convenient form of scope.MembershipGuard, with the junction and its two
// columns already filled in.
//
// resourceContainerCol is the container-id column on the table being guarded —
// one of your own columns, on your own table, whatever you happen to have named
// it. It is not one of authlayer's, so the container_id rename does not apply
// to it:
//
//	projects.AuthorizeWith(st.MembershipGuard(projectsTbl.Col("organization_id")))
//
// This is coarse, membership-level filtering. For per-action filtering use
// scope.Service.PermissionGuard.
func (st *Store[C, M]) MembershipGuard(resourceContainerCol *pg.Column) pg.Guard {
	return scope.MembershipGuard(st.s.Members,
		st.s.members.col("user_id"), st.s.members.col("container_id"), resourceContainerCol)
}

// CreateSchema issues CREATE TABLE IF NOT EXISTS for the containers, members
// and roles tables, followed by the composite constraints CREATE TABLE cannot
// carry: PRIMARY KEY (container_id, user_id) on the members table and
// UNIQUE (container_id, key) on the roles table. Those two are load-bearing —
// the engine does not pre-check membership or role-key uniqueness, it relies on
// the unique violation coming back from PostgreSQL — so they are emitted rather
// than left to the in-memory table registry. No foreign keys are declared
// between the three tables, so the order is arbitrary.
//
// Every statement is idempotent, so the call is safe to re-run. It is a
// convenience for development, tests, and getting started: it adds what is
// missing and never alters what is already there, so it will not migrate an
// existing schema forward — a table whose columns or constraints differ is left
// exactly as it stands, with no error. Production deployments should own these
// tables in their own migrations and skip this call.
func (st *Store[C, M]) CreateSchema(ctx context.Context) error {
	for _, t := range []*pg.Table{st.s.Containers, st.s.Members, st.s.Roles} {
		if _, err := st.db.ExecExpr(ctx, pg.CreateTableIfNotExists(t)); err != nil {
			return err
		}
		for _, ddl := range compositeConstraintDDL(t) {
			if _, err := st.db.ExecExpr(ctx, ddl); err != nil {
				return err
			}
		}
	}
	return nil
}

// ── Containers ──────────────────────────────────────────────────────────────

// CreateContainer persists a container the engine has already stamped (id,
// owner, timestamps). A unique-constraint violation on one of your own fields
// (a slug, say) surfaces as scope.ErrConflict.
func (st *Store[C, M]) CreateContainer(ctx context.Context, c C) (C, error) {
	_, err := st.db.Insert(st.s.Containers).Row(st.s.containers.row(c)...).Exec(ctx)
	if err != nil {
		var zero C
		if errors.Is(err, pg.ErrUniqueViolation) {
			return zero, scope.ErrConflict
		}
		return zero, err
	}
	return c, nil
}

// FindContainer loads a container by id, mapping drops' ErrNoRows to
// scope.ErrContainerNotFound.
func (st *Store[C, M]) FindContainer(ctx context.Context, id string) (C, error) {
	var c C
	err := st.db.Select().From(st.s.Containers).
		Where(st.s.containers.eq("id", id)).
		One(ctx, &c)
	if err != nil {
		var zero C
		return zero, mapNoRows(err, scope.ErrContainerNotFound)
	}
	return c, nil
}

// UpdateContainerOwner reassigns owner_id and refreshes updated_at. This is the
// one timestamp the store stamps itself, since the engine passes no container
// value here; everything else is stamped upstream.
func (st *Store[C, M]) UpdateContainerOwner(ctx context.Context, id, newOwnerID string) error {
	res, err := st.db.Update(st.s.Containers).
		Set(st.s.containers.bind("owner_id", newOwnerID),
			st.s.containers.bind("updated_at", time.Now().UTC())).
		Where(st.s.containers.eq("id", id)).
		Exec(ctx)
	return affectedOrErr(res, err, scope.ErrContainerNotFound)
}

// ── Members ─────────────────────────────────────────────────────────────────

// AddMember persists a membership the engine has already stamped (joined_at),
// returning scope.ErrAlreadyMember when (container, user) is taken.
func (st *Store[C, M]) AddMember(ctx context.Context, m M) (M, error) {
	_, err := st.db.Insert(st.s.Members).Row(st.s.members.row(m)...).Exec(ctx)
	if err != nil {
		var zero M
		if errors.Is(err, pg.ErrUniqueViolation) {
			return zero, scope.ErrAlreadyMember
		}
		return zero, err
	}
	return m, nil
}

// FindMember loads one membership by composite key, mapping ErrNoRows to
// scope.ErrNotMember. This is the hot path: it runs on every permission check
// for a non-owner.
func (st *Store[C, M]) FindMember(ctx context.Context, containerID, userID string) (M, error) {
	var m M
	err := st.db.Select().From(st.s.Members).
		Where(st.s.members.eq("container_id", containerID), st.s.members.eq("user_id", userID)).
		One(ctx, &m)
	if err != nil {
		var zero M
		return zero, mapNoRows(err, scope.ErrNotMember)
	}
	return m, nil
}

// ListMembers returns every membership of the container. A container with no
// members yields an empty slice rather than an error — the engine has already
// established the caller's standing before calling in.
func (st *Store[C, M]) ListMembers(ctx context.Context, containerID string) ([]M, error) {
	var out []M
	if err := st.db.Select().From(st.s.Members).
		Where(st.s.members.eq("container_id", containerID)).
		All(ctx, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// ListUserStandings returns one standing per membership the user holds, across
// every container, in a single join: the membership supplies the container and
// role, the container its owner.
//
// This is the query behind Service.ContainersWith and therefore behind every
// per-action query guard, so it is deliberately one round trip rather than a
// lookup per container.
func (st *Store[C, M]) ListUserStandings(ctx context.Context, userID string) ([]scope.MemberStanding, error) {
	var out []scope.MemberStanding
	err := st.db.Select(
		st.s.members.col("container_id"),
		st.s.members.col("role_key"),
		st.s.containers.col("owner_id"),
	).
		From(st.s.Members).
		Join(st.s.Containers, pg.Eq(st.s.containers.col("id"), st.s.members.col("container_id"))).
		Where(st.s.members.eq("user_id", userID)).
		All(ctx, &out)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ListUserContainers returns the containers the user is a member of, joined
// through the membership table. A user with no memberships yields an empty
// slice, not an error.
func (st *Store[C, M]) ListUserContainers(ctx context.Context, userID string) ([]C, error) {
	cols := st.s.Containers.Columns()
	exprs := make([]drops.Expression, len(cols))
	for i, c := range cols {
		exprs[i] = c
	}

	var out []C
	err := st.db.Select(exprs...).
		From(st.s.Containers).
		Join(st.s.Members, pg.Eq(st.s.containers.col("id"), st.s.members.col("container_id"))).
		Where(st.s.members.eq("user_id", userID)).
		All(ctx, &out)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// UpdateMemberRole rewrites role_key, reporting scope.ErrNotMember when the
// UPDATE matched no row.
func (st *Store[C, M]) UpdateMemberRole(ctx context.Context, containerID, userID, roleKey string) error {
	res, err := st.db.Update(st.s.Members).
		Set(st.s.members.bind("role_key", roleKey)).
		Where(st.s.members.eq("container_id", containerID), st.s.members.eq("user_id", userID)).
		Exec(ctx)
	return affectedOrErr(res, err, scope.ErrNotMember)
}

// RemoveMember deletes the membership row, reporting scope.ErrNotMember when
// the DELETE matched no row.
func (st *Store[C, M]) RemoveMember(ctx context.Context, containerID, userID string) error {
	res, err := st.db.Delete(st.s.Members).
		Where(st.s.members.eq("container_id", containerID), st.s.members.eq("user_id", userID)).
		Exec(ctx)
	return affectedOrErr(res, err, scope.ErrNotMember)
}

// CountMembersWithRole runs a COUNT over the members table. It backs the
// ErrRoleInUse check in DeleteRole; running both inside one transaction is what
// makes that check race-free.
func (st *Store[C, M]) CountMembersWithRole(ctx context.Context, containerID, roleKey string) (int, error) {
	n, err := st.db.Select().From(st.s.Members).
		Where(st.s.members.eq("container_id", containerID), st.s.members.eq("role_key", roleKey)).
		Count(ctx)
	return int(n), err
}

// ── Custom roles ────────────────────────────────────────────────────────────

// CreateRole persists a custom role the engine has already stamped (id,
// created_at). A duplicate (container, key) surfaces as scope.ErrRoleKeyTaken.
func (st *Store[C, M]) CreateRole(ctx context.Context, r scope.RoleRecord) (scope.RoleRecord, error) {
	_, err := st.db.Insert(st.s.Roles).Row(st.s.roles.row(r)...).Exec(ctx)
	if err != nil {
		if errors.Is(err, pg.ErrUniqueViolation) {
			return scope.RoleRecord{}, scope.ErrRoleKeyTaken
		}
		return scope.RoleRecord{}, err
	}
	return r, nil
}

// FindRole loads one custom role by (container, key), mapping ErrNoRows to
// scope.ErrRoleNotFound. The permissions column is returned as opaque bytes for
// the engine to decode.
func (st *Store[C, M]) FindRole(ctx context.Context, containerID, key string) (scope.RoleRecord, error) {
	var r scope.RoleRecord
	err := st.db.Select().From(st.s.Roles).
		Where(st.s.roles.eq("container_id", containerID), st.s.roles.eq("key", key)).
		One(ctx, &r)
	if err != nil {
		return scope.RoleRecord{}, mapNoRows(err, scope.ErrRoleNotFound)
	}
	return r, nil
}

// ListRoles returns the container's custom roles. The code-defined defaults are
// not stored, so they never appear here — scope.Service.ListRoles prepends them.
func (st *Store[C, M]) ListRoles(ctx context.Context, containerID string) ([]scope.RoleRecord, error) {
	var out []scope.RoleRecord
	if err := st.db.Select().From(st.s.Roles).
		Where(st.s.roles.eq("container_id", containerID)).
		All(ctx, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// UpdateRole replaces a custom role's name and encoded permissions, reporting
// scope.ErrRoleNotFound when no row matched. The bytes are stored verbatim.
func (st *Store[C, M]) UpdateRole(ctx context.Context, containerID, key, name string, permissions []byte) error {
	res, err := st.db.Update(st.s.Roles).
		Set(st.s.roles.bind("name", name), st.s.roles.bind("permissions", permissions)).
		Where(st.s.roles.eq("container_id", containerID), st.s.roles.eq("key", key)).
		Exec(ctx)
	return affectedOrErr(res, err, scope.ErrRoleNotFound)
}

// DeleteRole removes a custom role, reporting scope.ErrRoleNotFound when no row
// matched. The engine has already verified no member holds it.
func (st *Store[C, M]) DeleteRole(ctx context.Context, containerID, key string) error {
	res, err := st.db.Delete(st.s.Roles).
		Where(st.s.roles.eq("container_id", containerID), st.s.roles.eq("key", key)).
		Exec(ctx)
	return affectedOrErr(res, err, scope.ErrRoleNotFound)
}

// ── Transaction ─────────────────────────────────────────────────────────────

// WithTx runs fn inside a real PostgreSQL transaction, handing it a Store bound
// to the transaction handle and sharing this store's schema. Returning an error
// from fn rolls back.
func (st *Store[C, M]) WithTx(ctx context.Context, fn func(scope.Store[C, M]) error) error {
	return st.db.InTx(ctx, func(txdb *pg.DB) error {
		return fn(&Store[C, M]{db: txdb, s: st.s})
	})
}

// ── helpers ─────────────────────────────────────────────────────────────────

// mapNoRows converts drops' ErrNoRows into a domain not-found sentinel.
func mapNoRows(err, notFound error) error {
	if errors.Is(err, pg.ErrNoRows) {
		return notFound
	}
	return err
}

// affectedOrErr returns notFound when the statement matched no rows, else the
// original error (or nil on success).
func affectedOrErr(res drops.Result, err, notFound error) error {
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return notFound
	}
	return nil
}
