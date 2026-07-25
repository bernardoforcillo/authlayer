package dropsstore

import (
	"context"
	"errors"
	"time"

	"github.com/bernardoforcillo/authlayer/org"
	"github.com/bernardoforcillo/authlayer/scope"
	"github.com/bernardoforcillo/drops"
	"github.com/bernardoforcillo/drops/pg"
)

// Store is a drops-backed org.Store (scope.Store[Organization, Member]). It is a
// pure persistence layer: the engine stamps ids, owners, and timestamps before
// calling in, so the store only writes and reads the values it is handed.
type Store struct {
	db *pg.DB
	s  *Schema
}

// New returns a Store over db, building a fresh [Schema]. Pass it to org.New:
//
//	st := dropsstore.New(pg.New(stdlib.New(sqlDB)))
//	svc := org.New(org.NewAccess(appStatements), st)
//
// Use [Store.Schema] to reach the tables (to build a guard, or to generate DDL).
func New(db *pg.DB) *Store { return &Store{db: db, s: NewSchema()} }

// Schema exposes the tables so callers can build query guards, join against
// memberships, or emit their own DDL.
func (st *Store) Schema() *Schema { return st.s }

// MembershipGuard returns a drops guard restricting a table's rows to the
// context subject's organizations, using this store's members table — the
// convenient form of org.MembershipGuard, with the junction and its two columns
// already filled in.
//
// resourceOrgCol is the organization-id column on the table being guarded:
//
//	projects.AuthorizeWith(st.MembershipGuard(projectsTbl.Col("organization_id")))
func (st *Store) MembershipGuard(resourceOrgCol *pg.Column) pg.Guard {
	return org.MembershipGuard(st.s.Members, st.s.memUser.Column, st.s.memOrg.Column, resourceOrgCol)
}

// CreateSchema issues CREATE TABLE IF NOT EXISTS for organizations,
// organization_members and organization_roles, in that order.
//
// It is a convenience for development, tests, and getting started. It creates
// tables but never alters them, so it will not migrate an existing schema
// forward — production deployments should own these tables in their own
// migrations and skip this call. [Store.Schema] exposes the table definitions
// if you want to generate that DDL instead.
func (st *Store) CreateSchema(ctx context.Context) error {
	for _, t := range []*pg.Table{st.s.Organizations, st.s.Members, st.s.Roles} {
		if _, err := st.db.ExecExpr(ctx, pg.CreateTableIfNotExists(t)); err != nil {
			return err
		}
	}
	return nil
}

// ── row structs (drop-tagged for scanning) ──────────────────────────────────

type orgRow struct {
	ID        string    `drop:"id"`
	Name      string    `drop:"name"`
	Slug      string    `drop:"slug"`
	OwnerID   string    `drop:"owner_id"`
	CreatedAt time.Time `drop:"created_at"`
	UpdatedAt time.Time `drop:"updated_at"`
}

func (r orgRow) toOrg() org.Organization {
	return org.Organization{
		ContainerBase: scope.ContainerBase{ID: r.ID, OwnerID: r.OwnerID, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt},
		Name:          r.Name,
		Slug:          r.Slug,
	}
}

type memberRow struct {
	OrganizationID string    `drop:"organization_id"`
	UserID         string    `drop:"user_id"`
	RoleKey        string    `drop:"role_key"`
	JoinedAt       time.Time `drop:"joined_at"`
}

func (r memberRow) toMember() org.Member {
	return org.Member{MemberBase: scope.MemberBase{ContainerID: r.OrganizationID, UserID: r.UserID, RoleKey: r.RoleKey, JoinedAt: r.JoinedAt}}
}

type roleRow struct {
	ID             string    `drop:"id"`
	OrganizationID string    `drop:"organization_id"`
	Key            string    `drop:"key"`
	Name           string    `drop:"name"`
	Permissions    []byte    `drop:"permissions"`
	CreatedAt      time.Time `drop:"created_at"`
}

func (r roleRow) toRecord() scope.RoleRecord {
	return scope.RoleRecord{ID: r.ID, ContainerID: r.OrganizationID, Key: r.Key, Name: r.Name, Permissions: r.Permissions, CreatedAt: r.CreatedAt}
}

// ── Containers (organizations) ──────────────────────────────────────────────

// CreateContainer persists an organization the engine has already stamped
// (id, owner, timestamps). A duplicate slug surfaces as org.ErrSlugTaken.
func (st *Store) CreateContainer(ctx context.Context, o org.Organization) (org.Organization, error) {
	_, err := st.db.Insert(st.s.Organizations).Row(
		st.s.orgID.Val(o.ID),
		st.s.orgName.Val(o.Name),
		st.s.orgSlug.Val(o.Slug),
		st.s.orgOwner.Val(o.OwnerID),
		st.s.orgCreated.Val(o.CreatedAt),
		st.s.orgUpdated.Val(o.UpdatedAt),
	).Exec(ctx)
	if err != nil {
		if errors.Is(err, pg.ErrUniqueViolation) {
			return org.Organization{}, org.ErrSlugTaken
		}
		return org.Organization{}, err
	}
	return o, nil
}

// FindContainer loads an organization by id, mapping drops' ErrNoRows to
// org.ErrOrgNotFound.
func (st *Store) FindContainer(ctx context.Context, id string) (org.Organization, error) {
	var r orgRow
	err := st.db.Select().From(st.s.Organizations).Where(st.s.orgID.Eq(id)).One(ctx, &r)
	if err != nil {
		return org.Organization{}, mapNoRows(err, org.ErrOrgNotFound)
	}
	return r.toOrg(), nil
}

// UpdateContainerOwner reassigns owner_id and refreshes updated_at. This is the
// one timestamp the store stamps itself, since the engine passes no container
// value here; everything else is stamped upstream.
func (st *Store) UpdateContainerOwner(ctx context.Context, id, newOwnerID string) error {
	res, err := st.db.Update(st.s.Organizations).
		Set(st.s.orgOwner.Val(newOwnerID), st.s.orgUpdated.Val(time.Now().UTC())).
		Where(st.s.orgID.Eq(id)).
		Exec(ctx)
	return affectedOrErr(res, err, org.ErrOrgNotFound)
}

// ── Members ─────────────────────────────────────────────────────────────────

// AddMember persists a membership the engine has already stamped (joined_at).
func (st *Store) AddMember(ctx context.Context, m org.Member) (org.Member, error) {
	_, err := st.db.Insert(st.s.Members).Row(
		st.s.memOrg.Val(m.ContainerID),
		st.s.memUser.Val(m.UserID),
		st.s.memRole.Val(m.RoleKey),
		st.s.memJoined.Val(m.JoinedAt),
	).Exec(ctx)
	if err != nil {
		if errors.Is(err, pg.ErrUniqueViolation) {
			return org.Member{}, org.ErrAlreadyMember
		}
		return org.Member{}, err
	}
	return m, nil
}

// FindMember loads one membership by composite key, mapping ErrNoRows to
// org.ErrNotMember.
func (st *Store) FindMember(ctx context.Context, orgID, userID string) (org.Member, error) {
	var r memberRow
	err := st.db.Select().From(st.s.Members).
		Where(st.s.memOrg.Eq(orgID), st.s.memUser.Eq(userID)).
		One(ctx, &r)
	if err != nil {
		return org.Member{}, mapNoRows(err, org.ErrNotMember)
	}
	return r.toMember(), nil
}

// ListMembers returns every membership of the organization. An organization
// with no members yields an empty slice rather than an error — the engine has
// already established the caller's standing before calling in.
func (st *Store) ListMembers(ctx context.Context, orgID string) ([]org.Member, error) {
	var rows []memberRow
	if err := st.db.Select().From(st.s.Members).Where(st.s.memOrg.Eq(orgID)).All(ctx, &rows); err != nil {
		return nil, err
	}
	out := make([]org.Member, len(rows))
	for i, r := range rows {
		out[i] = r.toMember()
	}
	return out, nil
}

// UpdateMemberRole rewrites role_key, reporting org.ErrNotMember when the
// UPDATE matched no row.
func (st *Store) UpdateMemberRole(ctx context.Context, orgID, userID, roleKey string) error {
	res, err := st.db.Update(st.s.Members).
		Set(st.s.memRole.Val(roleKey)).
		Where(st.s.memOrg.Eq(orgID), st.s.memUser.Eq(userID)).
		Exec(ctx)
	return affectedOrErr(res, err, org.ErrNotMember)
}

// RemoveMember deletes the membership row, reporting org.ErrNotMember when the
// DELETE matched no row.
func (st *Store) RemoveMember(ctx context.Context, orgID, userID string) error {
	res, err := st.db.Delete(st.s.Members).
		Where(st.s.memOrg.Eq(orgID), st.s.memUser.Eq(userID)).
		Exec(ctx)
	return affectedOrErr(res, err, org.ErrNotMember)
}

// CountMembersWithRole runs a COUNT over the members table. It backs the
// ErrRoleInUse check in DeleteRole; running both inside one transaction is what
// makes that check race-free.
func (st *Store) CountMembersWithRole(ctx context.Context, orgID, roleKey string) (int, error) {
	n, err := st.db.Select().From(st.s.Members).
		Where(st.s.memOrg.Eq(orgID), st.s.memRole.Eq(roleKey)).
		Count(ctx)
	return int(n), err
}

// ── Custom roles ────────────────────────────────────────────────────────────

// CreateRole persists a custom role the engine has already stamped (id,
// created_at). A duplicate (organization, key) surfaces as org.ErrRoleKeyTaken.
func (st *Store) CreateRole(ctx context.Context, r scope.RoleRecord) (scope.RoleRecord, error) {
	_, err := st.db.Insert(st.s.Roles).Row(
		st.s.roleID.Val(r.ID),
		st.s.roleOrg.Val(r.ContainerID),
		st.s.roleKey.Val(r.Key),
		st.s.roleName.Val(r.Name),
		st.s.rolePerms.Val(r.Permissions),
		st.s.roleCreated.Val(r.CreatedAt),
	).Exec(ctx)
	if err != nil {
		if errors.Is(err, pg.ErrUniqueViolation) {
			return scope.RoleRecord{}, org.ErrRoleKeyTaken
		}
		return scope.RoleRecord{}, err
	}
	return r, nil
}

// FindRole loads one custom role by (organization, key), mapping ErrNoRows to
// org.ErrRoleNotFound. The permissions column is returned as opaque bytes for
// the engine to decode.
func (st *Store) FindRole(ctx context.Context, orgID, key string) (scope.RoleRecord, error) {
	var r roleRow
	err := st.db.Select().From(st.s.Roles).
		Where(st.s.roleOrg.Eq(orgID), st.s.roleKey.Eq(key)).
		One(ctx, &r)
	if err != nil {
		return scope.RoleRecord{}, mapNoRows(err, org.ErrRoleNotFound)
	}
	return r.toRecord(), nil
}

// ListRoles returns the organization's custom roles. The code-defined defaults
// are not stored, so they never appear here — scope.Service.ListRoles prepends
// them.
func (st *Store) ListRoles(ctx context.Context, orgID string) ([]scope.RoleRecord, error) {
	var rows []roleRow
	if err := st.db.Select().From(st.s.Roles).Where(st.s.roleOrg.Eq(orgID)).All(ctx, &rows); err != nil {
		return nil, err
	}
	out := make([]scope.RoleRecord, len(rows))
	for i, r := range rows {
		out[i] = r.toRecord()
	}
	return out, nil
}

// UpdateRole replaces a custom role's name and encoded permissions, reporting
// org.ErrRoleNotFound when no row matched. The bytes are stored verbatim.
func (st *Store) UpdateRole(ctx context.Context, orgID, key, name string, permissions []byte) error {
	res, err := st.db.Update(st.s.Roles).
		Set(st.s.roleName.Val(name), st.s.rolePerms.Val(permissions)).
		Where(st.s.roleOrg.Eq(orgID), st.s.roleKey.Eq(key)).
		Exec(ctx)
	return affectedOrErr(res, err, org.ErrRoleNotFound)
}

// DeleteRole removes a custom role, reporting org.ErrRoleNotFound when no row
// matched. The engine has already verified no member holds it.
func (st *Store) DeleteRole(ctx context.Context, orgID, key string) error {
	res, err := st.db.Delete(st.s.Roles).
		Where(st.s.roleOrg.Eq(orgID), st.s.roleKey.Eq(key)).
		Exec(ctx)
	return affectedOrErr(res, err, org.ErrRoleNotFound)
}

// ── Transaction ─────────────────────────────────────────────────────────────

// WithTx runs fn inside a real PostgreSQL transaction, handing it a Store bound
// to the transaction handle and sharing this store's schema. Returning an error
// from fn rolls back.
func (st *Store) WithTx(ctx context.Context, fn func(org.Store) error) error {
	return st.db.InTx(ctx, func(txdb *pg.DB) error {
		return fn(&Store{db: txdb, s: st.s})
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
