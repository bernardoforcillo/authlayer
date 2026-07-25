// Package dropsstore implements the org.Store persistence port on top of the
// drops PostgreSQL toolkit. Organizations, members, and custom roles are stored
// in three tables; membership uses a composite primary key (organization_id,
// user_id). The engine stamps ids and timestamps before the store writes them,
// so writes are plain INSERTs (no RETURNING) and reads scan into drop-tagged
// row structs.
package dropsstore

import (
	"time"

	"github.com/bernardoforcillo/drops/pg"
)

// Schema holds the tables and typed columns the store reads and writes:
//
//	organizations         id PK, name, slug UNIQUE, owner_id, created_at, updated_at
//	organization_members  (organization_id, user_id) PK, role_key, joined_at
//	organization_roles    id PK, organization_id, key, name, permissions BYTEA,
//	                      created_at, UNIQUE (organization_id, key)
//
// The unique constraints are load-bearing, not decoration: they are what turn a
// concurrent double-insert into org.ErrSlugTaken, org.ErrAlreadyMember, or
// org.ErrRoleKeyTaken instead of a duplicate row. Keep them if you manage these
// tables with your own migrations.
//
// permissions holds encoded grant names (see access.Permission.Encode), never
// bit indices, so the column survives changes to the application's statement
// set. No foreign keys to a users table are declared — authlayer treats user
// ids as opaque and does not own that table.
//
// Only the three *pg.Table fields are exported; the typed columns stay private
// so the schema can evolve. Reach for the tables when building guards or DDL.
type Schema struct {
	Organizations *pg.Table
	Members       *pg.Table
	Roles         *pg.Table

	orgID      *pg.Col[string]
	orgName    *pg.Col[string]
	orgSlug    *pg.Col[string]
	orgOwner   *pg.Col[string]
	orgCreated *pg.Col[time.Time]
	orgUpdated *pg.Col[time.Time]

	memOrg    *pg.Col[string]
	memUser   *pg.Col[string]
	memRole   *pg.Col[string]
	memJoined *pg.Col[time.Time]

	roleID      *pg.Col[string]
	roleOrg     *pg.Col[string]
	roleKey     *pg.Col[string]
	roleName    *pg.Col[string]
	rolePerms   *pg.Col[[]byte]
	roleCreated *pg.Col[time.Time]
}

// NewSchema builds the authlayer organization schema. [New] calls it, so use
// it directly only when you need the table definitions without a Store — to
// generate DDL for a migration, for instance.
func NewSchema() *Schema {
	s := &Schema{}

	orgs := pg.NewTable("organizations")
	s.Organizations = orgs
	s.orgID = pg.Add(orgs, pg.Text("id").PrimaryKey())
	s.orgName = pg.Add(orgs, pg.Text("name").NotNull())
	s.orgSlug = pg.Add(orgs, pg.Text("slug").NotNull().Unique())
	s.orgOwner = pg.Add(orgs, pg.Text("owner_id").NotNull())
	s.orgCreated = pg.Add(orgs, pg.Timestamp("created_at", true).NotNull())
	s.orgUpdated = pg.Add(orgs, pg.Timestamp("updated_at", true).NotNull())

	members := pg.NewTable("organization_members")
	s.Members = members
	s.memOrg = pg.Add(members, pg.Text("organization_id").NotNull())
	s.memUser = pg.Add(members, pg.Text("user_id").NotNull())
	s.memRole = pg.Add(members, pg.Text("role_key").NotNull())
	s.memJoined = pg.Add(members, pg.Timestamp("joined_at", true).NotNull())
	members.PrimaryKey(s.memOrg, s.memUser)

	roles := pg.NewTable("organization_roles")
	s.Roles = roles
	s.roleID = pg.Add(roles, pg.Text("id").PrimaryKey())
	s.roleOrg = pg.Add(roles, pg.Text("organization_id").NotNull())
	s.roleKey = pg.Add(roles, pg.Text("key").NotNull())
	s.roleName = pg.Add(roles, pg.Text("name").NotNull())
	s.rolePerms = pg.Add(roles, pg.Bytea("permissions").NotNull())
	s.roleCreated = pg.Add(roles, pg.Timestamp("created_at", true).NotNull())
	roles.AddUnique("organization_roles_org_key", s.roleOrg, s.roleKey)

	return s
}
