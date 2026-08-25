// Package dropsstore implements authlayer's scope.Store persistence port on top
// of the drops PostgreSQL toolkit.
//
// It is generic over the container type C and the member type M, and derives
// its columns from their drop: struct tags, so a new scope — teams, projects,
// workspaces — needs only a set of table names, not a new store. Custom roles
// share one fixed table shape (scope.RoleRecord).
//
// Membership uses a composite primary key (container_id, user_id). The engine
// stamps ids and timestamps before the store writes them, so writes are plain
// INSERTs and reads scan into drop-tagged values.
package dropsstore

import (
	"github.com/bernardoforcillo/authlayer/scope"
	"github.com/bernardoforcillo/drops/pg"
)

// Names are the three table names a scope instance persists to. The zero value
// means the organization defaults.
type Names struct {
	Containers string // default "organizations"
	Members    string // default "organization_members"
	Roles      string // default "organization_roles"
}

func (n Names) withDefaults() Names {
	if n.Containers == "" {
		n.Containers = "organizations"
	}
	if n.Members == "" {
		n.Members = "organization_members"
	}
	if n.Roles == "" {
		n.Roles = "organization_roles"
	}
	return n
}

type settings struct {
	names       Names
	uuidUserIDs bool
}

// Option customizes a Schema or Store at construction.
type Option func(*settings)

// WithNames overrides the three table names, so a second scope instance (teams,
// projects) can share this store implementation.
//
//	dropsstore.New[team.Team, team.Member](db, dropsstore.WithNames(dropsstore.Names{
//	    Containers: "teams", Members: "team_members", Roles: "team_roles",
//	}))
func WithNames(n Names) Option { return func(s *settings) { s.names = n } }

// WithTextUserIDs types user_id columns as text rather than uuid.
//
// authlayer generates UUIDv7 ids for everything it owns, users included, so
// uuid is the default. Use this only when the RBAC half is used on its own
// against an existing user table whose ids are not UUIDs.
func WithTextUserIDs() Option { return func(s *settings) { s.uuidUserIDs = false } }

// Schema holds the three tables and their derived columns:
//
//	<containers>  id PK, owner_id, created_at, updated_at, + your fields
//	<members>     (container_id, user_id) PK, role_key, joined_at, + your fields
//	<roles>       id PK, container_id, key, name, permissions BYTEA, created_at,
//	              UNIQUE (container_id, key)
//
// The unique constraints are load-bearing, not decoration: they are what turn a
// concurrent double-insert into scope.ErrConflict, scope.ErrAlreadyMember or
// scope.ErrRoleKeyTaken instead of a duplicate row. Keep them if you manage
// these tables with your own migrations.
//
// permissions holds encoded grant names (see access.Permission.Encode), never
// bit indices, so the column survives changes to the application's statement
// set. No foreign keys to a users table are declared.
type Schema[C any, M any] struct {
	Containers *pg.Table
	Members    *pg.Table
	Roles      *pg.Table

	containers *colSet
	members    *colSet
	roles      *colSet
}

// NewSchema builds the schema for one scope instance. [New] calls it, so use it
// directly only when you need the table definitions without a Store — to
// generate DDL for a migration, for instance.
func NewSchema[C any, M any](opts ...Option) *Schema[C, M] {
	cfg := settings{uuidUserIDs: true}
	for _, o := range opts {
		o(&cfg)
	}
	names := cfg.names.withDefaults()

	var zeroC C
	var zeroM M

	s := &Schema[C, M]{
		Containers: pg.NewTable(names.Containers),
		Members:    pg.NewTable(names.Members),
		Roles:      pg.NewTable(names.Roles),
	}
	s.containers = newColSet(s.Containers, zeroC, cfg.uuidUserIDs)
	s.members = newColSet(s.Members, zeroM, cfg.uuidUserIDs)
	s.roles = newColSet(s.Roles, scope.RoleRecord{}, cfg.uuidUserIDs)

	s.Members.PrimaryKey(s.members.col("container_id"), s.members.col("user_id"))
	s.Roles.AddUnique(names.Roles+"_container_key",
		s.roles.col("container_id"), s.roles.col("key"))

	return s
}
