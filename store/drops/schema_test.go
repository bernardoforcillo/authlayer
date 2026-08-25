package dropsstore

import (
	"testing"

	"github.com/bernardoforcillo/authlayer/org"
	"github.com/bernardoforcillo/authlayer/scope"
)

func TestSchemaDefaultTableNames(t *testing.T) {
	s := NewSchema[org.Organization, org.Member]()
	if s.Containers.Name() != "organizations" ||
		s.Members.Name() != "organization_members" ||
		s.Roles.Name() != "organization_roles" {
		t.Fatalf("unexpected table names: %s %s %s",
			s.Containers.Name(), s.Members.Name(), s.Roles.Name())
	}
}

func TestSchemaHonoursCustomNames(t *testing.T) {
	s := NewSchema[org.Organization, org.Member](WithNames(Names{
		Containers: "teams", Members: "team_members", Roles: "team_roles",
	}))
	if s.Containers.Name() != "teams" || s.Members.Name() != "team_members" || s.Roles.Name() != "team_roles" {
		t.Fatalf("custom names not applied: %s %s %s",
			s.Containers.Name(), s.Members.Name(), s.Roles.Name())
	}
}

// The composite PK is load-bearing: it is what turns a concurrent double-insert
// into ErrAlreadyMember instead of a duplicate row.
func TestSchemaMembersHaveCompositePrimaryKey(t *testing.T) {
	s := NewSchema[org.Organization, org.Member]()
	pk := s.Members.CompositePrimaryKey()
	if len(pk) != 2 {
		t.Fatalf("members composite PK has %d columns, want 2", len(pk))
	}
	got := []string{pk[0].Name(), pk[1].Name()}
	want := []string{"container_id", "user_id"}
	if got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("composite PK = %v, want %v", got, want)
	}
}

func TestSchemaIDColumnsAreUUID(t *testing.T) {
	s := NewSchema[org.Organization, org.Member]()
	for tbl, col := range map[string]string{
		"containers": "id",
		"members":    "container_id",
		"roles":      "container_id",
	} {
		var got string
		switch tbl {
		case "containers":
			got = s.Containers.Col(col).Type().TypeSQL()
		case "members":
			got = s.Members.Col(col).Type().TypeSQL()
		case "roles":
			got = s.Roles.Col(col).Type().TypeSQL()
		}
		if got != "uuid" {
			t.Fatalf("%s.%s type = %q, want uuid", tbl, col, got)
		}
	}
}

func TestSchemaWithTextUserIDs(t *testing.T) {
	s := NewSchema[org.Organization, org.Member](WithTextUserIDs())
	if got := s.Members.Col("user_id").Type().TypeSQL(); got != "text" {
		t.Fatalf("user_id type = %q, want text under WithTextUserIDs", got)
	}
	if got := s.Members.Col("container_id").Type().TypeSQL(); got != "uuid" {
		t.Fatalf("WithTextUserIDs leaked into container_id: %q", got)
	}
}

// The UNIQUE (container_id, key) constraint is load-bearing: it is what turns
// a concurrent double-insert into ErrRoleKeyTaken instead of a duplicate row.
func TestSchemaRolesHaveUniqueContainerKey(t *testing.T) {
	s := NewSchema[org.Organization, org.Member]()
	if s.Roles.Col("permissions") == nil {
		t.Fatal("roles table missing permissions column")
	}
	if s.Roles.Col("key") == nil {
		t.Fatal("roles table missing key column")
	}

	uniques := s.Roles.CompositeUniques()
	cols, ok := uniques["organization_roles_container_key"]
	if !ok {
		t.Fatalf("roles table missing UNIQUE constraint %q; have %v",
			"organization_roles_container_key", uniques)
	}
	if len(cols) != 2 {
		t.Fatalf("roles unique constraint has %d columns, want 2", len(cols))
	}
	got := []string{cols[0].Name(), cols[1].Name()}
	want := []string{"container_id", "key"}
	if got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("roles unique constraint columns = %v, want %v", got, want)
	}
}

// The constraint name is derived from the configured Roles table name, so a
// second scope instance (teams, projects) gets its own, non-colliding
// constraint rather than reusing "organization_roles_container_key".
func TestSchemaRolesUniqueConstraintNameFollowsCustomNames(t *testing.T) {
	s := NewSchema[org.Organization, org.Member](WithNames(Names{
		Containers: "teams", Members: "team_members", Roles: "team_roles",
	}))
	uniques := s.Roles.CompositeUniques()
	cols, ok := uniques["team_roles_container_key"]
	if !ok {
		t.Fatalf("roles table missing UNIQUE constraint %q; have %v",
			"team_roles_container_key", uniques)
	}
	got := []string{cols[0].Name(), cols[1].Name()}
	want := []string{"container_id", "key"}
	if got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("roles unique constraint columns = %v, want %v", got, want)
	}
}

// A second scope instance must need only table names, not a new store.
func TestSchemaSupportsASecondContainerType(t *testing.T) {
	type Team struct {
		scope.ContainerBase
		Name     string `drop:"name"`
		ParentID string `drop:"parent_id"`
	}
	type TeamMember struct {
		scope.MemberBase
	}

	s := NewSchema[Team, TeamMember](WithNames(Names{
		Containers: "teams", Members: "team_members", Roles: "team_roles",
	}))
	if got := s.Containers.Col("parent_id").Type().TypeSQL(); got != "uuid" {
		t.Fatalf("parent_id type = %q, want uuid", got)
	}
	if s.Containers.Col("name") == nil {
		t.Fatal("teams table missing the custom name column")
	}
}
