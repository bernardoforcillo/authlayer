package dropsstore

import (
	"testing"

	"github.com/bernardoforcillo/authlayer/org"
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

func TestSchemaRolesHaveUniqueContainerKey(t *testing.T) {
	s := NewSchema[org.Organization, org.Member]()
	if s.Roles.Col("permissions") == nil {
		t.Fatal("roles table missing permissions column")
	}
	if s.Roles.Col("key") == nil {
		t.Fatal("roles table missing key column")
	}
}
