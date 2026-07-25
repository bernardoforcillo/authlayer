package dropsstore

import "testing"

func TestSchemaMembersHaveCompositePrimaryKey(t *testing.T) {
	s := NewSchema()

	pk := s.Members.CompositePrimaryKey()
	if len(pk) != 2 {
		t.Fatalf("members composite PK has %d columns, want 2", len(pk))
	}
	got := []string{pk[0].Name(), pk[1].Name()}
	want := []string{"organization_id", "user_id"}
	if got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("composite PK = %v, want %v", got, want)
	}
}

func TestSchemaTablesAndColumns(t *testing.T) {
	s := NewSchema()
	if s.Organizations.Name() != "organizations" ||
		s.Members.Name() != "organization_members" ||
		s.Roles.Name() != "organization_roles" {
		t.Fatalf("unexpected table names: %s %s %s",
			s.Organizations.Name(), s.Members.Name(), s.Roles.Name())
	}
	if s.Roles.Col("permissions") == nil {
		t.Fatal("roles table missing permissions column")
	}
}
