package dropsstore

import (
	"strings"
	"testing"

	"github.com/bernardoforcillo/authlayer/org"
)

var (
	_ MigrationSource = (*Store[org.Organization, org.Member])(nil)
	_ MigrationSource = (*AuthStore)(nil)
	_ MigrationSource = (*InviteStore)(nil)
	_ MigrationSource = (*APIKeyStore)(nil)
	_ MigrationSource = (*IdentityStore)(nil)
	_ MigrationSource = (*CredentialStore)(nil)
	_ MigrationSource = (*MFAStore)(nil)
	_ MigrationSource = (*OAuthStore)(nil)
	_ MigrationSource = (*AuditStore)(nil)
	_ MigrationSource = (*AuditKeyStore)(nil)
	_ MigrationSource = (*ConsentStore)(nil)
)

// The chain is: tables first, then (when the store has post-baseline indexes)
// an index step that depends on it and is reversible; the table step is not.
func TestAuthMigrationsAreATableStepThenAReversibleIndexStep(t *testing.T) {
	ms := newAuthStore(&fakeDriver{}).Migrations()
	if len(ms) != 2 {
		t.Fatalf("got %d migrations, want 2", len(ms))
	}
	tables, idx := ms[0], ms[1]
	if tables.ID != "authlayer-users-001_tables" || idx.ID != "authlayer-users-002_indexes" {
		t.Fatalf("ids = %q, %q", tables.ID, idx.ID)
	}
	if tables.Branch != MigrationBranch || idx.Branch != MigrationBranch {
		t.Fatalf("branches = %q, %q, want %q", tables.Branch, idx.Branch, MigrationBranch)
	}
	if len(idx.Parents) != 1 || idx.Parents[0] != tables.ID {
		t.Fatalf("index step parents = %v, want [%s]", idx.Parents, tables.ID)
	}
	if tables.Down != nil {
		t.Fatal("the table step must be irreversible: dropping tables is data loss")
	}
	if idx.Down == nil {
		t.Fatal("the index step must be reversible")
	}
}

// 0.3.1's indexes belong to the table step; only the new ones to the second.
func TestMigrationTableStepLeavesPostBaselineIndexesToTheIndexStep(t *testing.T) {
	fd := &fakeDriver{}
	st := newAuthStore(fd)
	if err := st.Migrations()[0].Up(t.Context(), st.db); err != nil {
		t.Fatalf("Up: %v", err)
	}
	all := strings.Join(fd.execs, "\n")
	for _, want := range []string{"sessions_family_id_idx", "verifications_user_id_purpose_idx"} {
		if !strings.Contains(all, want) {
			t.Fatalf("table step never created baseline index %s:\n%s", want, all)
		}
	}
	for _, late := range []string{"sessions_user_id_idx", "sessions_expires_at_idx", "verifications_expires_at_idx"} {
		if strings.Contains(all, late) {
			t.Fatalf("table step created post-baseline index %s:\n%s", late, all)
		}
	}
}

// Two instances of one generic store type must not collide on IDs.
func TestMigrationIDsFollowCustomTableNames(t *testing.T) {
	a := newStore(&fakeDriver{}).Migrations()[0].ID
	b := New[org.Organization, org.Member](newStore(&fakeDriver{}).db,
		WithNames(Names{Containers: "teams", Members: "team_members", Roles: "team_roles"})).Migrations()[0].ID
	if a == b || b != "authlayer-teams-001_tables" {
		t.Fatalf("ids = %q, %q", a, b)
	}
}
