package dropsstore

import (
	"testing"

	"github.com/bernardoforcillo/authlayer/org"
)

// One IDOption value is accepted by every constructor and retypes the same
// columns the store's own legacy option does.
func TestSharedIDOptionsMatchTheLegacyPerStoreOptions(t *testing.T) {
	lib := TextLibraryIDs()
	usr := TextUserIDs()

	// RBAC: both flags apply independently.
	s := NewSchema[org.Organization, org.Member](lib, usr)
	if got := s.Containers.Col("id").Type().TypeSQL(); got != "text" {
		t.Fatalf("containers.id = %s, want text", got)
	}
	if got := s.Containers.Col("owner_id").Type().TypeSQL(); got != "text" {
		t.Fatalf("containers.owner_id = %s, want text", got)
	}
	// Library alone leaves user ids uuid.
	s = NewSchema[org.Organization, org.Member](lib)
	if got := s.Containers.Col("owner_id").Type().TypeSQL(); got != "uuid" {
		t.Fatalf("owner_id with only TextLibraryIDs = %s, want uuid", got)
	}

	// Auth owns the users table: TextLibraryIDs retypes user ids too,
	// TextUserIDs alone does nothing.
	a := NewAuthSchema(lib)
	if got := a.Sessions.Col("user_id").Type().TypeSQL(); got != "text" {
		t.Fatalf("sessions.user_id with TextLibraryIDs = %s, want text", got)
	}
	a = NewAuthSchema(usr)
	if got := a.Users.Col("id").Type().TypeSQL(); got != "uuid" {
		t.Fatalf("users.id with only TextUserIDs = %s, want uuid (ignored)", got)
	}
	legacy := NewAuthSchema(WithAuthTextLibraryIDs())
	shared := NewAuthSchema(lib)
	for _, c := range legacy.Sessions.Columns() {
		if got := shared.Sessions.Col(c.Name()).Type().TypeSQL(); got != c.Type().TypeSQL() {
			t.Fatalf("sessions.%s: shared %s vs legacy %s", c.Name(), got, c.Type().TypeSQL())
		}
	}

	// Every other constructor compiles with the shared options and honours them.
	if got := NewInviteSchema(lib, usr).EmailInvites.Col("invited_by").Type().TypeSQL(); got != "text" {
		t.Fatalf("email invites.invited_by = %s, want text", got)
	}
	if got := NewAPIKeySchema(lib, usr).Keys.Col("created_by").Type().TypeSQL(); got != "text" {
		t.Fatalf("api_keys.created_by = %s, want text", got)
	}
	if got := NewOAuthSchema(lib, usr).Grants.Col("user_id").Type().TypeSQL(); got != "text" {
		t.Fatalf("oauth_grants.user_id = %s, want text", got)
	}
	if got := NewIdentitySchema(lib).Identities.Col("user_id").Type().TypeSQL(); got != "text" {
		t.Fatalf("identities.user_id = %s, want text", got)
	}
	if got := NewCredentialSchema(lib).Credentials.Col("user_id").Type().TypeSQL(); got != "text" {
		t.Fatalf("credentials.user_id = %s, want text", got)
	}
	if got := NewMFASchema(lib).Factors.Col("user_id").Type().TypeSQL(); got != "text" {
		t.Fatalf("mfa_factors.user_id = %s, want text", got)
	}
	var _ AuditOption = lib
	if cfg := newAuditSettings([]AuditOption{lib}); !cfg.textIDs {
		t.Fatal("TextLibraryIDs did not retype the audit event id")
	}
}
