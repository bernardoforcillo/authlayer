//go:build integration

package dropsstore_test

import (
	"context"
	"database/sql"
	"testing"

	"github.com/bernardoforcillo/drops/pg"

	"github.com/bernardoforcillo/authlayer/org"
	dropsstore "github.com/bernardoforcillo/authlayer/store/drops"
)

func indexNames(t *testing.T, sqlDB *sql.DB, table string) map[string]bool {
	t.Helper()
	rows, err := sqlDB.Query(`SELECT indexname FROM pg_indexes WHERE schemaname = current_schema() AND tablename = $1`, table)
	if err != nil {
		t.Fatalf("pg_indexes: %v", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]bool{}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatal(err)
		}
		out[n] = true
	}
	return out
}

// TestMigrationsBuildTheSameSchemaAsCreateSchemaLive runs the TreeMigrator on an
// empty database and requires the tables, constraints and every index
// CreateSchema would have made; then rolls the index step back and forward, and
// finally re-adopts a database CreateSchema already populated.
func TestMigrationsBuildTheSameSchemaAsCreateSchemaLive(t *testing.T) {
	sqlDB, db := openLiveDB(t)
	ctx := context.Background()
	const trackSchema = "authlayer_migrations_test"

	auth := dropsstore.NewAuthStore(db)
	rbac := dropsstore.New[org.Organization, org.Member](db)
	oauthSt := dropsstore.NewOAuthStore(db)
	invite := dropsstore.NewInviteStore(db)
	apikey := dropsstore.NewAPIKeyStore(db)

	cleanup := func() {
		for _, q := range []string{
			`DROP SCHEMA IF EXISTS ` + trackSchema + ` CASCADE`,
		} {
			if _, err := sqlDB.ExecContext(ctx, q); err != nil {
				t.Fatalf("%s: %v", q, err)
			}
		}
		dropAuthTables(t, db, auth)
		dropAll(t, db, rbac)
		for _, tbl := range []*pg.Table{
			oauthSt.Schema().RefreshTokens, oauthSt.Schema().DeviceAuthorizations, oauthSt.Schema().Codes,
			oauthSt.Schema().Grants, oauthSt.Schema().Clients,
			apikey.Schema().Keys, apikey.Schema().ServiceAccounts,
			invite.Schema().Links, invite.Schema().EmailInvites,
		} {
			if _, err := db.ExecExpr(ctx, pg.DropTableIfExists(tbl)); err != nil {
				t.Fatalf("drop %s: %v", tbl.Name(), err)
			}
		}
	}
	cleanup()
	t.Cleanup(cleanup)

	newMigrator := func() *pg.TreeMigrator {
		m := pg.NewTreeMigrator(db).WithSchema(trackSchema)
		dropsstore.AddMigrations(m, auth, rbac, oauthSt, invite, apikey)
		return m
	}

	if err := newMigrator().Up(ctx); err != nil {
		t.Fatalf("Up on an empty database: %v", err)
	}
	want := map[string][]string{
		"sessions":             {"sessions_family_id_idx", "sessions_user_id_idx", "sessions_expires_at_idx", "sessions_token_hash"},
		"verifications":        {"verifications_user_id_purpose_idx", "verifications_expires_at_idx"},
		"organization_members": {"organization_members_user_id_idx", "organization_members_pkey"},
		"oauth_refresh_tokens": {"oauth_refresh_tokens_family_id_idx", "oauth_refresh_tokens_expires_at_idx"},
		"api_keys":             {"api_keys_expires_at_idx", "api_keys_revoked_at_idx"},
	}
	check := func(label string) {
		t.Helper()
		for table, names := range want {
			got := indexNames(t, sqlDB, table)
			for _, n := range names {
				if !got[n] {
					t.Fatalf("%s: %s lacks %s; have %v", label, table, n, got)
				}
			}
		}
	}
	check("after Up")

	// Down of the index step drops exactly its indexes and keeps the baseline.
	if err := newMigrator().DownTo(ctx, "authlayer-users-001_tables"); err != nil {
		// authlayer-users is the auth store's first table.
		t.Fatalf("DownTo: %v", err)
	}
	got := indexNames(t, sqlDB, "sessions")
	if got["sessions_user_id_idx"] || got["sessions_expires_at_idx"] {
		t.Fatalf("index step Down left its indexes behind: %v", got)
	}
	if !got["sessions_family_id_idx"] || !got["sessions_token_hash"] {
		t.Fatalf("index step Down removed baseline objects: %v", got)
	}
	if err := newMigrator().Up(ctx); err != nil {
		t.Fatalf("Up after rollback: %v", err)
	}
	check("after re-Up")

	// Adoption: a database CreateSchema built is picked up without error.
	if _, err := sqlDB.ExecContext(ctx, `DROP SCHEMA `+trackSchema+` CASCADE`); err != nil {
		t.Fatal(err)
	}
	if err := auth.CreateSchema(ctx); err != nil {
		t.Fatalf("CreateSchema: %v", err)
	}
	if err := newMigrator().Up(ctx); err != nil {
		t.Fatalf("Up over a CreateSchema-built database: %v", err)
	}
	check("after adoption")
}
