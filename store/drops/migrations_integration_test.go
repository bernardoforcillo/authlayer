//go:build integration

package dropsstore_test

import (
	"context"
	"database/sql"
	"strings"
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

// TestAuditAndConsentMigrationsMatchTheirSchemaLive: the audit and consent
// tables, now declared as pg.Tables, are created by the migrator with the same
// primary keys, partial indexes and guard triggers the stores' CreateSchema
// makes.
func TestAuditAndConsentMigrationsMatchTheirSchemaLive(t *testing.T) {
	sqlDB, db := openLiveDB(t)
	ctx := context.Background()
	const trackSchema = "authlayer_audit_migrations_test"
	audit := dropsstore.NewAuditStore(db)
	keys := dropsstore.NewAuditKeyStore(db)
	consent := dropsstore.NewConsentStore(db, "")
	cleanup := func() {
		if _, err := sqlDB.ExecContext(ctx, `DROP SCHEMA IF EXISTS `+trackSchema+` CASCADE`); err != nil {
			t.Fatal(err)
		}
		for _, d := range []interface{ DropSchema(context.Context) error }{audit, keys, consent} {
			if err := d.DropSchema(ctx); err != nil {
				t.Fatal(err)
			}
		}
	}
	cleanup()
	t.Cleanup(cleanup)

	m := pg.NewTreeMigrator(db).WithSchema(trackSchema)
	dropsstore.AddMigrations(m, audit, keys, consent)
	if err := m.Up(ctx); err != nil {
		t.Fatalf("Up: %v", err)
	}

	for table, want := range map[string][]string{
		"audit_events":    {"audit_events_pkey", "audit_events_seq_key", "audit_events_topic_time", "audit_events_open", "audit_events_container", "audit_events_resource"},
		"audit_seals":     {"audit_seals_pkey"},
		"consent_records": {"consent_records_pkey", "consent_records_current", "consent_records_subject"},
	} {
		got := indexNames(t, sqlDB, table)
		for _, n := range want {
			if !got[n] {
				t.Fatalf("%s lacks %s after the migrations; have %v", table, n, got)
			}
		}
	}
	// The partial predicate survived the move to drops.
	var def string
	if err := sqlDB.QueryRowContext(ctx, `SELECT indexdef FROM pg_indexes WHERE indexname = 'consent_records_current'`).Scan(&def); err != nil ||
		!strings.Contains(def, "UNIQUE") || !strings.Contains(def, "ended_at IS NULL") {
		t.Fatalf("consent_records_current = %q (err %v), want a UNIQUE partial index", def, err)
	}
	// The guards are still there: an event cannot be deleted outside retention.
	var triggers int
	if err := sqlDB.QueryRowContext(ctx, `SELECT count(*) FROM pg_trigger WHERE NOT tgisinternal AND tgrelid IN ('audit_events'::regclass, 'audit_seals'::regclass)`).Scan(&triggers); err != nil || triggers < 4 {
		t.Fatalf("audit guard triggers = %d (err %v), want at least 4", triggers, err)
	}
}
