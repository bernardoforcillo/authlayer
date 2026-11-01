//go:build integration

package dropsstore_test

import (
	"context"
	"strings"
	"testing"

	"github.com/bernardoforcillo/drops/pg"

	dropsstore "github.com/bernardoforcillo/authlayer/store/drops"
)

// TestCompositeForeignKeyRefusesAMismatchedContainerLive proves the 3NF guard on
// api_keys.container_id: a key naming an account in a different container is
// refused by the database, not only by the service.
func TestCompositeForeignKeyRefusesAMismatchedContainerLive(t *testing.T) {
	sqlDB, db := openLiveDB(t)
	ctx := context.Background()
	st := dropsstore.NewAPIKeyStore(db)
	drop := func() {
		for _, tbl := range []*pg.Table{st.Schema().Keys, st.Schema().ServiceAccounts} {
			if _, err := db.ExecExpr(ctx, pg.DropTableIfExists(tbl)); err != nil {
				t.Fatal(err)
			}
		}
	}
	drop()
	t.Cleanup(drop)
	if err := st.CreateSchema(ctx); err != nil {
		t.Fatal(err)
	}

	var valid bool
	if err := sqlDB.QueryRowContext(ctx,
		`SELECT convalidated FROM pg_constraint WHERE conname = 'api_keys_service_account_id_container_id_fkey'`).Scan(&valid); err != nil || !valid {
		t.Fatalf("on an empty table the foreign key must be validated: valid=%v err=%v", valid, err)
	}

	if _, err := sqlDB.ExecContext(ctx, `INSERT INTO service_accounts (id, container_id, name, description, created_by, created_at, updated_at)
		VALUES ('00000000-0000-0000-0000-00000000000a', '00000000-0000-0000-0000-0000000000c1', 'a', '', gen_random_uuid(), now(), now())`); err != nil {
		t.Fatalf("seed account: %v", err)
	}
	insert := func(container string) error {
		_, err := sqlDB.ExecContext(ctx, `INSERT INTO api_keys (id, service_account_id, container_id, name, prefix, token_hash, permissions, created_by, created_at)
			VALUES (gen_random_uuid(), '00000000-0000-0000-0000-00000000000a', $1, 'k', 'p', md5(random()::text), ''::bytea, gen_random_uuid(), now())`, container)
		return err
	}
	if err := insert("00000000-0000-0000-0000-0000000000c1"); err != nil {
		t.Fatalf("a key in its account's container must be accepted: %v", err)
	}
	err := insert("00000000-0000-0000-0000-0000000000c2")
	if err == nil || !strings.Contains(err.Error(), "api_keys_service_account_id_container_id_fkey") {
		t.Fatalf("a key in a different container than its account must be refused by the composite foreign key, got %v", err)
	}
}

// TestRelationsMigrationValidatesStrictlyLive: the 003 step fails, naming the
// constraint, when existing rows already disagree with their parent, and
// succeeds once they are fixed.
func TestRelationsMigrationValidatesStrictlyLive(t *testing.T) {
	sqlDB, db := openLiveDB(t)
	ctx := context.Background()
	const trackSchema = "authlayer_relations_test"
	st := dropsstore.NewAPIKeyStore(db)
	cleanup := func() {
		if _, err := sqlDB.ExecContext(ctx, `DROP SCHEMA IF EXISTS `+trackSchema+` CASCADE`); err != nil {
			t.Fatal(err)
		}
		for _, tbl := range []*pg.Table{st.Schema().Keys, st.Schema().ServiceAccounts} {
			if _, err := db.ExecExpr(ctx, pg.DropTableIfExists(tbl)); err != nil {
				t.Fatal(err)
			}
		}
	}
	cleanup()
	t.Cleanup(cleanup)

	m := pg.NewTreeMigrator(db).WithSchema(trackSchema)
	dropsstore.AddMigrations(m, st)
	// A database from before the constraint: tables and indexes only.
	if err := m.UpTo(ctx, "authlayer-service_accounts-002_indexes"); err != nil {
		t.Fatalf("UpTo 002: %v", err)
	}
	if _, err := sqlDB.ExecContext(ctx, `INSERT INTO service_accounts (id, container_id, name, description, created_by, created_at, updated_at)
		VALUES ('00000000-0000-0000-0000-00000000000a', '00000000-0000-0000-0000-0000000000c1', 'a', '', gen_random_uuid(), now(), now())`); err != nil {
		t.Fatal(err)
	}
	if _, err := sqlDB.ExecContext(ctx, `INSERT INTO api_keys (id, service_account_id, container_id, name, prefix, token_hash, permissions, created_by, created_at)
		VALUES ('00000000-0000-0000-0000-0000000000b1', '00000000-0000-0000-0000-00000000000a', '00000000-0000-0000-0000-0000000000c2', 'k', 'p', 'h', ''::bytea, gen_random_uuid(), now())`); err != nil {
		t.Fatal(err)
	}

	err := m.Up(ctx)
	if err == nil || !strings.Contains(err.Error(), "api_keys_service_account_id_container_id_fkey") {
		t.Fatalf("Up over a disagreeing row must fail naming the constraint, got %v", err)
	}
	if _, err := sqlDB.ExecContext(ctx, `DELETE FROM api_keys`); err != nil {
		t.Fatal(err)
	}
	if err := m.Up(ctx); err != nil {
		t.Fatalf("Up after fixing the data: %v", err)
	}
	var valid bool
	if err := sqlDB.QueryRowContext(ctx,
		`SELECT convalidated FROM pg_constraint WHERE conname = 'api_keys_service_account_id_container_id_fkey'`).Scan(&valid); err != nil || !valid {
		t.Fatalf("constraint not validated after the migration: valid=%v err=%v", valid, err)
	}
	// Down removes the key and its target, and leaves the tables.
	if err := m.DownTo(ctx, "authlayer-service_accounts-002_indexes"); err != nil {
		t.Fatalf("DownTo 002: %v", err)
	}
	var n int
	if err := sqlDB.QueryRowContext(ctx, `SELECT count(*) FROM pg_constraint WHERE conname IN ('api_keys_service_account_id_container_id_fkey','service_accounts_id_container_id_key')`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("Down left %d constraint(s) behind (err %v)", n, err)
	}
}
