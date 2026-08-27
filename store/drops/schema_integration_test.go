//go:build integration

package dropsstore_test

import (
	"context"
	"database/sql"
	"os"
	"testing"

	"github.com/bernardoforcillo/authlayer/org"
	dropsstore "github.com/bernardoforcillo/authlayer/store/drops"
	"github.com/bernardoforcillo/drops/pg"
	"github.com/bernardoforcillo/drops/stdlib"
	_ "github.com/jackc/pgx/v5/stdlib"
)

// Proves CreateSchema's plpgsql DO block actually lands the composite
// constraints on a real server, not merely that it parses.
func TestCreateSchemaLandsConstraintsOnRealPostgres(t *testing.T) {
	dsn := os.Getenv("AUTHLAYER_TEST_DSN")
	if dsn == "" {
		t.Skip("no DSN")
	}
	sqlDB, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })

	db := pg.New(stdlib.New(sqlDB))
	st := dropsstore.New[org.Organization, org.Member](db)
	ctx := context.Background()

	for _, tbl := range []string{"organization_roles", "organization_members", "organizations"} {
		if _, err := sqlDB.ExecContext(ctx, "DROP TABLE IF EXISTS "+tbl+" CASCADE"); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.CreateSchema(ctx); err != nil {
		t.Fatalf("CreateSchema: %v", err)
	}
	// Re-run: CreateSchema must stay idempotent on a real server.
	if err := st.CreateSchema(ctx); err != nil {
		t.Fatalf("CreateSchema (second run): %v", err)
	}
	t.Cleanup(func() {
		for _, tbl := range []string{"organization_roles", "organization_members", "organizations"} {
			_, _ = sqlDB.ExecContext(context.Background(), "DROP TABLE IF EXISTS "+tbl+" CASCADE")
		}
	})

	rows, err := sqlDB.QueryContext(ctx, `
		SELECT c.conname, c.contype, pg_get_constraintdef(c.oid)
		FROM pg_constraint c JOIN pg_class t ON t.oid = c.conrelid
		WHERE t.relname IN ('organizations','organization_members','organization_roles')
		ORDER BY t.relname, c.conname`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	found := map[string]string{}
	for rows.Next() {
		var name, typ, def string
		if err := rows.Scan(&name, &typ, &def); err != nil {
			t.Fatal(err)
		}
		t.Logf("%-42s %s  %s", name, typ, def)
		found[name] = def
	}

	if def, ok := found["organization_members_pkey"]; !ok {
		t.Error("MISSING: composite PK on organization_members")
	} else {
		t.Logf("composite PK present: %s", def)
	}
	if def, ok := found["organization_roles_container_key"]; !ok {
		t.Error("MISSING: UNIQUE(container_id, key) on organization_roles")
	} else {
		t.Logf("roles UNIQUE present: %s", def)
	}

	// And the uuid typing the whole of Plan 1 was about.
	var idType, userIDType string
	if err := sqlDB.QueryRowContext(ctx, `
		SELECT (SELECT data_type FROM information_schema.columns
		         WHERE table_name='organizations' AND column_name='id'),
		       (SELECT data_type FROM information_schema.columns
		         WHERE table_name='organization_members' AND column_name='user_id')`).
		Scan(&idType, &userIDType); err != nil {
		t.Fatal(err)
	}
	t.Logf("organizations.id = %s ; organization_members.user_id = %s", idType, userIDType)
	if idType != "uuid" || userIDType != "uuid" {
		t.Errorf("expected uuid columns, got id=%s user_id=%s", idType, userIDType)
	}
}
