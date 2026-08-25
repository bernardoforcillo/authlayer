//go:build integration

// Live end-to-end test against a real PostgreSQL. Run it with:
//
//	AUTHLAYER_TEST_DSN='postgres://user:pass@localhost:5432/db?sslmode=disable' \
//	    go test -tags integration ./store/drops/
//
// Without the tag and DSN it is not built, so the default `go test ./...` stays
// database-free.
package dropsstore_test

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"testing"

	"github.com/bernardoforcillo/authlayer/access"
	"github.com/bernardoforcillo/authlayer/org"
	dropsstore "github.com/bernardoforcillo/authlayer/store/drops"
	"github.com/bernardoforcillo/drops/pg"
	"github.com/bernardoforcillo/drops/stdlib"
	_ "github.com/jackc/pgx/v5/stdlib"
)

func TestDropsStoreIntegration(t *testing.T) {
	dsn := os.Getenv("AUTHLAYER_TEST_DSN")
	if dsn == "" {
		t.Skip("set AUTHLAYER_TEST_DSN to run the drops store integration test")
	}

	sqlDB, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	defer sqlDB.Close()

	db := pg.New(stdlib.New(sqlDB))
	st := dropsstore.New[org.Organization, org.Member](db)
	ctx := context.Background()

	dropAll(t, db, st)
	if err := st.CreateSchema(ctx); err != nil {
		t.Fatalf("CreateSchema: %v", err)
	}
	t.Cleanup(func() { dropAll(t, db, st) })

	svc := org.New(org.NewAccess(map[string][]access.Action{
		"project": {"create", "delete"},
	}), st)

	// Owner creates an org and adds an admin.
	alice := org.WithSubject(ctx, "alice")
	acme, err := svc.CreateOrganization(alice, "Acme", "acme")
	if err != nil {
		t.Fatalf("CreateOrganization: %v", err)
	}
	aliceOrg := org.WithOrg(alice, acme.ID)
	if _, err := svc.AddMember(aliceOrg, "bob", org.RoleAdmin); err != nil {
		t.Fatalf("AddMember: %v", err)
	}

	// The unique slug constraint surfaces as ErrSlugTaken.
	if _, err := svc.CreateOrganization(org.WithSubject(ctx, "x"), "Acme2", "acme"); !errors.Is(err, org.ErrSlugTaken) {
		t.Fatalf("duplicate slug err = %v, want ErrSlugTaken", err)
	}

	// Custom role round-trips through the roles table.
	if _, err := svc.CreateRole(aliceOrg, "editor", "Editor", map[string][]access.Action{
		"project": {"create"},
	}); err != nil {
		t.Fatalf("CreateRole: %v", err)
	}
	if err := svc.ChangeMemberRole(aliceOrg, "bob", "editor"); err != nil {
		t.Fatalf("ChangeMemberRole: %v", err)
	}

	bob := org.WithOrg(org.WithSubject(ctx, "bob"), acme.ID)
	if ok, _ := svc.Can(bob, "project", "create"); !ok {
		t.Fatal("editor bob should be allowed project:create")
	}
	if ok, _ := svc.Can(bob, org.ResourceOrganization, org.ActionDelete); ok {
		t.Fatal("editor bob must not be allowed organization:delete")
	}

	members, err := svc.ListMembers(aliceOrg)
	if err != nil || len(members) != 2 {
		t.Fatalf("ListMembers = %v (%d), %v", members, len(members), err)
	}
}

func dropAll(t *testing.T, db *pg.DB, st *dropsstore.Store[org.Organization, org.Member]) {
	t.Helper()
	s := st.Schema()
	for _, tbl := range []*pg.Table{s.Members, s.Roles, s.Containers} {
		if _, err := db.ExecExpr(context.Background(), pg.DropTableIfExists(tbl)); err != nil {
			t.Fatalf("drop %s: %v", tbl.Name(), err)
		}
	}
}
