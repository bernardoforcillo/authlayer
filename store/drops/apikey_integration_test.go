//go:build integration

// Live end-to-end tests for the API-key store against a real PostgreSQL. Run
// with:
//
//	AUTHLAYER_TEST_DSN='postgres://user:pass@localhost:5432/db?sslmode=disable' \
//	    go test -tags integration ./store/drops/
//
// Without the tag and DSN it is not built, so the default `go test ./...`
// stays database-free. The apikey.Store contract itself is the exported
// authlayer/apikey/apikeytest suite, run here against a live server exactly
// as store/memory runs it in-process; what this file adds is what stays
// BACKEND-SPECIFIC — the DDL the suite cannot see, the error class
// PostgreSQL answers a rejected duplicate hash with, and one end-to-end pass
// through the apikey.Service over the drops RBAC store.
package dropsstore_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/bernardoforcillo/drops/pg"

	"github.com/bernardoforcillo/authlayer/access"
	"github.com/bernardoforcillo/authlayer/apikey"
	"github.com/bernardoforcillo/authlayer/apikey/apikeytest"
	"github.com/bernardoforcillo/authlayer/internal/uid"
	"github.com/bernardoforcillo/authlayer/org"
	dropsstore "github.com/bernardoforcillo/authlayer/store/drops"
)

func dropAPIKeyTables(t *testing.T, db *pg.DB, st *dropsstore.APIKeyStore) {
	t.Helper()
	s := st.Schema()
	// Keys first: the foreign key would refuse dropping the accounts table
	// while the keys table still references it.
	for _, tbl := range []*pg.Table{s.Keys, s.ServiceAccounts} {
		if _, err := db.ExecExpr(context.Background(), pg.DropTableIfExists(tbl)); err != nil {
			t.Fatalf("drop %s: %v", tbl.Name(), err)
		}
	}
}

// newLiveAPIKeyStore opens a connection from AUTHLAYER_TEST_DSN, builds a
// fresh APIKeyStore and drops/recreates both tables so each test starts from
// an empty schema.
func newLiveAPIKeyStore(t *testing.T) (*sql.DB, *dropsstore.APIKeyStore) {
	t.Helper()
	sqlDB, db := openLiveDB(t)
	st := dropsstore.NewAPIKeyStore(db)
	ctx := context.Background()
	dropAPIKeyTables(t, db, st)
	if err := st.CreateSchema(ctx); err != nil {
		t.Fatalf("CreateSchema: %v", err)
	}
	t.Cleanup(func() { dropAPIKeyTables(t, db, st) })
	return sqlDB, st
}

// TestAPIKeyStoreSatisfiesTheStoreContractLive runs the exported apikeytest
// suite against a real server: every documented obligation of apikey.Store,
// the token-hash uniqueness, the atomic cascade and the orphan refusal
// included — the three properties only a real UNIQUE, a real FOREIGN KEY and
// a real transaction can demonstrate. The pool is warmed to
// apikeytest.RaceGoroutines connections before anything runs, for the reason
// TestInviteStoreSatisfiesTheStoreContractLive gives, and each check gets an
// empty schema through TRUNCATE rather than a drop-and-recreate.
func TestAPIKeyStoreSatisfiesTheStoreContractLive(t *testing.T) {
	sqlDB, db := openLiveDB(t)
	sqlDB.SetMaxOpenConns(apikeytest.RaceGoroutines)
	sqlDB.SetMaxIdleConns(apikeytest.RaceGoroutines)
	warmPool(t, sqlDB, apikeytest.RaceGoroutines)

	st := dropsstore.NewAPIKeyStore(db)
	ctx := context.Background()
	dropAPIKeyTables(t, db, st)
	if err := st.CreateSchema(ctx); err != nil {
		t.Fatalf("CreateSchema: %v", err)
	}
	t.Cleanup(func() { dropAPIKeyTables(t, db, st) })

	s := st.Schema()
	truncate := fmt.Sprintf("TRUNCATE %s, %s", s.Keys.Name(), s.ServiceAccounts.Name())
	apikeytest.RunStoreContract(t, func(t *testing.T) apikey.Store {
		if _, err := sqlDB.ExecContext(ctx, truncate); err != nil {
			t.Fatalf("%s: %v", truncate, err)
		}
		return st
	})
}

// TestAPIKeyStoreRefusalsSurfaceTheDriversErrorsLive covers what the
// port-level suite deliberately does not: WHICH error each refusal comes back
// as. A duplicate token hash is the driver's own pg.ErrUniqueViolation,
// unwrapped; a duplicate id is apikey.ErrIDTaken wrapping it; a key naming no
// account is apikey.ErrServiceAccountNotFound wrapping the driver's
// foreign-key violation — the constraint doing the port's work.
func TestAPIKeyStoreRefusalsSurfaceTheDriversErrorsLive(t *testing.T) {
	_, st := newLiveAPIKeyStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	mkAccount := func() apikey.ServiceAccount {
		return apikey.ServiceAccount{ID: uid.NewV7(), ContainerID: uid.NewV7(), Name: "ci", CreatedBy: uid.NewV7(), CreatedAt: now, UpdatedAt: now}
	}
	mkKey := func(sa apikey.ServiceAccount, hash string) apikey.Key {
		return apikey.Key{ID: uid.NewV7(), ServiceAccountID: sa.ID, ContainerID: sa.ContainerID, Name: "k", Prefix: "sk_ab12cd34", TokenHash: hash, CreatedBy: uid.NewV7(), CreatedAt: now}
	}
	a, b := mkAccount(), mkAccount()
	for _, sa := range []apikey.ServiceAccount{a, b} {
		if _, err := st.CreateServiceAccount(ctx, sa); err != nil {
			t.Fatalf("CreateServiceAccount: %v", err)
		}
	}
	dupAccount := mkAccount()
	dupAccount.ID = a.ID
	if _, err := st.CreateServiceAccount(ctx, dupAccount); !errors.Is(err, apikey.ErrIDTaken) || !errors.Is(err, pg.ErrUniqueViolation) {
		t.Fatalf("duplicate account id err = %v, want ErrIDTaken wrapping pg.ErrUniqueViolation", err)
	}

	first := mkKey(a, "hash-abc")
	if _, err := st.CreateKey(ctx, first); err != nil {
		t.Fatalf("CreateKey(first): %v", err)
	}
	// UNIQUE (token_hash): another account, same hash.
	if _, err := st.CreateKey(ctx, mkKey(b, "hash-abc")); !errors.Is(err, pg.ErrUniqueViolation) || errors.Is(err, apikey.ErrIDTaken) {
		t.Fatalf("duplicate token_hash err = %v, want pg.ErrUniqueViolation unwrapped", err)
	}
	// PRIMARY KEY: same id, its own hash.
	dupKey := mkKey(b, "hash-other")
	dupKey.ID = first.ID
	if _, err := st.CreateKey(ctx, dupKey); !errors.Is(err, apikey.ErrIDTaken) || !errors.Is(err, pg.ErrUniqueViolation) {
		t.Fatalf("duplicate key id err = %v, want ErrIDTaken wrapping pg.ErrUniqueViolation", err)
	}
	// FOREIGN KEY: an account that does not exist.
	if _, err := st.CreateKey(ctx, mkKey(mkAccount(), "hash-orphan")); !errors.Is(err, apikey.ErrServiceAccountNotFound) || !errors.Is(err, pg.ErrForeignKeyViolation) {
		t.Fatalf("orphan key err = %v, want ErrServiceAccountNotFound wrapping pg.ErrForeignKeyViolation", err)
	}
}

// TestAPIKeyStoreCreateSchemaLandsConstraintsOnRealPostgres reads the
// constraints and indexes back out of the catalog rather than inferring them
// from errors: the primary keys, the UNIQUE on token_hash, the cascading
// foreign key, and the three indexes. Also re-runs CreateSchema to confirm it
// stays idempotent against a real server.
func TestAPIKeyStoreCreateSchemaLandsConstraintsOnRealPostgres(t *testing.T) {
	sqlDB, st := newLiveAPIKeyStore(t)
	ctx := context.Background()
	if err := st.CreateSchema(ctx); err != nil {
		t.Fatalf("CreateSchema (second run): %v", err)
	}

	rows, err := sqlDB.QueryContext(ctx, `
		SELECT c.conname, pg_get_constraintdef(c.oid)
		FROM pg_constraint c JOIN pg_class t ON t.oid = c.conrelid
		WHERE t.relname IN ('service_accounts','api_keys')
		ORDER BY t.relname, c.conname`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	found := map[string]string{}
	for rows.Next() {
		var name, def string
		if err := rows.Scan(&name, &def); err != nil {
			t.Fatal(err)
		}
		t.Logf("%-40s %s", name, def)
		found[name] = def
	}
	for _, want := range []struct{ name, def string }{
		{"service_accounts_pkey", "PRIMARY KEY (id)"},
		{"api_keys_pkey", "PRIMARY KEY (id)"},
		{"api_keys_token_hash_key", "UNIQUE (token_hash)"},
		{"api_keys_service_account_id_fkey", "FOREIGN KEY (service_account_id) REFERENCES service_accounts(id) ON DELETE CASCADE"},
	} {
		def, ok := found[want.name]
		if !ok {
			t.Errorf("MISSING: constraint %s", want.name)
			continue
		}
		if def != want.def {
			t.Errorf("%s definition = %q, want %q", want.name, def, want.def)
		}
	}

	idx, err := sqlDB.QueryContext(ctx, `SELECT indexname FROM pg_indexes WHERE tablename IN ('service_accounts','api_keys')`)
	if err != nil {
		t.Fatal(err)
	}
	defer idx.Close()
	indexes := map[string]bool{}
	for idx.Next() {
		var name string
		if err := idx.Scan(&name); err != nil {
			t.Fatal(err)
		}
		indexes[name] = true
	}
	for _, want := range []string{"service_accounts_container_id_idx", "api_keys_service_account_id_idx", "api_keys_container_id_idx"} {
		if !indexes[want] {
			t.Errorf("MISSING: index %s (have %v)", want, indexes)
		}
	}
}

// TestAPIKeyServiceOverDropsLive is the one end-to-end pass: an organization
// in the drops RBAC store, a service account created through apikey.Service
// (record here, membership there), a restricted key, an authentication, a
// Can under the cap, a revocation, and the cascade delete — every step
// against the live server.
func TestAPIKeyServiceOverDropsLive(t *testing.T) {
	_, db := openLiveDB(t)
	ctx := context.Background()
	rbac := dropsstore.New[org.Organization, org.Member](db)
	dropAll(t, db, rbac)
	if err := rbac.CreateSchema(ctx); err != nil {
		t.Fatalf("CreateSchema (rbac): %v", err)
	}
	t.Cleanup(func() { dropAll(t, db, rbac) })
	keys := dropsstore.NewAPIKeyStore(db)
	dropAPIKeyTables(t, db, keys)
	if err := keys.CreateSchema(ctx); err != nil {
		t.Fatalf("CreateSchema (apikey): %v", err)
	}
	t.Cleanup(func() { dropAPIKeyTables(t, db, keys) })

	orgSvc := org.New(org.NewAccess(map[string][]access.Action{"project": {"read", "write"}}), rbac)
	svc := apikey.New(orgSvc.Service, keys)

	owner := org.WithSubject(ctx, uid.NewV7())
	acme, err := orgSvc.CreateOrganization(owner, "Acme", "acme")
	if err != nil {
		t.Fatalf("CreateOrganization: %v", err)
	}
	owner = org.WithOrg(owner, acme.ID)

	sa, err := svc.CreateServiceAccount(owner, "ci", "deploys", org.RoleAdmin)
	if err != nil {
		t.Fatalf("CreateServiceAccount: %v", err)
	}
	k, plain, err := svc.CreateKey(owner, sa.ID, "github", apikey.WithPermissions(map[string][]access.Action{"project": {"read"}}))
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	p, err := svc.Authenticate(ctx, plain)
	if err != nil || p.ID != sa.ID || p.KeyID != k.ID || p.Permissions == nil {
		t.Fatalf("Authenticate = %+v, %v", p, err)
	}
	pctx := apikey.WithPrincipal(ctx, p)
	if ok, err := orgSvc.Can(pctx, "project", "read"); err != nil || !ok {
		t.Fatalf("key project:read = %v,%v; want true", ok, err)
	}
	if ok, err := orgSvc.Can(pctx, "project", "write"); err != nil || ok {
		t.Fatalf("key project:write = %v,%v; want false — the cap removed it", ok, err)
	}
	if ok, err := orgSvc.Can(pctx, org.ResourceMember, org.ActionCreate); err != nil || ok {
		t.Fatalf("key member:create = %v,%v; want false — admin holds it, the cap does not", ok, err)
	}
	if err := svc.RevokeKey(owner, k.ID); err != nil {
		t.Fatalf("RevokeKey: %v", err)
	}
	if _, err := svc.Authenticate(ctx, plain); !errors.Is(err, apikey.ErrKeyRevoked) {
		t.Fatalf("Authenticate after revoke = %v, want ErrKeyRevoked", err)
	}
	if err := svc.DeleteServiceAccount(owner, sa.ID); err != nil {
		t.Fatalf("DeleteServiceAccount: %v", err)
	}
	if _, err := svc.Authenticate(ctx, plain); !errors.Is(err, apikey.ErrKeyNotFound) {
		t.Fatalf("Authenticate after delete = %v, want ErrKeyNotFound", err)
	}
	if _, _, err := orgSvc.Standing(ctx, acme.ID, sa.ID); !errors.Is(err, org.ErrNotMember) {
		t.Fatalf("membership after delete = %v, want ErrNotMember", err)
	}
}
