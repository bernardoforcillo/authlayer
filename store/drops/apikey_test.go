package dropsstore

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/bernardoforcillo/drops/pg"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/bernardoforcillo/authlayer/apikey"
)

// This is the UNIT suite for the API-key store: it runs against a fake
// driver and can therefore prove only what a builder produces — the schema's
// shape, and the SQL each method renders. Every property that belongs to a
// SERVER rather than a builder (the foreign key really cascading, the UNIQUE
// really refusing a second hash, the transaction really rolling back) is
// proved in apikey_integration_test.go against a real PostgreSQL, where the
// exported apikeytest suite also runs.

func newAPIKeyStore(fd *fakeDriver) *APIKeyStore {
	return NewAPIKeyStore(pg.New(fd))
}

// ── schema / naming ─────────────────────────────────────────────────────

func TestAPIKeySchemaDefaultTableNames(t *testing.T) {
	s := NewAPIKeySchema()
	if s.ServiceAccounts.Name() != "service_accounts" || s.Keys.Name() != "api_keys" {
		t.Fatalf("unexpected table names: %s %s", s.ServiceAccounts.Name(), s.Keys.Name())
	}
}

func TestAPIKeySchemaHonoursCustomNames(t *testing.T) {
	s := NewAPIKeySchema(WithAPIKeyNames(APIKeyNames{ServiceAccounts: "team_bots", Keys: "team_bot_keys"}))
	if s.ServiceAccounts.Name() != "team_bots" || s.Keys.Name() != "team_bot_keys" {
		t.Fatalf("custom names not applied: %s %s", s.ServiceAccounts.Name(), s.Keys.Name())
	}
	// Index names derive from the table name, so two differently-named
	// instances in one database cannot collide on them.
	for _, idx := range s.Keys.Indexes() {
		if !strings.HasPrefix(idx.Name(), "team_bot_keys_") {
			t.Fatalf("index %q not renamed with the table", idx.Name())
		}
	}
	if idx := s.ServiceAccounts.Indexes(); len(idx) != 1 || idx[0].Name() != "team_bots_container_id_idx" {
		t.Fatalf("service-account index not renamed with the table: %v", idx)
	}
}

func TestAPIKeySchemaIDColumnsDefaultToUUID(t *testing.T) {
	s := NewAPIKeySchema()
	for tag, got := range map[string]string{
		"service_accounts.id":           s.ServiceAccounts.Col("id").Type().TypeSQL(),
		"service_accounts.container_id": s.ServiceAccounts.Col("container_id").Type().TypeSQL(),
		"service_accounts.created_by":   s.ServiceAccounts.Col("created_by").Type().TypeSQL(),
		"api_keys.id":                   s.Keys.Col("id").Type().TypeSQL(),
		"api_keys.service_account_id":   s.Keys.Col("service_account_id").Type().TypeSQL(),
		"api_keys.container_id":         s.Keys.Col("container_id").Type().TypeSQL(),
		"api_keys.created_by":           s.Keys.Col("created_by").Type().TypeSQL(),
	} {
		if got != "uuid" {
			t.Fatalf("%s type = %q, want uuid by default", tag, got)
		}
	}
}

// WithAPIKeyTextLibraryIDs retypes every library-minted id — including
// service_account_id, which references an id this package mints — and leaves
// created_by alone; WithAPIKeyTextUserIDs does the reverse.
func TestAPIKeySchemaIDColumnsFollowTheOptions(t *testing.T) {
	lib := NewAPIKeySchema(WithAPIKeyTextLibraryIDs())
	for tag, got := range map[string]string{
		"service_accounts.id":           lib.ServiceAccounts.Col("id").Type().TypeSQL(),
		"service_accounts.container_id": lib.ServiceAccounts.Col("container_id").Type().TypeSQL(),
		"api_keys.id":                   lib.Keys.Col("id").Type().TypeSQL(),
		"api_keys.service_account_id":   lib.Keys.Col("service_account_id").Type().TypeSQL(),
		"api_keys.container_id":         lib.Keys.Col("container_id").Type().TypeSQL(),
	} {
		if got != "text" {
			t.Fatalf("%s type = %q, want text under WithAPIKeyTextLibraryIDs", tag, got)
		}
	}
	if got := lib.Keys.Col("created_by").Type().TypeSQL(); got != "uuid" {
		t.Fatalf("WithAPIKeyTextLibraryIDs leaked into created_by: %q", got)
	}

	usr := NewAPIKeySchema(WithAPIKeyTextUserIDs())
	for tag, got := range map[string]string{
		"service_accounts.created_by": usr.ServiceAccounts.Col("created_by").Type().TypeSQL(),
		"api_keys.created_by":         usr.Keys.Col("created_by").Type().TypeSQL(),
	} {
		if got != "text" {
			t.Fatalf("%s type = %q, want text under WithAPIKeyTextUserIDs", tag, got)
		}
	}
	if got := usr.Keys.Col("service_account_id").Type().TypeSQL(); got != "uuid" {
		t.Fatalf("WithAPIKeyTextUserIDs leaked into service_account_id: %q", got)
	}
}

// token_hash is UNIQUE through the record's own tag, so it lands inline in
// the CREATE TABLE; the schema registers no separate constraint for it.
func TestAPIKeySchemaTokenHashIsUniqueInline(t *testing.T) {
	s := NewAPIKeySchema()
	if !s.Keys.Col("token_hash").IsUnique() {
		t.Fatal("api_keys.token_hash is not UNIQUE — two rows could answer one presented key")
	}
	if n := len(s.Keys.CompositeUniques()); n != 0 {
		t.Fatalf("api_keys registers %d composite unique(s), want 0 — token_hash is inline", n)
	}
}

// The foreign key is the cascade and the orphan refusal at once.
func TestAPIKeySchemaKeysReferenceAccountsWithCascade(t *testing.T) {
	s := NewAPIKeySchema()
	fk := s.Keys.Col("service_account_id").ForeignKey()
	if fk == nil {
		t.Fatal("api_keys.service_account_id declares no foreign key")
	}
	if fk.Target.Table().Name() != "service_accounts" || fk.Target.Name() != "id" {
		t.Fatalf("foreign key targets %s.%s, want service_accounts.id", fk.Target.Table().Name(), fk.Target.Name())
	}
	if fk.OnDelete != "CASCADE" {
		t.Fatalf("ON DELETE %q, want CASCADE", fk.OnDelete)
	}
}

func TestAPIKeySchemaNullableColumns(t *testing.T) {
	s := NewAPIKeySchema()
	for _, c := range []struct {
		tbl *pg.Table
		col string
	}{
		{s.ServiceAccounts, "disabled_at"},
		{s.Keys, "expires_at"},
		{s.Keys, "last_used_at"},
		{s.Keys, "revoked_at"},
	} {
		if c.tbl.Col(c.col).IsNotNull() {
			t.Fatalf("%s.%s is NOT NULL, want nullable — nil is a state the Service acts on", c.tbl.Name(), c.col)
		}
	}
	for _, col := range []string{"created_at", "updated_at"} {
		if !s.ServiceAccounts.Col(col).IsNotNull() {
			t.Fatalf("service_accounts.%s is nullable, want NOT NULL", col)
		}
	}
}

// ── CreateSchema ────────────────────────────────────────────────────────

// Accounts before keys (the FK needs its target), the REFERENCES clause and
// the UNIQUE inline, then the three indexes.
func TestAPIKeyStoreCreateSchemaEmitsTablesInOrderThenIndexes(t *testing.T) {
	fd := &fakeDriver{}
	if err := newAPIKeyStore(fd).CreateSchema(context.Background()); err != nil {
		t.Fatalf("CreateSchema: %v", err)
	}
	if len(fd.execs) != 5 {
		t.Fatalf("CreateSchema issued %d statements, want 5 (two tables, three indexes):\n%s", len(fd.execs), strings.Join(fd.execs, "\n"))
	}
	if !strings.Contains(fd.execs[0], `CREATE TABLE IF NOT EXISTS "service_accounts"`) {
		t.Fatalf("first statement is not the service_accounts table: %s", fd.execs[0])
	}
	if !strings.Contains(fd.execs[1], `"service_accounts_container_id_idx"`) {
		t.Fatalf("second statement is not the service_accounts index: %s", fd.execs[1])
	}
	keys := fd.execs[2]
	if !strings.Contains(keys, `CREATE TABLE IF NOT EXISTS "api_keys"`) {
		t.Fatalf("third statement is not the api_keys table: %s", keys)
	}
	if !strings.Contains(keys, `REFERENCES "service_accounts" ("id") ON DELETE CASCADE`) {
		t.Fatalf("api_keys DDL carries no cascading foreign key:\n%s", keys)
	}
	if !strings.Contains(keys, `"token_hash" text NOT NULL UNIQUE`) {
		t.Fatalf("api_keys DDL does not declare token_hash UNIQUE inline:\n%s", keys)
	}
	if !strings.Contains(keys, `"permissions" bytea NOT NULL`) {
		t.Fatalf("api_keys DDL types permissions oddly:\n%s", keys)
	}
	for i, want := range []string{"api_keys_service_account_id_idx", "api_keys_container_id_idx"} {
		if got := fd.execs[3+i]; !strings.Contains(got, "CREATE INDEX IF NOT EXISTS") || !strings.Contains(got, want) {
			t.Fatalf("statement %d = %s, want CREATE INDEX IF NOT EXISTS %s", 3+i, got, want)
		}
	}
}

// ── statement shapes ────────────────────────────────────────────────────

func TestDeleteServiceAccountIsOneTransactionKeysFirst(t *testing.T) {
	fd := &fakeDriver{affected: 1}
	if err := newAPIKeyStore(fd).DeleteServiceAccount(context.Background(), "sa1"); err != nil {
		t.Fatalf("DeleteServiceAccount: %v", err)
	}
	if fd.begins != 1 || fd.commits != 1 || fd.rollbacks != 0 {
		t.Fatalf("begins/commits/rollbacks = %d/%d/%d, want 1/1/0", fd.begins, fd.commits, fd.rollbacks)
	}
	if len(fd.execs) != 2 {
		t.Fatalf("DeleteServiceAccount issued %d statements, want 2:\n%s", len(fd.execs), strings.Join(fd.execs, "\n"))
	}
	if !strings.HasPrefix(fd.execs[0], `DELETE FROM "api_keys"`) || !strings.Contains(fd.execs[0], `"service_account_id" = $1`) {
		t.Fatalf("first statement is not the keys delete: %s", fd.execs[0])
	}
	if !strings.HasPrefix(fd.execs[1], `DELETE FROM "service_accounts"`) || !strings.Contains(fd.execs[1], `"id" = $1`) {
		t.Fatalf("second statement is not the account delete: %s", fd.execs[1])
	}
}

// Zero rows on the account delete is the sentinel, and rolls back.
func TestDeleteServiceAccountZeroRowsIsNotFoundAndRollsBack(t *testing.T) {
	fd := &fakeDriver{affected: 0}
	err := newAPIKeyStore(fd).DeleteServiceAccount(context.Background(), "sa1")
	if !errors.Is(err, apikey.ErrServiceAccountNotFound) {
		t.Fatalf("err = %v, want ErrServiceAccountNotFound", err)
	}
	if fd.rollbacks != 1 || fd.commits != 0 {
		t.Fatalf("rollbacks/commits = %d/%d, want 1/0", fd.rollbacks, fd.commits)
	}
}

func TestSetServiceAccountDisabledRendersBothStampsAndNullClears(t *testing.T) {
	fd := &fakeDriver{affected: 1}
	st := newAPIKeyStore(fd)
	now := time.Now().UTC()
	if err := st.SetServiceAccountDisabled(context.Background(), "sa1", &now, now); err != nil {
		t.Fatalf("disable: %v", err)
	}
	if sql := fd.execs[0]; !strings.HasPrefix(sql, `UPDATE "service_accounts"`) || !strings.Contains(sql, `"disabled_at" = $`) || !strings.Contains(sql, `"updated_at" = $`) {
		t.Fatalf("disable rendered %s, want both stamps", sql)
	}
	if err := st.SetServiceAccountDisabled(context.Background(), "sa1", nil, now); err != nil {
		t.Fatalf("enable: %v", err)
	}
	if sql := fd.execs[1]; !strings.Contains(sql, `"disabled_at" = NULL`) {
		t.Fatalf("enable rendered %s, want disabled_at = NULL", sql)
	}
	fd.affected = 0
	if err := st.SetServiceAccountDisabled(context.Background(), "nope", nil, now); !errors.Is(err, apikey.ErrServiceAccountNotFound) {
		t.Fatalf("zero rows = %v, want ErrServiceAccountNotFound", err)
	}
}

// The three refusals CreateKey classifies, each from the driver's own error.
func TestCreateKeyClassifiesTheDriversErrors(t *testing.T) {
	k := apikey.Key{ID: "k1", ServiceAccountID: "sa1", ContainerID: "c1", TokenHash: "h", Permissions: []byte{}}

	_, err := newAPIKeyStore(&fakeDriver{execErr: pg.ErrForeignKeyViolation}).CreateKey(context.Background(), k)
	if !errors.Is(err, apikey.ErrServiceAccountNotFound) {
		t.Fatalf("foreign-key violation classified as %v, want ErrServiceAccountNotFound", err)
	}

	pk := &pgconn.PgError{Code: "23505", ConstraintName: "api_keys_pkey"}
	_, err = newAPIKeyStore(&fakeDriver{execErr: pk}).CreateKey(context.Background(), k)
	if !errors.Is(err, apikey.ErrIDTaken) || !errors.Is(err, pg.ErrUniqueViolation) {
		t.Fatalf("primary-key violation classified as %v, want ErrIDTaken wrapping the unique violation", err)
	}

	hash := &pgconn.PgError{Code: "23505", ConstraintName: "api_keys_token_hash_key"}
	_, err = newAPIKeyStore(&fakeDriver{execErr: hash}).CreateKey(context.Background(), k)
	if errors.Is(err, apikey.ErrIDTaken) || errors.Is(err, apikey.ErrServiceAccountNotFound) || !errors.Is(err, pg.ErrUniqueViolation) {
		t.Fatalf("token-hash violation classified as %v, want the unique violation through unwrapped", err)
	}
}

func TestCreateServiceAccountClassifiesAnIDCollision(t *testing.T) {
	pk := &pgconn.PgError{Code: "23505", ConstraintName: "service_accounts_pkey"}
	_, err := newAPIKeyStore(&fakeDriver{execErr: pk}).CreateServiceAccount(context.Background(), apikey.ServiceAccount{ID: "sa1"})
	if !errors.Is(err, apikey.ErrIDTaken) || !errors.Is(err, pg.ErrUniqueViolation) {
		t.Fatalf("err = %v, want ErrIDTaken wrapping the unique violation", err)
	}
}

func TestPurgeExpiredRendersBothReasonsInOneStatement(t *testing.T) {
	fd := &fakeDriver{affected: 3}
	n, err := newAPIKeyStore(fd).PurgeExpired(context.Background(), time.Now())
	if err != nil || n != 3 {
		t.Fatalf("PurgeExpired = %d, %v; want 3 from rows affected", n, err)
	}
	if len(fd.execs) != 1 {
		t.Fatalf("PurgeExpired issued %d statements, want 1", len(fd.execs))
	}
	sql := fd.execs[0]
	for _, want := range []string{`DELETE FROM "api_keys"`, `"expires_at" IS NOT NULL`, `"expires_at" < $`, `"revoked_at" IS NOT NULL`, `"revoked_at" < $`, " OR "} {
		if !strings.Contains(sql, want) {
			t.Fatalf("PurgeExpired rendered %s, want it to contain %q", sql, want)
		}
	}
}

func TestKeyUpdatesAreRowsAffectedGated(t *testing.T) {
	now := time.Now().UTC()
	for _, tc := range []struct {
		name string
		call func(st *APIKeyStore) error
		sql  string
	}{
		{"RevokeKey", func(st *APIKeyStore) error { return st.RevokeKey(context.Background(), "k1", now) }, `"revoked_at" = $`},
		{"TouchKey", func(st *APIKeyStore) error { return st.TouchKey(context.Background(), "k1", now) }, `"last_used_at" = $`},
		{"DeleteKey", func(st *APIKeyStore) error { return st.DeleteKey(context.Background(), "k1") }, `DELETE FROM "api_keys"`},
	} {
		fd := &fakeDriver{affected: 1}
		if err := tc.call(newAPIKeyStore(fd)); err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if !strings.Contains(fd.execs[0], tc.sql) || !strings.Contains(fd.execs[0], `"id" = $`) {
			t.Fatalf("%s rendered %s", tc.name, fd.execs[0])
		}
		if err := tc.call(newAPIKeyStore(&fakeDriver{affected: 0})); !errors.Is(err, apikey.ErrKeyNotFound) {
			t.Fatalf("%s with zero rows = %v, want ErrKeyNotFound", tc.name, err)
		}
	}
}

func TestAPIKeyFindsMapNoRows(t *testing.T) {
	st := newAPIKeyStore(&fakeDriver{})
	if _, err := st.FindServiceAccount(context.Background(), "x"); !errors.Is(err, apikey.ErrServiceAccountNotFound) {
		t.Fatalf("FindServiceAccount = %v, want ErrServiceAccountNotFound", err)
	}
	if _, err := st.FindKey(context.Background(), "x"); !errors.Is(err, apikey.ErrKeyNotFound) {
		t.Fatalf("FindKey = %v, want ErrKeyNotFound", err)
	}
	if _, err := st.FindKeyByHash(context.Background(), "x"); !errors.Is(err, apikey.ErrKeyNotFound) {
		t.Fatalf("FindKeyByHash = %v, want ErrKeyNotFound", err)
	}
}
