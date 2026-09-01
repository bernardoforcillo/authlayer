package dropsstore

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/bernardoforcillo/drops"
	"github.com/bernardoforcillo/drops/pg"

	"github.com/bernardoforcillo/authlayer/auth"
)

// This is the UNIT suite for the MFA store: it runs against a fake driver
// and can therefore prove only what a builder produces — the schema's
// shape, and the SQL each method renders. Every property that belongs to a
// SERVER rather than a builder (the primary key really being on the table,
// the compare-and-set really admitting one winner, the planner really
// picking the index) is proved in mfa_integration_test.go against a real
// PostgreSQL. This project has already shipped a Critical by treating a
// `go vet -tags integration` pass as evidence about a database-shaped
// change; a suite that asserts a method was CALLED is the same mistake
// wearing test clothes.

func newMFAStore(fd *fakeDriver) *MFAStore {
	return NewMFAStore(pg.New(fd))
}

// ── schema / naming ─────────────────────────────────────────────────────

func TestMFASchemaDefaultTableNames(t *testing.T) {
	s := NewMFASchema()
	if got := s.Factors.Name(); got != "mfa_factors" {
		t.Fatalf("factors table = %q, want mfa_factors", got)
	}
	if got := s.RecoveryCodes.Name(); got != "mfa_recovery_codes" {
		t.Fatalf("recovery codes table = %q, want mfa_recovery_codes", got)
	}
}

func TestMFASchemaHonoursCustomNames(t *testing.T) {
	s := NewMFASchema(WithMFANames(MFANames{Factors: "app_factors", RecoveryCodes: "app_codes"}))
	if got := s.Factors.Name(); got != "app_factors" {
		t.Fatalf("factors table = %q, want app_factors", got)
	}
	if got := s.RecoveryCodes.Name(); got != "app_codes" {
		t.Fatalf("recovery codes table = %q, want app_codes", got)
	}
	// The index name is derived from the table name, so a renamed table
	// must not collide with a default-named one in the same database —
	// that is the whole point of the option.
	idx := s.RecoveryCodes.Indexes()
	if len(idx) != 1 || idx[0].Name() != "app_codes_user_id_code_hash_idx" {
		t.Fatalf("index not renamed with the table; have %v", idx)
	}
}

// user_id is the factors table's PRIMARY KEY, which is how "at most one
// factor per user" is enforced at all — see MFASchema's doc. It is declared
// through the drop tag's "pk" option, so this pins both the schema and that
// option's effect.
func TestMFASchemaFactorsArePrimaryKeyedOnUserID(t *testing.T) {
	s := NewMFASchema()
	col := s.Factors.Col("user_id")
	if col == nil {
		t.Fatal("mfa_factors has no user_id column")
	}
	if !col.IsPrimaryKey() {
		t.Fatal("mfa_factors.user_id is not the PRIMARY KEY — two rows could then exist for one user, and which secret authenticates the account would be decided by row order")
	}
	if !col.IsNotNull() {
		t.Fatal("mfa_factors.user_id is nullable")
	}
	// The table has no surrogate id at all: auth.MFAFactor declares none.
	if s.Factors.Col("id") != nil {
		t.Fatal("mfa_factors declares an id column; the factor is keyed by user_id")
	}
}

func TestMFASchemaIDColumnsDefaultToUUID(t *testing.T) {
	s := NewMFASchema()
	if got := s.Factors.Col("user_id").Type().TypeSQL(); got != "uuid" {
		t.Fatalf("mfa_factors.user_id type = %q, want uuid", got)
	}
	for _, tag := range []string{"id", "user_id"} {
		if got := s.RecoveryCodes.Col(tag).Type().TypeSQL(); got != "uuid" {
			t.Fatalf("mfa_recovery_codes.%s type = %q, want uuid", tag, got)
		}
	}
	// code_hash is a password-grade hash, never an id.
	if got := s.RecoveryCodes.Col("code_hash").Type().TypeSQL(); got != "text" {
		t.Fatalf("mfa_recovery_codes.code_hash type = %q, want text", got)
	}
}

// WithMFATextLibraryIDs moves both id families together, because the
// user_id columns reference the users table AuthStore owns.
func TestMFASchemaWithMFATextLibraryIDs(t *testing.T) {
	s := NewMFASchema(WithMFATextLibraryIDs())
	if got := s.Factors.Col("user_id").Type().TypeSQL(); got != "text" {
		t.Fatalf("mfa_factors.user_id type = %q, want text under WithMFATextLibraryIDs", got)
	}
	for _, tag := range []string{"id", "user_id"} {
		if got := s.RecoveryCodes.Col(tag).Type().TypeSQL(); got != "text" {
			t.Fatalf("mfa_recovery_codes.%s type = %q, want text under WithMFATextLibraryIDs", tag, got)
		}
	}
	// The option must not disturb the key or the index, neither of which is
	// about id types.
	if !s.Factors.Col("user_id").IsPrimaryKey() {
		t.Fatal("WithMFATextLibraryIDs dropped the factors primary key")
	}
	if len(s.RecoveryCodes.Indexes()) != 1 {
		t.Fatalf("WithMFATextLibraryIDs disturbed the index: %d registered", len(s.RecoveryCodes.Indexes()))
	}
}

// (user_id, code_hash) serves ListRecoveryCodes and ReplaceRecoveryCodes
// through its leading column and ConsumeRecoveryCode through both. That the
// PLANNER picks it is proven live; this pins that it is registered, in that
// column order, and non-unique.
func TestMFASchemaRegistersTheRecoveryCodeIndex(t *testing.T) {
	s := NewMFASchema()
	idx := s.RecoveryCodes.Indexes()
	if len(idx) != 1 || idx[0].Name() != "mfa_recovery_codes_user_id_code_hash_idx" {
		t.Fatalf("indexes = %v, want exactly mfa_recovery_codes_user_id_code_hash_idx", idx)
	}
	if len(s.RecoveryCodes.CompositeUniques()) != 0 {
		t.Fatalf("the recovery codes table declares a composite UNIQUE (%v); the index is deliberately not unique — see MFASchema's doc", s.RecoveryCodes.CompositeUniques())
	}
}

// The three nullable columns are the three states the service acts on:
// "not confirmed", "no step used yet", and "not spent". A NOT NULL on any
// of them would make the corresponding row unwritable.
func TestMFASchemaNullableColumns(t *testing.T) {
	s := NewMFASchema()
	for _, c := range []struct {
		tbl  *pg.Table
		name string
	}{
		{s.Factors, "confirmed_at"},
		{s.Factors, "last_step"},
		{s.RecoveryCodes, "used_at"},
	} {
		col := c.tbl.Col(c.name)
		if col == nil {
			t.Fatalf("%s has no %s column", c.tbl.Name(), c.name)
		}
		if col.IsNotNull() {
			t.Fatalf("%s.%s is NOT NULL; nil is a state this column must be able to hold", c.tbl.Name(), c.name)
		}
	}
	if got := s.Factors.Col("last_step").Type().TypeSQL(); got != "bigint" {
		t.Fatalf("mfa_factors.last_step type = %q, want bigint — a TOTP step is a Unix time divided by the period and outruns int32 in 2038", got)
	}
}

// ── DDL ─────────────────────────────────────────────────────────────────

func TestMFAStoreCreateSchemaEmitsBothTablesAndTheIndex(t *testing.T) {
	fd := &fakeDriver{}
	if err := newMFAStore(fd).CreateSchema(context.Background()); err != nil {
		t.Fatalf("CreateSchema: %v", err)
	}
	all := strings.Join(fd.execs, "\n")
	for _, want := range []string{
		`CREATE TABLE IF NOT EXISTS "mfa_factors"`,
		`CREATE TABLE IF NOT EXISTS "mfa_recovery_codes"`,
		`CREATE INDEX IF NOT EXISTS "mfa_recovery_codes_user_id_code_hash_idx"`,
	} {
		if !strings.Contains(all, want) {
			t.Fatalf("CreateSchema did not emit %s; it emitted:\n%s", want, all)
		}
	}
}

// last_step must reach the database as a nullable bigint. It is the one
// column whose Go type (*int64) this package had no support for before the
// MFA store existed, so rendering the DDL is how that support is checked
// end to end.
func TestMFAStoreCreateSchemaDeclaresLastStepNullableBigint(t *testing.T) {
	fd := &fakeDriver{}
	if err := newMFAStore(fd).CreateSchema(context.Background()); err != nil {
		t.Fatalf("CreateSchema: %v", err)
	}
	ddl := fd.execs[0]
	if !strings.Contains(ddl, `"last_step" bigint`) {
		t.Fatalf("DDL does not declare last_step as bigint: %s", ddl)
	}
	if strings.Contains(ddl, `"last_step" bigint NOT NULL`) {
		t.Fatalf("DDL declares last_step NOT NULL; nil means the factor has authenticated no step yet: %s", ddl)
	}
	// PRIMARY KEY implies NOT NULL, and drops renders the shorter form.
	if !strings.Contains(ddl, `"user_id" uuid PRIMARY KEY`) {
		t.Fatalf("DDL does not make user_id the primary key: %s", ddl)
	}
}

// ── rendered SQL ────────────────────────────────────────────────────────

// UpsertFactor must be ONE statement with an ON CONFLICT DO UPDATE that
// assigns every non-key column. Omitting confirmed_at from that list is the
// merge auth.MFAStore.UpsertFactor's MUST forbids — a new secret inheriting
// an old confirmation gates every login with a secret nobody scanned.
func TestUpsertFactorRendersAWholeRowUpsert(t *testing.T) {
	fd := &fakeDriver{affected: 1}
	st := newMFAStore(fd)

	if err := st.UpsertFactor(context.Background(), auth.MFAFactor{
		UserID:    "11111111-1111-7111-8111-111111111111",
		SecretEnc: "enc",
		CreatedAt: time.Unix(0, 0).UTC(),
	}); err != nil {
		t.Fatalf("UpsertFactor: %v", err)
	}
	if len(fd.execs) != 1 {
		t.Fatalf("UpsertFactor issued %d statements, want 1: %v", len(fd.execs), fd.execs)
	}
	sql := fd.execs[0]
	if !strings.Contains(sql, `ON CONFLICT ("user_id") DO UPDATE`) {
		t.Fatalf("UpsertFactor is not an upsert on user_id: %s", sql)
	}
	for _, col := range []string{"secret_enc", "confirmed_at", "created_at", "last_step"} {
		if !strings.Contains(sql, `"`+col+`" =`) {
			t.Fatalf("the DO UPDATE does not assign %s, so an existing row keeps its old value — that is the merge the port forbids: %s", col, sql)
		}
	}
}

// ConfirmFactor's compare-and-set lives entirely in its WHERE clause.
func TestConfirmFactorRendersTheCompareAndSet(t *testing.T) {
	fd := &fakeDriver{affected: 1}
	st := newMFAStore(fd)

	ok, err := st.ConfirmFactor(context.Background(), "u1", time.Unix(0, 0).UTC())
	if err != nil || !ok {
		t.Fatalf("ConfirmFactor = (%v, %v), want (true, nil)", ok, err)
	}
	sql := fd.execs[0]
	if !strings.Contains(sql, `"confirmed_at" IS NULL`) {
		t.Fatalf("ConfirmFactor's UPDATE has no `confirmed_at IS NULL` predicate — without it every concurrent caller wins: %s", sql)
	}
	if !strings.Contains(sql, `"user_id" = `) {
		t.Fatalf("ConfirmFactor's UPDATE is not keyed on user_id: %s", sql)
	}
	if len(fd.execs) != 1 || len(fd.queries) != 0 {
		t.Fatalf("a winning ConfirmFactor issued %d execs and %d queries, want one exec and no follow-up read", len(fd.execs), len(fd.queries))
	}
}

// AdvanceStep is the replay guard, and both arms of its predicate are
// load-bearing: `last_step < $` refuses a spent step, `last_step IS NULL`
// admits the factor's first ever code.
func TestAdvanceStepRendersBothArmsOfTheGuard(t *testing.T) {
	fd := &fakeDriver{affected: 1}
	st := newMFAStore(fd)

	ok, err := st.AdvanceStep(context.Background(), "u1", 58023700)
	if err != nil || !ok {
		t.Fatalf("AdvanceStep = (%v, %v), want (true, nil)", ok, err)
	}
	sql := fd.execs[0]
	if !strings.Contains(sql, `"last_step" IS NULL`) {
		t.Fatalf("AdvanceStep's UPDATE cannot match a factor whose last_step is NULL, so a freshly confirmed factor could never authenticate: %s", sql)
	}
	if !strings.Contains(sql, `"last_step" < `) {
		t.Fatalf("AdvanceStep's UPDATE has no `last_step < $` predicate — that IS the replay guard, and without it a shoulder-surfed code stays valid for its whole skew window: %s", sql)
	}
}

// Zero rows affected is ambiguous between "no factor" and "the predicate
// refused", so both CAS methods re-read the row to classify themselves. The
// follow-up read must be a read: it must not write anything.
func TestTheCompareAndSetsClassifyZeroRowsWithAReadOnlyFollowUp(t *testing.T) {
	for _, tc := range []struct {
		name string
		call func(st *MFAStore) (bool, error)
	}{
		{"ConfirmFactor", func(st *MFAStore) (bool, error) {
			return st.ConfirmFactor(context.Background(), "u1", time.Unix(0, 0).UTC())
		}},
		{"AdvanceStep", func(st *MFAStore) (bool, error) {
			return st.AdvanceStep(context.Background(), "u1", 7)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// affected 0, and a Query that returns one row: the factor
			// exists, so the refusal is the predicate's.
			fd := &fakeDriver{affected: 0, rows: mfaFactorRows()}
			ok, err := tc.call(newMFAStore(fd))
			if err != nil {
				t.Fatalf("%s: %v", tc.name, err)
			}
			if ok {
				t.Fatalf("%s reported true when the UPDATE affected no row", tc.name)
			}
			if len(fd.execs) != 1 {
				t.Fatalf("%s issued %d execs, want 1 — the follow-up must be a read: %v", tc.name, len(fd.execs), fd.execs)
			}
			if len(fd.queries) != 1 || !strings.HasPrefix(fd.queries[0], "SELECT") {
				t.Fatalf("%s did not classify itself with a single SELECT: %v", tc.name, fd.queries)
			}
		})
	}
}

// ConsumeRecoveryCode must match on the user AND the hash AND unusedness.
// Dropping the user_id predicate would let one account's recovery code be
// spent against another's; dropping used_at IS NULL would make a
// single-use credential reusable.
func TestConsumeRecoveryCodeRendersAllThreePredicates(t *testing.T) {
	fd := &fakeDriver{affected: 1}
	st := newMFAStore(fd)

	ok, err := st.ConsumeRecoveryCode(context.Background(), "u1", "hash", time.Unix(0, 0).UTC())
	if err != nil || !ok {
		t.Fatalf("ConsumeRecoveryCode = (%v, %v), want (true, nil)", ok, err)
	}
	sql := fd.execs[0]
	for _, want := range []string{`"user_id" = `, `"code_hash" = `, `"used_at" IS NULL`} {
		if !strings.Contains(sql, want) {
			t.Fatalf("ConsumeRecoveryCode's UPDATE is missing the %s predicate: %s", want, sql)
		}
	}
}

func TestConsumeRecoveryCodeReportsFalseWhenNothingBurned(t *testing.T) {
	fd := &fakeDriver{affected: 0}
	ok, err := newMFAStore(fd).ConsumeRecoveryCode(context.Background(), "u1", "hash", time.Unix(0, 0).UTC())
	if err != nil {
		t.Fatalf("ConsumeRecoveryCode returned an error for a code that matched nothing: %v", err)
	}
	if ok {
		t.Fatalf("ConsumeRecoveryCode reported true when the UPDATE affected no row")
	}
}

// ReplaceRecoveryCodes is one transaction: delete, then insert.
func TestReplaceRecoveryCodesIsOneTransaction(t *testing.T) {
	fd := &fakeDriver{affected: 1}
	st := newMFAStore(fd)
	at := time.Unix(0, 0).UTC()

	codes := []auth.RecoveryCode{
		{ID: "c1", UserID: "u1", CodeHash: "h1", CreatedAt: at},
		{ID: "c2", UserID: "u1", CodeHash: "h2", CreatedAt: at},
	}
	if err := st.ReplaceRecoveryCodes(context.Background(), "u1", codes); err != nil {
		t.Fatalf("ReplaceRecoveryCodes: %v", err)
	}
	if fd.begins != 1 || fd.commits != 1 {
		t.Fatalf("ReplaceRecoveryCodes ran %d transactions (%d commits), want exactly one — a half-applied replacement is either codes the user cannot use or an account with none", fd.begins, fd.commits)
	}
	if len(fd.execs) != 2 {
		t.Fatalf("ReplaceRecoveryCodes issued %d statements, want a DELETE and one multi-row INSERT: %v", len(fd.execs), fd.execs)
	}
	if !strings.HasPrefix(fd.execs[0], "DELETE") {
		t.Fatalf("ReplaceRecoveryCodes did not delete the old set first: %s", fd.execs[0])
	}
	if !strings.HasPrefix(fd.execs[1], "INSERT") {
		t.Fatalf("ReplaceRecoveryCodes' second statement is not the INSERT: %s", fd.execs[1])
	}
}

// An empty set is a revocation: the DELETE runs, and no INSERT is
// attempted (an INSERT with no rows is not valid SQL).
func TestReplaceRecoveryCodesWithNoCodesDeletesAndStops(t *testing.T) {
	fd := &fakeDriver{affected: 3}
	if err := newMFAStore(fd).ReplaceRecoveryCodes(context.Background(), "u1", nil); err != nil {
		t.Fatalf("ReplaceRecoveryCodes(nil): %v", err)
	}
	if len(fd.execs) != 1 || !strings.HasPrefix(fd.execs[0], "DELETE") {
		t.Fatalf("ReplaceRecoveryCodes(nil) issued %v, want a single DELETE", fd.execs)
	}
	if fd.commits != 1 {
		t.Fatalf("ReplaceRecoveryCodes(nil) committed %d times, want 1", fd.commits)
	}
}

// A code naming another user is refused BEFORE the transaction opens, so
// the user's working codes are never removed by a call that then fails.
func TestReplaceRecoveryCodesRefusesAForeignCodeBeforeWriting(t *testing.T) {
	fd := &fakeDriver{affected: 1}
	st := newMFAStore(fd)
	at := time.Unix(0, 0).UTC()

	err := st.ReplaceRecoveryCodes(context.Background(), "u1", []auth.RecoveryCode{
		{ID: "c1", UserID: "u1", CodeHash: "h1", CreatedAt: at},
		{ID: "c2", UserID: "u2", CodeHash: "h2", CreatedAt: at},
	})
	if err == nil || !strings.Contains(err.Error(), "another user") {
		t.Fatalf("ReplaceRecoveryCodes err = %v, want ErrRecoveryCodeUserMismatch", err)
	}
	if fd.begins != 0 || len(fd.execs) != 0 {
		t.Fatalf("a refused ReplaceRecoveryCodes issued %d statements in %d transactions, want none at all", len(fd.execs), fd.begins)
	}
}

// mfaFactorRows returns a fake result set holding one factor row, for the
// zero-rows classification tests.
func mfaFactorRows() drops.Rows {
	return &fakeRows{
		cols: []string{"user_id", "secret_enc", "confirmed_at", "created_at", "last_step"},
		data: [][]any{{"u1", "enc", (*time.Time)(nil), time.Unix(0, 0).UTC(), (*int64)(nil)}},
	}
}
