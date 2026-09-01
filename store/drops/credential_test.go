package dropsstore

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/bernardoforcillo/drops/pg"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/bernardoforcillo/authlayer/auth"
)

func newCredentialStore(fd *fakeDriver) *CredentialStore {
	return NewCredentialStore(pg.New(fd))
}

// ── schema / naming ─────────────────────────────────────────────────────────

func TestCredentialSchemaDefaultTableNames(t *testing.T) {
	s := NewCredentialSchema()
	if got := s.Credentials.Name(); got != "credentials" {
		t.Fatalf("credentials table name = %q, want credentials", got)
	}
	if got := s.Challenges.Name(); got != "passkey_challenges" {
		t.Fatalf("challenges table name = %q, want passkey_challenges", got)
	}
}

func TestCredentialSchemaHonoursCustomNames(t *testing.T) {
	s := NewCredentialSchema(WithCredentialNames(CredentialNames{
		Credentials: "app_passkeys", Challenges: "app_ceremonies",
	}))
	if got := s.Credentials.Name(); got != "app_passkeys" {
		t.Fatalf("credentials table name = %q, want app_passkeys", got)
	}
	if got := s.Challenges.Name(); got != "app_ceremonies" {
		t.Fatalf("challenges table name = %q, want app_ceremonies", got)
	}
	// Constraints and indexes are derived from the table names, so a renamed
	// table must not collide with a default-named one in the same database —
	// that is the whole point of the option.
	if _, ok := s.Credentials.CompositeUniques()["app_passkeys_credential_id"]; !ok {
		t.Fatalf("unique constraint not renamed with the table; have %v", s.Credentials.CompositeUniques())
	}
	if _, ok := s.Challenges.CompositeUniques()["app_ceremonies_challenge_hash"]; !ok {
		t.Fatalf("challenge hash constraint not renamed; have %v", s.Challenges.CompositeUniques())
	}
	idx := s.Credentials.Indexes()
	if len(idx) != 1 || idx[0].Name() != "app_passkeys_user_id_idx" {
		t.Fatalf("index not renamed with the table; have %v", idx)
	}
}

// The column types are the half of this schema a fake driver CAN check, and
// three of them are load-bearing:
//
//   - credential_id and public_key are bytea, so credential ids are matched
//     as exact bytes rather than through a text collation;
//   - sign_count is BIGINT, because auth.Credential.SignCount is a uint32 and
//     PostgreSQL has no unsigned types — an `integer` column would
//     misrepresent every counter above 2^31, and a counter compared wrong is
//     a compare-and-set that accepts what it should refuse;
//   - the challenges table's user_id is uuid AND nullable, because a login
//     ceremony names no account at all.
func TestCredentialSchemaColumnTypes(t *testing.T) {
	s := NewCredentialSchema()
	for tag, want := range map[string]string{
		"id":            "uuid",
		"user_id":       "uuid",
		"credential_id": "bytea",
		"public_key":    "bytea",
		"sign_count":    "bigint",
		"transports":    "text",
		"label":         "text",
	} {
		if got := s.Credentials.Col(tag).Type().TypeSQL(); got != want {
			t.Fatalf("credentials.%s type = %q, want %s", tag, got, want)
		}
	}
	for tag, want := range map[string]string{
		"id":             "uuid",
		"user_id":        "uuid",
		"ceremony":       "text",
		"challenge_hash": "text",
	} {
		if got := s.Challenges.Col(tag).Type().TypeSQL(); got != want {
			t.Fatalf("passkey_challenges.%s type = %q, want %s", tag, got, want)
		}
	}
}

// last_used_at (never used yet) and the challenges' user_id (a login ceremony
// names no account) are the schema's only nullable columns. Everything else
// must be NOT NULL: a nullable credential_id or sign_count would let a row
// exist that no lookup and no comparison can act on.
func TestCredentialSchemaNullability(t *testing.T) {
	s := NewCredentialSchema()
	if s.Credentials.Col("last_used_at").IsNotNull() {
		t.Fatal("credentials.last_used_at is NOT NULL; nil is how a caller tells 'never used' from a timestamp")
	}
	if s.Challenges.Col("user_id").IsNotNull() {
		t.Fatal("passkey_challenges.user_id is NOT NULL; a login ceremony names no account, so every login challenge would fail to write")
	}
	for _, tag := range []string{"id", "user_id", "credential_id", "public_key", "sign_count", "transports", "label", "created_at"} {
		if !s.Credentials.Col(tag).IsNotNull() {
			t.Errorf("credentials.%s is nullable, want NOT NULL", tag)
		}
	}
	for _, tag := range []string{"id", "ceremony", "challenge_hash", "expires_at", "created_at"} {
		if !s.Challenges.Col(tag).IsNotNull() {
			t.Errorf("passkey_challenges.%s is nullable, want NOT NULL", tag)
		}
	}
}

// WithCredentialTextLibraryIDs types the minted-id columns as text so
// auth.WithIDGenerator can be honoured against PostgreSQL at all. The
// load-bearing details are that user_id moves WITH id (it references users.id,
// which WithAuthTextLibraryIDs moves in the same direction) and that
// credential_id stays bytea — it is an authenticator's opaque identifier, not
// an id this library mints.
func TestCredentialSchemaWithCredentialTextLibraryIDs(t *testing.T) {
	s := NewCredentialSchema(WithCredentialTextLibraryIDs())
	for _, tag := range []string{"id", "user_id"} {
		if got := s.Credentials.Col(tag).Type().TypeSQL(); got != "text" {
			t.Fatalf("credentials.%s type = %q, want text under WithCredentialTextLibraryIDs", tag, got)
		}
		if got := s.Challenges.Col(tag).Type().TypeSQL(); got != "text" {
			t.Fatalf("passkey_challenges.%s type = %q, want text under WithCredentialTextLibraryIDs", tag, got)
		}
	}
	if got := s.Credentials.Col("credential_id").Type().TypeSQL(); got != "bytea" {
		t.Fatalf("credentials.credential_id type = %q under WithCredentialTextLibraryIDs, want bytea — it is not an id this library mints", got)
	}
	if s.Challenges.Col("user_id").IsNotNull() {
		t.Fatal("WithCredentialTextLibraryIDs made passkey_challenges.user_id NOT NULL")
	}
	if _, ok := s.Credentials.CompositeUniques()["credentials_credential_id"]; !ok {
		t.Fatalf("WithCredentialTextLibraryIDs disturbed the unique constraint: %v", s.Credentials.CompositeUniques())
	}
}

// UNIQUE (credential_id) is what makes ErrCredentialRegistered a guarantee
// rather than advice — see auth.Credential.CredentialID's own MUST. Without
// it two rows can name one authenticator credential against two different
// users, and a login resolving that credential id lands on whichever the
// server returns first.
func TestCredentialSchemaRegistersCredentialIDUnique(t *testing.T) {
	s := NewCredentialSchema()
	cols, ok := s.Credentials.CompositeUniques()["credentials_credential_id"]
	if !ok {
		t.Fatalf("credentials table missing UNIQUE (credential_id); have %v", s.Credentials.CompositeUniques())
	}
	if len(cols) != 1 || cols[0].Name() != "credential_id" {
		t.Fatalf("unique constraint columns = %v, want [credential_id]", cols)
	}
}

// UNIQUE (challenge_hash) discharges auth.Challenge.Hash's MUST:
// FindChallengeByHash assumes at most one row can match, and without the
// constraint its result silently depends on row order.
func TestCredentialSchemaRegistersChallengeHashUnique(t *testing.T) {
	s := NewCredentialSchema()
	cols, ok := s.Challenges.CompositeUniques()["passkey_challenges_challenge_hash"]
	if !ok {
		t.Fatalf("challenges table missing UNIQUE (challenge_hash); have %v", s.Challenges.CompositeUniques())
	}
	if len(cols) != 1 || cols[0].Name() != "challenge_hash" {
		t.Fatalf("unique constraint columns = %v, want [challenge_hash]", cols)
	}
}

// The user_id index serves ListCredentialsByUser and the locking SELECT
// inside DeleteCredentialIfNotLast. That the PLANNER picks it is proven live
// by TestCredentialStoreListCredentialsByUserUsesTheIndexLive; this only pins
// that it is registered at all, and non-unique (a user legitimately holds
// several passkeys).
func TestCredentialSchemaRegistersUserIDIndex(t *testing.T) {
	s := NewCredentialSchema()
	idx := s.Credentials.Indexes()
	if len(idx) != 1 {
		t.Fatalf("credentials indexes = %v, want exactly one on user_id", idx)
	}
	if idx[0].Name() != "credentials_user_id_idx" {
		t.Fatalf("index name = %q, want credentials_user_id_idx", idx[0].Name())
	}
}

// ── CreateSchema ────────────────────────────────────────────────────────────

// CreateSchema must emit every statement CREATE TABLE cannot carry, for BOTH
// tables. A missing ALTER here is a missing constraint on any table that
// already exists — the self-healing property the plpgsql guard exists for.
func TestCredentialStoreCreateSchemaEmitsEveryStatement(t *testing.T) {
	fd := &fakeDriver{}
	if err := newCredentialStore(fd).CreateSchema(context.Background()); err != nil {
		t.Fatalf("CreateSchema: %v", err)
	}
	joined := strings.Join(fd.execs, "\n")
	for _, want := range []string{
		`CREATE TABLE IF NOT EXISTS "credentials"`,
		`CREATE TABLE IF NOT EXISTS "passkey_challenges"`,
		`ADD CONSTRAINT "credentials_credential_id" UNIQUE ("credential_id")`,
		`ADD CONSTRAINT "passkey_challenges_challenge_hash" UNIQUE ("challenge_hash")`,
		`CREATE INDEX IF NOT EXISTS "credentials_user_id_idx"`,
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("CreateSchema did not emit %s; statements:\n%s", want, joined)
		}
	}
	if !strings.Contains(joined, "sign_count") || !strings.Contains(joined, "bigint") {
		t.Errorf("the credentials DDL does not declare sign_count bigint:\n%s", joined)
	}
}

func TestCredentialStoreCreateSchemaPropagatesFailure(t *testing.T) {
	boom := errors.New("ddl boom")
	fd := &fakeDriver{execErr: boom}
	if err := newCredentialStore(fd).CreateSchema(context.Background()); !errors.Is(err, boom) {
		t.Fatalf("CreateSchema err = %v, want the driver error", err)
	}
}

// ── the compare-and-set ─────────────────────────────────────────────────────

// The statement UpdateSignCount renders is the whole clone detection: a
// single UPDATE whose WHERE carries `sign_count < $n`. A fake driver cannot
// prove PostgreSQL applies it atomically, but it CAN prove the predicate is
// in the statement at all — and a dropped predicate is exactly the mutation
// that turns this method into "accept whatever the assertion said".
func TestUpdateSignCountRendersACompareAndSet(t *testing.T) {
	fd := &fakeDriver{affected: 1}
	ok, err := newCredentialStore(fd).UpdateSignCount(context.Background(), "cred-1", 42, time.Now())
	if err != nil || !ok {
		t.Fatalf("UpdateSignCount = %v, %v; want true, nil", ok, err)
	}
	stmt := lastExec(fd)
	if !strings.Contains(stmt, `UPDATE "credentials"`) {
		t.Fatalf("statement is not an update of the credentials table: %s", stmt)
	}
	if !strings.Contains(stmt, `"sign_count" <`) {
		t.Fatalf("statement carries no strictly-less predicate on sign_count, so it is not a compare-and-set: %s", stmt)
	}
	if !strings.Contains(stmt, `"last_used_at"`) {
		t.Fatalf("a winning compare-and-set must stamp last_used_at: %s", stmt)
	}
}

// Zero rows affected is ambiguous: no such credential, or a credential whose
// counter did not increase. The follow-up read is what classifies it, and
// the two answers mean different things to the service — one is an error, the
// other is the cloned-authenticator refusal.
func TestUpdateSignCountClassifiesZeroRowsAffected(t *testing.T) {
	t.Run("the credential exists, so the counter was refused", func(t *testing.T) {
		fd := &fakeDriver{affected: 0, rows: &fakeRows{
			cols: []string{"id"}, data: [][]any{{"cred-1"}},
		}}
		ok, err := newCredentialStore(fd).UpdateSignCount(context.Background(), "cred-1", 42, time.Now())
		if err != nil {
			t.Fatalf("UpdateSignCount err = %v, want nil — a refused counter is an answer, not a failure", err)
		}
		if ok {
			t.Fatal("UpdateSignCount = true with no rows affected")
		}
	})

	t.Run("no such credential", func(t *testing.T) {
		fd := &fakeDriver{affected: 0, rows: &fakeRows{cols: []string{"id"}}}
		ok, err := newCredentialStore(fd).UpdateSignCount(context.Background(), "nobody", 42, time.Now())
		if !errors.Is(err, auth.ErrCredentialNotFound) {
			t.Fatalf("UpdateSignCount err = %v, want ErrCredentialNotFound", err)
		}
		if ok {
			t.Fatal("UpdateSignCount = true for an unknown id")
		}
	})
}

// ── error classification ────────────────────────────────────────────────────

// A unique violation on the primary key is a duplicate surrogate id; any
// other is the credential_id constraint, since that is the table's only other
// unique-enforcing constraint. Getting this backwards would tell a caller a
// re-registered authenticator was an id collision.
func TestCreateCredentialClassifiesUniqueViolations(t *testing.T) {
	for _, tc := range []struct {
		name       string
		constraint string
		want       error
	}{
		{"primary key", "credentials_pkey", auth.ErrIDTaken},
		{"credential id", "credentials_credential_id", auth.ErrCredentialRegistered},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fd := &fakeDriver{execErr: &pgconn.PgError{Code: "23505", ConstraintName: tc.constraint}}
			_, err := newCredentialStore(fd).CreateCredential(context.Background(), auth.Credential{ID: "c1"})
			if !errors.Is(err, tc.want) {
				t.Fatalf("CreateCredential err = %v, want %v", err, tc.want)
			}
		})
	}
}

// A challenge-hash collision is NOT auth.ErrIDTaken: the port classifies only
// the surrogate id on a create, and reporting a hash collision as an id
// collision would tell a caller something false about which column collided.
func TestCreateChallengeClassifiesUniqueViolations(t *testing.T) {
	t.Run("primary key is ErrIDTaken", func(t *testing.T) {
		fd := &fakeDriver{execErr: &pgconn.PgError{Code: "23505", ConstraintName: "passkey_challenges_pkey"}}
		_, err := newCredentialStore(fd).CreateChallenge(context.Background(), auth.Challenge{ID: "ch1"})
		if !errors.Is(err, auth.ErrIDTaken) {
			t.Fatalf("CreateChallenge err = %v, want ErrIDTaken", err)
		}
	})
	t.Run("challenge hash is the driver's own error", func(t *testing.T) {
		fd := &fakeDriver{execErr: &pgconn.PgError{Code: "23505", ConstraintName: "passkey_challenges_challenge_hash"}}
		_, err := newCredentialStore(fd).CreateChallenge(context.Background(), auth.Challenge{ID: "ch1"})
		if errors.Is(err, auth.ErrIDTaken) {
			t.Fatalf("CreateChallenge reported a hash collision as ErrIDTaken: %v", err)
		}
		if !errors.Is(err, pg.ErrUniqueViolation) {
			t.Fatalf("CreateChallenge err = %v, want the unique violation through unwrapped", err)
		}
	})
}

// Every by-id mutation reports not-found on zero rows affected rather than
// silently succeeding. A "success" for a row that was not there is how a
// claim stops being a claim — see DeleteChallenge's own doc.
func TestCredentialStoreZeroRowsAffectedIsNotFound(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name string
		call func(*CredentialStore) error
		want error
	}{
		{"TouchCredential", func(st *CredentialStore) error { return st.TouchCredential(ctx, "c1", time.Now()) }, auth.ErrCredentialNotFound},
		{"DeleteCredential", func(st *CredentialStore) error { return st.DeleteCredential(ctx, "c1") }, auth.ErrCredentialNotFound},
		{"DeleteChallenge", func(st *CredentialStore) error { return st.DeleteChallenge(ctx, "ch1") }, auth.ErrChallengeNotFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fd := &fakeDriver{affected: 0}
			if err := tc.call(newCredentialStore(fd)); !errors.Is(err, tc.want) {
				t.Fatalf("%s err = %v, want %v", tc.name, err, tc.want)
			}
		})
	}
}

// DeleteCredentialIfNotLast must be a TRANSACTION — see its own doc for why a
// single conditional DELETE cannot work. This pins that it opens one at all,
// which is the property a fake driver can see; that the decision is really
// serialized is proven live.
func TestDeleteCredentialIfNotLastRunsInATransaction(t *testing.T) {
	fd := &fakeDriver{affected: 1, rows: &fakeRows{
		cols: []string{"id"}, data: [][]any{{"c1"}, {"c2"}},
	}}
	if err := newCredentialStore(fd).DeleteCredentialIfNotLast(context.Background(), "u1", "c1", false); err != nil {
		t.Fatalf("DeleteCredentialIfNotLast: %v", err)
	}
	if fd.begins != 1 || fd.commits != 1 {
		t.Fatalf("begins = %d, commits = %d; want one transaction", fd.begins, fd.commits)
	}
	joined := strings.Join(fd.execs, "\n")
	if !strings.Contains(joined, "pg_advisory_xact_lock") {
		t.Fatalf("no per-user advisory lock was taken; the decision is not serialized:\n%s", joined)
	}
	if !strings.Contains(strings.Join(fd.queries, "\n"), "FOR UPDATE") {
		t.Fatalf("the deciding SELECT does not lock its rows:\n%s", strings.Join(fd.queries, "\n"))
	}
}
