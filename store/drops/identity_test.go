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

func newIdentityStore(fd *fakeDriver) *IdentityStore {
	return NewIdentityStore(pg.New(fd))
}

// lastExec returns the most recent statement the fake driver executed, or ""
// when it executed none.
func lastExec(fd *fakeDriver) string {
	if len(fd.execs) == 0 {
		return ""
	}
	return fd.execs[len(fd.execs)-1]
}

// ── schema / naming ─────────────────────────────────────────────────────────

func TestIdentitySchemaDefaultTableName(t *testing.T) {
	if got := NewIdentitySchema().Identities.Name(); got != "identities" {
		t.Fatalf("table name = %q, want identities", got)
	}
}

func TestIdentitySchemaHonoursCustomNames(t *testing.T) {
	s := NewIdentitySchema(WithIdentityNames(IdentityNames{Identities: "app_identities"}))
	if got := s.Identities.Name(); got != "app_identities" {
		t.Fatalf("table name = %q, want app_identities", got)
	}
	// The constraint and the index are derived from the table name, so a
	// renamed table must not collide with a default-named one in the same
	// database — that is the whole point of the option.
	if _, ok := s.Identities.CompositeUniques()["app_identities_provider_subject"]; !ok {
		t.Fatalf("unique constraint not renamed with the table; have %v", s.Identities.CompositeUniques())
	}
	idx := s.Identities.Indexes()
	if len(idx) != 1 || idx[0].Name() != "app_identities_user_id_idx" {
		t.Fatalf("index not renamed with the table; have %v", idx)
	}
}

// uuid is the default for both id columns, because authlayer mints UUIDv7.
// user_id is a reference to the users table AuthStore owns, so it follows
// identities.id rather than being configurable on its own — see
// TestIdentitySchemaWithIdentityTextLibraryIDs.
func TestIdentitySchemaIDColumnsDefaultToUUID(t *testing.T) {
	s := NewIdentitySchema()
	for tag, want := range map[string]string{
		"id":      "uuid",
		"user_id": "uuid",
		// provider and subject are opaque provider strings, never ids.
		"provider": "text",
		"subject":  "text",
		"email":    "text",
	} {
		if got := s.Identities.Col(tag).Type().TypeSQL(); got != want {
			t.Fatalf("identities.%s type = %q, want %s", tag, got, want)
		}
	}
}

// WithIdentityTextLibraryIDs types both id columns as text so
// auth.WithIDGenerator can be honoured against PostgreSQL at all. The
// load-bearing detail is that user_id moves WITH id rather than staying
// uuid: it references users.id, which AuthStore owns and
// WithAuthTextLibraryIDs moves in the same direction, and a text users.id
// against a uuid identities.user_id would fail the first link with the very
// 22P02 the option exists to remove.
func TestIdentitySchemaWithIdentityTextLibraryIDs(t *testing.T) {
	s := NewIdentitySchema(WithIdentityTextLibraryIDs())
	for _, tag := range []string{"id", "user_id"} {
		if got := s.Identities.Col(tag).Type().TypeSQL(); got != "text" {
			t.Fatalf("identities.%s type = %q, want text under WithIdentityTextLibraryIDs", tag, got)
		}
	}
	// The UNIQUE constraint and the index are what make this store correct,
	// and neither is an id column, so the option must leave both registered
	// exactly as before.
	if _, ok := s.Identities.CompositeUniques()["identities_provider_subject"]; !ok {
		t.Fatalf("WithIdentityTextLibraryIDs disturbed the unique constraint: %v", s.Identities.CompositeUniques())
	}
	if len(s.Identities.Indexes()) != 1 {
		t.Fatalf("WithIdentityTextLibraryIDs disturbed the index: %d registered", len(s.Identities.Indexes()))
	}
}

// UNIQUE (provider, subject) is the constraint that makes ErrIdentityLinked
// a guarantee rather than advice — see auth.Identity.Subject's own MUST. It
// is composite, so CREATE TABLE cannot carry it and nothing inline can
// declare it; it exists only because it is registered here and emitted by
// CreateSchema.
func TestIdentitySchemaRegistersProviderSubjectUnique(t *testing.T) {
	s := NewIdentitySchema()
	cols, ok := s.Identities.CompositeUniques()["identities_provider_subject"]
	if !ok {
		t.Fatalf("identities table missing UNIQUE (provider, subject); have %v", s.Identities.CompositeUniques())
	}
	if len(cols) != 2 || cols[0].Name() != "provider" || cols[1].Name() != "subject" {
		t.Fatalf("unique constraint columns = %v, want [provider subject] in that order", cols)
	}
}

// The user_id index serves ListIdentitiesByUser and the locking SELECT
// inside DeleteIdentityIfNotLast. That the PLANNER picks it is proven live
// by TestIdentityStoreListIdentitiesByUserUsesTheIndexLive; this only pins
// that it is registered at all, and non-unique (a user legitimately holds
// several identities).
func TestIdentitySchemaRegistersUserIDIndex(t *testing.T) {
	s := NewIdentitySchema()
	idx := s.Identities.Indexes()
	if len(idx) != 1 || idx[0].Name() != "identities_user_id_idx" {
		t.Fatalf("indexes = %v, want exactly identities_user_id_idx", idx)
	}
}

// last_used_at is the schema's only nullable column: auth.Identity.LastUsedAt
// is a *time.Time whose nil means "this link has never signed the user in",
// which is a fact distinct from any timestamp. Rendering the DDL is how that
// is checked end to end — a NOT NULL here would fail every LinkIdentity,
// which creates a row with no sign-in behind it.
func TestIdentitySchemaLastUsedAtIsNullable(t *testing.T) {
	fd := &fakeDriver{}
	if err := newIdentityStore(fd).CreateSchema(context.Background()); err != nil {
		t.Fatalf("CreateSchema: %v", err)
	}
	sql := fd.execs[0]
	if !strings.Contains(sql, "\"last_used_at\" timestamptz") {
		t.Fatalf("DDL does not declare last_used_at: %s", sql)
	}
	if strings.Contains(sql, "\"last_used_at\" timestamptz NOT NULL") {
		t.Fatalf("last_used_at is NOT NULL; a link made without a sign-in could never be written:\n%s", sql)
	}
	// The columns that must NOT be nullable, as a control on the assertion
	// above: if the renderer stopped emitting NOT NULL at all, the check
	// would pass for the wrong reason.
	if !strings.Contains(sql, "\"created_at\" timestamptz NOT NULL") {
		t.Fatalf("created_at lost its NOT NULL, so the last_used_at assertion proves nothing:\n%s", sql)
	}
}

func TestIdentityStoreCreateSchemaEmitsTableConstraintAndIndex(t *testing.T) {
	fd := &fakeDriver{}
	if err := newIdentityStore(fd).CreateSchema(context.Background()); err != nil {
		t.Fatalf("CreateSchema: %v", err)
	}
	joined := strings.Join(fd.execs, "\n")
	for _, want := range []string{
		"CREATE TABLE IF NOT EXISTS",
		"ADD CONSTRAINT \"identities_provider_subject\" UNIQUE (\"provider\", \"subject\")",
		"CREATE INDEX IF NOT EXISTS",
		"identities_user_id_idx",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("CreateSchema did not emit %q; statements:\n%s", want, joined)
		}
	}
}

// ── error classification ────────────────────────────────────────────────────

// A unique violation whose driver-reported constraint name ends "_pkey" is
// the row's own id colliding — see isPrimaryKeyViolation's doc for why this
// reads *pgconn.PgError.ConstraintName directly. The original error must
// stay reachable through the result rather than being discarded.
func TestCreateIdentityMapsIDCollision(t *testing.T) {
	execErr := &pgconn.PgError{Code: "23505", ConstraintName: "identities_pkey"}
	st := newIdentityStore(&fakeDriver{execErr: execErr})
	_, err := st.CreateIdentity(context.Background(), auth.Identity{ID: "i1"})
	if !errors.Is(err, auth.ErrIDTaken) {
		t.Fatalf("CreateIdentity err = %v, want ErrIDTaken", err)
	}
	if !errors.Is(err, pg.ErrUniqueViolation) {
		t.Fatalf("CreateIdentity err = %v, want it to still wrap pg.ErrUniqueViolation", err)
	}
}

// A unique violation whose constraint name is NOT the primary key must be
// the table's only other unique-enforcing constraint — (provider, subject) —
// and is the one this port promises as ErrIdentityLinked.
func TestCreateIdentityMapsProviderSubjectCollision(t *testing.T) {
	execErr := &pgconn.PgError{Code: "23505", ConstraintName: "identities_provider_subject"}
	st := newIdentityStore(&fakeDriver{execErr: execErr})
	_, err := st.CreateIdentity(context.Background(), auth.Identity{ID: "i1", Provider: "google", Subject: "sub-1"})
	if !errors.Is(err, auth.ErrIdentityLinked) {
		t.Fatalf("CreateIdentity err = %v, want ErrIdentityLinked", err)
	}
	if !errors.Is(err, pg.ErrUniqueViolation) {
		t.Fatalf("CreateIdentity err = %v, want it to still wrap pg.ErrUniqueViolation", err)
	}
}

// A unique violation with no constraint name reported cannot be identified
// as the primary key, so it falls through to ErrIdentityLinked — the
// documented fallback, and the fail-closed direction: refusing a link is
// safe, silently reporting "your id was taken" for a subject collision is
// not.
func TestCreateIdentityUnclassifiedUniqueViolationDefaultsToIdentityLinked(t *testing.T) {
	st := newIdentityStore(&fakeDriver{execErr: pg.ErrUniqueViolation})
	_, err := st.CreateIdentity(context.Background(), auth.Identity{ID: "i1"})
	if !errors.Is(err, auth.ErrIdentityLinked) {
		t.Fatalf("CreateIdentity err = %v, want ErrIdentityLinked", err)
	}
}

// A non-unique-violation error is propagated untouched: an outage is not a
// conflict, and reporting one as the other would let a caller treat a dead
// database as "already linked".
func TestCreateIdentityPropagatesOtherErrors(t *testing.T) {
	boom := errors.New("connection refused")
	st := newIdentityStore(&fakeDriver{execErr: boom})
	_, err := st.CreateIdentity(context.Background(), auth.Identity{ID: "i1"})
	if !errors.Is(err, boom) {
		t.Fatalf("CreateIdentity err = %v, want the driver error", err)
	}
	if errors.Is(err, auth.ErrIdentityLinked) || errors.Is(err, auth.ErrIDTaken) {
		t.Fatalf("CreateIdentity misclassified a non-conflict as a conflict: %v", err)
	}
}

// ── email normalization on write ────────────────────────────────────────────

// CreateIdentity normalizes Email before writing, as the port requires, and
// returns what it stored rather than what it was handed — a caller that
// round-trips the result must see the same value a later read will.
func TestCreateIdentityNormalizesEmail(t *testing.T) {
	fd := &fakeDriver{}
	got, err := newIdentityStore(fd).CreateIdentity(context.Background(), auth.Identity{
		ID: "i1", UserID: "u1", Provider: "google", Subject: "sub-1",
		Email: "  Nia@Example.COM ",
	})
	if err != nil {
		t.Fatalf("CreateIdentity: %v", err)
	}
	if got.Email != "nia@example.com" {
		t.Fatalf("returned Email = %q, want the normalized address", got.Email)
	}
	// Provider and Subject are matched byte-for-byte everywhere in the
	// package, so this method must not normalize them too.
	if got.Provider != "google" || got.Subject != "sub-1" {
		t.Fatalf("CreateIdentity rewrote the account key: %+v", got)
	}
}

// ── lookups and mutations ───────────────────────────────────────────────────

func TestFindIdentityByProviderSubjectMapsNoRows(t *testing.T) {
	st := newIdentityStore(&fakeDriver{})
	_, err := st.FindIdentityByProviderSubject(context.Background(), "google", "sub-1")
	if !errors.Is(err, auth.ErrIdentityNotFound) {
		t.Fatalf("err = %v, want ErrIdentityNotFound", err)
	}
}

// A NULL last_used_at scans back as a nil pointer rather than a zero time:
// "never used" must survive the round trip, since it is what an application
// distinguishes a fresh link by.
func TestFindIdentityByProviderSubjectScansNullLastUsedAt(t *testing.T) {
	now := time.Now().UTC()
	fd := &fakeDriver{rows: &fakeRows{
		cols: []string{"id", "user_id", "provider", "subject", "email", "created_at", "last_used_at"},
		data: [][]any{{"i1", "u1", "google", "sub-1", "nia@example.com", now, (*time.Time)(nil)}},
	}}
	got, err := newIdentityStore(fd).FindIdentityByProviderSubject(context.Background(), "google", "sub-1")
	if err != nil {
		t.Fatalf("FindIdentityByProviderSubject: %v", err)
	}
	if got.LastUsedAt != nil {
		t.Fatalf("LastUsedAt = %v, want nil for a link that has never signed anyone in", got.LastUsedAt)
	}
	if got.ID != "i1" || got.UserID != "u1" {
		t.Fatalf("scanned %+v, want the seeded row", got)
	}
}

func TestTouchIdentityReportsAMissAsNotFound(t *testing.T) {
	st := newIdentityStore(&fakeDriver{affected: 0})
	if err := st.TouchIdentity(context.Background(), "nope", time.Now()); !errors.Is(err, auth.ErrIdentityNotFound) {
		t.Fatalf("err = %v, want ErrIdentityNotFound", err)
	}
}

func TestTouchIdentityUpdatesLastUsedAt(t *testing.T) {
	fd := &fakeDriver{affected: 1}
	if err := newIdentityStore(fd).TouchIdentity(context.Background(), "i1", time.Now()); err != nil {
		t.Fatalf("TouchIdentity: %v", err)
	}
	stmt := strings.Join(fd.execs, "\n")
	if !strings.Contains(stmt, "UPDATE") || !strings.Contains(stmt, "last_used_at") {
		t.Fatalf("TouchIdentity issued %q, want an UPDATE of last_used_at", stmt)
	}
}

// DeleteIdentityIfNotLast must be a TRANSACTION, not a bare statement — see
// its doc for why a single conditional DELETE cannot express the check. The
// fake driver counts Begin, so this pins the shape rather than trusting the
// prose.
func TestDeleteIdentityIfNotLastRunsInATransaction(t *testing.T) {
	fd := &fakeDriver{}
	err := newIdentityStore(fd).DeleteIdentityIfNotLast(context.Background(), "u1", "google", false)
	// No rows come back from the fake, so the user has no identity at that
	// provider at all.
	if !errors.Is(err, auth.ErrIdentityNotFound) {
		t.Fatalf("err = %v, want ErrIdentityNotFound for a user with no rows", err)
	}
	if fd.begins != 1 {
		t.Fatalf("begins = %d, want exactly 1 — the decision and the delete must share one transaction", fd.begins)
	}
	// The advisory lock is the first statement of that transaction: it is
	// what makes two concurrent unlinks of one user serial, so the second
	// decides against the first's committed result. See the method's doc.
	if len(fd.execs) == 0 || !strings.Contains(fd.execs[0], "pg_advisory_xact_lock") {
		t.Fatalf("first statement = %q, want the per-user advisory lock; all: %v", lastExec(fd), fd.execs)
	}
	if !strings.Contains(fd.execs[0], "authlayer:identities:user") {
		t.Fatalf("advisory lock does not use this store's own namespace: %q", fd.execs[0])
	}
	// And the locking read is a FOR UPDATE over the user's rows.
	q := strings.Join(fd.queries, "\n")
	if !strings.Contains(q, "FOR UPDATE") || !strings.Contains(q, "user_id") {
		t.Fatalf("queries = %q, want a SELECT ... WHERE user_id ... FOR UPDATE", q)
	}
}

// The refusal must write NOTHING: no DELETE may be issued when the account
// would be left with no credential at all.
func TestDeleteIdentityIfNotLastRefusesTheLastCredentialWithoutDeleting(t *testing.T) {
	fd := &fakeDriver{rows: &fakeRows{
		cols: []string{"id", "provider"},
		data: [][]any{{"i1", "google"}},
	}}
	err := newIdentityStore(fd).DeleteIdentityIfNotLast(context.Background(), "u1", "google", false)
	if !errors.Is(err, auth.ErrLastCredential) {
		t.Fatalf("err = %v, want ErrLastCredential", err)
	}
	for _, s := range fd.execs {
		if strings.Contains(s, "DELETE") {
			t.Fatalf("the refusal issued a DELETE anyway: %q", s)
		}
	}
	if fd.rollbacks != 1 {
		t.Fatalf("rollbacks = %d, want 1 — the refusal must roll the transaction back", fd.rollbacks)
	}
}

// A password-less user whose two identities are BOTH at the provider being
// unlinked is refused, because the survivor count is what remains AFTER the
// delete rather than the user's total row count. This is the case a naive
// "more than one row, so it is safe" check gets wrong, and it mirrors
// store/memory exactly.
func TestDeleteIdentityIfNotLastCountsSurvivorsNotRows(t *testing.T) {
	fd := &fakeDriver{rows: &fakeRows{
		cols: []string{"id", "provider"},
		data: [][]any{{"i1", "google"}, {"i2", "google"}},
	}}
	err := newIdentityStore(fd).DeleteIdentityIfNotLast(context.Background(), "u1", "google", false)
	if !errors.Is(err, auth.ErrLastCredential) {
		t.Fatalf("err = %v, want ErrLastCredential — both rows are at the provider being unlinked, so nothing survives", err)
	}
}

// A surviving identity at another provider makes the delete safe, and it is
// then issued for every row at the named provider.
func TestDeleteIdentityIfNotLastDeletesWhenASiblingSurvives(t *testing.T) {
	fd := &fakeDriver{rows: &fakeRows{
		cols: []string{"id", "provider"},
		data: [][]any{{"i1", "google"}, {"i2", "github"}},
	}}
	if err := newIdentityStore(fd).DeleteIdentityIfNotLast(context.Background(), "u1", "google", false); err != nil {
		t.Fatalf("DeleteIdentityIfNotLast: %v", err)
	}
	if !strings.Contains(lastExec(fd), "DELETE") {
		t.Fatalf("last statement = %q, want the DELETE", lastExec(fd))
	}
	if fd.commits != 1 {
		t.Fatalf("commits = %d, want 1", fd.commits)
	}
}

// A password is the other way the account stays reachable, so the only
// identity may then go.
func TestDeleteIdentityIfNotLastDeletesTheOnlyIdentityWhenTheUserHasAPassword(t *testing.T) {
	fd := &fakeDriver{rows: &fakeRows{
		cols: []string{"id", "provider"},
		data: [][]any{{"i1", "google"}},
	}}
	if err := newIdentityStore(fd).DeleteIdentityIfNotLast(context.Background(), "u1", "google", true); err != nil {
		t.Fatalf("DeleteIdentityIfNotLast: %v", err)
	}
	if !strings.Contains(lastExec(fd), "DELETE") {
		t.Fatalf("last statement = %q, want the DELETE", lastExec(fd))
	}
}
