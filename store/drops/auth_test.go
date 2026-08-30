package dropsstore

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/bernardoforcillo/drops"
	"github.com/bernardoforcillo/drops/pg"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/bernardoforcillo/authlayer/auth"
)

func newAuthStore(fd *fakeDriver) *AuthStore {
	return NewAuthStore(pg.New(fd))
}

// ── schema / naming ─────────────────────────────────────────────────────────

func TestAuthSchemaDefaultTableNames(t *testing.T) {
	s := NewAuthSchema()
	if s.Users.Name() != "users" || s.Sessions.Name() != "sessions" || s.Verifications.Name() != "verifications" {
		t.Fatalf("unexpected table names: %s %s %s", s.Users.Name(), s.Sessions.Name(), s.Verifications.Name())
	}
}

func TestAuthSchemaHonoursCustomNames(t *testing.T) {
	s := NewAuthSchema(WithAuthNames(AuthNames{
		Users: "app_users", Sessions: "app_sessions", Verifications: "app_verifications",
	}))
	if s.Users.Name() != "app_users" || s.Sessions.Name() != "app_sessions" || s.Verifications.Name() != "app_verifications" {
		t.Fatalf("custom names not applied: %s %s %s", s.Users.Name(), s.Sessions.Name(), s.Verifications.Name())
	}
}

// uuid is the default for every id column here, users.id and the two
// referencing user_id columns alike, because authlayer mints UUIDv7. There is
// still no text-USER-id option on this store — it owns the users table it
// points at, so a text user_id against a uuid users.id would be incoherent.
// The knob that does exist is [WithAuthTextLibraryIDs], which moves all five
// id columns together; see TestAuthSchemaWithAuthTextLibraryIDs.
func TestAuthSchemaIDColumnsDefaultToUUID(t *testing.T) {
	s := NewAuthSchema()
	if got := s.Users.Col("id").Type().TypeSQL(); got != "uuid" {
		t.Fatalf("users.id type = %q, want uuid", got)
	}
	if got := s.Sessions.Col("user_id").Type().TypeSQL(); got != "uuid" {
		t.Fatalf("sessions.user_id type = %q, want uuid", got)
	}
	if got := s.Verifications.Col("user_id").Type().TypeSQL(); got != "uuid" {
		t.Fatalf("verifications.user_id type = %q, want uuid", got)
	}
	if got := s.Sessions.Col("id").Type().TypeSQL(); got != "uuid" {
		t.Fatalf("sessions.id type = %q, want uuid", got)
	}
	if got := s.Verifications.Col("id").Type().TypeSQL(); got != "uuid" {
		t.Fatalf("verifications.id type = %q, want uuid", got)
	}
	// token_hash is a hashed opaque token, not an id, so it stays text.
	if got := s.Sessions.Col("token_hash").Type().TypeSQL(); got != "text" {
		t.Fatalf("sessions.token_hash type = %q, want text", got)
	}
}

// WithAuthTextLibraryIDs types every id this store mints as text, so
// auth.WithIDGenerator can be honoured against PostgreSQL at all.
//
// The load-bearing detail is that sessions.user_id and verifications.user_id
// move WITH it rather than staying uuid. They are foreign references to
// users.id, which this store owns; leaving them uuid while users.id went text
// would fail the first CreateSession with the same 22P02 the option exists to
// remove — a hatch that fixed SignUp and broke Login. That is why this store
// takes one option covering both families rather than mirroring
// Schema/InviteSchema's independent pair.
func TestAuthSchemaWithAuthTextLibraryIDs(t *testing.T) {
	s := NewAuthSchema(WithAuthTextLibraryIDs())
	for tag, got := range map[string]string{
		"users.id":              s.Users.Col("id").Type().TypeSQL(),
		"sessions.id":           s.Sessions.Col("id").Type().TypeSQL(),
		"sessions.user_id":      s.Sessions.Col("user_id").Type().TypeSQL(),
		"verifications.id":      s.Verifications.Col("id").Type().TypeSQL(),
		"verifications.user_id": s.Verifications.Col("user_id").Type().TypeSQL(),
	} {
		if got != "text" {
			t.Fatalf("%s type = %q, want text under WithAuthTextLibraryIDs", tag, got)
		}
	}
	// The three UNIQUE constraints and the two indexes are what make this
	// store correct, and none of them is an id column, so the option must
	// leave every one of them registered exactly as before.
	if len(s.Sessions.CompositeUniques()) != 1 || len(s.Verifications.CompositeUniques()) != 1 ||
		len(s.Users.CompositeUniques()) != 1 {
		t.Fatalf("WithAuthTextLibraryIDs disturbed the unique constraints: users=%v sessions=%v verifications=%v",
			s.Users.CompositeUniques(), s.Sessions.CompositeUniques(), s.Verifications.CompositeUniques())
	}
	if len(s.Sessions.Indexes()) != 1 || len(s.Verifications.Indexes()) != 1 {
		t.Fatalf("WithAuthTextLibraryIDs disturbed the indexes: sessions=%d verifications=%d",
			len(s.Sessions.Indexes()), len(s.Verifications.Indexes()))
	}
}

// UserBase.Email carries "unique" directly on its drop: tag (see
// auth.UserBase), so it is declared inline on the column — the same
// mechanism org.Organization.Slug uses — for a fresh table's own CREATE
// TABLE. It is ALSO registered via AddUnique/CompositeUniques, under the
// exact name PostgreSQL auto-assigns the inline declaration
// ("users_email_key"), so CreateSchema's guarded ALTER TABLE self-heals a
// pre-existing table that predates the constraint — see AuthSchema's own
// doc for why the inline declaration alone is not sufficient (CREATE TABLE
// IF NOT EXISTS is a no-op against an existing table) and
// TestAuthStoreCreateSchemaSelfHealsMissingEmailUniqueLive for the live
// proof. Asserting both halves pins that this is deliberate double
// coverage, not an accidental gap in either direction.
func TestAuthSchemaUsersEmailUniqueIsDeclaredBothInlineAndAsSelfHealingConstraint(t *testing.T) {
	s := NewAuthSchema()
	if !s.Users.Col("email").IsUnique() {
		t.Fatal("users.email is not marked unique on the column itself")
	}
	cols, ok := s.Users.CompositeUniques()["users_email_key"]
	if !ok {
		t.Fatalf("users table missing the registered self-healing UNIQUE(email) constraint; have %v", s.Users.CompositeUniques())
	}
	if len(cols) != 1 || cols[0].Name() != "email" {
		t.Fatalf("registered unique constraint columns = %v, want [email]", cols)
	}
}

// The UNIQUE(token_hash) constraints are load-bearing: MarkRotated's and
// FindSessionByHash's single-winner/single-match assumptions both rest on
// this, per auth.Session.TokenHash's doc.
func TestAuthSchemaSessionsHaveTokenHashUnique(t *testing.T) {
	s := NewAuthSchema()
	uniques := s.Sessions.CompositeUniques()
	cols, ok := uniques["sessions_token_hash"]
	if !ok {
		t.Fatalf("sessions table missing UNIQUE(token_hash) constraint; have %v", uniques)
	}
	if len(cols) != 1 || cols[0].Name() != "token_hash" {
		t.Fatalf("unique constraint columns = %v, want [token_hash]", cols)
	}
}

// Verification's counterpart, per auth.Verification.TokenHash's doc.
func TestAuthSchemaVerificationsHaveTokenHashUnique(t *testing.T) {
	s := NewAuthSchema()
	uniques := s.Verifications.CompositeUniques()
	cols, ok := uniques["verifications_token_hash"]
	if !ok {
		t.Fatalf("verifications table missing UNIQUE(token_hash) constraint; have %v", uniques)
	}
	if len(cols) != 1 || cols[0].Name() != "token_hash" {
		t.Fatalf("unique constraint columns = %v, want [token_hash]", cols)
	}
}

// The constraint names follow the configured table names, so a second auth
// instance (a different app sharing this library) does not collide with
// the default one.
func TestAuthSchemaTokenHashConstraintNamesFollowCustomNames(t *testing.T) {
	s := NewAuthSchema(WithAuthNames(AuthNames{
		Users: "app_users", Sessions: "app_sessions", Verifications: "app_verifications",
	}))
	if _, ok := s.Sessions.CompositeUniques()["app_sessions_token_hash"]; !ok {
		t.Fatalf("sessions table missing app_sessions_token_hash; have %v", s.Sessions.CompositeUniques())
	}
	if _, ok := s.Verifications.CompositeUniques()["app_verifications_token_hash"]; !ok {
		t.Fatalf("verifications table missing app_verifications_token_hash; have %v", s.Verifications.CompositeUniques())
	}
}

// drops' CreateTableIfNotExists writes column definitions only, so the
// three UNIQUE constraints (all now registered via AddUnique, including
// email — see AuthSchema's doc for why the inline tag alone is not
// sufficient) would never self-heal onto a pre-existing table unless
// CreateSchema emits them itself. Assert the SQL, not the registry.
func TestAuthStoreCreateSchemaEmitsUniqueConstraints(t *testing.T) {
	fd := &fakeDriver{}
	st := newAuthStore(fd)
	if err := st.CreateSchema(context.Background()); err != nil {
		t.Fatalf("CreateSchema: %v", err)
	}

	// 3 CREATE TABLE + 3 ALTER TABLE ADD CONSTRAINT (users, sessions,
	// verifications) + 2 CREATE INDEX IF NOT EXISTS (sessions.family_id and
	// verifications (user_id, purpose) — see [NewAuthSchema]'s own comments
	// on those two registrations).
	if len(fd.execs) != 8 {
		t.Fatalf("CreateSchema issued %d statements, want 8:\n%s",
			len(fd.execs), strings.Join(fd.execs, "\n--\n"))
	}

	all := strings.Join(fd.execs, "\n--\n")
	for _, w := range []string{
		`ALTER TABLE "users" ADD CONSTRAINT "users_email_key" UNIQUE ("email");`,
		`ALTER TABLE "sessions" ADD CONSTRAINT "sessions_token_hash" UNIQUE ("token_hash");`,
		`ALTER TABLE "verifications" ADD CONSTRAINT "verifications_token_hash" UNIQUE ("token_hash");`,
		`CREATE INDEX IF NOT EXISTS "sessions_family_id_idx" ON "sessions" ("family_id")`,
		`CREATE INDEX IF NOT EXISTS "verifications_user_id_purpose_idx" ON "verifications" ("user_id", "purpose")`,
	} {
		if !strings.Contains(all, w) {
			t.Fatalf("CreateSchema never emitted:\n%s\ngot:\n%s", w, all)
		}
	}
	for _, sql := range fd.execs {
		if strings.Contains(sql, "ALTER TABLE") && !strings.Contains(sql, "EXCEPTION") {
			t.Fatalf("unguarded ALTER, so CreateSchema is not re-runnable:\n%s", sql)
		}
	}
}

// ── Users ────────────────────────────────────────────────────────────────

func TestCreateUserInsertsNormalizedUser(t *testing.T) {
	fd := &fakeDriver{}
	st := newAuthStore(fd)

	now := time.Now().UTC()
	in := auth.UserBase{ID: "user1", Email: "  Bob@Example.com  ", PasswordHash: "hash1", CreatedAt: now, UpdatedAt: now}
	got, err := st.CreateUser(context.Background(), in)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if got.Email != "bob@example.com" {
		t.Fatalf("CreateUser returned Email = %q, want normalized %q", got.Email, "bob@example.com")
	}
	if len(fd.execs) != 1 || !strings.Contains(fd.execs[0], "INSERT") || !strings.Contains(fd.execs[0], `"users"`) {
		t.Fatalf("unexpected exec: %v", fd.execs)
	}
}

// A unique violation whose driver-reported constraint name ends "_pkey" is
// classified as ErrIDTaken — see [isPrimaryKeyViolation]'s doc for why this
// reads *pgconn.PgError.ConstraintName directly rather than drops' own
// pg.PgError.Constraint (silently always empty through this driver — see
// that doc for why) or a follow-up database read (broken inside a
// transaction — also see that doc, and
// TestCreateUserDuplicateEmailInsideTxReturnsErrEmailTakenLive). The
// original error must still be reachable through the result, not
// discarded.
func TestCreateUserMapsIDCollision(t *testing.T) {
	execErr := &pgconn.PgError{Code: "23505", ConstraintName: "users_pkey"}
	st := newAuthStore(&fakeDriver{execErr: execErr})
	_, err := st.CreateUser(context.Background(), auth.UserBase{ID: "user1"})
	if !errors.Is(err, auth.ErrIDTaken) {
		t.Fatalf("CreateUser err = %v, want ErrIDTaken", err)
	}
	if !errors.Is(err, pg.ErrUniqueViolation) {
		t.Fatalf("CreateUser err = %v, want it to still wrap pg.ErrUniqueViolation rather than discard the original error", err)
	}
}

// A unique violation whose driver-reported constraint name does NOT end
// "_pkey" must be the users table's only other unique-enforcing
// constraint — email — and is classified as ErrEmailTaken.
func TestCreateUserMapsEmailCollision(t *testing.T) {
	execErr := &pgconn.PgError{Code: "23505", ConstraintName: "users_email_key"}
	st := newAuthStore(&fakeDriver{execErr: execErr})
	_, err := st.CreateUser(context.Background(), auth.UserBase{ID: "user1"})
	if !errors.Is(err, auth.ErrEmailTaken) {
		t.Fatalf("CreateUser err = %v, want ErrEmailTaken", err)
	}
	if !errors.Is(err, pg.ErrUniqueViolation) {
		t.Fatalf("CreateUser err = %v, want it to still wrap pg.ErrUniqueViolation rather than discard the original error", err)
	}
}

// A unique violation with no constraint name reported at all (a driver
// that doesn't expose one) cannot be identified as the primary key, so it
// falls through to the same classification as an actual email collision —
// matching this store's documented fallback.
func TestCreateUserUnclassifiedUniqueViolationDefaultsToEmailTaken(t *testing.T) {
	st := newAuthStore(&fakeDriver{execErr: pg.ErrUniqueViolation})
	_, err := st.CreateUser(context.Background(), auth.UserBase{ID: "user1"})
	if !errors.Is(err, auth.ErrEmailTaken) {
		t.Fatalf("CreateUser err = %v, want ErrEmailTaken", err)
	}
}

func TestFindUserByIDScansRow(t *testing.T) {
	now := time.Now().UTC()
	fd := &fakeDriver{rows: &fakeRows{
		cols: []string{"id", "email", "email_verified_at", "password_hash", "created_at", "updated_at"},
		data: [][]any{{"user1", "bob@example.com", (*time.Time)(nil), "hash1", now, now}},
	}}
	st := newAuthStore(fd)

	got, err := st.FindUserByID(context.Background(), "user1")
	if err != nil {
		t.Fatalf("FindUserByID: %v", err)
	}
	if got.ID != "user1" || got.Email != "bob@example.com" || got.EmailVerifiedAt != nil {
		t.Fatalf("scanned user = %+v", got)
	}
}

func TestFindUserByIDNotFound(t *testing.T) {
	st := newAuthStore(&fakeDriver{})
	if _, err := st.FindUserByID(context.Background(), "nope"); !errors.Is(err, auth.ErrUserNotFound) {
		t.Fatalf("err = %v, want ErrUserNotFound", err)
	}
}

func TestFindUserByEmailNormalizesAndQueries(t *testing.T) {
	now := time.Now().UTC()
	fd := &fakeDriver{rows: &fakeRows{
		cols: []string{"id", "email", "email_verified_at", "password_hash", "created_at", "updated_at"},
		data: [][]any{{"user1", "bob@example.com", (*time.Time)(nil), "hash1", now, now}},
	}}
	st := newAuthStore(fd)

	got, err := st.FindUserByEmail(context.Background(), "  Bob@Example.com  ")
	if err != nil {
		t.Fatalf("FindUserByEmail: %v", err)
	}
	if got.ID != "user1" {
		t.Fatalf("FindUserByEmail returned id %q, want user1", got.ID)
	}
	if !strings.Contains(fd.queries[0], `"users"."email" = `) {
		t.Fatalf("query does not key on email: %q", fd.queries[0])
	}
}

func TestFindUserByEmailNotFound(t *testing.T) {
	st := newAuthStore(&fakeDriver{})
	if _, err := st.FindUserByEmail(context.Background(), "nope@example.com"); !errors.Is(err, auth.ErrUserNotFound) {
		t.Fatalf("err = %v, want ErrUserNotFound", err)
	}
}

// ── MarkEmailVerified: atomicity predicate pinning ──────────────────────────

// markEmailVerifiedExecSQL runs a successful MarkEmailVerified and returns
// the single UPDATE it issued, for the SQL-shape assertions below.
func markEmailVerifiedExecSQL(t *testing.T) string {
	t.Helper()
	fd := &fakeDriver{affected: 1}
	st := newAuthStore(fd)
	if err := st.MarkEmailVerified(context.Background(), "user1", "bob@example.com", time.Now().UTC()); err != nil {
		t.Fatalf("MarkEmailVerified: %v", err)
	}
	if len(fd.execs) != 1 {
		t.Fatalf("MarkEmailVerified issued %d execs, want exactly 1 (a single UPDATE)", len(fd.execs))
	}
	return fd.execs[0]
}

func TestMarkEmailVerifiedIsASingleUpdateOnUsersTable(t *testing.T) {
	sql := markEmailVerifiedExecSQL(t)
	if !strings.HasPrefix(sql, `UPDATE "users"`) {
		t.Fatalf("exec does not open with UPDATE on the users table: %q", sql)
	}
}

// A regression that drops the id predicate (e.g. matching on email alone)
// would let MarkEmailVerified certify the wrong user's row.
func TestMarkEmailVerifiedGuardsOnID(t *testing.T) {
	sql := markEmailVerifiedExecSQL(t)
	if !strings.Contains(sql, `"id" = $`) {
		t.Fatalf("UPDATE does not key on id: %q", sql)
	}
}

// The central regression this task exists to pin: dropping the email
// predicate (leaving only WHERE id = $) would satisfy every other test here
// while reopening exactly the UpdateUserEmail race auth.Store.MarkEmailVerified's
// doc describes — see [AuthStore.MarkEmailVerified]'s own doc.
func TestMarkEmailVerifiedGuardsOnEmail(t *testing.T) {
	sql := markEmailVerifiedExecSQL(t)
	if !strings.Contains(sql, `"email" = $`) {
		t.Fatalf("UPDATE does not key on email — dropping this predicate reopens the UpdateUserEmail race: %q", sql)
	}
}

func TestMarkEmailVerifiedSetsBothTimestamps(t *testing.T) {
	sql := markEmailVerifiedExecSQL(t)
	if !strings.Contains(sql, `"email_verified_at" = $`) {
		t.Fatalf("UPDATE does not set email_verified_at: %q", sql)
	}
	if !strings.Contains(sql, `"updated_at" = $`) {
		t.Fatalf("UPDATE does not set updated_at: %q", sql)
	}
}

func TestMarkEmailVerifiedUserNotFound(t *testing.T) {
	// affected: 0, and the classifying FindUserByID also sees no row.
	st := newAuthStore(&fakeDriver{affected: 0})
	err := st.MarkEmailVerified(context.Background(), "nonesuch", "bob@example.com", time.Now())
	if !errors.Is(err, auth.ErrUserNotFound) {
		t.Fatalf("err = %v, want ErrUserNotFound", err)
	}
}

func TestMarkEmailVerifiedMismatch(t *testing.T) {
	now := time.Now().UTC()
	// affected: 0 (the UPDATE's WHERE didn't match), but the classifying
	// FindUserByID finds the user — its current email must not match what
	// was requested.
	fd := &fakeDriver{affected: 0, rows: &fakeRows{
		cols: []string{"id", "email", "email_verified_at", "password_hash", "created_at", "updated_at"},
		data: [][]any{{"user1", "carol@example.com", (*time.Time)(nil), "hash1", now, now}},
	}}
	st := newAuthStore(fd)
	err := st.MarkEmailVerified(context.Background(), "user1", "bob@example.com", now)
	if !errors.Is(err, auth.ErrEmailMismatch) {
		t.Fatalf("err = %v, want ErrEmailMismatch", err)
	}
}

// ── UpdateUserPassword / UpdateUserEmail ────────────────────────────────────

func TestUpdateUserPasswordSetsHashAndTimestamp(t *testing.T) {
	fd := &fakeDriver{affected: 1}
	st := newAuthStore(fd)
	if err := st.UpdateUserPassword(context.Background(), "user1", "new-hash", time.Now()); err != nil {
		t.Fatalf("UpdateUserPassword: %v", err)
	}
	if !strings.Contains(fd.execs[0], `"password_hash" = $`) {
		t.Fatalf("UPDATE does not set password_hash: %q", fd.execs[0])
	}
}

func TestUpdateUserPasswordNotFound(t *testing.T) {
	st := newAuthStore(&fakeDriver{affected: 0})
	if err := st.UpdateUserPassword(context.Background(), "nonesuch", "h", time.Now()); !errors.Is(err, auth.ErrUserNotFound) {
		t.Fatalf("err = %v, want ErrUserNotFound", err)
	}
}

func TestUpdateUserEmailNormalizesClearsVerificationAndStamps(t *testing.T) {
	fd := &fakeDriver{affected: 1}
	st := newAuthStore(fd)
	if err := st.UpdateUserEmail(context.Background(), "user1", "  New@Example.com  ", time.Now()); err != nil {
		t.Fatalf("UpdateUserEmail: %v", err)
	}
	sql := fd.execs[0]
	if !strings.Contains(sql, `"email" = $`) {
		t.Fatalf("UPDATE does not set email: %q", sql)
	}
	if !strings.Contains(sql, `"email_verified_at" = NULL`) {
		t.Fatalf("UPDATE does not clear email_verified_at to NULL: %q", sql)
	}
	if !strings.Contains(sql, `"updated_at" = $`) {
		t.Fatalf("UPDATE does not set updated_at: %q", sql)
	}
	if !strings.Contains(sql, `"id" = $`) {
		t.Fatalf("UPDATE does not key on id: %q", sql)
	}
}

func TestUpdateUserEmailMapsUniqueViolationToEmailTaken(t *testing.T) {
	st := newAuthStore(&fakeDriver{execErr: pg.ErrUniqueViolation})
	err := st.UpdateUserEmail(context.Background(), "user1", "taken@example.com", time.Now())
	if !errors.Is(err, auth.ErrEmailTaken) {
		t.Fatalf("err = %v, want ErrEmailTaken", err)
	}
}

func TestUpdateUserEmailNotFound(t *testing.T) {
	st := newAuthStore(&fakeDriver{affected: 0})
	err := st.UpdateUserEmail(context.Background(), "nonesuch", "new@example.com", time.Now())
	if !errors.Is(err, auth.ErrUserNotFound) {
		t.Fatalf("err = %v, want ErrUserNotFound", err)
	}
}

// ── Sessions ─────────────────────────────────────────────────────────────

func TestCreateSessionInsertsStampedSession(t *testing.T) {
	fd := &fakeDriver{}
	st := newAuthStore(fd)
	now := time.Now().UTC()
	sess := auth.Session{ID: "sess1", UserID: "user1", TokenHash: "hash1", FamilyID: "fam1", ExpiresAt: now.Add(time.Hour), CreatedAt: now}
	got, err := st.CreateSession(context.Background(), sess)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if got != sess {
		t.Fatalf("CreateSession returned %+v, want %+v unchanged", got, sess)
	}
	if len(fd.execs) != 1 || !strings.Contains(fd.execs[0], "INSERT") || !strings.Contains(fd.execs[0], `"sessions"`) {
		t.Fatalf("unexpected exec: %v", fd.execs)
	}
}

// A unique violation whose driver-reported constraint name ends "_pkey" is
// classified as ErrIDTaken — see [isPrimaryKeyViolation]'s doc.
func TestCreateSessionMapsIDCollision(t *testing.T) {
	execErr := &pgconn.PgError{Code: "23505", ConstraintName: "sessions_pkey"}
	st := newAuthStore(&fakeDriver{execErr: execErr})
	_, err := st.CreateSession(context.Background(), auth.Session{ID: "sess1"})
	if !errors.Is(err, auth.ErrIDTaken) {
		t.Fatalf("err = %v, want ErrIDTaken", err)
	}
	if !errors.Is(err, pg.ErrUniqueViolation) {
		t.Fatalf("err = %v, want it to still wrap pg.ErrUniqueViolation rather than discard the original error", err)
	}
}

// A TokenHash collision is this method's caller's obligation, not this
// method's own check (see auth.Session.TokenHash's doc): its constraint
// name does not end "_pkey", so it must NOT be mis-reported as ErrIDTaken —
// it propagates as the raw unique violation, unwrapped.
func TestCreateSessionPropagatesTokenHashCollisionUnmapped(t *testing.T) {
	execErr := &pgconn.PgError{Code: "23505", ConstraintName: "sessions_token_hash"}
	st := newAuthStore(&fakeDriver{execErr: execErr})
	_, err := st.CreateSession(context.Background(), auth.Session{ID: "sess1"})
	if errors.Is(err, auth.ErrIDTaken) {
		t.Fatalf("err = %v, must NOT be reported as ErrIDTaken for a token_hash collision", err)
	}
	if !errors.Is(err, pg.ErrUniqueViolation) {
		t.Fatalf("err = %v, want the raw pg.ErrUniqueViolation propagated", err)
	}
}

func TestFindSessionByHashScansRow(t *testing.T) {
	now := time.Now().UTC()
	fd := &fakeDriver{rows: &fakeRows{
		cols: []string{"id", "user_id", "token_hash", "family_id", "expires_at", "created_at", "rotated_at", "user_agent", "ip"},
		data: [][]any{{"sess1", "user1", "hash1", "fam1", now.Add(time.Hour), now, (*time.Time)(nil), "ua", "1.2.3.4"}},
	}}
	st := newAuthStore(fd)
	got, err := st.FindSessionByHash(context.Background(), "hash1")
	if err != nil {
		t.Fatalf("FindSessionByHash: %v", err)
	}
	if got.ID != "sess1" || got.RotatedAt != nil {
		t.Fatalf("scanned session = %+v", got)
	}
}

func TestFindSessionByHashNotFound(t *testing.T) {
	st := newAuthStore(&fakeDriver{})
	if _, err := st.FindSessionByHash(context.Background(), "nope"); !errors.Is(err, auth.ErrSessionNotFound) {
		t.Fatalf("err = %v, want ErrSessionNotFound", err)
	}
}

func TestListSessionsByUserQueriesByUser(t *testing.T) {
	st := newAuthStore(&fakeDriver{})
	got, err := st.ListSessionsByUser(context.Background(), "user1")
	if err != nil {
		t.Fatalf("ListSessionsByUser: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("got %d sessions from an empty result, want 0", len(got))
	}
}

func TestDeleteSessionAffectsRowsOrNotFound(t *testing.T) {
	st := newAuthStore(&fakeDriver{affected: 0})
	if err := st.DeleteSession(context.Background(), "sess1"); !errors.Is(err, auth.ErrSessionNotFound) {
		t.Fatalf("err = %v, want ErrSessionNotFound", err)
	}

	fd := &fakeDriver{affected: 1}
	st = newAuthStore(fd)
	if err := st.DeleteSession(context.Background(), "sess1"); err != nil {
		t.Fatalf("DeleteSession: %v", err)
	}
	if !strings.Contains(fd.execs[0], "DELETE") || !strings.Contains(fd.execs[0], `"sessions"`) {
		t.Fatalf("unexpected exec: %v", fd.execs)
	}
}

func TestDeleteSessionsByFamilyNoMatchesIsNotError(t *testing.T) {
	fd := &fakeDriver{affected: 0}
	st := newAuthStore(fd)
	if err := st.DeleteSessionsByFamily(context.Background(), "fam1"); err != nil {
		t.Fatalf("DeleteSessionsByFamily: %v", err)
	}
	// fd.execs[0] is the per-family pg_advisory_xact_lock call — see this
	// method's own "Revocation-versus-revocation" doc — issued as the
	// transaction's first statement, before the row-locking SELECT (which
	// routes through fd.queries, not fd.execs — see markRotatedWinSQL's own
	// comment on that routing) and the DELETE.
	if len(fd.execs) != 2 {
		t.Fatalf("execs = %v, want exactly 2 (advisory lock, then DELETE)", fd.execs)
	}
	if !strings.Contains(fd.execs[0], "pg_advisory_xact_lock") {
		t.Fatalf("execs[0] is not the advisory lock: %q", fd.execs[0])
	}
	if !strings.Contains(fd.execs[1], `"family_id" = `) {
		t.Fatalf("DELETE does not key on family_id: %q", fd.execs[1])
	}
}

// ── MarkRotated: atomicity predicate pinning ────────────────────────────────

// sessionCols/sessionRow build a RETURNING-shaped result row for the
// sessions table, matching Session's drop: tag order in auth.go.
func sessionCols() []string {
	return []string{"id", "user_id", "token_hash", "family_id", "expires_at", "created_at", "rotated_at", "user_agent", "ip"}
}

func sessionRow(rotatedAt *time.Time) []any {
	now := time.Now().UTC()
	return []any{"sess1", "user1", "hash1", "fam1", now.Add(time.Hour), now, rotatedAt, "ua", "1.2.3.4"}
}

// markRotatedWinSQL runs a winning MarkRotated call and returns the single
// UPDATE...RETURNING statement it issued, for the SQL-shape assertions
// below. It goes through db.Query (RETURNING routes an UpdateBuilder.One
// through Query, not Exec — see AuthStore.MarkRotated's doc), so the
// statement lands in fd.queries, not fd.execs.
func markRotatedWinSQL(t *testing.T) string {
	t.Helper()
	now := time.Now().UTC()
	fd := &fakeDriver{rows: &fakeRows{cols: sessionCols(), data: [][]any{sessionRow(&now)}}}
	st := newAuthStore(fd)
	got, ok, err := st.MarkRotated(context.Background(), "hash1", now)
	if err != nil {
		t.Fatalf("MarkRotated: %v", err)
	}
	if !ok {
		t.Fatal("MarkRotated ok = false, want true when the RETURNING clause yields a row")
	}
	if got.RotatedAt == nil || !got.RotatedAt.Equal(now) {
		t.Fatalf("MarkRotated RotatedAt = %v, want %v", got.RotatedAt, now)
	}
	if len(fd.queries) != 1 {
		t.Fatalf("MarkRotated issued %d queries, want exactly 1 (a single UPDATE...RETURNING)", len(fd.queries))
	}
	return fd.queries[0]
}

func TestMarkRotatedIsASingleUpdateOnSessionsTableWithReturning(t *testing.T) {
	sql := markRotatedWinSQL(t)
	if !strings.HasPrefix(sql, `UPDATE "sessions"`) {
		t.Fatalf("query does not open with UPDATE on the sessions table: %q", sql)
	}
	if !strings.Contains(sql, "RETURNING") {
		t.Fatalf("query has no RETURNING clause: %q", sql)
	}
}

func TestMarkRotatedGuardsOnTokenHash(t *testing.T) {
	sql := markRotatedWinSQL(t)
	if !strings.Contains(sql, `"token_hash" = $`) {
		t.Fatalf("UPDATE does not key on token_hash: %q", sql)
	}
}

// The central regression this task exists to pin: dropping "rotated_at IS
// NULL" would let every concurrent caller win — see
// [AuthStore.MarkRotated]'s doc for why that is an undetectable-parallel-
// session bug, not a cosmetic one.
func TestMarkRotatedGuardsOnRotatedAtIsNull(t *testing.T) {
	sql := markRotatedWinSQL(t)
	if !strings.Contains(sql, `"rotated_at" IS NULL`) {
		t.Fatalf("UPDATE does not guard on rotated_at IS NULL — this predicate is what makes MarkRotated a compare-and-set: %q", sql)
	}
}

// Expiry must NOT be part of the predicate — see the interface doc for why
// an expired-but-unrotated session must still be markable. RETURNING
// legitimately mentions expires_at as a returned column, so this checks
// only the WHERE clause, not the whole statement.
func TestMarkRotatedDoesNotGuardOnExpiresAt(t *testing.T) {
	sql := markRotatedWinSQL(t)
	where := sql
	if i := strings.Index(where, "WHERE"); i >= 0 {
		where = where[i:]
	}
	if j := strings.Index(where, "RETURNING"); j >= 0 {
		where = where[:j]
	}
	if strings.Contains(where, "expires_at") {
		t.Fatalf("MarkRotated's WHERE clause mentions expires_at, but expiry must not gate rotation: %q", where)
	}
}

func TestMarkRotatedSetsRotatedAt(t *testing.T) {
	sql := markRotatedWinSQL(t)
	if !strings.Contains(sql, `SET "rotated_at" = $`) {
		t.Fatalf("UPDATE does not SET rotated_at: %q", sql)
	}
}

// A tokenHash matching no session at all: the UPDATE...RETURNING yields
// nothing, and the classifying FindSessionByHash also finds nothing.
func TestMarkRotatedNotFoundAtAll(t *testing.T) {
	st := newAuthStore(&fakeDriver{})
	_, ok, err := st.MarkRotated(context.Background(), "nonesuch", time.Now())
	if !errors.Is(err, auth.ErrSessionNotFound) {
		t.Fatalf("err = %v, want ErrSessionNotFound", err)
	}
	if ok {
		t.Fatal("ok = true for a nonexistent session")
	}
}

// A tokenHash matching an already-rotated session: the UPDATE...RETURNING
// yields nothing (rotated_at IS NULL fails), but the classifying
// FindSessionByHash finds the existing, already-rotated row — reported as
// (that session, false, nil), not an error, matching auth.Store's doc. This
// needs two DIFFERENT Query results in sequence (empty, then one row),
// which is exactly what fakeDriver.rowsSeq exists for.
func TestMarkRotatedAlreadyRotatedReturnsExistingSessionOkFalse(t *testing.T) {
	first := time.Now().UTC().Add(-time.Minute)
	fd := &fakeDriver{rowsSeq: []drops.Rows{
		&fakeRows{cols: sessionCols(), data: nil},
		&fakeRows{cols: sessionCols(), data: [][]any{sessionRow(&first)}},
	}}
	st := newAuthStore(fd)

	got, ok, err := st.MarkRotated(context.Background(), "hash1", time.Now().UTC())
	if err != nil {
		t.Fatalf("MarkRotated err = %v, want nil (this is a replay, not a failure)", err)
	}
	if ok {
		t.Fatal("MarkRotated ok = true against an already-rotated session, want false")
	}
	if got.RotatedAt == nil || !got.RotatedAt.Equal(first) {
		t.Fatalf("MarkRotated returned RotatedAt = %v, want the existing rotation's stamp %v", got.RotatedAt, first)
	}
	if len(fd.queries) != 2 {
		t.Fatalf("issued %d queries, want 2 (the UPDATE...RETURNING, then the classifying re-read)", len(fd.queries))
	}
}

func TestMarkRotatedPropagatesQueryError(t *testing.T) {
	sentinel := errors.New("boom")
	st := newAuthStore(&fakeDriver{queryErr: sentinel})
	_, ok, err := st.MarkRotated(context.Background(), "hash1", time.Now())
	if ok {
		t.Fatal("ok = true despite a Query error")
	}
	if !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want the sentinel propagated", err)
	}
}

// ── CreateSuccessorSession: retry-attempt isolation (FIX 3) ────────────────

// retryCommitFailsOnceDriver is a bespoke drops.Driver, local to this test,
// for FIX 3's regression: pg.DB.WithRetry re-invokes InTx's ENTIRE closure
// on a retryable transaction failure (see pg.RetryPolicy's own doc), so
// this driver's FIRST Commit fails with a retryable sentinel — forcing
// exactly one retry — and every Commit after that succeeds. Exec always
// succeeds (the successor INSERT). Query always returns the same shared
// rows value; since store_test.go's fakeRows cursor is stateful and
// exhausts after being scanned through once (the same mechanism this
// package's own markRotatedWinSQL/TestMarkRotatedAlreadyRotatedReturnsExistingSessionOkFalse
// rely on elsewhere), the FIRST attempt's SELECT finds the predecessor row,
// and the SECOND (retried) attempt's own SELECT legitimately finds none —
// a plausible outcome (something else revoked the family between the first
// attempt's rollback and the second attempt's fresh snapshot), not a driver
// artifact.
type retryCommitFailsOnceDriver struct {
	rows        drops.Rows
	commitCalls int
}

func (d *retryCommitFailsOnceDriver) Exec(context.Context, string, ...any) (drops.Result, error) {
	return fakeResult{1}, nil
}
func (d *retryCommitFailsOnceDriver) Query(context.Context, string, ...any) (drops.Rows, error) {
	return d.rows, nil
}
func (d *retryCommitFailsOnceDriver) Begin(context.Context) (drops.Tx, error) {
	return &retryCommitFailsOnceTx{d}, nil
}

type retryCommitFailsOnceTx struct{ d *retryCommitFailsOnceDriver }

func (t *retryCommitFailsOnceTx) Exec(ctx context.Context, sql string, args ...any) (drops.Result, error) {
	return t.d.Exec(ctx, sql, args...)
}
func (t *retryCommitFailsOnceTx) Query(ctx context.Context, sql string, args ...any) (drops.Rows, error) {
	return t.d.Query(ctx, sql, args...)
}
func (t *retryCommitFailsOnceTx) Begin(ctx context.Context) (drops.Tx, error) {
	return t.d.Begin(ctx)
}
func (t *retryCommitFailsOnceTx) Commit(context.Context) error {
	t.d.commitCalls++
	if t.d.commitCalls == 1 {
		return pg.ErrSerializationFailure
	}
	return nil
}
func (t *retryCommitFailsOnceTx) Rollback(context.Context) error { return nil }

// TestCreateSuccessorSessionResetsPerRetryAttempt is FIX 3's regression
// test: created and won are declared OUTSIDE the InTx closure, so they must
// be reset as its first statement on every invocation, not just assumed
// zero once at the top of CreateSuccessorSession. This driver makes attempt
// 1 genuinely find the predecessor and insert successfully (which would set
// won = true), then fails ONLY that attempt's COMMIT with a retryable
// error, forcing pg.DB.WithRetry to re-run the closure. That second attempt
// legitimately finds no predecessor row and takes the early ErrNoRows
// return, which reports ok=false — but without the reset, the stale
// won=true (and the now-rolled-back created) from attempt 1 would survive
// into this second attempt's return value, since the overall InTx call
// still reports success (nil error) and CreateSuccessorSession trusts
// created/won unconditionally once InTx returns.
func TestCreateSuccessorSessionResetsPerRetryAttempt(t *testing.T) {
	predRow := &fakeRows{cols: []string{"id"}, data: [][]any{{"pred1"}}}
	drv := &retryCommitFailsOnceDriver{rows: predRow}
	db := pg.New(drv).WithRetry(pg.RetryPolicy{
		MaxAttempts: 3,
		Errors:      []error{pg.ErrSerializationFailure},
	})
	st := NewAuthStore(db)

	got, ok, err := st.CreateSuccessorSession(context.Background(), "pred1", auth.Session{ID: "succ1", TokenHash: "hash-succ"})
	if err != nil {
		t.Fatalf("CreateSuccessorSession err = %v, want nil — the retried attempt's own ErrNoRows classification is not itself a failure", err)
	}
	if ok {
		t.Fatal("CreateSuccessorSession ok = true, want false — the SECOND (retried) attempt found no predecessor and must not report a stale win carried over from the FIRST, rolled-back attempt")
	}
	if got != (auth.Session{}) {
		t.Fatalf("CreateSuccessorSession returned %+v, want the zero value — a rolled-back attempt's session must not leak through a later attempt's ok=false return", got)
	}
	if drv.commitCalls != 2 {
		t.Fatalf("commit called %d times, want exactly 2 (attempt 1 fails, attempt 2 succeeds) — otherwise this test is not exercising the retry path it claims to", drv.commitCalls)
	}
}

// ── Verifications ────────────────────────────────────────────────────────

func TestCreateVerificationNormalizesEmailAndInserts(t *testing.T) {
	fd := &fakeDriver{}
	st := newAuthStore(fd)
	got, err := st.CreateVerification(context.Background(), auth.Verification{
		ID: "ver1", TokenHash: "hash1", Purpose: "signup", Email: "  Bob@Example.com  ",
	})
	if err != nil {
		t.Fatalf("CreateVerification: %v", err)
	}
	if got.Email != "bob@example.com" {
		t.Fatalf("CreateVerification returned Email = %q, want normalized %q", got.Email, "bob@example.com")
	}
	if len(fd.execs) != 1 || !strings.Contains(fd.execs[0], "INSERT") || !strings.Contains(fd.execs[0], `"verifications"`) {
		t.Fatalf("unexpected exec: %v", fd.execs)
	}
}

// A unique violation whose driver-reported constraint name ends "_pkey" is
// classified as ErrIDTaken — see [isPrimaryKeyViolation]'s doc.
func TestCreateVerificationMapsIDCollision(t *testing.T) {
	execErr := &pgconn.PgError{Code: "23505", ConstraintName: "verifications_pkey"}
	st := newAuthStore(&fakeDriver{execErr: execErr})
	_, err := st.CreateVerification(context.Background(), auth.Verification{ID: "ver1"})
	if !errors.Is(err, auth.ErrIDTaken) {
		t.Fatalf("err = %v, want ErrIDTaken", err)
	}
	if !errors.Is(err, pg.ErrUniqueViolation) {
		t.Fatalf("err = %v, want it to still wrap pg.ErrUniqueViolation rather than discard the original error", err)
	}
}

// A TokenHash collision — its constraint name does not end "_pkey" — must
// NOT be mis-reported as ErrIDTaken: it propagates as the raw unique
// violation, unwrapped.
func TestCreateVerificationPropagatesTokenHashCollisionUnmapped(t *testing.T) {
	execErr := &pgconn.PgError{Code: "23505", ConstraintName: "verifications_token_hash"}
	st := newAuthStore(&fakeDriver{execErr: execErr})
	_, err := st.CreateVerification(context.Background(), auth.Verification{ID: "ver1"})
	if errors.Is(err, auth.ErrIDTaken) {
		t.Fatalf("err = %v, must NOT be reported as ErrIDTaken for a token_hash collision", err)
	}
	if !errors.Is(err, pg.ErrUniqueViolation) {
		t.Fatalf("err = %v, want the raw pg.ErrUniqueViolation propagated", err)
	}
}

func TestFindVerificationByHashScansRow(t *testing.T) {
	now := time.Now().UTC()
	fd := &fakeDriver{rows: &fakeRows{
		cols: []string{"id", "user_id", "token_hash", "purpose", "email", "expires_at", "created_at"},
		data: [][]any{{"ver1", "user1", "hash1", "signup", "bob@example.com", now.Add(time.Hour), now}},
	}}
	st := newAuthStore(fd)
	got, err := st.FindVerificationByHash(context.Background(), "hash1")
	if err != nil {
		t.Fatalf("FindVerificationByHash: %v", err)
	}
	if got.ID != "ver1" || got.Purpose != "signup" {
		t.Fatalf("scanned verification = %+v", got)
	}
}

func TestFindVerificationByHashNotFound(t *testing.T) {
	st := newAuthStore(&fakeDriver{})
	if _, err := st.FindVerificationByHash(context.Background(), "nope"); !errors.Is(err, auth.ErrVerificationNotFound) {
		t.Fatalf("err = %v, want ErrVerificationNotFound", err)
	}
}

func TestDeleteVerificationAffectsRowsOrNotFound(t *testing.T) {
	st := newAuthStore(&fakeDriver{affected: 0})
	if err := st.DeleteVerification(context.Background(), "ver1"); !errors.Is(err, auth.ErrVerificationNotFound) {
		t.Fatalf("err = %v, want ErrVerificationNotFound", err)
	}

	fd := &fakeDriver{affected: 1}
	st = newAuthStore(fd)
	if err := st.DeleteVerification(context.Background(), "ver1"); err != nil {
		t.Fatalf("DeleteVerification: %v", err)
	}
	if !strings.Contains(fd.execs[0], "DELETE") || !strings.Contains(fd.execs[0], `"verifications"`) {
		t.Fatalf("unexpected exec: %v", fd.execs)
	}
}

func TestDeleteVerificationsByUserAndPurposeKeysOnBoth(t *testing.T) {
	fd := &fakeDriver{affected: 0}
	st := newAuthStore(fd)
	if err := st.DeleteVerificationsByUserAndPurpose(context.Background(), "user1", "password_reset"); err != nil {
		t.Fatalf("DeleteVerificationsByUserAndPurpose: %v", err)
	}
	if !strings.Contains(fd.execs[0], `"user_id" = `) || !strings.Contains(fd.execs[0], `"purpose" = `) {
		t.Fatalf("DELETE does not key on both user_id and purpose: %q", fd.execs[0])
	}
}

// ── PurgeExpired ─────────────────────────────────────────────────────────

func TestAuthPurgeExpiredIssuesScopedDeletesOnBothTables(t *testing.T) {
	fd := &fakeDriver{affected: 3}
	st := newAuthStore(fd)

	n, err := st.PurgeExpired(context.Background(), time.Now())
	if err != nil {
		t.Fatalf("PurgeExpired: %v", err)
	}
	if n != 6 {
		t.Fatalf("PurgeExpired = %d, want 6 (3 sessions + 3 verifications)", n)
	}
	if len(fd.execs) != 2 {
		t.Fatalf("PurgeExpired issued %d execs, want 2 (one DELETE per table)", len(fd.execs))
	}
	if !strings.Contains(fd.execs[0], `"sessions"`) || !strings.Contains(fd.execs[0], `"expires_at" <`) {
		t.Fatalf("sessions DELETE unexpected: %q", fd.execs[0])
	}
	if !strings.Contains(fd.execs[1], `"verifications"`) || !strings.Contains(fd.execs[1], `"expires_at" <`) {
		t.Fatalf("verifications DELETE unexpected: %q", fd.execs[1])
	}
}

func TestAuthPurgeExpiredNothingToPurge(t *testing.T) {
	st := newAuthStore(&fakeDriver{affected: 0})
	n, err := st.PurgeExpired(context.Background(), time.Now())
	if err != nil {
		t.Fatalf("PurgeExpired: %v", err)
	}
	if n != 0 {
		t.Fatalf("PurgeExpired = %d, want 0", n)
	}
}
