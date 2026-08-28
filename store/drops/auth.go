package dropsstore

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/bernardoforcillo/authlayer/auth"
	"github.com/bernardoforcillo/drops"
	"github.com/bernardoforcillo/drops/pg"
	"github.com/jackc/pgx/v5/pgconn"
)

// AuthNames are the three table names an AuthStore persists to. The zero
// value defaults to "users", "sessions" and "verifications".
type AuthNames struct {
	Users         string // default "users"
	Sessions      string // default "sessions"
	Verifications string // default "verifications"
}

func (n AuthNames) withDefaults() AuthNames {
	if n.Users == "" {
		n.Users = "users"
	}
	if n.Sessions == "" {
		n.Sessions = "sessions"
	}
	if n.Verifications == "" {
		n.Verifications = "verifications"
	}
	return n
}

type authSettings struct {
	names AuthNames
}

// AuthOption customizes an [AuthSchema] or [AuthStore] at construction.
type AuthOption func(*authSettings)

// WithAuthNames overrides the three table names, so a consumer that already
// owns tables named "users" etc. for something else can point this store
// elsewhere.
func WithAuthNames(n AuthNames) AuthOption {
	return func(s *authSettings) { s.names = n }
}

// AuthSchema holds the three authentication tables and their derived
// columns:
//
//	<users>          id PK, email, email_verified_at, password_hash,
//	                 created_at, updated_at, UNIQUE (email)
//	<sessions>       id PK, user_id, token_hash, family_id, expires_at,
//	                 created_at, rotated_at, user_agent, ip,
//	                 UNIQUE (token_hash)
//	<verifications>  id PK, user_id, token_hash, purpose, email, expires_at,
//	                 created_at, UNIQUE (token_hash)
//
// All three UNIQUE constraints are load-bearing, not decoration — see
// [auth.UserBase.Email], [auth.Session.TokenHash] and
// [auth.Verification.TokenHash]'s own doc comments for what silently
// breaks without each. email carries the "unique" option directly on
// [auth.UserBase]'s `drop:` tag (matching [org.Organization]'s Slug
// precedent — see columns.go), so it is emitted inline as part of a fresh
// table's own CREATE TABLE. That inline declaration is NOT sufficient by
// itself, though: [AuthStore.CreateSchema]'s CREATE TABLE IF NOT EXISTS is
// a no-op against a table that already exists — one created by an older
// version of this code, or by hand — so the inline UNIQUE column
// definition never reaches such a table at all. email is therefore ALSO
// registered as a one-column [pg.Table.AddUnique] call, under the exact
// name PostgreSQL auto-assigns the inline declaration on a fresh table
// (<Users>_email_key), so [AuthStore.CreateSchema]'s guarded ALTER TABLE
// self-heals a pre-existing table missing the constraint while silently
// no-op'ing (via the same duplicate_object guard [compositeConstraintDDL]
// already relies on) against a fresh one that already has it inline. Proven
// live: before this second registration existed, CreateSchema against a
// hand-created users table lacking UNIQUE(email) left two rows sharing one
// address, and CreateUser returned nil for the duplicate — see
// TestAuthStoreCreateSchemaSelfHealsMissingEmailUniqueLive. Neither
// TokenHash field carries the tag's "unique" option at all — see those
// fields' own doc for why enforcing their uniqueness is a MUST on a
// backend without being declared inline — so both are registered as
// one-column AddUnique calls the same way, following the idiom
// [InviteSchema] uses for EmailInvite.TokenHash and Link.Code.
// [AuthStore.CreateSchema] emits all three ALTER TABLE statements CREATE
// TABLE cannot carry (or, for email on a fresh table, does not need to).
//
// user_id on sessions and verifications is always typed uuid, unlike
// [Schema]'s or [InviteSchema]'s user-id columns: this store owns the users
// table it is pointing at, and that table's own id (a library-minted
// column — see columns.go's libraryIDColumns) is uuid unconditionally, so
// there is no configuration under which a text user_id would still be
// consistent with it. Unlike [WithTextUserIDs] or
// [WithInviteTextUserIDs], no such option is offered here.
//
// [auth.UserBase], [auth.Session] and [auth.Verification] are fixed
// shapes, unlike the generic scope Store, so unlike [Schema] this type is
// not parameterized.
type AuthSchema struct {
	// Users is the credential and identity table. See [auth.UserBase].
	Users *pg.Table
	// Sessions is the refresh-token / rotation-chain table. See
	// [auth.Session] and the auth package doc's "Sessions, families, and
	// rotation" section.
	Sessions *pg.Table
	// Verifications is the one-time signup / email-change / password-reset
	// token table. See [auth.Verification].
	Verifications *pg.Table

	users         *colSet
	sessions      *colSet
	verifications *colSet
}

// NewAuthSchema builds the schema for one auth store instance. [NewAuthStore]
// calls it, so use it directly only when you need the table definitions
// without a store — to generate DDL for a migration, for instance.
func NewAuthSchema(opts ...AuthOption) *AuthSchema {
	cfg := authSettings{}
	for _, o := range opts {
		o(&cfg)
	}
	names := cfg.names.withDefaults()

	s := &AuthSchema{
		Users:         pg.NewTable(names.Users),
		Sessions:      pg.NewTable(names.Sessions),
		Verifications: pg.NewTable(names.Verifications),
	}
	// uuidUserIDs is always true here — see [AuthSchema]'s doc for why this
	// store, unlike Schema/InviteSchema, offers no text-user-id escape
	// hatch: it owns the users table these two reference, and that table's
	// own id is uuid unconditionally.
	s.users = newColSet(s.Users, auth.UserBase{}, true)
	s.sessions = newColSet(s.Sessions, auth.Session{}, true)
	s.verifications = newColSet(s.Verifications, auth.Verification{}, true)

	s.Sessions.AddUnique(names.Sessions+"_token_hash", s.sessions.col("token_hash"))
	s.Verifications.AddUnique(names.Verifications+"_token_hash", s.verifications.col("token_hash"))
	// email_key matches PostgreSQL's own default name for the inline
	// column-level UNIQUE the "unique" tag option already declares (see
	// [AuthSchema]'s doc): on a fresh table the ALTER below hits that same
	// name and is swallowed as "already there"; on a pre-existing table
	// missing the constraint entirely, it adds it.
	s.Users.AddUnique(names.Users+"_email_key", s.users.col("email"))

	return s
}

// AuthStore is a drops-backed auth.Store. Like [InviteStore] it is pure
// persistence and, because auth.UserBase, auth.Session and
// auth.Verification are fixed shapes, it is not generic the way [Store] is
// over C and M.
type AuthStore struct {
	db *pg.DB
	s  *AuthSchema
}

// Compile-time proof the drops auth store satisfies the port.
var _ auth.Store = (*AuthStore)(nil)

// NewAuthStore returns an AuthStore over db, building a fresh [AuthSchema].
func NewAuthStore(db *pg.DB, opts ...AuthOption) *AuthStore {
	return &AuthStore{db: db, s: NewAuthSchema(opts...)}
}

// Schema exposes the tables so callers can build guards, join against them,
// or emit their own DDL.
func (st *AuthStore) Schema() *AuthSchema { return st.s }

// CreateSchema issues CREATE TABLE IF NOT EXISTS for all three tables,
// followed by all three UNIQUE constraints as guarded ALTER TABLE
// statements — see [AuthSchema]'s doc for why email's is registered this
// way too, not only the two TokenHash ones CREATE TABLE could never carry
// in the first place. Every statement is idempotent, so the call is safe
// to re-run and self-heals a pre-existing table missing a constraint; like
// [Store.CreateSchema] and
// [InviteStore.CreateSchema] it adds what is missing and never alters what
// is already there, so production deployments that own these tables via
// their own migrations should skip it. No foreign keys are declared between
// the three tables, matching this codebase's other schemas.
func (st *AuthStore) CreateSchema(ctx context.Context) error {
	for _, t := range []*pg.Table{st.s.Users, st.s.Sessions, st.s.Verifications} {
		if _, err := st.db.ExecExpr(ctx, pg.CreateTableIfNotExists(t)); err != nil {
			return err
		}
		for _, ddl := range compositeConstraintDDL(t) {
			if _, err := st.db.ExecExpr(ctx, ddl); err != nil {
				return err
			}
		}
	}
	return nil
}

// isPrimaryKeyViolation reports whether a unique-violation error was
// PostgreSQL's own primary-key constraint colliding, by reading the
// constraint name straight off the driver's own *pgconn.PgError —
// PostgreSQL auto-names a single-column inline PRIMARY KEY "<table>_pkey"
// (see [AuthSchema]'s doc on how id is declared), so that suffix reliably
// distinguishes an id collision from every other UNIQUE constraint the
// same table might carry.
//
// This reads *pgconn.PgError directly rather than drops' own
// pg.PgError.Constraint or a follow-up database read, for two reasons
// found the hard way against this store's live integration suite:
//
//   - pg.PgError.Constraint is documented as populated "when the driver
//     reports it", but jackc/pgx/v5's pgconn.PgError carries ConstraintName
//     as a plain struct FIELD, not the ConstraintName() string METHOD
//     drops' own classifyError looks for via
//     errors.As(err, &interface{ ConstraintName() string }). That
//     interface therefore never matches a real pgx error, so
//     pg.PgError.Constraint is silently "" on every genuine conflict.
//     Reaching past drops' wrapper to *pgconn.PgError directly — already in
//     the module graph via the pgx dependency this codebase already
//     requires, so this needs no go.mod change — sidesteps that gap. The
//     tradeoff is a direct dependency on pgx's concrete error type in a
//     file that otherwise only depends on drops' own abstractions; that
//     coupling is deliberate and confined to this one function.
//   - An earlier version of this function instead re-queried the table
//     ("does a row with this id exist") as a read-only follow-up after the
//     INSERT failed — safe when composed on its own, but broken when the
//     caller's INSERT runs inside its own transaction (e.g. via
//     [pg.DB.InTx]): a failed statement aborts a PostgreSQL transaction
//     immediately, so ANY further statement on that same transaction —
//     including a plain read-only SELECT — fails with SQLSTATE 25P02
//     ("current transaction is aborted"), not the row-existence answer the
//     classifier needed. Proven live: a duplicate-email CreateUser inside
//     InTx returned neither ErrEmailTaken, ErrIDTaken, nor even the
//     original pg.ErrUniqueViolation — just the 25P02 from the doomed
//     follow-up read. See TestCreateUserDuplicateEmailInsideTxReturnsErrEmailTakenLive.
//     Reading the already-in-hand error's own constraint name needs no
//     further statement at all, so it works identically whether the
//     caller composed the INSERT into a transaction or not.
func isPrimaryKeyViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && strings.HasSuffix(pgErr.ConstraintName, "_pkey")
}

// ── Users ───────────────────────────────────────────────────────────────

// CreateUser normalizes u.Email (see [auth.NormalizeEmail]), inserts u, and
// returns it unchanged. A unique violation is classified via
// [isPrimaryKeyViolation] — see its doc for why this reads the driver's own
// *pgconn.PgError rather than re-querying or trusting drops' own
// pg.PgError.Constraint: ErrIDTaken when the row's own id already exists,
// ErrEmailTaken otherwise (the users table's only other unique-enforcing
// constraint — see [AuthSchema]'s doc). Either sentinel wraps the original
// error rather than discarding it, so a caller that wants the underlying
// pg.ErrUniqueViolation (or, via errors.As, the driver's own
// *pgconn.PgError) back can still reach it through this error's chain.
//
// This is a single INSERT with no preliminary SELECT, so it satisfies
// [auth.Store.CreateUser]'s write-before-classify obligation by
// construction: ErrEmailTaken can only ever come from the insert attempt
// itself failing, never from a separately-authorized read that could
// succeed on its own under a write-denying condition. FindUserByEmail's
// paired read-your-writes obligation holds the same way: both methods
// read/write through the same st.db connection, so there is no replica
// hop between a CreateUser and the FindUserByEmail authlayer/auth.Service.SignUp
// runs immediately afterward.
func (st *AuthStore) CreateUser(ctx context.Context, u auth.UserBase) (auth.UserBase, error) {
	u.Email = auth.NormalizeEmail(u.Email)
	_, err := st.db.Insert(st.s.Users).Row(st.s.users.row(u)...).Exec(ctx)
	if err == nil {
		return u, nil
	}
	if !errors.Is(err, pg.ErrUniqueViolation) {
		return auth.UserBase{}, err
	}
	if isPrimaryKeyViolation(err) {
		return auth.UserBase{}, fmt.Errorf("%w: %w", auth.ErrIDTaken, err)
	}
	return auth.UserBase{}, fmt.Errorf("%w: %w", auth.ErrEmailTaken, err)
}

// FindUserByID loads a user by id, mapping drops' ErrNoRows to
// auth.ErrUserNotFound.
func (st *AuthStore) FindUserByID(ctx context.Context, id string) (auth.UserBase, error) {
	var u auth.UserBase
	err := st.db.Select().From(st.s.Users).
		Where(st.s.users.eq("id", id)).
		One(ctx, &u)
	if err != nil {
		return auth.UserBase{}, mapNoRows(err, auth.ErrUserNotFound)
	}
	return u, nil
}

// FindUserByEmail normalizes email (see [auth.NormalizeEmail]) and loads the
// user with that normalized address, mapping drops' ErrNoRows to
// auth.ErrUserNotFound.
func (st *AuthStore) FindUserByEmail(ctx context.Context, email string) (auth.UserBase, error) {
	var u auth.UserBase
	err := st.db.Select().From(st.s.Users).
		Where(st.s.users.eq("email", auth.NormalizeEmail(email))).
		One(ctx, &u)
	if err != nil {
		return auth.UserBase{}, mapNoRows(err, auth.ErrUserNotFound)
	}
	return u, nil
}

// MarkEmailVerified stamps EmailVerifiedAt and UpdatedAt with now as one
// statement:
//
//	UPDATE <users> SET email_verified_at = $1, updated_at = $1
//	 WHERE id = $2 AND email = $3
//
// The email = $3 predicate is what makes the check and the write one atomic
// step, exactly as [auth.Store.MarkEmailVerified]'s doc requires: PostgreSQL
// evaluates the whole WHERE clause and applies the SET under a single row
// operation, so there is no window in which a concurrent
// [AuthStore.UpdateUserEmail] can land between "checked" and "written" —
// unlike a SELECT to compare followed by a separate UPDATE, which the
// interface doc explicitly calls out as insufficient even when each half is
// individually safe.
//
// Zero rows affected is ambiguous between "no such user" and "user exists
// but its current email does not match" — a single UPDATE cannot say which,
// so, on that path only, a read-only follow-up (FindUserByID) classifies
// the failure into auth.ErrUserNotFound or auth.ErrEmailMismatch. That
// follow-up cannot reopen the race the UPDATE above closes: it never
// writes, and the UPDATE has already committed (or not) by the time it
// runs — the same reasoning [InviteStore.ConsumeLink] and
// [AuthStore.MarkRotated] rely on for their own zero-rows classification.
func (st *AuthStore) MarkEmailVerified(ctx context.Context, userID, email string, now time.Time) error {
	email = auth.NormalizeEmail(email)
	res, err := st.db.Update(st.s.Users).
		Set(
			st.s.users.bind("email_verified_at", &now),
			st.s.users.bind("updated_at", now),
		).
		Where(st.s.users.eq("id", userID), st.s.users.eq("email", email)).
		Exec(ctx)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n > 0 {
		return nil
	}

	if _, ferr := st.FindUserByID(ctx, userID); errors.Is(ferr, auth.ErrUserNotFound) {
		return auth.ErrUserNotFound
	} else if ferr != nil {
		return ferr
	}
	return auth.ErrEmailMismatch
}

// UpdateUserPassword overwrites PasswordHash and stamps UpdatedAt with now,
// reporting auth.ErrUserNotFound when userID matches no row.
func (st *AuthStore) UpdateUserPassword(ctx context.Context, userID, passwordHash string, now time.Time) error {
	res, err := st.db.Update(st.s.Users).
		Set(
			st.s.users.bind("password_hash", passwordHash),
			st.s.users.bind("updated_at", now),
		).
		Where(st.s.users.eq("id", userID)).
		Exec(ctx)
	return affectedOrErr(res, err, auth.ErrUserNotFound)
}

// UpdateUserEmail normalizes email (see [auth.NormalizeEmail]) and
// overwrites Email, unconditionally clears EmailVerifiedAt to NULL, and
// stamps UpdatedAt with now, as one statement:
//
//	UPDATE <users> SET email = $1, email_verified_at = NULL, updated_at = $2
//	 WHERE id = $3
//
// This single UPDATE is what makes the uniqueness check and the write one
// atomic step, exactly as [auth.Store.UpdateUserEmail]'s doc requires:
// rather than a separate pre-check SELECT, the table's own UNIQUE(email)
// index (see [AuthSchema]) is what performs the check, under the same row
// operation as the write, and rejects it with pg.ErrUniqueViolation
// (mapped to auth.ErrEmailTaken) if a *different* row already holds the
// normalized address. Updating a row to the address it already holds is
// never flagged as a conflict: a UNIQUE index only rejects a value some
// OTHER row holds, never the row's own current value, so this needs no
// special-cased exclusion the way store/memory's linear scan does.
//
// email_verified_at is bound to a typed nil *time.Time, which colSet.bind
// renders as the NULL keyword rather than a parameter (see columns.go) —
// the same nullable-clear mechanism [InviteStore] never needed and this
// store is the first to exercise on a write.
func (st *AuthStore) UpdateUserEmail(ctx context.Context, userID, email string, now time.Time) error {
	email = auth.NormalizeEmail(email)
	res, err := st.db.Update(st.s.Users).
		Set(
			st.s.users.bind("email", email),
			st.s.users.bind("email_verified_at", (*time.Time)(nil)),
			st.s.users.bind("updated_at", now),
		).
		Where(st.s.users.eq("id", userID)).
		Exec(ctx)
	if err != nil {
		if errors.Is(err, pg.ErrUniqueViolation) {
			return auth.ErrEmailTaken
		}
		return err
	}
	return affectedOrErr(res, nil, auth.ErrUserNotFound)
}

// ── Sessions ────────────────────────────────────────────────────────────

// CreateSession persists an already-stamped session and returns it
// unchanged. A unique violation is classified via [isPrimaryKeyViolation]:
// ErrIDTaken (wrapping the original error, never discarding it) when the
// row's own id already exists; otherwise it is propagated unchanged, since
// it must then be TokenHash's own UNIQUE constraint — this method's
// caller's obligation to avoid colliding, not this method's own check, per
// [auth.Session.TokenHash]'s doc.
func (st *AuthStore) CreateSession(ctx context.Context, sess auth.Session) (auth.Session, error) {
	return st.insertSession(ctx, st.db, sess)
}

// insertSession is CreateSession's implementation, parameterized over which
// *pg.DB to issue the INSERT against: st.db for an ordinary call, a
// transaction-scoped DB (from [pg.DB.InTx]) for
// [AuthStore.CreateSuccessorSession]'s composition — so both share the
// identical column binding and unique-violation classification rather than
// one being a hand-copied near-duplicate of the other that could silently
// drift from it.
func (st *AuthStore) insertSession(ctx context.Context, db *pg.DB, sess auth.Session) (auth.Session, error) {
	_, err := db.Insert(st.s.Sessions).Row(st.s.sessions.row(sess)...).Exec(ctx)
	if err == nil {
		return sess, nil
	}
	if !errors.Is(err, pg.ErrUniqueViolation) {
		return auth.Session{}, err
	}
	if isPrimaryKeyViolation(err) {
		return auth.Session{}, fmt.Errorf("%w: %w", auth.ErrIDTaken, err)
	}
	return auth.Session{}, err
}

// FindSessionByHash loads the session whose TokenHash matches, mapping
// drops' ErrNoRows to auth.ErrSessionNotFound.
func (st *AuthStore) FindSessionByHash(ctx context.Context, tokenHash string) (auth.Session, error) {
	var sess auth.Session
	err := st.db.Select().From(st.s.Sessions).
		Where(st.s.sessions.eq("token_hash", tokenHash)).
		One(ctx, &sess)
	if err != nil {
		return auth.Session{}, mapNoRows(err, auth.ErrSessionNotFound)
	}
	return sess, nil
}

// ListSessionsByUser returns every session belonging to userID, rotated or
// not, expired or not — the caller filters. A user with none yields nil,
// not an error.
func (st *AuthStore) ListSessionsByUser(ctx context.Context, userID string) ([]auth.Session, error) {
	var out []auth.Session
	if err := st.db.Select().From(st.s.Sessions).
		Where(st.s.sessions.eq("user_id", userID)).
		All(ctx, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// DeleteSession removes a session by id, reporting auth.ErrSessionNotFound
// when no row matched.
func (st *AuthStore) DeleteSession(ctx context.Context, id string) error {
	res, err := st.db.Delete(st.s.Sessions).
		Where(st.s.sessions.eq("id", id)).
		Exec(ctx)
	return affectedOrErr(res, err, auth.ErrSessionNotFound)
}

// DeleteSessionsByFamily removes every session sharing familyID. Deleting
// zero rows is not an error.
func (st *AuthStore) DeleteSessionsByFamily(ctx context.Context, familyID string) error {
	_, err := st.db.Delete(st.s.Sessions).
		Where(st.s.sessions.eq("family_id", familyID)).
		Exec(ctx)
	return err
}

// MarkRotated implements auth.Store's central compare-and-set as one
// statement:
//
//	UPDATE <sessions> SET rotated_at = $1
//	 WHERE token_hash = $2 AND rotated_at IS NULL
//	 RETURNING <every session column>
//
// rotated_at IS NULL is the predicate that turns this from a plain UPDATE
// into a compare-and-set: PostgreSQL decides "does a row match this hash,
// and is it still unrotated" and applies the SET under a single row lock —
// there is no window between a check and a write for a second concurrent
// caller to land in, exactly the atomicity [auth.Store.MarkRotated]'s doc
// requires. Dropping that predicate would let every concurrent caller win,
// which is precisely the undetectable-parallel-session failure this method
// exists to prevent. This is only a single-winner guarantee when TokenHash
// actually identifies at most one row — see [auth.Session.TokenHash]'s doc,
// enforced here by [AuthSchema]'s UNIQUE(token_hash).
//
// Expiry is deliberately absent from the WHERE — see the interface doc for
// why an expired-but-unrotated session must still be markable, and why
// folding an ExpiresAt check in here would be wrong.
//
// RETURNING gets the winning caller the full updated row in the same round
// trip, rather than a second read after a successful write. When the
// UPDATE matches nothing — no row parses out of the RETURNING clause, so
// [pg.UpdateBuilder.One] reports pg.ErrNoRows — that is ambiguous between
// "no session has this token hash at all" and "a session has it but is
// already rotated": a single UPDATE cannot say which. Exactly as
// [InviteStore.ConsumeLink] does for the identical ambiguity, only that
// zero-rows path re-reads the row (via FindSessionByHash), purely to
// classify the failure into auth.ErrSessionNotFound or (that session,
// false, nil). That follow-up read never writes, so it cannot reopen the
// atomicity gap above — the UPDATE has already committed, or not, by the
// time it runs.
func (st *AuthStore) MarkRotated(ctx context.Context, tokenHash string, now time.Time) (auth.Session, bool, error) {
	cols := st.s.Sessions.Columns()
	returning := make([]drops.Expression, len(cols))
	for i, c := range cols {
		returning[i] = c
	}

	var sess auth.Session
	err := st.db.Update(st.s.Sessions).
		Set(st.s.sessions.bind("rotated_at", &now)).
		Where(
			st.s.sessions.eq("token_hash", tokenHash),
			pg.IsNull(st.s.sessions.col("rotated_at")),
		).
		Returning(returning...).
		One(ctx, &sess)
	if err == nil {
		return sess, true, nil
	}
	if !errors.Is(err, pg.ErrNoRows) {
		return auth.Session{}, false, err
	}

	existing, ferr := st.FindSessionByHash(ctx, tokenHash)
	if ferr != nil {
		return auth.Session{}, false, ferr
	}
	return existing, false, nil
}

// CreateSuccessorSession implements auth.Store's rotation-race closure — see
// that method's own doc on [auth.Store] for the full contract and why it
// exists. The existence check for predecessorID and the insert of sess are
// composed into one PostgreSQL transaction via [pg.DB.InTx]:
//
//	BEGIN;
//	SELECT id FROM <sessions> WHERE id = $1 FOR UPDATE;  -- predecessorID
//	-- if no row: COMMIT (nothing further; ok=false)
//	-- if found:  INSERT INTO <sessions> (...) VALUES (...);  COMMIT; ok=true
//
// FOR UPDATE takes a row lock on the predecessor for as long as this
// transaction stays open, so a concurrent [AuthStore.DeleteSessionsByFamily]
// call also targeting that row — the reuse-triggered (or explicit
// [github.com/bernardoforcillo/authlayer/auth.Service.LogoutAll]-triggered)
// family revocation this method exists to not silently undo — blocks on
// that same row until this transaction commits or rolls back, rather than
// racing it. If the predecessor is already gone when the SELECT runs
// ([pg.ErrNoRows]), the transaction commits having done nothing further:
// no INSERT is attempted, ok is false, and the family is left exactly as
// revoked as DeleteSessionsByFamily made it — the SPECIFIC defect this
// method was written to fix: an unconditional INSERT reached after a
// completed revocation used to resurrect the family with one live session.
//
// This closes that scenario — and any interleaving where
// DeleteSessionsByFamily's own row-lock attempt on the predecessor is
// already blocked behind, or resolves before, this transaction even
// starts — with certainty: PostgreSQL's row lock guarantees a DELETE
// targeting a row this transaction holds FOR UPDATE cannot proceed until
// this transaction ends, and a DELETE that has ALREADY committed leaves
// nothing for the SELECT to find. It does NOT close a narrower window
// where this transaction's FOR UPDATE lock is acquired (and this
// transaction commits, inserting sess) BEFORE a concurrent DeleteSessionsByFamily
// statement has even taken ITS OWN read snapshot: PostgreSQL's per-statement
// MVCC snapshot means that DELETE can still correctly remove the
// predecessor (a row already within its snapshot, re-checked via
// EvalPlanQual once unblocked) while never seeing sess at all, since sess
// did not exist under a snapshot taken before this transaction committed —
// leaving sess as the family's sole survivor. Closing that fully would need
// a family-level lock (an advisory lock keyed by family_id, held by every
// mutator of that family) rather than a per-row one; not implemented here,
// because it is a materially narrower window than the one this method was
// written to close (this call's several preceding steps — FindUserByID,
// GenerateOpaque, token.Issue — make it, in practice, arrive well after a
// racing replay's own near-immediate DeleteSessionsByFamily has already
// taken its snapshot) and widening the fix to a family-level lock was not
// requested. See this package's own integration test for the scenario this
// DOES close deterministically.
func (st *AuthStore) CreateSuccessorSession(ctx context.Context, predecessorID string, sess auth.Session) (auth.Session, bool, error) {
	var created auth.Session
	won := false

	err := st.db.InTx(ctx, func(txdb *pg.DB) error {
		var predecessor struct {
			ID string `drop:"id"`
		}
		selErr := txdb.Select(st.s.sessions.col("id")).
			From(st.s.Sessions).
			Where(st.s.sessions.eq("id", predecessorID)).
			ForUpdate().
			One(ctx, &predecessor)
		if errors.Is(selErr, pg.ErrNoRows) {
			// The predecessor is already gone: the family was revoked out
			// from under this rotation. Commit having done nothing further.
			return nil
		}
		if selErr != nil {
			return selErr
		}

		c, cerr := st.insertSession(ctx, txdb, sess)
		if cerr != nil {
			return cerr
		}
		created, won = c, true
		return nil
	})
	if err != nil {
		return auth.Session{}, false, err
	}
	return created, won, nil
}

// ── Verifications ───────────────────────────────────────────────────────

// CreateVerification normalizes v.Email (see [auth.NormalizeEmail]) —
// unconditionally, regardless of v.Purpose, matching store/memory — inserts
// the result, and returns it. A unique violation is classified via
// [isPrimaryKeyViolation]: ErrIDTaken (wrapping the original error, never
// discarding it) when the row's own id already exists; otherwise it is
// propagated unchanged, since it must then be TokenHash's own UNIQUE
// constraint — this method's caller's obligation, per
// [auth.Verification.TokenHash]'s doc.
func (st *AuthStore) CreateVerification(ctx context.Context, v auth.Verification) (auth.Verification, error) {
	v.Email = auth.NormalizeEmail(v.Email)
	_, err := st.db.Insert(st.s.Verifications).Row(st.s.verifications.row(v)...).Exec(ctx)
	if err == nil {
		return v, nil
	}
	if !errors.Is(err, pg.ErrUniqueViolation) {
		return auth.Verification{}, err
	}
	if isPrimaryKeyViolation(err) {
		return auth.Verification{}, fmt.Errorf("%w: %w", auth.ErrIDTaken, err)
	}
	return auth.Verification{}, err
}

// FindVerificationByHash loads the verification whose TokenHash matches,
// mapping drops' ErrNoRows to auth.ErrVerificationNotFound.
func (st *AuthStore) FindVerificationByHash(ctx context.Context, tokenHash string) (auth.Verification, error) {
	var v auth.Verification
	err := st.db.Select().From(st.s.Verifications).
		Where(st.s.verifications.eq("token_hash", tokenHash)).
		One(ctx, &v)
	if err != nil {
		return auth.Verification{}, mapNoRows(err, auth.ErrVerificationNotFound)
	}
	return v, nil
}

// DeleteVerification removes a verification by id, reporting
// auth.ErrVerificationNotFound when no row matched.
func (st *AuthStore) DeleteVerification(ctx context.Context, id string) error {
	res, err := st.db.Delete(st.s.Verifications).
		Where(st.s.verifications.eq("id", id)).
		Exec(ctx)
	return affectedOrErr(res, err, auth.ErrVerificationNotFound)
}

// DeleteVerificationsByUserAndPurpose removes every verification for
// (userID, purpose). Deleting zero rows is not an error.
func (st *AuthStore) DeleteVerificationsByUserAndPurpose(ctx context.Context, userID, purpose string) error {
	_, err := st.db.Delete(st.s.Verifications).
		Where(st.s.verifications.eq("user_id", userID), st.s.verifications.eq("purpose", purpose)).
		Exec(ctx)
	return err
}

// ── Housekeeping ────────────────────────────────────────────────────────

// PurgeExpired deletes every Session and Verification expired strictly
// before before — both by ExpiresAt — and returns how many rows were
// removed in total, across both tables. UserBase rows are never purged.
// Housekeeping, not a security boundary — unlike MarkRotated or
// MarkEmailVerified this is not required to be atomic with anything else,
// so it is two plain DELETEs rather than one statement, matching
// [InviteStore.PurgeExpired].
func (st *AuthStore) PurgeExpired(ctx context.Context, before time.Time) (int, error) {
	res1, err := st.db.Delete(st.s.Sessions).
		Where(pg.Lt(st.s.sessions.col("expires_at"), before)).
		Exec(ctx)
	if err != nil {
		return 0, err
	}
	a1, err := res1.RowsAffected()
	if err != nil {
		return 0, err
	}

	res2, err := st.db.Delete(st.s.Verifications).
		Where(pg.Lt(st.s.verifications.col("expires_at"), before)).
		Exec(ctx)
	if err != nil {
		return 0, err
	}
	a2, err := res2.RowsAffected()
	if err != nil {
		return 0, err
	}

	return int(a1 + a2), nil
}
