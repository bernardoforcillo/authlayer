package dropsstore

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/bernardoforcillo/drops/pg"

	"github.com/bernardoforcillo/authlayer/auth"
)

// MFANames are the two table names an MFAStore persists to. The zero value
// defaults to "mfa_factors" and "mfa_recovery_codes".
type MFANames struct {
	Factors       string // default "mfa_factors"
	RecoveryCodes string // default "mfa_recovery_codes"
}

func (n MFANames) withDefaults() MFANames {
	if n.Factors == "" {
		n.Factors = "mfa_factors"
	}
	if n.RecoveryCodes == "" {
		n.RecoveryCodes = "mfa_recovery_codes"
	}
	return n
}

type mfaSettings struct {
	names MFANames
	ids   idTypes
}

// MFAOption customizes an [MFASchema] or [MFAStore] at construction.
type MFAOption func(*mfaSettings)

// WithMFANames overrides the two table names, so a consumer that already
// owns a table by either name can point this store elsewhere.
func WithMFANames(n MFANames) MFAOption {
	return func(s *mfaSettings) { s.names = n }
}

// WithMFATextLibraryIDs types every id column on the two MFA tables as text
// rather than uuid: mfa_recovery_codes.id, and the mfa_factors.user_id and
// mfa_recovery_codes.user_id columns that reference users.id.
//
// authlayer generates UUIDv7 ids (internal/uid) for every recovery code it
// mints, so uuid is the default and stays the default. Use this when
// [github.com/bernardoforcillo/authlayer/auth.WithIDGenerator] has replaced
// that generator with one whose output PostgreSQL's uuid parser does not
// accept — a ULID, a database sequence, a readable "usr_a1b2c3":
//
//	st := dropsstore.NewAuthStore(db, dropsstore.WithAuthTextLibraryIDs())
//	mfa := dropsstore.NewMFAStore(db, dropsstore.WithMFATextLibraryIDs())
//	svc := auth.New(st, auth.WithMFAStore(mfa), auth.WithIDGenerator(ulid.Make))
//
// Like [WithAuthTextLibraryIDs] and [WithIdentityTextLibraryIDs], this is
// ONE option covering both id families rather than two: the user_id columns
// are references to the users table [AuthStore] owns, not values supplied
// from outside, so no coherent configuration exists in which they disagree
// with users.id. It MUST be passed alongside [WithAuthTextLibraryIDs].
//
// Changing it changes the DDL [MFAStore.CreateSchema] emits for a table
// that does not exist yet. Like every other part of that call it will not
// migrate a table that already exists.
func WithMFATextLibraryIDs() MFAOption {
	return func(s *mfaSettings) { s.ids = idTypes{library: false, user: false} }
}

// MFASchema holds the two second-factor tables and their derived columns:
//
//	<mfa_factors>         user_id PK, secret_enc, confirmed_at, created_at,
//	                      last_step
//	<mfa_recovery_codes>  id PK, user_id, code_hash, used_at, created_at,
//	                      INDEX (user_id, code_hash)
//
// # user_id is the factors table's PRIMARY KEY, and that is the port's rule
//
// [auth.MFAFactor] carries no surrogate id: a user has at most one factor,
// and that rule IS the key rather than a constraint bolted beside a
// separate one. The column declares it through the `drop:"user_id,pk"` tag
// option (see columns.go), so it is part of a fresh table's own CREATE
// TABLE. Without it two rows could exist for one user, and which secret
// authenticates the account — and which last_step guards it — would be
// decided by whichever row the server returned first.
//
// It is also what [MFAStore.UpsertFactor]'s ON CONFLICT (user_id) infers
// its arbiter index from, so the upsert is a single atomic statement rather
// than a delete-then-insert that a concurrent double-submit can fail.
//
// # (user_id, code_hash) is one index serving three statements
//
// [MFAStore.ListRecoveryCodes] and [MFAStore.ReplaceRecoveryCodes] filter
// on user_id alone, and [MFAStore.ConsumeRecoveryCode] on the pair; a
// composite index leading with user_id serves all three. Column order is
// (user_id, code_hash) rather than the reverse because user_id is the
// selective half and the only one two of the three statements mention at
// all — the same reasoning [AuthSchema]'s (user_id, purpose) index records.
//
// It is deliberately NOT unique. Two rows sharing (user_id, code_hash)
// cannot arise from a salted hasher, but the port does not require the
// hasher to be salted, and a unique constraint would turn an
// astronomically-unlikely collision into a refused enrolment. The
// single-winner property does not need it either: ConsumeRecoveryCode's one
// UPDATE burns EVERY matching unused row under one set of row locks, so a
// duplicate is spent along with its twin rather than surviving it — which
// is exactly what auth.MFAStore.ConsumeRecoveryCode requires of an
// implementation that somehow holds one.
//
// # The two nullable columns
//
// confirmed_at ([auth.MFAFactor.ConfirmedAt]) and last_step
// ([auth.MFAFactor.LastStep]) are both nullable, and in both cases NULL is
// a state the service acts on rather than a missing value: "this factor has
// not been confirmed, so it must not gate a login" and "this factor has
// authenticated no step yet, so any step is acceptable". used_at on the
// recovery codes is the third. colSet types a *time.Time or *int64 column
// without NOT NULL and renders a nil one as the NULL keyword; no special
// handling is needed here beyond letting the model's own pointer types
// through.
//
// [auth.MFAFactor] and [auth.RecoveryCode] are fixed shapes, unlike the
// generic scope Store, so unlike [Schema] this type is not parameterized.
type MFASchema struct {
	// Factors is the enrolled-TOTP-factor table. See [auth.MFAFactor] —
	// secret_enc holds ciphertext, never a base32 secret.
	Factors *pg.Table
	// RecoveryCodes is the single-use recovery-code table. See
	// [auth.RecoveryCode] — code_hash holds a password-grade hash, never a
	// code.
	RecoveryCodes *pg.Table

	factors *colSet
	codes   *colSet
}

// NewMFASchema builds the schema for one MFA store instance.
// [NewMFAStore] calls it, so use it directly only when you need the table
// definitions without a store — to generate DDL for a migration, for
// instance.
func NewMFASchema(opts ...MFAOption) *MFASchema {
	cfg := mfaSettings{ids: uuidIDs()}
	for _, o := range opts {
		o(&cfg)
	}
	names := cfg.names.withDefaults()

	s := &MFASchema{
		Factors:       pg.NewTable(names.Factors),
		RecoveryCodes: pg.NewTable(names.RecoveryCodes),
	}
	// One idTypes for both tables, with both families always set the same
	// way — see [WithMFATextLibraryIDs] for why these tables, like the auth
	// and identity ones, have no text-user-id option of their own.
	s.factors = newColSet(s.Factors, auth.MFAFactor{}, cfg.ids)
	s.codes = newColSet(s.RecoveryCodes, auth.RecoveryCode{}, cfg.ids)

	s.RecoveryCodes.AddIndex(pg.NewIndex(
		names.RecoveryCodes+"_user_id_code_hash_idx", s.RecoveryCodes,
		s.codes.col("user_id"), s.codes.col("code_hash"),
	))

	return s
}

// MFAStore is a drops-backed auth.MFAStore: the `mfa_factors` and
// `mfa_recovery_codes` tables, and nothing else. It is the optional
// second-factor port, wired with
// [github.com/bernardoforcillo/authlayer/auth.WithMFAStore]; an application
// offering no second factor never constructs one, and never creates the
// tables.
//
// It does NOT own the users table — that belongs to [AuthStore], which may
// be an entirely different backend — and reads no user row.
//
// Like [AuthStore], [IdentityStore] and [InviteStore] it is pure
// persistence: it encrypts nothing, hashes nothing, mints nothing, and
// authorizes nothing. The TOTP secret arrives already encrypted and the
// recovery codes already hashed; a dump of these two tables yields no
// working credential to anyone who does not also hold the cipher key.
type MFAStore struct {
	db *pg.DB
	s  *MFASchema
}

// Compile-time proof the drops MFA store satisfies the port.
var _ auth.MFAStore = (*MFAStore)(nil)

// NewMFAStore returns an MFAStore over db, building a fresh [MFASchema].
func NewMFAStore(db *pg.DB, opts ...MFAOption) *MFAStore {
	return &MFAStore{db: db, s: NewMFASchema(opts...)}
}

// Schema exposes the tables so callers can build guards, join against them,
// or emit their own DDL.
func (st *MFAStore) Schema() *MFASchema { return st.s }

// CreateSchema issues CREATE TABLE IF NOT EXISTS for both tables, then
// CREATE INDEX IF NOT EXISTS for the recovery-code index. Every statement
// is idempotent, so the call is safe to re-run and self-heals a
// pre-existing table missing the index.
//
// Like every other CreateSchema in this package it adds what is missing and
// never alters what is already there, so production deployments that own
// these tables via their own migrations should skip it. In particular it
// cannot RETYPE an existing table, so [WithMFATextLibraryIDs] has no effect
// on one, and it cannot add a missing COLUMN or the factors table's PRIMARY
// KEY — both live inside the CREATE TABLE that no-ops away entirely against
// a table that already exists. No foreign key to the users table is
// declared, matching this codebase's other schemas — and here it is also
// forced: [AuthStore] may be a different backend.
func (st *MFAStore) CreateSchema(ctx context.Context) error {
	for _, t := range []*pg.Table{st.s.Factors, st.s.RecoveryCodes} {
		if _, err := st.db.ExecExpr(ctx, pg.CreateTableIfNotExists(t)); err != nil {
			return err
		}
		for _, ddl := range compositeConstraintDDL(t) {
			if _, err := st.db.ExecExpr(ctx, ddl); err != nil {
				return err
			}
		}
		for _, idx := range t.Indexes() {
			if _, err := st.db.ExecExpr(ctx, pg.CreateIndexIfNotExists(idx)); err != nil {
				return err
			}
		}
	}
	return nil
}

// UpsertFactor writes f as its user's one factor:
//
//	INSERT INTO <mfa_factors> (user_id, secret_enc, confirmed_at, created_at, last_step)
//	VALUES ($1, $2, $3, $4, $5)
//	ON CONFLICT (user_id) DO UPDATE
//	   SET secret_enc = $6, confirmed_at = $7, created_at = $8, last_step = $9
//
// Every non-key column is assigned, including the NULLs a fresh enrolment
// carries, which is what makes this the whole-row REPLACEMENT
// auth.MFAStore.UpsertFactor's MUST requires rather than a merge. Omitting
// confirmed_at from that SET list would leave a brand-new secret marked
// confirmed by a previous enrolment — a factor gating every login with a
// secret no authenticator holds — and omitting last_step would refuse the
// new secret's first genuine code as a replay.
//
// The DO UPDATE assignments bind the same values the VALUES clause does,
// rather than reading them back through EXCLUDED. The two are equivalent
// here (the row is not modified between the two clauses) and the explicit
// bindings keep this method free of a second way to name a column.
//
// It is ONE statement, so a concurrent double-submit of an enrolment
// resolves into one row without either caller seeing a unique violation —
// which a delete-then-insert pair in a transaction could not promise. The
// arbiter index is the PRIMARY KEY on user_id; see [MFASchema] for why that
// column is the key.
func (st *MFAStore) UpsertFactor(ctx context.Context, f auth.MFAFactor) error {
	_, err := st.db.Insert(st.s.Factors).
		Row(st.s.factors.row(f)...).
		OnConflictUpdate(st.s.factors.col("user_id")).
		Set(
			st.s.factors.bind("secret_enc", f.SecretEnc),
			st.s.factors.bind("confirmed_at", f.ConfirmedAt),
			st.s.factors.bind("created_at", f.CreatedAt),
			st.s.factors.bind("last_step", f.LastStep),
		).
		Done().
		Exec(ctx)
	return err
}

// FindFactor loads the user's factor, mapping drops' ErrNoRows to
// auth.ErrFactorNotFound. At most one row can match, and that is enforced
// by the database rather than assumed: user_id is the table's PRIMARY KEY.
func (st *MFAStore) FindFactor(ctx context.Context, userID string) (auth.MFAFactor, error) {
	var f auth.MFAFactor
	err := st.db.Select().From(st.s.Factors).
		Where(st.s.factors.eq("user_id", userID)).
		One(ctx, &f)
	if err != nil {
		return auth.MFAFactor{}, mapNoRows(err, auth.ErrFactorNotFound)
	}
	return f, nil
}

// ConfirmFactor implements the port's confirmation compare-and-set as one
// statement:
//
//	UPDATE <mfa_factors> SET confirmed_at = $1
//	 WHERE user_id = $2 AND confirmed_at IS NULL
//
// `confirmed_at IS NULL` is the predicate that turns a plain UPDATE into a
// compare-and-set: PostgreSQL decides "is this factor still unconfirmed"
// and applies the SET under a single row lock, so there is no window
// between a check and a write for a second caller to land in. Dropping it
// would let every concurrent caller win, and the winner is the one that
// hands the user their recovery codes — see the port's own doc for the
// user-visible lockout two winners produce.
//
// Zero rows affected is ambiguous between "no factor at all" and "already
// confirmed", which a single UPDATE cannot distinguish, so that path
// re-reads the row purely to classify itself — exactly as
// [AuthStore.MarkRotated] does for the identical ambiguity. The follow-up
// read never writes, so it cannot reopen the atomicity above: the UPDATE
// has already committed, or not, by the time it runs.
func (st *MFAStore) ConfirmFactor(ctx context.Context, userID string, now time.Time) (bool, error) {
	res, err := st.db.Update(st.s.Factors).
		Set(st.s.factors.bind("confirmed_at", &now)).
		Where(
			st.s.factors.eq("user_id", userID),
			pg.IsNull(st.s.factors.col("confirmed_at")),
		).
		Exec(ctx)
	return st.wonOrClassify(ctx, userID, res, err)
}

// AdvanceStep implements the REPLAY GUARD as one statement:
//
//	UPDATE <mfa_factors> SET last_step = $1
//	 WHERE user_id = $2 AND (last_step IS NULL OR last_step < $3)
//
// The disjunction is the compare-and-set. `last_step < $3` refuses a step
// already spent and every step below it — the whole point of the method,
// since a TOTP code stays valid across the skew window and a code read over
// someone's shoulder is a usable credential until the step it belongs to is
// burnt. `last_step IS NULL` admits the factor's very first code, which
// would otherwise be refused: NULL compares false against everything, so
// without that arm a freshly confirmed factor could never authenticate at
// all.
//
// Being one statement is what makes it atomic. Two concurrent
// presentations of the SAME code — an attacker replaying a captured code
// alongside the user's own submission, which is the natural shape of the
// attack — both take the row lock in turn, and the second re-evaluates its
// predicate against the first's committed write and matches nothing.
//
// Zero rows affected is ambiguous between "no factor" and "that step is a
// replay", so it classifies itself with a follow-up read, exactly as
// [MFAStore.ConfirmFactor] does.
func (st *MFAStore) AdvanceStep(ctx context.Context, userID string, step int64) (bool, error) {
	res, err := st.db.Update(st.s.Factors).
		Set(st.s.factors.bind("last_step", &step)).
		Where(
			st.s.factors.eq("user_id", userID),
			pg.Or(
				pg.IsNull(st.s.factors.col("last_step")),
				pg.Lt(st.s.factors.col("last_step"), step),
			),
		).
		Exec(ctx)
	return st.wonOrClassify(ctx, userID, res, err)
}

// wonOrClassify turns a compare-and-set UPDATE's result into the port's
// (bool, error): one row affected is a win; zero rows is ambiguous between
// "no such factor" and "the predicate refused", so the factor is re-read to
// say which. It is shared by [MFAStore.ConfirmFactor] and
// [MFAStore.AdvanceStep] because the ambiguity, and its resolution, are
// identical for both.
func (st *MFAStore) wonOrClassify(ctx context.Context, userID string, res interface {
	RowsAffected() (int64, error)
}, err error,
) (bool, error) {
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	if n > 0 {
		return true, nil
	}
	if _, err := st.FindFactor(ctx, userID); err != nil {
		return false, err
	}
	return false, nil
}

// DeleteFactor removes the user's factor row — a single DELETE keyed on the
// primary key — reporting auth.ErrFactorNotFound when it affects no row.
//
// It touches the recovery codes not at all. See
// auth.MFAStore.DeleteFactor for why the extent of that cascade belongs to
// the caller, and what the caller therefore owes when disabling MFA.
func (st *MFAStore) DeleteFactor(ctx context.Context, userID string) error {
	res, err := st.db.Delete(st.s.Factors).
		Where(st.s.factors.eq("user_id", userID)).
		Exec(ctx)
	return affectedOrErr(res, err, auth.ErrFactorNotFound)
}

// ReplaceRecoveryCodes replaces the user's whole set inside one
// transaction:
//
//	BEGIN;
//	DELETE FROM <mfa_recovery_codes> WHERE user_id = $1;
//	INSERT INTO <mfa_recovery_codes> (...) VALUES (...), (...), ...;
//	COMMIT;
//
// The transaction is what makes it all-or-nothing, which the port requires:
// half of this is either a set of codes the user has already been shown and
// cannot use, or an account with no recovery codes at all whose user
// believes they hold ten — and neither is recoverable by retrying, since
// the plaintext codes are displayed exactly once.
//
// The foreign-user check runs BEFORE the transaction opens, so a call
// carrying a code that names somebody else never reaches a statement at
// all. Id collisions are left to the PRIMARY KEY: a duplicate inside the
// batch, or an id another user's row already holds, fails the INSERT with a
// unique violation that is classified as auth.ErrIDTaken and rolls the
// whole transaction back — the uniqueness decision and the write are one
// step, as [AuthStore.CreateUser] and [IdentityStore.CreateIdentity]
// require of themselves. An id belonging to a row this same call deletes is
// free to reuse, because that DELETE runs first inside the same
// transaction.
//
// An empty or nil codes issues the DELETE and no INSERT, which is how a
// caller revokes recovery codes without issuing new ones.
func (st *MFAStore) ReplaceRecoveryCodes(ctx context.Context, userID string, codes []auth.RecoveryCode) error {
	for _, c := range codes {
		if c.UserID != userID {
			return fmt.Errorf("%w: code %s names user %s", auth.ErrRecoveryCodeUserMismatch, c.ID, c.UserID)
		}
	}

	return st.db.InTx(ctx, func(txdb *pg.DB) error {
		if _, err := txdb.Delete(st.s.RecoveryCodes).
			Where(st.s.codes.eq("user_id", userID)).
			Exec(ctx); err != nil {
			return err
		}
		if len(codes) == 0 {
			return nil
		}

		rows := make([][]pg.ColumnValue, len(codes))
		for i, c := range codes {
			rows[i] = st.s.codes.row(c)
		}
		_, err := txdb.Insert(st.s.RecoveryCodes).Rows(rows...).Exec(ctx)
		if err != nil && errors.Is(err, pg.ErrUniqueViolation) {
			// The table's only unique-enforcing constraint is the primary
			// key on id — the (user_id, code_hash) index is deliberately
			// not unique, see [MFASchema] — so a unique violation here can
			// only be an id collision.
			return fmt.Errorf("%w: %w", auth.ErrIDTaken, err)
		}
		return err
	})
}

// ConsumeRecoveryCode burns the user's matching unused code as one
// statement:
//
//	UPDATE <mfa_recovery_codes> SET used_at = $1
//	 WHERE user_id = $2 AND code_hash = $3 AND used_at IS NULL
//
// `used_at IS NULL` is the compare-and-set: PostgreSQL decides "is this
// code still unspent" and stamps it under one row lock, so of any number of
// concurrent consumers exactly one is told it burnt the code. Without that
// predicate a single-use credential is usable as often as it is presented.
//
// The user_id predicate is not decoration either: matching on the hash
// alone would let one account's recovery code be spent against another's.
//
// It affects EVERY matching unused row rather than one of them, which the
// port requires of an implementation that somehow holds duplicates — a
// duplicate is spent alongside its twin rather than surviving as a live
// second copy of a code that has just been used. Zero rows affected is
// (false, nil): a wrong hash, an already-spent code and a user with no
// codes are all the same answer, deliberately, because this is a credential
// check and any finer distinction would tell an attacker which half of
// (user, code) they got wrong.
func (st *MFAStore) ConsumeRecoveryCode(ctx context.Context, userID, codeHash string, now time.Time) (bool, error) {
	res, err := st.db.Update(st.s.RecoveryCodes).
		Set(st.s.codes.bind("used_at", &now)).
		Where(
			st.s.codes.eq("user_id", userID),
			st.s.codes.eq("code_hash", codeHash),
			pg.IsNull(st.s.codes.col("used_at")),
		).
		Exec(ctx)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// ListRecoveryCodes returns every recovery code belonging to userID, used
// and unused alike, and only that user's. A user with none yields nil, not
// an error — callers MUST use len() rather than a nil comparison, since
// store/memory returns an empty non-nil slice for the same case and the
// port leaves the choice unspecified. Order is whatever the server returns
// and is likewise unspecified.
//
// The user_id predicate is served by [MFASchema]'s (user_id, code_hash)
// index through its leading column; see that type's doc, and the live
// EXPLAIN test that proves the planner picks it.
func (st *MFAStore) ListRecoveryCodes(ctx context.Context, userID string) ([]auth.RecoveryCode, error) {
	var out []auth.RecoveryCode
	if err := st.db.Select().From(st.s.RecoveryCodes).
		Where(st.s.codes.eq("user_id", userID)).
		All(ctx, &out); err != nil {
		return nil, err
	}
	return out, nil
}
