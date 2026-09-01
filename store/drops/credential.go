package dropsstore

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/bernardoforcillo/drops/pg"

	"github.com/bernardoforcillo/authlayer/auth"
)

// CredentialNames are the two table names a CredentialStore persists to. The
// zero value defaults to "credentials" and "passkey_challenges".
//
// It is a struct rather than bare string parameters so it reads and evolves
// exactly like [AuthNames], [IdentityNames], [InviteNames] and [Names] do.
type CredentialNames struct {
	Credentials string // default "credentials"
	Challenges  string // default "passkey_challenges"
}

func (n CredentialNames) withDefaults() CredentialNames {
	if n.Credentials == "" {
		n.Credentials = "credentials"
	}
	if n.Challenges == "" {
		n.Challenges = "passkey_challenges"
	}
	return n
}

type credentialSettings struct {
	names CredentialNames
	ids   idTypes
}

// CredentialOption customizes a [CredentialSchema] or [CredentialStore] at
// construction.
type CredentialOption func(*credentialSettings)

// WithCredentialNames overrides the two table names, so a consumer that
// already owns a table called "credentials" for something else can point this
// store elsewhere.
func WithCredentialNames(n CredentialNames) CredentialOption {
	return func(s *credentialSettings) { s.names = n }
}

// WithCredentialTextLibraryIDs types every id column on both tables as text
// rather than uuid: credentials.id, passkey_challenges.id, and — the part
// that makes this one option rather than two — the user_id columns that
// reference users.id.
//
// It is the exact counterpart of [WithIdentityTextLibraryIDs]; see that
// option for the full argument, which applies here unchanged, including why
// there is deliberately no text-USER-id option of its own (no coherent
// configuration exists in which these columns disagree with users.id) and why
// changing it does nothing to a table that already exists.
//
// It MUST be passed alongside [WithAuthTextLibraryIDs].
//
// Note what it does NOT reach: credentials.credential_id is bytea whatever
// this option says. That column holds an authenticator's own opaque
// identifier, not an id this library mints, and it is matched byte-for-byte —
// see [auth.Credential.CredentialID].
func WithCredentialTextLibraryIDs() CredentialOption {
	return func(s *credentialSettings) { s.ids = idTypes{library: false, user: false} }
}

// CredentialSchema holds the two passkey tables and their derived columns:
//
//	<credentials>         id PK, user_id, credential_id, public_key,
//	                      sign_count, transports, label, created_at,
//	                      last_used_at, UNIQUE (credential_id),
//	                      INDEX (user_id)
//	<passkey_challenges>  id PK, user_id (NULL), ceremony, challenge_hash,
//	                      expires_at, created_at, UNIQUE (challenge_hash)
//
// # UNIQUE (credential_id) is the load-bearing one
//
// [auth.Credential.CredentialID]'s doc states the MUST this constraint
// discharges. Without it two rows can name the same authenticator credential
// against two DIFFERENT local users, and a login resolving that credential id
// lands on whichever row the server happens to return first — one passkey
// silently able to sign in as either of two people, decided by row order.
// It is also what fails the loser of two concurrent registrations of one
// authenticator instead of letting both write. [auth.Credential] carries no
// "unique" tag option for the column and could not usefully: like the two
// TokenHash columns in [AuthSchema] it is registered through
// [pg.Table.AddUnique] and emitted by [CredentialStore.CreateSchema] as a
// guarded ALTER TABLE, so a pre-existing table missing the constraint
// self-heals.
//
// UNIQUE (challenge_hash) discharges [auth.Challenge.Hash]'s own MUST, for
// the reason [auth.Verification.TokenHash]'s does: FindChallengeByHash
// assumes at most one row can match.
//
// # INDEX (user_id) is not decoration either
//
// Three methods filter on credentials.user_id alone:
// [CredentialStore.ListCredentialsByUser] (every "your passkeys" screen, and
// the last-credential arithmetic behind every unlink),
// [CredentialStore.DeleteCredentialIfNotLast] (whose locking SELECT reads
// exactly the user's rows, inside a transaction, on every removal) and the
// service's own sweeps. Without the index all three sequentially scan a table
// that grows with the whole deployment's passkey count rather than with one
// user's, and the removal pays it while holding a transaction open.
// TestCredentialStoreListCredentialsByUserUsesTheIndexLive proves the planner
// actually picks it, with a control that drops it and requires the plan to
// degrade — an index the planner ignores is not an index.
//
// The challenges table carries no index beyond its two constraints. Its only
// non-hash predicate is PurgeExpiredChallenges' expires_at, which is a
// janitor sweep that visits most of the table anyway — the same reason the
// verifications table indexes (user_id, purpose) and not expires_at.
//
// # The two nullable columns
//
// credentials.last_used_at is nil until the credential first signs its user
// in, exactly as identities.last_used_at is.
// passkey_challenges.user_id is nil for a LOGIN ceremony, which names no
// account at all — see [auth.Challenge.UserID]. Both are pointer fields on
// the model, and colSet types a pointer field without NOT NULL and renders a
// nil one as the NULL keyword (see columns.go); the user_id one is why
// columns.go grew a nullable-string case, since writing "" into a uuid column
// fails outright.
//
// # sign_count is bigint, not integer
//
// [auth.Credential.SignCount] is a uint32 and PostgreSQL has no unsigned
// types, so `integer` would misrepresent every counter above 2^31 — and a
// counter compared wrong is a compare-and-set that accepts what it should
// refuse. colSet maps uint32 to bigint for this column and no other.
type CredentialSchema struct {
	// Credentials is the passkey table. See [auth.Credential] — public_key
	// is opaque bytes this package never parses.
	Credentials *pg.Table
	// Challenges is the outstanding-ceremony table. See [auth.Challenge]:
	// rows here are one-time, short-lived, and grant nothing on their own.
	Challenges *pg.Table

	credentials *colSet
	challenges  *colSet
}

// NewCredentialSchema builds the schema for one credential store instance.
// [NewCredentialStore] calls it, so use it directly only when you need the
// table definitions without a store — to generate DDL for a migration, for
// instance.
func NewCredentialSchema(opts ...CredentialOption) *CredentialSchema {
	cfg := credentialSettings{ids: uuidIDs()}
	for _, o := range opts {
		o(&cfg)
	}
	names := cfg.names.withDefaults()

	s := &CredentialSchema{
		Credentials: pg.NewTable(names.Credentials),
		Challenges:  pg.NewTable(names.Challenges),
	}
	// One idTypes for both tables, both families always set together — see
	// [WithCredentialTextLibraryIDs].
	s.credentials = newColSet(s.Credentials, auth.Credential{}, cfg.ids)
	s.challenges = newColSet(s.Challenges, auth.Challenge{}, cfg.ids)

	s.Credentials.AddUnique(names.Credentials+"_credential_id",
		s.credentials.col("credential_id"))
	s.Credentials.AddIndex(pg.NewIndex(
		names.Credentials+"_user_id_idx", s.Credentials, s.credentials.col("user_id")))
	s.Challenges.AddUnique(names.Challenges+"_challenge_hash",
		s.challenges.col("challenge_hash"))

	return s
}

// CredentialStore is a drops-backed auth.CredentialStore: the `credentials`
// and `passkey_challenges` tables, and nothing else. It is the optional
// passkey port, wired with
// [github.com/bernardoforcillo/authlayer/auth.WithCredentialStore]; an
// application offering no passkeys never constructs one, and never creates
// the tables.
//
// It verifies nothing about a WebAuthn ceremony — see auth/credential.go's
// package doc for the list of what the application owes. Like [AuthStore] and
// [IdentityStore] it is pure persistence: it hashes nothing, mints nothing,
// and authorizes nothing.
//
// It does NOT own the users table — that belongs to [AuthStore], which may
// even be a different backend — which is why
// [CredentialStore.DeleteCredentialIfNotLast] is told whether the account has
// another way in rather than working it out.
type CredentialStore struct {
	db *pg.DB
	s  *CredentialSchema
}

// Compile-time proof the drops credential store satisfies the port.
var _ auth.CredentialStore = (*CredentialStore)(nil)

// NewCredentialStore returns a CredentialStore over db, building a fresh
// [CredentialSchema].
func NewCredentialStore(db *pg.DB, opts ...CredentialOption) *CredentialStore {
	return &CredentialStore{db: db, s: NewCredentialSchema(opts...)}
}

// Schema exposes the tables so callers can build guards, join against them,
// or emit their own DDL.
func (st *CredentialStore) Schema() *CredentialSchema { return st.s }

// CreateSchema issues CREATE TABLE IF NOT EXISTS for both tables, followed by
// their UNIQUE constraints as guarded ALTER TABLEs and CREATE INDEX IF NOT
// EXISTS for the user_id index. Every statement is idempotent, so the call is
// safe to re-run and self-heals a pre-existing table missing a constraint or
// the index.
//
// Like every other CreateSchema here it adds what is missing and never alters
// what is already there, so production deployments that own these tables via
// their own migrations should skip it. In particular it cannot RETYPE an
// existing table: against one that already exists the CREATE TABLE is a
// no-op, so [WithCredentialTextLibraryIDs] has no effect on it. No foreign
// key to the users table is declared, matching this codebase's other schemas
// — and here it is also forced: [AuthStore] may be an entirely different
// backend.
func (st *CredentialStore) CreateSchema(ctx context.Context) error {
	for _, tbl := range []*pg.Table{st.s.Credentials, st.s.Challenges} {
		if _, err := st.db.ExecExpr(ctx, pg.CreateTableIfNotExists(tbl)); err != nil {
			return err
		}
		for _, ddl := range compositeConstraintDDL(tbl) {
			if _, err := st.db.ExecExpr(ctx, ddl); err != nil {
				return err
			}
		}
		for _, idx := range tbl.Indexes() {
			if _, err := st.db.ExecExpr(ctx, pg.CreateIndexIfNotExists(idx)); err != nil {
				return err
			}
		}
	}
	return nil
}

// ── Credentials ─────────────────────────────────────────────────────────

// CreateCredential inserts c and returns it unchanged. Nothing is normalized:
// credential_id and public_key are opaque bytes and label and transports are
// the application's own strings.
//
// A unique violation is classified via [isPrimaryKeyViolation] — see its doc
// for why this reads the driver's own *pgconn.PgError rather than re-querying:
// auth.ErrIDTaken when the row's own id already exists,
// auth.ErrCredentialRegistered otherwise, since UNIQUE (credential_id) is the
// table's only other unique-enforcing constraint (see [CredentialSchema]).
// Either sentinel wraps the original error rather than discarding it.
//
// This is a single INSERT with no preliminary SELECT, so the uniqueness
// decision and the write are one step exactly as auth.CredentialStore's doc
// requires: ErrCredentialRegistered can only ever come from the insert
// attempt itself failing against the constraint, never from a separate read
// that could race a concurrent registration. An existing row is therefore
// never silently replaced or re-pointed at a different user.
func (st *CredentialStore) CreateCredential(ctx context.Context, c auth.Credential) (auth.Credential, error) {
	_, err := st.db.Insert(st.s.Credentials).Row(st.s.credentials.row(c)...).Exec(ctx)
	if err == nil {
		return c, nil
	}
	if !errors.Is(err, pg.ErrUniqueViolation) {
		return auth.Credential{}, err
	}
	if isPrimaryKeyViolation(err) {
		return auth.Credential{}, fmt.Errorf("%w: %w", auth.ErrIDTaken, err)
	}
	return auth.Credential{}, fmt.Errorf("%w: %w", auth.ErrCredentialRegistered, err)
}

// FindCredentialByCredentialID loads the credential the authenticator named,
// mapping drops' ErrNoRows to auth.ErrCredentialNotFound.
//
// The comparison is bytea equality — byte-for-byte, with no collation and no
// folding, which is the property auth.Credential.CredentialID requires and
// the reason the column is bytea rather than text.
//
// At most one row can match, and that is enforced by the database rather than
// assumed: [CredentialSchema]'s UNIQUE (credential_id) is what makes "the row
// IS the account" a fact rather than a coin flip over row order.
func (st *CredentialStore) FindCredentialByCredentialID(ctx context.Context, credentialID []byte) (auth.Credential, error) {
	var c auth.Credential
	err := st.db.Select().From(st.s.Credentials).
		Where(st.s.credentials.eq("credential_id", credentialID)).
		One(ctx, &c)
	if err != nil {
		return auth.Credential{}, mapNoRows(err, auth.ErrCredentialNotFound)
	}
	return c, nil
}

// ListCredentialsByUser returns every credential belonging to userID, and
// only that user's. A user with none yields nil, not an error — callers MUST
// use len() rather than a nil comparison, since store/memory returns an empty
// non-nil slice for the same case and the port leaves the choice unspecified.
// Order is whatever the server returns and is likewise unspecified.
//
// The user_id predicate is served by [CredentialSchema]'s index on that
// column; see that type's doc, and the live EXPLAIN test that proves the
// planner picks it.
func (st *CredentialStore) ListCredentialsByUser(ctx context.Context, userID string) ([]auth.Credential, error) {
	var out []auth.Credential
	if err := st.db.Select().From(st.s.Credentials).
		Where(st.s.credentials.eq("user_id", userID)).
		All(ctx, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// UpdateSignCount implements the port's compare-and-set as one statement:
//
//	UPDATE <credentials> SET sign_count = $1, last_used_at = $2
//	 WHERE id = $3 AND sign_count < $1
//
// `sign_count < $1` is the predicate that turns this from a plain UPDATE into
// a compare-and-set: PostgreSQL decides "does a row have this id, and is its
// stored counter lower than the one presented" and applies the SET under a
// single row lock — there is no window between a check and a write for a
// second concurrent caller to land in, exactly the atomicity
// auth.CredentialStore.UpdateSignCount requires. Dropping the predicate would
// let every replayed assertion win, which is precisely the clone and replay
// detection this method exists to provide, and the only one in the package.
//
// Strictly-less, not less-or-equal: an equal counter must be REFUSED. An
// authenticator that maintains a counter increments it on every assertion, so
// the same value arriving twice is a replay or a clone.
//
// Zero rows affected is ambiguous between "no credential has this id" and "a
// credential has it but its counter is not lower", which a single UPDATE
// cannot distinguish. Exactly as [AuthStore.MarkRotated] does for the
// identical ambiguity, that path re-reads the row purely to classify the
// failure into auth.ErrCredentialNotFound or (false, nil). The follow-up read
// never writes, so it cannot reopen the atomicity gap above — the UPDATE has
// already committed, or not, by the time it runs.
func (st *CredentialStore) UpdateSignCount(ctx context.Context, id string, newCount uint32, now time.Time) (bool, error) {
	res, err := st.db.Update(st.s.Credentials).
		Set(
			st.s.credentials.bind("sign_count", newCount),
			st.s.credentials.bind("last_used_at", &now),
		).
		Where(
			st.s.credentials.eq("id", id),
			pg.Lt(st.s.credentials.col("sign_count"), int64(newCount)),
		).
		Exec(ctx)
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

	// Classify the miss. A row that exists means the counter was refused;
	// no row means the id names nothing.
	var existing auth.Credential
	if ferr := st.db.Select(st.s.credentials.col("id")).From(st.s.Credentials).
		Where(st.s.credentials.eq("id", id)).
		One(ctx, &existing); ferr != nil {
		return false, mapNoRows(ferr, auth.ErrCredentialNotFound)
	}
	return false, nil
}

// TouchCredential stamps last_used_at with now, leaving sign_count alone, and
// reports auth.ErrCredentialNotFound when id matches no row. It is what a
// counter-less authenticator's login calls instead of UpdateSignCount — see
// that method and auth.CredentialStore.TouchCredential.
//
// now is bound through a *time.Time so it takes colSet.bind's nullable path
// (see columns.go); the value is never nil here, so the column moves from
// NULL to a timestamp and never back.
func (st *CredentialStore) TouchCredential(ctx context.Context, id string, now time.Time) error {
	res, err := st.db.Update(st.s.Credentials).
		Set(st.s.credentials.bind("last_used_at", &now)).
		Where(st.s.credentials.eq("id", id)).
		Exec(ctx)
	return affectedOrErr(res, err, auth.ErrCredentialNotFound)
}

// DeleteCredential removes the one row named by its surrogate id — a single
// DELETE keyed on the primary key — reporting auth.ErrCredentialNotFound when
// it affects no row.
//
// It is deliberately NOT the transaction
// [CredentialStore.DeleteCredentialIfNotLast] is, because it decides nothing:
// there is no reachability question here to be read under one snapshot and
// written under another. See auth.CredentialStore.DeleteCredential for which
// callers may use it and why removing a credential without a check is correct
// for each of them.
func (st *CredentialStore) DeleteCredential(ctx context.Context, id string) error {
	res, err := st.db.Delete(st.s.Credentials).
		Where(st.s.credentials.eq("id", id)).
		Exec(ctx)
	return affectedOrErr(res, err, auth.ErrCredentialNotFound)
}

// DeleteCredentialIfNotLast removes userID's credential named by id, but only
// when the account stays reachable afterwards — either another of that user's
// credentials survives or userHasOtherCredential is true. Otherwise it
// returns auth.ErrLastCredential and removes NOTHING.
// auth.ErrCredentialNotFound means id names no credential of that user, which
// includes a credential belonging to somebody else.
//
// # Why this is a transaction and not one conditional DELETE
//
// [IdentityStore.DeleteIdentityIfNotLast]'s doc argues this at length and the
// argument is identical here, so read it there. In short: a single statement
// is atomic with respect to the rows it WRITES, but the decision is about the
// rows it READS — the siblings — and a subquery under READ COMMITTED neither
// locks what it reads nor sees another transaction's uncommitted delete. Two
// concurrent removals of a password-less, identity-less user's last two
// passkeys would both see a sibling, both conclude the account stays
// reachable, and both delete, leaving nothing that can sign the user in and
// both callers told they succeeded. Adding FOR UPDATE to the subquery trades
// that silent lockout for a lock-order inversion and SQLSTATE 40P01.
//
// So this is a transaction, satisfying the port's second permitted form:
//
//	BEGIN;
//	SELECT pg_advisory_xact_lock(hashtext('authlayer:credentials:user'), hashtext($1));
//	SELECT id FROM <credentials> WHERE user_id = $1 ORDER BY id FOR UPDATE;
//	-- decide from the locked rows
//	DELETE FROM <credentials> WHERE id = $2 AND user_id = $1;
//	COMMIT;
//
// The per-user advisory lock is what makes the decision serial: taken first,
// it forces two concurrent removals for the SAME user to run one after the
// other, so the second's SELECT takes a fresh READ COMMITTED snapshot that
// already contains the first's committed delete. It is transaction-scoped
// (released at COMMIT or ROLLBACK) and per-user (different users hash to
// different keys and stay fully concurrent). The fixed
// 'authlayer:credentials:user' namespace keeps this key space from colliding
// with the identity store's and [AuthStore.DeleteSessionsByFamily]'s, which
// take the same kind of lock in their own namespaces.
//
// SELECT ... FOR UPDATE then holds the rows the decision was made on for the
// rest of the transaction, so a writer that does NOT take the advisory lock —
// application SQL of its own — cannot remove a surviving credential between
// the decision and the commit. ORDER BY id is for determinism between such
// writers, not what makes this correct.
//
// A concurrent CreateCredential for this user can land between the decision
// and the commit, since an INSERT takes no lock this transaction holds. That
// is harmless in the only direction it can move: it adds a way in, so a
// delete this call allowed stays safe, and one it refused was refused against
// the smaller row set — fail-closed, self-correcting on retry.
func (st *CredentialStore) DeleteCredentialIfNotLast(ctx context.Context, userID, id string, userHasOtherCredential bool) error {
	return st.db.InTx(ctx, func(txdb *pg.DB) error {
		// Serialize this method against itself for this user, before
		// anything is read. A pg.DB.WithRetry policy can re-run this whole
		// closure, which is safe: the lock is transaction-scoped, so a
		// rolled-back attempt releases it, and the closure keeps no state
		// across attempts.
		if _, err := txdb.Exec(ctx,
			"SELECT pg_advisory_xact_lock(hashtext('authlayer:credentials:user'), hashtext($1))",
			userID); err != nil {
			return err
		}

		var rows []struct {
			ID string `drop:"id"`
		}
		if err := txdb.Select(st.s.credentials.col("id")).
			From(st.s.Credentials).
			Where(st.s.credentials.eq("user_id", userID)).
			OrderBy(st.s.credentials.col("id")).
			ForUpdate().
			All(ctx, &rows); err != nil {
			return err
		}

		doomed, survivors := 0, 0
		for _, r := range rows {
			if r.ID == id {
				doomed++
			} else {
				survivors++
			}
		}
		if doomed == 0 {
			return auth.ErrCredentialNotFound
		}
		if survivors == 0 && !userHasOtherCredential {
			// Removes nothing. Returning an error rolls the transaction
			// back, so the advisory lock and the row locks are released
			// with the table untouched.
			return auth.ErrLastCredential
		}

		// user_id is in the predicate as well as id, even though the row set
		// above was already scoped to the user: the DELETE must not widen if
		// this method is ever called with an id the SELECT did not lock.
		_, err := txdb.Delete(st.s.Credentials).
			Where(
				st.s.credentials.eq("id", id),
				st.s.credentials.eq("user_id", userID),
			).
			Exec(ctx)
		return err
	})
}

// ── Challenges ──────────────────────────────────────────────────────────

// CreateChallenge inserts c and returns it unchanged. A UserID of nil — a
// login ceremony, which names no account — is written as SQL NULL by
// colSet.bind's nullable path.
//
// A unique violation on the primary key is auth.ErrIDTaken; any other unique
// violation is the challenge_hash constraint, and is returned as the driver's
// own error unwrapped, exactly as [AuthStore.CreateVerification] does for a
// duplicate token hash. The port classifies only ErrIDTaken on a create, and
// a 32-byte crypto/rand collision is not a condition a caller can act on.
func (st *CredentialStore) CreateChallenge(ctx context.Context, c auth.Challenge) (auth.Challenge, error) {
	_, err := st.db.Insert(st.s.Challenges).Row(st.s.challenges.row(c)...).Exec(ctx)
	if err == nil {
		return c, nil
	}
	if errors.Is(err, pg.ErrUniqueViolation) && isPrimaryKeyViolation(err) {
		return auth.Challenge{}, fmt.Errorf("%w: %w", auth.ErrIDTaken, err)
	}
	return auth.Challenge{}, err
}

// FindChallengeByHash loads the challenge whose challenge_hash matches,
// mapping drops' ErrNoRows to auth.ErrChallengeNotFound. It checks neither
// expiry nor ceremony — both belong to the service layer, which checks them
// before claiming so that a wrongly-presented challenge is not burned.
//
// At most one row can match: [CredentialSchema]'s UNIQUE (challenge_hash).
func (st *CredentialStore) FindChallengeByHash(ctx context.Context, hash string) (auth.Challenge, error) {
	var c auth.Challenge
	err := st.db.Select().From(st.s.Challenges).
		Where(st.s.challenges.eq("challenge_hash", hash)).
		One(ctx, &c)
	if err != nil {
		return auth.Challenge{}, mapNoRows(err, auth.ErrChallengeNotFound)
	}
	return c, nil
}

// DeleteChallenge removes the challenge named by id — a single DELETE keyed
// on the primary key — reporting auth.ErrChallengeNotFound when it affects no
// row.
//
// This is the CLAIM, and the rows-affected gate is what makes it a claim
// rather than a hint: PostgreSQL locks the row it deletes, so of any number
// of concurrent callers presenting the same challenge, exactly one statement
// removes a row and every other one affects nothing and is told so. Nothing
// is issued before this returns nil — see [auth.Service.FinishPasskeyLogin]'s
// "Claim before apply".
func (st *CredentialStore) DeleteChallenge(ctx context.Context, id string) error {
	res, err := st.db.Delete(st.s.Challenges).
		Where(st.s.challenges.eq("id", id)).
		Exec(ctx)
	return affectedOrErr(res, err, auth.ErrChallengeNotFound)
}

// PurgeExpiredChallenges deletes every challenge whose expires_at is strictly
// before `before`, returning how many rows went. Housekeeping only, on the
// same strictly-before boundary [AuthStore.PurgeExpired] uses so the two
// janitors agree.
func (st *CredentialStore) PurgeExpiredChallenges(ctx context.Context, before time.Time) (int, error) {
	res, err := st.db.Delete(st.s.Challenges).
		Where(pg.Lt(st.s.challenges.col("expires_at"), before)).
		Exec(ctx)
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, err
	}
	return int(n), nil
}
