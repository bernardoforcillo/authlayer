package dropsstore

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/bernardoforcillo/drops/pg"

	"github.com/bernardoforcillo/authlayer/auth"
)

// IdentityNames is the one table name an IdentityStore persists to. The zero
// value defaults to "identities".
//
// It is a struct rather than a bare string parameter so it reads and evolves
// exactly like [AuthNames], [InviteNames] and [Names] do — one option, one
// value, named fields — rather than being the single odd naming knob in the
// package.
type IdentityNames struct {
	Identities string // default "identities"
}

func (n IdentityNames) withDefaults() IdentityNames {
	if n.Identities == "" {
		n.Identities = "identities"
	}
	return n
}

type identitySettings struct {
	names IdentityNames
	ids   idTypes
}

// IdentityOption customizes an [IdentitySchema] or [IdentityStore] at
// construction.
type IdentityOption func(*identitySettings)

// WithIdentityNames overrides the table name, so a consumer that already owns
// a table named "identities" for something else can point this store
// elsewhere.
func WithIdentityNames(n IdentityNames) IdentityOption {
	return func(s *identitySettings) { s.names = n }
}

// WithIdentityTextLibraryIDs types both id columns on the identities table as
// text rather than uuid: identities.id, and — the part that makes this one
// option rather than two — the identities.user_id column that references
// users.id.
//
// authlayer generates UUIDv7 ids (internal/uid) for every identity it links,
// so uuid is the default and stays the default. Use this when
// [github.com/bernardoforcillo/authlayer/auth.WithIDGenerator] has replaced
// that generator with one whose output PostgreSQL's uuid parser does not
// accept — a ULID, a database sequence, a readable "usr_a1b2c3":
//
//	st := dropsstore.NewAuthStore(db, dropsstore.WithAuthTextLibraryIDs())
//	ids := dropsstore.NewIdentityStore(db, dropsstore.WithIdentityTextLibraryIDs())
//	svc := auth.New(st, auth.WithIdentityStore(ids), auth.WithIDGenerator(ulid.Make))
//
// Without it, such a generator fails the first
// [github.com/bernardoforcillo/authlayer/auth.Service.SignInWith] with
// SQLSTATE 22P02 (invalid_text_representation) — at the store, on the first
// write, which store/memory never reproduces.
//
// Like [WithAuthTextLibraryIDs] and unlike [WithTextLibraryIDs] /
// [WithTextUserIDs] on the scope Store, this is ONE option covering both id
// families rather than two. identities.user_id is a reference to the users
// table [AuthStore] owns, not a value supplied from outside, so it must be
// typed exactly as users.id is: leaving it uuid while users.id went text
// would produce a hatch that fixed nothing and failed the first sign-in with
// the very error it was added to remove. There is deliberately no
// text-USER-id option here for the same reason — no coherent configuration
// exists in which these two columns disagree.
//
// It MUST be passed alongside [WithAuthTextLibraryIDs] (and alongside
// [WithTextLibraryIDs] / [WithInviteTextLibraryIDs] when the same deployment
// also uses the RBAC and invitation halves): identities.user_id references
// the auth store's users.id, so the two have to agree.
//
// Changing it changes the DDL [IdentityStore.CreateSchema] emits for a table
// that does not exist yet. Like every other part of that call it will not
// migrate a table that already exists: CreateSchema issues CREATE TABLE IF
// NOT EXISTS, which is a no-op against a pre-existing table, so against one
// the type choice this option makes is silently a no-op too.
func WithIdentityTextLibraryIDs() IdentityOption {
	return func(s *identitySettings) { s.ids = idTypes{library: false, user: false} }
}

// IdentitySchema holds the external-identity table and its derived columns:
//
//	<identities>  id PK, user_id, provider, subject, email, created_at,
//	              last_used_at, UNIQUE (provider, subject), INDEX (user_id)
//
// # UNIQUE (provider, subject) is the load-bearing one
//
// It is what makes [auth.ErrIdentityLinked] a guarantee rather than advice,
// and [auth.Identity.Subject]'s doc states the MUST this constraint
// discharges. Without it two rows can name the same external account against
// two DIFFERENT local users, and a sign-in resolving that subject lands on
// whichever row the server happens to return first — one external account
// silently able to sign in as either of two people, decided by row order.
// It is also the only thing standing behind
// [github.com/bernardoforcillo/authlayer/auth.Service.SignInWith]'s
// documented "what is not atomic here" window: two concurrent first
// sign-ins for the same new external account can both pass the lookup, and
// this constraint is what fails the loser instead of letting both write.
// [auth.Identity] carries no "unique" tag option for either column and could
// not — the constraint is composite, so CREATE TABLE cannot carry it at all
// — so it is registered through [pg.Table.AddUnique] and emitted by
// [IdentityStore.CreateSchema] as a guarded ALTER TABLE, the same idiom
// [InviteSchema] uses for its own composite constraint.
//
// # INDEX (user_id) is not decoration either
//
// Both [IdentityStore.ListIdentitiesByUser] (every connected-accounts
// screen) and [IdentityStore.DeleteIdentityIfNotLast] (whose locking SELECT
// reads exactly the user's rows, inside a transaction, on every unlink)
// filter on user_id alone. Without the index both sequentially scan a table
// that grows with the whole deployment's identity count rather than with one
// user's, and the unlink pays it while holding a transaction open.
// TestIdentityStoreListIdentitiesByUserUsesTheIndexLive proves the planner
// actually picks it, with a control that drops it and requires the plan to
// degrade — an index the planner ignores is not an index.
//
// # last_used_at is the schema's only nullable column
//
// [auth.Identity.LastUsedAt] is a *time.Time, and nil means "this link has
// never signed the user in" — a fact an application acts on, distinct from
// any timestamp value. colSet.add types a *time.Time column without NOT
// NULL, and colSet.bind renders a nil one as the NULL keyword rather than a
// parameter (see columns.go); no special handling is needed here beyond
// letting the model's own pointer type through.
//
// [auth.Identity] is a fixed shape, unlike the generic scope Store, so
// unlike [Schema] this type is not parameterized.
type IdentitySchema struct {
	// Identities is the external-identity table. See [auth.Identity] — it
	// holds no provider access or refresh token, deliberately, so a dump of
	// it cannot be replayed against a provider on a user's behalf.
	Identities *pg.Table

	identities *colSet
}

// NewIdentitySchema builds the schema for one identity store instance.
// [NewIdentityStore] calls it, so use it directly only when you need the
// table definition without a store — to generate DDL for a migration, for
// instance.
func NewIdentitySchema(opts ...IdentityOption) *IdentitySchema {
	cfg := identitySettings{ids: uuidIDs()}
	for _, o := range opts {
		o(&cfg)
	}
	names := cfg.names.withDefaults()

	s := &IdentitySchema{Identities: pg.NewTable(names.Identities)}
	// One idTypes, with both families always set the same way — see
	// [WithIdentityTextLibraryIDs] for why this table, like the three auth
	// tables and unlike Schema/InviteSchema, has no text-user-id option of
	// its own: user_id references the users table [AuthStore] owns, so it
	// must be typed as users.id is, whichever that is.
	s.identities = newColSet(s.Identities, auth.Identity{}, cfg.ids)

	s.Identities.AddUnique(names.Identities+"_provider_subject",
		s.identities.col("provider"), s.identities.col("subject"))
	s.Identities.AddIndex(pg.NewIndex(
		names.Identities+"_user_id_idx", s.Identities, s.identities.col("user_id")))

	return s
}

// IdentityStore is a drops-backed auth.IdentityStore: the `identities` table,
// and nothing else. It is the optional external-identity port, wired with
// [github.com/bernardoforcillo/authlayer/auth.WithIdentityStore]; an
// application offering no external sign-in never constructs one, and never
// creates the table.
//
// It does NOT own the users table — that belongs to [AuthStore], which may
// even be a different backend — which is why
// [IdentityStore.DeleteIdentityIfNotLast] is told whether the user holds a
// password rather than reading it. See auth.IdentityStore's own doc for why
// that parameter is safe.
//
// Like [AuthStore] and [InviteStore] it is pure persistence: it hashes
// nothing, mints nothing, and authorizes nothing. Because [auth.Identity] is
// a fixed shape it is not generic the way [Store] is over C and M.
type IdentityStore struct {
	db *pg.DB
	s  *IdentitySchema
}

// Compile-time proof the drops identity store satisfies the port.
var _ auth.IdentityStore = (*IdentityStore)(nil)

// NewIdentityStore returns an IdentityStore over db, building a fresh
// [IdentitySchema].
func NewIdentityStore(db *pg.DB, opts ...IdentityOption) *IdentityStore {
	return &IdentityStore{db: db, s: NewIdentitySchema(opts...)}
}

// Schema exposes the table so callers can build guards, join against it, or
// emit their own DDL.
func (st *IdentityStore) Schema() *IdentitySchema { return st.s }

// CreateSchema issues CREATE TABLE IF NOT EXISTS for the identities table,
// followed by the UNIQUE (provider, subject) constraint as a guarded ALTER
// TABLE — CREATE TABLE could never carry a composite constraint in the first
// place — and then CREATE INDEX IF NOT EXISTS for the user_id index. Every
// statement is idempotent, so the call is safe to re-run and self-heals a
// pre-existing table missing the constraint or the index.
//
// Like [Store.CreateSchema], [AuthStore.CreateSchema] and
// [InviteStore.CreateSchema] it adds what is missing and never alters what is
// already there, so production deployments that own this table via their own
// migrations should skip it. In particular it cannot RETYPE an existing
// table: against a table that already exists the CREATE TABLE is a no-op, so
// [WithIdentityTextLibraryIDs] has no effect on it. No foreign key to the
// users table is declared, matching this codebase's other schemas — and here
// it is also forced: [AuthStore] may be an entirely different backend.
func (st *IdentityStore) CreateSchema(ctx context.Context) error {
	if _, err := st.db.ExecExpr(ctx, pg.CreateTableIfNotExists(st.s.Identities)); err != nil {
		return err
	}
	for _, ddl := range compositeConstraintDDL(st.s.Identities) {
		if _, err := st.db.ExecExpr(ctx, ddl); err != nil {
			return err
		}
	}
	for _, idx := range st.s.Identities.Indexes() {
		if _, err := st.db.ExecExpr(ctx, pg.CreateIndexIfNotExists(idx)); err != nil {
			return err
		}
	}
	return nil
}

// CreateIdentity normalizes i.Email (see [auth.NormalizeEmail]), inserts i,
// and returns it unchanged. Provider and Subject are written byte-for-byte —
// neither folded nor normalized — matching [auth.Identity.Provider]'s and
// [auth.Identity.Subject]'s docs.
//
// A unique violation is classified via [isPrimaryKeyViolation] — see its doc
// for why this reads the driver's own *pgconn.PgError rather than re-querying
// or trusting drops' own pg.PgError.Constraint: auth.ErrIDTaken when the
// row's own id already exists, auth.ErrIdentityLinked otherwise, since
// UNIQUE (provider, subject) is the table's only other unique-enforcing
// constraint (see [IdentitySchema]). Either sentinel wraps the original error
// rather than discarding it, so a caller that wants the underlying
// pg.ErrUniqueViolation (or, via errors.As, the driver's own *pgconn.PgError)
// back can still reach it through this error's chain.
//
// This is a single INSERT with no preliminary SELECT, so the uniqueness
// decision and the write are one step exactly as auth.IdentityStore's doc
// requires: ErrIdentityLinked can only ever come from the insert attempt
// itself failing against the constraint, never from a separate read that
// could race a concurrent link. An existing row is therefore never silently
// replaced or re-pointed at a different user.
func (st *IdentityStore) CreateIdentity(ctx context.Context, i auth.Identity) (auth.Identity, error) {
	i.Email = auth.NormalizeEmail(i.Email)
	_, err := st.db.Insert(st.s.Identities).Row(st.s.identities.row(i)...).Exec(ctx)
	if err == nil {
		return i, nil
	}
	if !errors.Is(err, pg.ErrUniqueViolation) {
		return auth.Identity{}, err
	}
	if isPrimaryKeyViolation(err) {
		return auth.Identity{}, fmt.Errorf("%w: %w", auth.ErrIDTaken, err)
	}
	return auth.Identity{}, fmt.Errorf("%w: %w", auth.ErrIdentityLinked, err)
}

// FindIdentityByProviderSubject loads the identity for (provider, subject),
// mapping drops' ErrNoRows to auth.ErrIdentityNotFound. Both are matched
// byte-for-byte; neither is normalized or case-folded.
//
// At most one row can match, and that is enforced by the database rather than
// assumed: [IdentitySchema]'s UNIQUE (provider, subject) is what makes "the
// hit IS the account" — the first rung of
// [github.com/bernardoforcillo/authlayer/auth.Service.SignInWith]'s ladder —
// a fact rather than a coin flip over row order.
func (st *IdentityStore) FindIdentityByProviderSubject(ctx context.Context, provider, subject string) (auth.Identity, error) {
	var i auth.Identity
	err := st.db.Select().From(st.s.Identities).
		Where(st.s.identities.eq("provider", provider), st.s.identities.eq("subject", subject)).
		One(ctx, &i)
	if err != nil {
		return auth.Identity{}, mapNoRows(err, auth.ErrIdentityNotFound)
	}
	return i, nil
}

// ListIdentitiesByUser returns every identity belonging to userID, and only
// that user's. A user with none yields nil, not an error — callers MUST use
// len() rather than a nil comparison, since store/memory returns an empty
// non-nil slice for the same case and the port leaves the choice
// unspecified. Order is whatever the server returns and is likewise
// unspecified.
//
// The user_id predicate is served by [IdentitySchema]'s index on that column;
// see that type's doc, and the live EXPLAIN test that proves the planner
// picks it.
func (st *IdentityStore) ListIdentitiesByUser(ctx context.Context, userID string) ([]auth.Identity, error) {
	var out []auth.Identity
	if err := st.db.Select().From(st.s.Identities).
		Where(st.s.identities.eq("user_id", userID)).
		All(ctx, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// TouchIdentity stamps last_used_at with now, reporting
// auth.ErrIdentityNotFound when id matches no row. It is the only mutation
// this store performs on an existing row.
//
// now is bound through a *time.Time so it takes colSet.bind's nullable path
// (see columns.go); the value is never nil here, so the column moves from
// NULL to a timestamp and never back. Nothing in the port can clear it again
// — "never used" is a state a link leaves once and does not re-enter.
func (st *IdentityStore) TouchIdentity(ctx context.Context, id string, now time.Time) error {
	res, err := st.db.Update(st.s.Identities).
		Set(st.s.identities.bind("last_used_at", &now)).
		Where(st.s.identities.eq("id", id)).
		Exec(ctx)
	return affectedOrErr(res, err, auth.ErrIdentityNotFound)
}

// DeleteIdentity removes the one row named by id — a single DELETE keyed on
// the primary key — reporting auth.ErrIdentityNotFound when it affects no
// row.
//
// It is deliberately NOT the transaction [IdentityStore.DeleteIdentityIfNotLast]
// is, because it decides nothing: there is no reachability question here to
// be read under one snapshot and written under another, so a bare statement
// satisfies the port's contract outright. See auth.IdentityStore.DeleteIdentity
// for which callers may use it and why removing a credential without a check
// is correct for each of them.
func (st *IdentityStore) DeleteIdentity(ctx context.Context, id string) error {
	res, err := st.db.Delete(st.s.Identities).
		Where(st.s.identities.eq("id", id)).
		Exec(ctx)
	return affectedOrErr(res, err, auth.ErrIdentityNotFound)
}

// DeleteIdentityIfNotLast removes every one of userID's identities at
// provider, but only when the account stays reachable afterwards — either
// another identity survives the delete or userHasPassword is true. Otherwise
// it returns auth.ErrLastCredential and removes NOTHING.
// auth.ErrIdentityNotFound means the user had no identity at that provider at
// all.
//
// # Why this is a transaction and not one conditional DELETE
//
// Every other check-and-write in this package is a single statement whose
// WHERE clause carries the check — [AuthStore.MarkRotated],
// [AuthStore.MarkEmailVerified], [InviteStore.ConsumeLink] — and that shape
// was tried here first. It does not work, and the reason is worth stating
// because the statement LOOKS right:
//
//	DELETE FROM <identities>
//	 WHERE user_id = $1 AND provider = $2
//	   AND ($3 OR EXISTS (SELECT 1 FROM <identities>
//	                       WHERE user_id = $1 AND provider <> $2))
//
// A single statement is atomic with respect to the rows it WRITES: PostgreSQL
// takes a row lock on each row it deletes, so no concurrent writer can slip
// between this statement's decision and its own write on THOSE rows. But the
// decision here is not about those rows. It is about the OTHER ones — the
// siblings the EXISTS subquery reads — and a subquery under READ COMMITTED
// neither locks what it reads nor sees another transaction's uncommitted
// delete. Two concurrent unlinks of a password-less user's last two
// identities therefore both evaluate EXISTS against a snapshot in which the
// sibling is still present, both conclude the account stays reachable, and
// both delete. The account ends with no identity and no password, nothing in
// this package can sign it in again, and both callers were told they
// succeeded. That is precisely the permanent, silent lockout
// auth.IdentityStore.DeleteIdentityIfNotLast's "It MUST be atomic" section
// exists to forbid, reproduced by the statement that appears to implement it.
// TestDeleteIdentityIfNotLastIsAtomicUnderConcurrencyLive fails against that
// statement; the mutation was run.
//
// Adding FOR UPDATE to the subquery does not rescue it. Each caller would
// then lock the row the other is deleting while deleting the row the other
// locked — a textbook lock-order inversion, which PostgreSQL resolves by
// aborting one side with SQLSTATE 40P01. Trading a silent lockout for a
// deadlock at the moment a user removes a credential is not a fix.
//
// So this is a transaction, and the port's contract is satisfied by its
// second permitted form ("one statement, one transaction, or one acquisition
// of the mutex"):
//
//	BEGIN;
//	SELECT pg_advisory_xact_lock(hashtext('authlayer:identities:user'), hashtext($1));
//	SELECT id, provider FROM <identities> WHERE user_id = $1 ORDER BY id FOR UPDATE;
//	-- decide from the locked rows
//	DELETE FROM <identities> WHERE user_id = $1 AND provider = $2;
//	COMMIT;
//
// # What each of the two locks does
//
// The per-user advisory lock is what makes the decision serial. Taken as the
// very first statement, it forces two concurrent unlinks of the SAME user to
// run one after the other: the second waits, and when it proceeds its SELECT
// takes a fresh READ COMMITTED snapshot that already contains the first
// call's committed delete — so it sees the true post-delete row set and
// refuses correctly, rather than deciding against a sibling that is already
// gone. It is scoped to this transaction (pg_advisory_xact_lock releases at
// COMMIT or ROLLBACK and never needs an explicit unlock) and to this user
// (different users hash to different keys and stay fully concurrent). The
// fixed 'authlayer:identities:user' namespace keeps this key space from
// colliding with whatever else the *pg.DB passed to [NewIdentityStore] uses
// advisory locks for — including [AuthStore.DeleteSessionsByFamily], which
// takes the same kind of lock in its own namespace for its own, unrelated
// reason.
//
// SELECT ... FOR UPDATE then holds the rows the decision was actually made
// on for the rest of the transaction, so a writer that does NOT take the
// advisory lock — application code with its own SQL against this table —
// cannot remove a surviving identity between the decision and the commit.
// ORDER BY id is for determinism between such writers, not what makes this
// correct; the advisory lock is, and [AuthStore.DeleteSessionsByFamily]'s own
// doc explains at length why an ORDER BY alone cannot be.
//
// # What is decided, and from what
//
// The survivor count is what remains AFTER the delete, not the user's total
// row count, and the delete takes every row matching (userID, provider)
// rather than an arbitrary one — nothing in the data model forbids a user
// holding two identities at the same provider, so a password-less user whose
// only two identities are both at provider P is refused even though the table
// holds two rows for them. This mirrors store/memory's implementation
// exactly, which is what lets one contract describe both.
//
// A concurrent CreateIdentity for this user can land between the decision and
// the commit, since an INSERT takes no lock this transaction holds. That is
// harmless in the only direction it can move: it adds a way in, so a delete
// this call allowed stays safe, and a delete it refused was refused against
// the smaller row set — fail-closed, self-correcting on retry.
func (st *IdentityStore) DeleteIdentityIfNotLast(ctx context.Context, userID, provider string, userHasPassword bool) error {
	return st.db.InTx(ctx, func(txdb *pg.DB) error {
		// Serialize this method against itself for this user, before
		// anything is read — see "What each of the two locks does". A
		// pg.DB.WithRetry policy can re-run this whole closure, which is
		// safe: the lock is transaction-scoped, so a rolled-back attempt
		// releases it, and the closure keeps no state across attempts.
		if _, err := txdb.Exec(ctx,
			"SELECT pg_advisory_xact_lock(hashtext('authlayer:identities:user'), hashtext($1))",
			userID); err != nil {
			return err
		}

		var rows []struct {
			ID       string `drop:"id"`
			Provider string `drop:"provider"`
		}
		if err := txdb.Select(st.s.identities.col("id"), st.s.identities.col("provider")).
			From(st.s.Identities).
			Where(st.s.identities.eq("user_id", userID)).
			OrderBy(st.s.identities.col("id")).
			ForUpdate().
			All(ctx, &rows); err != nil {
			return err
		}

		doomed, survivors := 0, 0
		for _, r := range rows {
			if r.Provider == provider {
				doomed++
			} else {
				survivors++
			}
		}
		if doomed == 0 {
			return auth.ErrIdentityNotFound
		}
		if survivors == 0 && !userHasPassword {
			// Removes nothing. Returning an error rolls the transaction
			// back, so the advisory lock and the row locks are released
			// with the table untouched.
			return auth.ErrLastCredential
		}

		_, err := txdb.Delete(st.s.Identities).
			Where(st.s.identities.eq("user_id", userID), st.s.identities.eq("provider", provider)).
			Exec(ctx)
		return err
	})
}
