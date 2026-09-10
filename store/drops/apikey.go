package dropsstore

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/bernardoforcillo/drops/pg"

	"github.com/bernardoforcillo/authlayer/apikey"
)

// APIKeyNames are the two table names an APIKeyStore persists to. The zero
// value defaults to "service_accounts" and "api_keys" — unlike the invite
// tables these are not prefixed with the organization scope's name, because
// a service account belongs to whichever scope its container_id names and
// the table shape does not change per scope; override them via
// [WithAPIKeyNames] if a second scope instance must keep its own.
type APIKeyNames struct {
	ServiceAccounts string // default "service_accounts"
	Keys            string // default "api_keys"
}

func (n APIKeyNames) withDefaults() APIKeyNames {
	if n.ServiceAccounts == "" {
		n.ServiceAccounts = "service_accounts"
	}
	if n.Keys == "" {
		n.Keys = "api_keys"
	}
	return n
}

type apikeySettings struct {
	names APIKeyNames
	ids   idTypes
}

// APIKeyOption customizes an [APIKeySchema] or [APIKeyStore] at construction.
type APIKeyOption func(*apikeySettings)

// WithAPIKeyNames overrides the two table names.
func WithAPIKeyNames(n APIKeyNames) APIKeyOption {
	return func(s *apikeySettings) { s.names = n }
}

// WithAPIKeyTextUserIDs types created_by — on both tables — as text rather
// than uuid. Mirrors [WithTextUserIDs] on the scope Store: created_by holds
// the id of the USER who created the account or minted the key, a value
// supplied from the application's own users table, so it follows that
// table's key type. It does not reach the ids authlayer mints for itself;
// [WithAPIKeyTextLibraryIDs] is the option for those, and the two compose.
func WithAPIKeyTextUserIDs() APIKeyOption {
	return func(s *apikeySettings) { s.ids.user = false }
}

// WithAPIKeyTextLibraryIDs types the library-minted id columns — an
// account's and a key's own id, the container_id referencing the scope, and
// api_keys.service_account_id referencing the account — as text rather than
// uuid. Mirrors [WithTextLibraryIDs] on the scope Store, and must be passed
// alongside it: container_id here references that store's containers table,
// so the two have to agree.
//
// uuid remains the default, since authlayer mints UUIDv7. Use this when
// [github.com/bernardoforcillo/authlayer/apikey.WithIDGenerator] (or
// scope.WithIDGenerator, for the containers) produces something PostgreSQL's
// uuid parser rejects.
func WithAPIKeyTextLibraryIDs() APIKeyOption {
	return func(s *apikeySettings) { s.ids.library = false }
}

// APIKeySchema holds the two service-account tables and their derived
// columns:
//
//	<service_accounts>  id PK, container_id, name, description, created_by,
//	                    created_at, updated_at, disabled_at,
//	                    INDEX (container_id)
//	<api_keys>          id PK, service_account_id REFERENCES <service_accounts>(id)
//	                    ON DELETE CASCADE, container_id, name, prefix,
//	                    token_hash UNIQUE, permissions BYTEA, expires_at,
//	                    last_used_at, created_by, created_at, revoked_at,
//	                    INDEX (service_account_id), INDEX (container_id)
//
// # UNIQUE (token_hash) is load-bearing
//
// [apikey.Key.TokenHash] carries the MUST this constraint discharges, and it
// is the same one [AuthSchema] records for sessions.token_hash: two rows
// sharing a hash would make [APIKeyStore.FindKeyByHash] return whichever the
// server reached first, so WHICH ACCOUNT, at WHICH CAP, a presented key acts
// as would be decided by row order. It also gives the authentication path —
// one lookup per request — an index instead of a sequential scan. Unlike
// sessions and the invite tables it is declared INLINE, through the record's
// own `drop:"token_hash,unique"` tag, so it is part of the CREATE TABLE
// rather than a guarded ALTER TABLE afterwards. The consequence is the one
// [MFASchema] notes for the factors primary key: [APIKeyStore.CreateSchema]
// cannot self-heal a pre-existing api_keys table that lacks it, since CREATE
// TABLE IF NOT EXISTS no-ops away entirely. Own the tables through your own
// migrations and keep the constraint.
//
// # The foreign key IS the cascade
//
// This is the one schema in this package that declares a foreign key,
// because here both sides of it are owned by the same store — unlike the
// RBAC, invite and auth tables, which reference a users table authlayer may
// not own or sit in a different backend from each other.
// api_keys.service_account_id REFERENCES service_accounts(id) ON DELETE
// CASCADE does two jobs: it is what makes [APIKeyStore.CreateKey] refuse a
// key naming no account (the port's MUST, surfaced as a foreign-key
// violation and classified as apikey.ErrServiceAccountNotFound), and it
// makes a DELETE on the account remove its keys in the same statement.
// [APIKeyStore.DeleteServiceAccount] does not rely on it alone — it deletes
// the keys explicitly inside the same transaction, so the cascade MUST
// holds against a hand-migrated schema that dropped the constraint — but
// with the constraint in place no path, this store's or anyone else's, can
// leave a key behind its account.
//
// # permissions is NOT NULL, and empty means no cap
//
// [apikey.Key.Permissions] is nil for an unrestricted key and encoded grant
// names otherwise. The column is declared NOT NULL like every bytea column
// this package derives, so [APIKeyStore.CreateKey] writes a nil slice as an
// empty one; "no cap" is therefore an empty blob in the table, never a
// NULL, and a hand-written migration should declare it the same way.
//
// # The indexes
//
// (service_account_id) serves [APIKeyStore.ListKeys] and the explicit
// cascade delete; (container_id) on both tables serves
// [APIKeyStore.ListServiceAccounts] and any application query that scopes
// keys by tenant. All three are emitted as CREATE INDEX IF NOT EXISTS, so
// CreateSchema self-heals a table missing one.
//
// [apikey.ServiceAccount] and [apikey.Key] are fixed shapes, so like
// [InviteSchema] this type is not parameterized.
type APIKeySchema struct {
	// ServiceAccounts is the service-account table. See
	// [apikey.ServiceAccount].
	ServiceAccounts *pg.Table
	// Keys is the API-key table. See [apikey.Key] — token_hash holds the
	// sha256 of a plaintext that is never stored; permissions holds encoded
	// grant names, never bit indices.
	Keys *pg.Table

	accounts *colSet
	keys     *colSet
}

// NewAPIKeySchema builds the schema for one store instance. [NewAPIKeyStore]
// calls it, so use it directly only when you need the table definitions
// without a store — to generate DDL for a migration, for instance.
func NewAPIKeySchema(opts ...APIKeyOption) *APIKeySchema {
	cfg := apikeySettings{ids: uuidIDs()}
	for _, o := range opts {
		o(&cfg)
	}
	names := cfg.names.withDefaults()

	s := &APIKeySchema{
		ServiceAccounts: pg.NewTable(names.ServiceAccounts),
		Keys:            pg.NewTable(names.Keys),
	}
	s.accounts = newColSet(s.ServiceAccounts, apikey.ServiceAccount{}, cfg.ids)
	s.keys = newColSet(s.Keys, apikey.Key{}, cfg.ids)

	s.Keys.ForeignKey(s.keys.col("service_account_id"), s.accounts.col("id"), pg.OnDelete("CASCADE"))

	s.ServiceAccounts.AddIndex(pg.NewIndex(
		names.ServiceAccounts+"_container_id_idx", s.ServiceAccounts, s.accounts.col("container_id")))
	s.Keys.AddIndex(pg.NewIndex(
		names.Keys+"_service_account_id_idx", s.Keys, s.keys.col("service_account_id")))
	s.Keys.AddIndex(pg.NewIndex(
		names.Keys+"_container_id_idx", s.Keys, s.keys.col("container_id")))

	return s
}

// APIKeyStore is a drops-backed apikey.Store. Like [InviteStore] it is pure
// persistence: it hashes nothing, interprets no permission bytes, and
// authorizes nothing — the apikey.Service decides, and hands it fully-formed
// values to write or keys to read by.
type APIKeyStore struct {
	db *pg.DB
	s  *APIKeySchema
}

// Compile-time proof the drops store satisfies the port.
var _ apikey.Store = (*APIKeyStore)(nil)

// NewAPIKeyStore returns an APIKeyStore over db, building a fresh
// [APIKeySchema].
func NewAPIKeyStore(db *pg.DB, opts ...APIKeyOption) *APIKeyStore {
	return &APIKeyStore{db: db, s: NewAPIKeySchema(opts...)}
}

// Schema exposes the tables so callers can build guards, join against them,
// or emit their own DDL.
func (st *APIKeyStore) Schema() *APIKeySchema { return st.s }

// CreateSchema issues CREATE TABLE IF NOT EXISTS for the service-account
// table and then the key table — in that order, since the key table's
// foreign key references the first — each followed by CREATE INDEX IF NOT
// EXISTS for its indexes. Every statement is idempotent, so the call is safe
// to re-run and self-heals a table missing an index.
//
// Like every other CreateSchema in this package it adds what is missing and
// never alters what is already there, so production deployments that own
// these tables via their own migrations should skip it. In particular it
// cannot RETYPE an existing table, so [WithAPIKeyTextLibraryIDs] has no
// effect on one, and it cannot add the UNIQUE (token_hash) or the foreign
// key to an api_keys table that already exists — both live inside the CREATE
// TABLE that no-ops away against a table that is already there (see
// [APIKeySchema]).
func (st *APIKeyStore) CreateSchema(ctx context.Context) error {
	for _, t := range []*pg.Table{st.s.ServiceAccounts, st.s.Keys} {
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

// ── Service accounts ────────────────────────────────────────────────────────

// CreateServiceAccount persists an already-stamped account and returns it
// unchanged. The table's only unique-enforcing constraint is the primary key,
// so a unique violation here can only be an id collision and is classified
// as apikey.ErrIDTaken, wrapping the original error.
func (st *APIKeyStore) CreateServiceAccount(ctx context.Context, sa apikey.ServiceAccount) (apikey.ServiceAccount, error) {
	_, err := st.db.Insert(st.s.ServiceAccounts).Row(st.s.accounts.row(sa)...).Exec(ctx)
	if err != nil {
		if errors.Is(err, pg.ErrUniqueViolation) {
			return apikey.ServiceAccount{}, fmt.Errorf("%w: %w", apikey.ErrIDTaken, err)
		}
		return apikey.ServiceAccount{}, err
	}
	return sa, nil
}

// FindServiceAccount loads an account by id, mapping drops' ErrNoRows to
// apikey.ErrServiceAccountNotFound.
func (st *APIKeyStore) FindServiceAccount(ctx context.Context, id string) (apikey.ServiceAccount, error) {
	var sa apikey.ServiceAccount
	err := st.db.Select().From(st.s.ServiceAccounts).
		Where(st.s.accounts.eq("id", id)).
		One(ctx, &sa)
	if err != nil {
		return apikey.ServiceAccount{}, mapNoRows(err, apikey.ErrServiceAccountNotFound)
	}
	return sa, nil
}

// ListServiceAccounts returns every account in containerID, disabled or not.
// A container with none yields nil, not an error — the port permits either.
func (st *APIKeyStore) ListServiceAccounts(ctx context.Context, containerID string) ([]apikey.ServiceAccount, error) {
	var out []apikey.ServiceAccount
	if err := st.db.Select().From(st.s.ServiceAccounts).
		Where(st.s.accounts.eq("container_id", containerID)).
		All(ctx, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// SetServiceAccountDisabled writes disabled_at = at (NULL re-enables) and
// updated_at = now, reporting apikey.ErrServiceAccountNotFound when no row
// matched.
func (st *APIKeyStore) SetServiceAccountDisabled(ctx context.Context, id string, at *time.Time, now time.Time) error {
	res, err := st.db.Update(st.s.ServiceAccounts).
		Set(st.s.accounts.bind("disabled_at", at), st.s.accounts.bind("updated_at", now)).
		Where(st.s.accounts.eq("id", id)).
		Exec(ctx)
	return affectedOrErr(res, err, apikey.ErrServiceAccountNotFound)
}

// DeleteServiceAccount removes the account and its keys in ONE transaction:
//
//	DELETE FROM <api_keys> WHERE service_account_id = $1;
//	DELETE FROM <service_accounts> WHERE id = $1;   -- rows affected decides
//
// The keys go first and explicitly, even though the schema's ON DELETE
// CASCADE would remove them with the account: the port's cascade MUST is
// discharged by this method's own transaction, so it holds against a
// hand-migrated schema that dropped the constraint, and the constraint
// stays as the backstop nothing can route around. Zero rows on the second
// statement is apikey.ErrServiceAccountNotFound and rolls the transaction
// back — there were no keys to roll back in that case, but a rows-affected
// answer is what makes two concurrent deletes of one account tell exactly
// one caller it won.
func (st *APIKeyStore) DeleteServiceAccount(ctx context.Context, id string) error {
	return st.db.InTx(ctx, func(txdb *pg.DB) error {
		if _, err := txdb.Delete(st.s.Keys).
			Where(st.s.keys.eq("service_account_id", id)).
			Exec(ctx); err != nil {
			return err
		}
		res, err := txdb.Delete(st.s.ServiceAccounts).
			Where(st.s.accounts.eq("id", id)).
			Exec(ctx)
		return affectedOrErr(res, err, apikey.ErrServiceAccountNotFound)
	})
}

// ── Keys ────────────────────────────────────────────────────────────────────

// CreateKey persists an already-stamped key and returns it unchanged. It is
// a single INSERT, and the three refusals the port names all come back from
// the same statement, classified from the driver's own error: a primary-key
// violation is apikey.ErrIDTaken (see [isPrimaryKeyViolation] for why the
// constraint name is read off the error rather than re-queried); a
// foreign-key violation — service_account_id naming no account, refused by
// the constraint [APIKeySchema] declares — is apikey.ErrServiceAccountNotFound;
// any other unique violation is the token_hash constraint and is let through
// unwrapped as pg.ErrUniqueViolation, since the port classifies no hash
// collision. Each classified sentinel wraps the original error.
//
// A nil Permissions — "no cap", the shape every unrestricted key has — is
// written as an EMPTY bytea, not NULL: the column is NOT NULL (colSet types
// every []byte column that way, as it does organization_roles.permissions),
// and a nil slice would bind as NULL and fail the insert with SQLSTATE
// 23502. It reads back as an empty, non-nil slice, which the Service and
// the port treat exactly as nil — len is what both consult — and which the
// returned record carries too.
func (st *APIKeyStore) CreateKey(ctx context.Context, k apikey.Key) (apikey.Key, error) {
	if k.Permissions == nil {
		k.Permissions = []byte{}
	}
	_, err := st.db.Insert(st.s.Keys).Row(st.s.keys.row(k)...).Exec(ctx)
	switch {
	case err == nil:
		return k, nil
	case errors.Is(err, pg.ErrForeignKeyViolation):
		return apikey.Key{}, fmt.Errorf("%w: %w", apikey.ErrServiceAccountNotFound, err)
	case errors.Is(err, pg.ErrUniqueViolation) && isPrimaryKeyViolation(err):
		return apikey.Key{}, fmt.Errorf("%w: %w", apikey.ErrIDTaken, err)
	default:
		return apikey.Key{}, err
	}
}

// FindKeyByHash loads the key whose token_hash matches — the one lookup every
// authentication performs, served by the UNIQUE index — mapping ErrNoRows to
// apikey.ErrKeyNotFound. Revoked and expired keys are returned.
func (st *APIKeyStore) FindKeyByHash(ctx context.Context, tokenHash string) (apikey.Key, error) {
	var k apikey.Key
	err := st.db.Select().From(st.s.Keys).
		Where(st.s.keys.eq("token_hash", tokenHash)).
		One(ctx, &k)
	if err != nil {
		return apikey.Key{}, mapNoRows(err, apikey.ErrKeyNotFound)
	}
	return k, nil
}

// FindKey loads a key by id, mapping ErrNoRows to apikey.ErrKeyNotFound.
func (st *APIKeyStore) FindKey(ctx context.Context, id string) (apikey.Key, error) {
	var k apikey.Key
	err := st.db.Select().From(st.s.Keys).
		Where(st.s.keys.eq("id", id)).
		One(ctx, &k)
	if err != nil {
		return apikey.Key{}, mapNoRows(err, apikey.ErrKeyNotFound)
	}
	return k, nil
}

// ListKeys returns every key of serviceAccountID, revoked or expired or not.
// An account with none yields nil, not an error.
func (st *APIKeyStore) ListKeys(ctx context.Context, serviceAccountID string) ([]apikey.Key, error) {
	var out []apikey.Key
	if err := st.db.Select().From(st.s.Keys).
		Where(st.s.keys.eq("service_account_id", serviceAccountID)).
		All(ctx, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// RevokeKey stamps revoked_at with now, reporting apikey.ErrKeyNotFound when
// no row matched. Revoking a revoked key overwrites the timestamp, matching
// [InviteStore.RevokeLink].
func (st *APIKeyStore) RevokeKey(ctx context.Context, id string, now time.Time) error {
	res, err := st.db.Update(st.s.Keys).
		Set(st.s.keys.bind("revoked_at", &now)).
		Where(st.s.keys.eq("id", id)).
		Exec(ctx)
	return affectedOrErr(res, err, apikey.ErrKeyNotFound)
}

// TouchKey stamps last_used_at with now, reporting apikey.ErrKeyNotFound when
// no row matched. One UPDATE by primary key; the Service calls it on every
// successful authentication and treats a failure as a logging event.
func (st *APIKeyStore) TouchKey(ctx context.Context, id string, now time.Time) error {
	res, err := st.db.Update(st.s.Keys).
		Set(st.s.keys.bind("last_used_at", &now)).
		Where(st.s.keys.eq("id", id)).
		Exec(ctx)
	return affectedOrErr(res, err, apikey.ErrKeyNotFound)
}

// DeleteKey removes a key by id, reporting apikey.ErrKeyNotFound when no row
// matched.
func (st *APIKeyStore) DeleteKey(ctx context.Context, id string) error {
	res, err := st.db.Delete(st.s.Keys).
		Where(st.s.keys.eq("id", id)).
		Exec(ctx)
	return affectedOrErr(res, err, apikey.ErrKeyNotFound)
}

// PurgeExpired deletes, in one statement, every key whose expires_at OR
// whose revoked_at is strictly before `before`:
//
//	DELETE FROM <api_keys>
//	 WHERE (expires_at IS NOT NULL AND expires_at < $1)
//	    OR (revoked_at IS NOT NULL AND revoked_at < $1)
//
// and returns rows affected. A live key with no expiry never matches, and
// accounts are never touched. Housekeeping, not a security boundary — see
// the port.
func (st *APIKeyStore) PurgeExpired(ctx context.Context, before time.Time) (int, error) {
	expiresAt := st.s.keys.col("expires_at")
	revokedAt := st.s.keys.col("revoked_at")
	res, err := st.db.Delete(st.s.Keys).
		Where(pg.Or(
			pg.And(pg.IsNotNull(expiresAt), pg.Lt(expiresAt, before)),
			pg.And(pg.IsNotNull(revokedAt), pg.Lt(revokedAt, before)),
		)).
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
