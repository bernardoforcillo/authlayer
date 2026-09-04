package dropsstore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/bernardoforcillo/drops"
	"github.com/bernardoforcillo/drops/pg"

	"github.com/bernardoforcillo/authlayer/oauth"
)

// OAuthNames are the five table names an OAuthStore persists to. The zero
// value defaults to oauth_clients, oauth_grants, oauth_codes,
// oauth_device_authorizations and oauth_refresh_tokens — prefixed, since
// "clients" and "grants" are words an application's own schema is likely to
// hold; override them via [WithOAuthNames].
type OAuthNames struct {
	Clients              string // default "oauth_clients"
	Grants               string // default "oauth_grants"
	Codes                string // default "oauth_codes"
	DeviceAuthorizations string // default "oauth_device_authorizations"
	RefreshTokens        string // default "oauth_refresh_tokens"
}

func (n OAuthNames) withDefaults() OAuthNames {
	if n.Clients == "" {
		n.Clients = "oauth_clients"
	}
	if n.Grants == "" {
		n.Grants = "oauth_grants"
	}
	if n.Codes == "" {
		n.Codes = "oauth_codes"
	}
	if n.DeviceAuthorizations == "" {
		n.DeviceAuthorizations = "oauth_device_authorizations"
	}
	if n.RefreshTokens == "" {
		n.RefreshTokens = "oauth_refresh_tokens"
	}
	return n
}

type oauthSettings struct {
	names OAuthNames
	ids   idTypes
}

// OAuthOption customizes an [OAuthSchema] or [OAuthStore] at construction.
type OAuthOption func(*oauthSettings)

// WithOAuthNames overrides the five table names.
func WithOAuthNames(n OAuthNames) OAuthOption {
	return func(s *oauthSettings) { s.names = n }
}

// WithOAuthTextUserIDs types the two user-id columns — oauth_clients.created_by
// and oauth_grants.user_id — as text rather than uuid. Mirrors
// [WithTextUserIDs] on the scope Store: both hold ids from the application's
// own users table, so they follow that table's key type. It does not reach
// the ids authlayer mints for itself; [WithOAuthTextLibraryIDs] is the
// option for those, and the two compose.
func WithOAuthTextUserIDs() OAuthOption {
	return func(s *oauthSettings) { s.ids.user = false }
}

// WithOAuthTextLibraryIDs types the library-minted id columns — every
// table's own id, the container_id and service_account_id references on
// clients, and client_id, grant_id and family_id wherever they appear — as
// text rather than uuid. Mirrors [WithTextLibraryIDs] on the scope Store,
// and must be passed alongside it and alongside [WithAPIKeyTextLibraryIDs]:
// container_id references that store's containers table and
// service_account_id the API-key store's accounts, so the three have to
// agree.
//
// uuid remains the default, since authlayer mints UUIDv7. Use this when
// [github.com/bernardoforcillo/authlayer/oauth.WithIDGenerator] produces
// something PostgreSQL's uuid parser rejects.
func WithOAuthTextLibraryIDs() OAuthOption {
	return func(s *oauthSettings) { s.ids.library = false }
}

// clientRow is the table shape of an [oauth.Client]. It differs from the
// record in exactly the places PostgreSQL's types force it to: the three
// string lists are jsonb documents (see [OAuthSchema]), and the three ids
// the record leaves "" for an application-level or dynamically registered
// client — container_id, service_account_id, created_by — are nullable,
// because "" is not a uuid and the columns are uuid by default. [toClient]
// and [fromClient] convert; nothing else reads the row type.
type clientRow struct {
	ID               string          `drop:"id"`
	ContainerID      *string         `drop:"container_id"`
	Name             string          `drop:"name"`
	SecretHash       string          `drop:"secret_hash"`
	Public           bool            `drop:"public"`
	RedirectURIs     json.RawMessage `drop:"redirect_uris"`
	GrantTypes       json.RawMessage `drop:"grant_types"`
	Scopes           json.RawMessage `drop:"scopes"`
	ServiceAccountID *string         `drop:"service_account_id"`
	Permissions      []byte          `drop:"permissions"`
	CreatedBy        *string         `drop:"created_by"`
	CreatedAt        time.Time       `drop:"created_at"`
	UpdatedAt        time.Time       `drop:"updated_at"`
	DisabledAt       *time.Time      `drop:"disabled_at"`
}

// deviceRow is the table shape of an [oauth.DeviceAuthorization]: grant_id
// is nullable, since a pending authorization names no grant and "" is not
// a uuid.
type deviceRow struct {
	ID             string             `drop:"id"`
	DeviceCodeHash string             `drop:"device_code_hash,unique"`
	UserCode       string             `drop:"user_code,unique"`
	ClientID       string             `drop:"client_id"`
	Scope          string             `drop:"scope"`
	Status         oauth.DeviceStatus `drop:"status"`
	GrantID        *string            `drop:"grant_id"`
	Interval       int                `drop:"interval"`
	LastPolledAt   *time.Time         `drop:"last_polled_at"`
	ExpiresAt      time.Time          `drop:"expires_at"`
	CreatedAt      time.Time          `drop:"created_at"`
}

// nullable maps "" to NULL and anything else to itself.
func nullable(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// deref maps NULL to "".
func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// jsonList encodes a string list as a jsonb array, nil as "[]": the column
// is NOT NULL and a nil list means "no entries", never "no document".
func jsonList(list []string) json.RawMessage {
	if list == nil {
		list = []string{}
	}
	b, err := json.Marshal(list)
	if err != nil {
		// A []string cannot fail to marshal; the error path exists for
		// the compiler.
		panic("authlayer/store/drops: marshal string list: " + err.Error())
	}
	return b
}

// stringList decodes a jsonb array back into a list; an empty or absent
// document is nil.
func stringList(raw json.RawMessage) ([]string, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var out []string
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("authlayer/store/drops: decode string list: %w", err)
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

func fromClient(c oauth.Client) clientRow {
	perms := c.Permissions
	if perms == nil {
		perms = []byte{}
	}
	return clientRow{
		ID:               c.ID,
		ContainerID:      nullable(c.ContainerID),
		Name:             c.Name,
		SecretHash:       c.SecretHash,
		Public:           c.Public,
		RedirectURIs:     jsonList(c.RedirectURIs),
		GrantTypes:       jsonList(c.GrantTypes),
		Scopes:           jsonList(c.Scopes),
		ServiceAccountID: nullable(c.ServiceAccountID),
		Permissions:      perms,
		CreatedBy:        nullable(c.CreatedBy),
		CreatedAt:        c.CreatedAt,
		UpdatedAt:        c.UpdatedAt,
		DisabledAt:       c.DisabledAt,
	}
}

func toClient(r clientRow) (oauth.Client, error) {
	uris, err := stringList(r.RedirectURIs)
	if err != nil {
		return oauth.Client{}, err
	}
	grants, err := stringList(r.GrantTypes)
	if err != nil {
		return oauth.Client{}, err
	}
	scopes, err := stringList(r.Scopes)
	if err != nil {
		return oauth.Client{}, err
	}
	return oauth.Client{
		ID:               r.ID,
		ContainerID:      deref(r.ContainerID),
		Name:             r.Name,
		SecretHash:       r.SecretHash,
		Public:           r.Public,
		RedirectURIs:     uris,
		GrantTypes:       grants,
		Scopes:           scopes,
		ServiceAccountID: deref(r.ServiceAccountID),
		Permissions:      r.Permissions,
		CreatedBy:        deref(r.CreatedBy),
		CreatedAt:        r.CreatedAt,
		UpdatedAt:        r.UpdatedAt,
		DisabledAt:       r.DisabledAt,
	}, nil
}

func fromDevice(d oauth.DeviceAuthorization) deviceRow {
	return deviceRow{
		ID: d.ID, DeviceCodeHash: d.DeviceCodeHash, UserCode: d.UserCode, ClientID: d.ClientID,
		Scope: d.Scope, Status: d.Status, GrantID: nullable(d.GrantID), Interval: d.Interval,
		LastPolledAt: d.LastPolledAt, ExpiresAt: d.ExpiresAt, CreatedAt: d.CreatedAt,
	}
}

func toDevice(r deviceRow) oauth.DeviceAuthorization {
	return oauth.DeviceAuthorization{
		ID: r.ID, DeviceCodeHash: r.DeviceCodeHash, UserCode: r.UserCode, ClientID: r.ClientID,
		Scope: r.Scope, Status: r.Status, GrantID: deref(r.GrantID), Interval: r.Interval,
		LastPolledAt: r.LastPolledAt, ExpiresAt: r.ExpiresAt, CreatedAt: r.CreatedAt,
	}
}

// OAuthSchema holds the five OAuth tables and their derived columns:
//
//	<oauth_clients>      id PK, container_id NULL, name, secret_hash, public BOOLEAN,
//	                     redirect_uris JSONB, grant_types JSONB, scopes JSONB,
//	                     service_account_id NULL, permissions BYTEA, created_by NULL,
//	                     created_at, updated_at, disabled_at NULL,
//	                     INDEX (container_id)
//	<oauth_grants>       id PK, client_id REFERENCES <oauth_clients>(id) ON DELETE CASCADE,
//	                     user_id, container_id, scope, permissions BYTEA, created_at,
//	                     expires_at NULL, last_used_at NULL, revoked_at NULL,
//	                     INDEX (user_id), INDEX (client_id)
//	<oauth_codes>        id PK, code_hash UNIQUE, client_id REFERENCES <oauth_clients>(id)
//	                     ON DELETE CASCADE, grant_id REFERENCES <oauth_grants>(id)
//	                     ON DELETE CASCADE, redirect_uri, code_challenge, expires_at,
//	                     created_at, redeemed_at NULL,
//	                     INDEX (grant_id), INDEX (client_id)
//	<oauth_device_authorizations>
//	                     id PK, device_code_hash UNIQUE, user_code UNIQUE, client_id
//	                     REFERENCES <oauth_clients>(id) ON DELETE CASCADE, scope, status,
//	                     grant_id NULL, interval, last_polled_at NULL, expires_at,
//	                     created_at, INDEX (client_id)
//	<oauth_refresh_tokens>
//	                     id PK, token_hash UNIQUE, grant_id REFERENCES <oauth_grants>(id)
//	                     ON DELETE CASCADE, client_id REFERENCES <oauth_clients>(id)
//	                     ON DELETE CASCADE, family_id, expires_at, created_at,
//	                     rotated_at NULL, INDEX (grant_id), INDEX (client_id),
//	                     INDEX (family_id)
//
// # The four UNIQUEs are load-bearing
//
// code_hash, device_code_hash, user_code and token_hash each carry a MUST
// on the record type ([oauth.AuthorizationCode], [oauth.DeviceAuthorization],
// [oauth.RefreshToken]), and every one discharges the same obligation
// [AuthSchema] records for sessions.token_hash: the three compare-and-sets
// below are single-winner only if a hash identifies at most one row. All
// four are declared INLINE through the records' own `,unique` tag options,
// so they are part of the CREATE TABLE — and, as [APIKeySchema] notes for
// the same shape, cannot be self-healed onto a pre-existing table by
// CreateSchema.
//
// # The foreign keys are the cascades, and the referential refusals
//
// Every reference between these tables is a foreign key with ON DELETE
// CASCADE, because every table is owned by this one store — the same
// reasoning [APIKeySchema] gives, extended to five tables. They do two
// jobs. They are what makes CreateGrant, CreateCode,
// CreateDeviceAuthorization and CreateRefreshToken refuse a row naming no
// client or no grant (the port's referential MUSTs, surfaced as a
// foreign-key violation and classified as ErrClientNotFound or
// ErrGrantNotFound). And they back the two atomic cascades:
// [OAuthStore.DeleteClient] and [OAuthStore.RevokeGrant] delete their
// dependents explicitly inside one transaction, so the port's MUST holds
// against a hand-migrated schema that dropped a constraint, with the
// constraint as the backstop nothing can route around.
// oauth_device_authorizations.grant_id deliberately has NO foreign key: it
// is NULL until approval and its row is inert once the grant is gone —
// the Service checks the grant's liveness after every redemption — so a
// cascade there would buy nothing and a SET NULL would rewrite history.
//
// # jsonb for the three lists, and nullable ids
//
// redirect_uris, grant_types and scopes are each one jsonb array. They are
// application-shaped lists no query filters on, so a child table per list
// would be three joins on every client load for nothing, and a text[]
// column is a driver type database/sql cannot scan into a Go slice. A nil
// list is written as "[]", never NULL. container_id, service_account_id
// and created_by are nullable because an application-level or dynamically
// registered client has none of them and "" is not a uuid; the row type
// converts "" ↔ NULL, and [OAuthStore.ListClients] with "" queries
// container_id IS NULL. permissions, on clients and grants, is NOT NULL
// with a nil cap written as an empty bytea, exactly as [APIKeySchema]
// treats api_keys.permissions.
//
// # The indexes
//
// clients(container_id) serves ListClients; grants(user_id) ListGrantsByUser
// and grants(client_id) the client cascade; codes and refresh tokens carry
// (grant_id) for the grant cascades and (client_id) for the client one;
// refresh_tokens(family_id) serves DeleteRefreshFamily; device
// authorizations carry (client_id) for the client cascade. The four UNIQUE
// columns are the lookup keys every token path uses and need no separate
// index. All are emitted as CREATE INDEX IF NOT EXISTS.
type OAuthSchema struct {
	// Clients is the client table. See [oauth.Client].
	Clients *pg.Table
	// Grants is the delegation table. See [oauth.Grant].
	Grants *pg.Table
	// Codes is the authorization-code table. See [oauth.AuthorizationCode].
	Codes *pg.Table
	// DeviceAuthorizations is the device-flow table. See
	// [oauth.DeviceAuthorization].
	DeviceAuthorizations *pg.Table
	// RefreshTokens is the refresh-token table. See [oauth.RefreshToken].
	RefreshTokens *pg.Table

	clients *colSet
	grants  *colSet
	codes   *colSet
	devices *colSet
	refresh *colSet
}

// NewOAuthSchema builds the schema for one store instance. [NewOAuthStore]
// calls it, so use it directly only when you need the table definitions
// without a store — to generate DDL for a migration, for instance.
func NewOAuthSchema(opts ...OAuthOption) *OAuthSchema {
	cfg := oauthSettings{ids: uuidIDs()}
	for _, o := range opts {
		o(&cfg)
	}
	// The references between these tables hold ids oauth.Service mints, so
	// they follow WithOAuthTextLibraryIDs — scoped to this schema; see
	// idTypes.extraLibrary for why not the global list.
	cfg.ids.extraLibrary = map[string]bool{"client_id": true, "grant_id": true, "family_id": true}
	names := cfg.names.withDefaults()

	s := &OAuthSchema{
		Clients:              pg.NewTable(names.Clients),
		Grants:               pg.NewTable(names.Grants),
		Codes:                pg.NewTable(names.Codes),
		DeviceAuthorizations: pg.NewTable(names.DeviceAuthorizations),
		RefreshTokens:        pg.NewTable(names.RefreshTokens),
	}
	s.clients = newColSet(s.Clients, clientRow{}, cfg.ids)
	s.grants = newColSet(s.Grants, oauth.Grant{}, cfg.ids)
	s.codes = newColSet(s.Codes, oauth.AuthorizationCode{}, cfg.ids)
	s.devices = newColSet(s.DeviceAuthorizations, deviceRow{}, cfg.ids)
	s.refresh = newColSet(s.RefreshTokens, oauth.RefreshToken{}, cfg.ids)

	cascade := pg.OnDelete("CASCADE")
	s.Grants.ForeignKey(s.grants.col("client_id"), s.clients.col("id"), cascade)
	s.Codes.ForeignKey(s.codes.col("client_id"), s.clients.col("id"), cascade)
	s.Codes.ForeignKey(s.codes.col("grant_id"), s.grants.col("id"), cascade)
	s.DeviceAuthorizations.ForeignKey(s.devices.col("client_id"), s.clients.col("id"), cascade)
	s.RefreshTokens.ForeignKey(s.refresh.col("grant_id"), s.grants.col("id"), cascade)
	s.RefreshTokens.ForeignKey(s.refresh.col("client_id"), s.clients.col("id"), cascade)

	idx := func(t *pg.Table, cs *colSet, col string) {
		t.AddIndex(pg.NewIndex(t.Name()+"_"+col+"_idx", t, cs.col(col)))
	}
	idx(s.Clients, s.clients, "container_id")
	idx(s.Grants, s.grants, "user_id")
	idx(s.Grants, s.grants, "client_id")
	idx(s.Codes, s.codes, "grant_id")
	idx(s.Codes, s.codes, "client_id")
	idx(s.DeviceAuthorizations, s.devices, "client_id")
	idx(s.RefreshTokens, s.refresh, "grant_id")
	idx(s.RefreshTokens, s.refresh, "client_id")
	idx(s.RefreshTokens, s.refresh, "family_id")
	return s
}

// tables lists the five in creation order: every referenced table before
// the tables that reference it.
func (s *OAuthSchema) tables() []*pg.Table {
	return []*pg.Table{s.Clients, s.Grants, s.Codes, s.DeviceAuthorizations, s.RefreshTokens}
}

// OAuthStore is a drops-backed oauth.Store. Like [APIKeyStore] it is pure
// persistence: it hashes nothing, signs nothing, interprets no permission
// bytes and authorizes nothing — the oauth.Service decides, and hands it
// fully-formed values to write or hashes to read by.
type OAuthStore struct {
	db *pg.DB
	s  *OAuthSchema
}

// Compile-time proof the drops store satisfies the port.
var _ oauth.Store = (*OAuthStore)(nil)

// NewOAuthStore returns an OAuthStore over db, building a fresh
// [OAuthSchema].
func NewOAuthStore(db *pg.DB, opts ...OAuthOption) *OAuthStore {
	return &OAuthStore{db: db, s: NewOAuthSchema(opts...)}
}

// Schema exposes the tables so callers can build guards, join against them,
// or emit their own DDL.
func (st *OAuthStore) Schema() *OAuthSchema { return st.s }

// CreateSchema issues CREATE TABLE IF NOT EXISTS for the five tables in
// dependency order — clients, grants, then the three that reference them —
// each followed by CREATE INDEX IF NOT EXISTS for its indexes. Every
// statement is idempotent, so the call is safe to re-run and self-heals a
// table missing an index.
//
// Like every other CreateSchema in this package it adds what is missing and
// never alters what is already there, so production deployments that own
// these tables via their own migrations should skip it. In particular it
// cannot RETYPE an existing table, so [WithOAuthTextLibraryIDs] has no
// effect on one, and it cannot add a UNIQUE or a foreign key to a table
// that already exists — all live inside the CREATE TABLE that no-ops away
// against a table that is already there (see [OAuthSchema]).
func (st *OAuthStore) CreateSchema(ctx context.Context) error {
	for _, t := range st.s.tables() {
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

// classifyCreate maps a driver error from one of the five INSERTs: a
// primary-key violation is oauth.ErrIDTaken; a foreign-key violation is the
// referential refusal the port names (refNotFound — ErrClientNotFound or
// ErrGrantNotFound, per the table); any other unique violation is one of
// the four hash or user-code constraints and is let through unwrapped as
// pg.ErrUniqueViolation, since the port classifies no such collision.
func classifyCreate(err, refNotFound error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, pg.ErrForeignKeyViolation):
		return fmt.Errorf("%w: %w", refNotFound, err)
	case errors.Is(err, pg.ErrUniqueViolation) && isPrimaryKeyViolation(err):
		return fmt.Errorf("%w: %w", oauth.ErrIDTaken, err)
	default:
		return err
	}
}

// returningAll lists every column of t for a RETURNING clause.
func returningAll(t *pg.Table) []drops.Expression {
	cols := t.Columns()
	out := make([]drops.Expression, len(cols))
	for i, c := range cols {
		out[i] = c
	}
	return out
}

// ── Clients ─────────────────────────────────────────────────────────────

// CreateClient persists an already-stamped client and returns it
// unchanged. The table's only unique-enforcing constraint is the primary
// key, so a unique violation here can only be an id collision and is
// classified as oauth.ErrIDTaken, wrapping the original error.
func (st *OAuthStore) CreateClient(ctx context.Context, c oauth.Client) (oauth.Client, error) {
	_, err := st.db.Insert(st.s.Clients).Row(st.s.clients.row(fromClient(c))...).Exec(ctx)
	if err != nil {
		if errors.Is(err, pg.ErrUniqueViolation) {
			return oauth.Client{}, fmt.Errorf("%w: %w", oauth.ErrIDTaken, err)
		}
		return oauth.Client{}, err
	}
	return c, nil
}

// FindClient loads a client by id, mapping drops' ErrNoRows to
// oauth.ErrClientNotFound. Disabled clients are returned.
func (st *OAuthStore) FindClient(ctx context.Context, id string) (oauth.Client, error) {
	var r clientRow
	err := st.db.Select().From(st.s.Clients).Where(st.s.clients.eq("id", id)).One(ctx, &r)
	if err != nil {
		return oauth.Client{}, mapNoRows(err, oauth.ErrClientNotFound)
	}
	return toClient(r)
}

// ListClients returns every client whose container_id is containerID —
// or, for "", whose container_id IS NULL: the application-level clients.
// A container with none yields nil, not an error.
func (st *OAuthStore) ListClients(ctx context.Context, containerID string) ([]oauth.Client, error) {
	q := st.db.Select().From(st.s.Clients)
	if containerID == "" {
		q = q.Where(pg.IsNull(st.s.clients.col("container_id")))
	} else {
		q = q.Where(st.s.clients.eq("container_id", containerID))
	}
	var rows []clientRow
	if err := q.All(ctx, &rows); err != nil {
		return nil, err
	}
	out := make([]oauth.Client, 0, len(rows))
	for _, r := range rows {
		c, err := toClient(r)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}

// UpdateClient replaces the mutable columns of the row c.ID names — name,
// secret_hash, redirect_uris, grant_types, scopes, service_account_id,
// permissions, updated_at, disabled_at — reporting oauth.ErrClientNotFound
// when no row matched. id, container_id, public, created_by and created_at
// are not in the SET.
func (st *OAuthStore) UpdateClient(ctx context.Context, c oauth.Client) error {
	r := fromClient(c)
	cs := st.s.clients
	res, err := st.db.Update(st.s.Clients).
		Set(
			cs.bind("name", r.Name),
			cs.bind("secret_hash", r.SecretHash),
			cs.bind("redirect_uris", r.RedirectURIs),
			cs.bind("grant_types", r.GrantTypes),
			cs.bind("scopes", r.Scopes),
			cs.bind("service_account_id", r.ServiceAccountID),
			cs.bind("permissions", r.Permissions),
			cs.bind("updated_at", r.UpdatedAt),
			cs.bind("disabled_at", r.DisabledAt),
		).
		Where(cs.eq("id", c.ID)).
		Exec(ctx)
	return affectedOrErr(res, err, oauth.ErrClientNotFound)
}

// DeleteClient removes the client and everything of it in ONE transaction:
//
//	DELETE FROM <oauth_refresh_tokens>        WHERE client_id = $1;
//	DELETE FROM <oauth_codes>                 WHERE client_id = $1;
//	DELETE FROM <oauth_device_authorizations> WHERE client_id = $1;
//	DELETE FROM <oauth_grants>                WHERE client_id = $1;
//	DELETE FROM <oauth_clients>               WHERE id = $1;   -- rows affected decides
//
// The dependents go first and explicitly, even though the foreign keys'
// ON DELETE CASCADE would remove them with the client, for the reason
// [APIKeyStore.DeleteServiceAccount] gives: the port's cascade MUST is
// discharged by this method's own transaction and holds against a
// hand-migrated schema, with the constraints as the backstop. Zero rows on
// the last statement is oauth.ErrClientNotFound and rolls the transaction
// back — a rows-affected answer, so two concurrent deletes of one client
// tell exactly one caller it won.
func (st *OAuthStore) DeleteClient(ctx context.Context, id string) error {
	return st.db.InTx(ctx, func(txdb *pg.DB) error {
		for _, dep := range []struct {
			t  *pg.Table
			cs *colSet
		}{
			{st.s.RefreshTokens, st.s.refresh},
			{st.s.Codes, st.s.codes},
			{st.s.DeviceAuthorizations, st.s.devices},
			{st.s.Grants, st.s.grants},
		} {
			if _, err := txdb.Delete(dep.t).Where(dep.cs.eq("client_id", id)).Exec(ctx); err != nil {
				return err
			}
		}
		res, err := txdb.Delete(st.s.Clients).Where(st.s.clients.eq("id", id)).Exec(ctx)
		return affectedOrErr(res, err, oauth.ErrClientNotFound)
	})
}

// ── Grants ──────────────────────────────────────────────────────────────

// CreateGrant persists an already-stamped grant and returns it unchanged,
// classifying a primary-key violation as oauth.ErrIDTaken and a foreign-key
// violation — client_id naming no client, refused by the constraint — as
// oauth.ErrClientNotFound, each wrapping the driver's error. A nil
// Permissions is written as an empty bytea, as [APIKeyStore.CreateKey]
// writes a nil cap.
func (st *OAuthStore) CreateGrant(ctx context.Context, g oauth.Grant) (oauth.Grant, error) {
	if g.Permissions == nil {
		g.Permissions = []byte{}
	}
	_, err := st.db.Insert(st.s.Grants).Row(st.s.grants.row(g)...).Exec(ctx)
	if err := classifyCreate(err, oauth.ErrClientNotFound); err != nil {
		return oauth.Grant{}, err
	}
	return g, nil
}

// FindGrant loads a grant by id, mapping ErrNoRows to oauth.ErrGrantNotFound.
// Revoked and expired grants are returned.
func (st *OAuthStore) FindGrant(ctx context.Context, id string) (oauth.Grant, error) {
	var g oauth.Grant
	err := st.db.Select().From(st.s.Grants).Where(st.s.grants.eq("id", id)).One(ctx, &g)
	if err != nil {
		return oauth.Grant{}, mapNoRows(err, oauth.ErrGrantNotFound)
	}
	return g, nil
}

// ListGrantsByUser returns every grant of userID, revoked or expired or
// not. A user with none yields nil, not an error.
func (st *OAuthStore) ListGrantsByUser(ctx context.Context, userID string) ([]oauth.Grant, error) {
	var out []oauth.Grant
	if err := st.db.Select().From(st.s.Grants).Where(st.s.grants.eq("user_id", userID)).All(ctx, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// RevokeGrant stamps revoked_at and deletes the grant's refresh tokens in
// ONE transaction:
//
//	DELETE FROM <oauth_refresh_tokens> WHERE grant_id = $1;
//	UPDATE <oauth_grants> SET revoked_at = $2 WHERE id = $1;   -- rows affected decides
//
// Zero rows on the UPDATE is oauth.ErrGrantNotFound and rolls back (there
// were no tokens to roll back, since none can exist without the grant).
// Revoking a revoked grant overwrites the timestamp.
func (st *OAuthStore) RevokeGrant(ctx context.Context, id string, now time.Time) error {
	return st.db.InTx(ctx, func(txdb *pg.DB) error {
		if _, err := txdb.Delete(st.s.RefreshTokens).Where(st.s.refresh.eq("grant_id", id)).Exec(ctx); err != nil {
			return err
		}
		res, err := txdb.Update(st.s.Grants).
			Set(st.s.grants.bind("revoked_at", &now)).
			Where(st.s.grants.eq("id", id)).
			Exec(ctx)
		return affectedOrErr(res, err, oauth.ErrGrantNotFound)
	})
}

// TouchGrant stamps last_used_at with now, reporting oauth.ErrGrantNotFound
// when no row matched.
func (st *OAuthStore) TouchGrant(ctx context.Context, id string, now time.Time) error {
	res, err := st.db.Update(st.s.Grants).
		Set(st.s.grants.bind("last_used_at", &now)).
		Where(st.s.grants.eq("id", id)).
		Exec(ctx)
	return affectedOrErr(res, err, oauth.ErrGrantNotFound)
}

// ── Authorization codes ─────────────────────────────────────────────────

// CreateCode persists an already-stamped code and returns it unchanged: a
// primary-key violation is oauth.ErrIDTaken, a foreign-key violation
// (grant_id naming no grant) oauth.ErrGrantNotFound, and the UNIQUE on
// code_hash is let through as pg.ErrUniqueViolation unwrapped — see
// [classifyCreate].
func (st *OAuthStore) CreateCode(ctx context.Context, c oauth.AuthorizationCode) (oauth.AuthorizationCode, error) {
	_, err := st.db.Insert(st.s.Codes).Row(st.s.codes.row(c)...).Exec(ctx)
	if err := classifyCreate(err, oauth.ErrGrantNotFound); err != nil {
		return oauth.AuthorizationCode{}, err
	}
	return c, nil
}

// RedeemCode implements the port's compare-and-set as one statement:
//
//	UPDATE <oauth_codes> SET redeemed_at = $1
//	 WHERE code_hash = $2 AND redeemed_at IS NULL
//	 RETURNING <every column>
//
// redeemed_at IS NULL in the WHERE is what makes this a compare-and-set —
// PostgreSQL decides "unredeemed" and applies the SET under one row lock,
// exactly as [AuthStore.MarkRotated] does for a session. A single-winner
// guarantee only because code_hash is UNIQUE. Expiry is deliberately
// absent from the WHERE. When nothing matches, one follow-up read by hash
// classifies the miss into oauth.ErrCodeNotFound or (row, false, nil); that
// read never writes, so it cannot reopen the gap.
func (st *OAuthStore) RedeemCode(ctx context.Context, codeHash string, now time.Time) (oauth.AuthorizationCode, bool, error) {
	var c oauth.AuthorizationCode
	err := st.db.Update(st.s.Codes).
		Set(st.s.codes.bind("redeemed_at", &now)).
		Where(st.s.codes.eq("code_hash", codeHash), pg.IsNull(st.s.codes.col("redeemed_at"))).
		Returning(returningAll(st.s.Codes)...).
		One(ctx, &c)
	if err == nil {
		return c, true, nil
	}
	if !errors.Is(err, pg.ErrNoRows) {
		return oauth.AuthorizationCode{}, false, err
	}
	err = st.db.Select().From(st.s.Codes).Where(st.s.codes.eq("code_hash", codeHash)).One(ctx, &c)
	if err != nil {
		return oauth.AuthorizationCode{}, false, mapNoRows(err, oauth.ErrCodeNotFound)
	}
	return c, false, nil
}

// ── Device authorizations ───────────────────────────────────────────────

// CreateDeviceAuthorization persists an already-stamped authorization and
// returns it unchanged, on [classifyCreate]'s terms: a foreign-key
// violation is oauth.ErrClientNotFound, and either UNIQUE (device_code_hash,
// user_code) is let through as pg.ErrUniqueViolation. A "" GrantID is
// written as NULL.
func (st *OAuthStore) CreateDeviceAuthorization(ctx context.Context, d oauth.DeviceAuthorization) (oauth.DeviceAuthorization, error) {
	_, err := st.db.Insert(st.s.DeviceAuthorizations).Row(st.s.devices.row(fromDevice(d))...).Exec(ctx)
	if err := classifyCreate(err, oauth.ErrClientNotFound); err != nil {
		return oauth.DeviceAuthorization{}, err
	}
	return d, nil
}

func (st *OAuthStore) findDevice(ctx context.Context, where drops.Expression) (oauth.DeviceAuthorization, error) {
	var r deviceRow
	err := st.db.Select().From(st.s.DeviceAuthorizations).Where(where).One(ctx, &r)
	if err != nil {
		return oauth.DeviceAuthorization{}, mapNoRows(err, oauth.ErrDeviceNotFound)
	}
	return toDevice(r), nil
}

// FindDeviceByCodeHash loads the authorization whose device_code_hash
// matches, mapping ErrNoRows to oauth.ErrDeviceNotFound.
func (st *OAuthStore) FindDeviceByCodeHash(ctx context.Context, deviceCodeHash string) (oauth.DeviceAuthorization, error) {
	return st.findDevice(ctx, st.s.devices.eq("device_code_hash", deviceCodeHash))
}

// FindDeviceByUserCode loads the authorization whose user_code matches
// exactly, mapping ErrNoRows to oauth.ErrDeviceNotFound.
func (st *OAuthStore) FindDeviceByUserCode(ctx context.Context, userCode string) (oauth.DeviceAuthorization, error) {
	return st.findDevice(ctx, st.s.devices.eq("user_code", userCode))
}

// SetDeviceStatus implements the port's compare-and-set as one statement:
//
//	UPDATE <oauth_device_authorizations> SET status = $to [, grant_id = $g]
//	 WHERE id = $1 AND status = $from
//
// status = $from in the WHERE is the compare; rows affected is the answer.
// grant_id is in the SET only when to is approved. When nothing matches,
// one follow-up read by id classifies the miss into oauth.ErrDeviceNotFound
// or (false, nil).
func (st *OAuthStore) SetDeviceStatus(ctx context.Context, id string, from, to oauth.DeviceStatus, grantID string, _ time.Time) (bool, error) {
	ds := st.s.devices
	sets := []pg.ColumnValue{ds.bind("status", to)}
	if to == oauth.DeviceStatusApproved {
		sets = append(sets, ds.bind("grant_id", nullable(grantID)))
	}
	res, err := st.db.Update(st.s.DeviceAuthorizations).
		Set(sets...).
		Where(ds.eq("id", id), ds.eq("status", from)).
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
	if _, err := st.findDevice(ctx, ds.eq("id", id)); err != nil {
		return false, err
	}
	return false, nil
}

// TouchDevicePoll stamps last_polled_at with now, reporting
// oauth.ErrDeviceNotFound when no row matched.
func (st *OAuthStore) TouchDevicePoll(ctx context.Context, id string, now time.Time) error {
	res, err := st.db.Update(st.s.DeviceAuthorizations).
		Set(st.s.devices.bind("last_polled_at", &now)).
		Where(st.s.devices.eq("id", id)).
		Exec(ctx)
	return affectedOrErr(res, err, oauth.ErrDeviceNotFound)
}

// ── Refresh tokens ──────────────────────────────────────────────────────

// CreateRefreshToken persists an already-stamped token and returns it
// unchanged, on [classifyCreate]'s terms: a foreign-key violation on
// grant_id is oauth.ErrGrantNotFound (one on client_id would be
// oauth.ErrClientNotFound in spirit but is reported the same way — the
// Service never writes a token whose grant exists and client does not),
// and the UNIQUE on token_hash is let through as pg.ErrUniqueViolation.
func (st *OAuthStore) CreateRefreshToken(ctx context.Context, r oauth.RefreshToken) (oauth.RefreshToken, error) {
	_, err := st.db.Insert(st.s.RefreshTokens).Row(st.s.refresh.row(r)...).Exec(ctx)
	if err := classifyCreate(err, oauth.ErrGrantNotFound); err != nil {
		return oauth.RefreshToken{}, err
	}
	return r, nil
}

// FindRefreshTokenByHash loads the token whose token_hash matches, mapping
// ErrNoRows to oauth.ErrRefreshNotFound. Rotated and expired tokens are
// returned.
func (st *OAuthStore) FindRefreshTokenByHash(ctx context.Context, tokenHash string) (oauth.RefreshToken, error) {
	var r oauth.RefreshToken
	err := st.db.Select().From(st.s.RefreshTokens).Where(st.s.refresh.eq("token_hash", tokenHash)).One(ctx, &r)
	if err != nil {
		return oauth.RefreshToken{}, mapNoRows(err, oauth.ErrRefreshNotFound)
	}
	return r, nil
}

// MarkRefreshRotated implements the port's compare-and-set exactly as
// [AuthStore.MarkRotated] does, statement for statement:
//
//	UPDATE <oauth_refresh_tokens> SET rotated_at = $1
//	 WHERE token_hash = $2 AND rotated_at IS NULL
//	 RETURNING <every column>
//
// with the same follow-up read to classify a miss into
// oauth.ErrRefreshNotFound or (row, false, nil), and the same reasons.
func (st *OAuthStore) MarkRefreshRotated(ctx context.Context, tokenHash string, now time.Time) (oauth.RefreshToken, bool, error) {
	var r oauth.RefreshToken
	err := st.db.Update(st.s.RefreshTokens).
		Set(st.s.refresh.bind("rotated_at", &now)).
		Where(st.s.refresh.eq("token_hash", tokenHash), pg.IsNull(st.s.refresh.col("rotated_at"))).
		Returning(returningAll(st.s.RefreshTokens)...).
		One(ctx, &r)
	if err == nil {
		return r, true, nil
	}
	if !errors.Is(err, pg.ErrNoRows) {
		return oauth.RefreshToken{}, false, err
	}
	err = st.db.Select().From(st.s.RefreshTokens).Where(st.s.refresh.eq("token_hash", tokenHash)).One(ctx, &r)
	if err != nil {
		return oauth.RefreshToken{}, false, mapNoRows(err, oauth.ErrRefreshNotFound)
	}
	return r, false, nil
}

// DeleteRefreshFamily removes every token whose family_id matches. Zero
// rows is the ordinary case, not a miss.
func (st *OAuthStore) DeleteRefreshFamily(ctx context.Context, familyID string) error {
	_, err := st.db.Delete(st.s.RefreshTokens).Where(st.s.refresh.eq("family_id", familyID)).Exec(ctx)
	return err
}

// ── Housekeeping ────────────────────────────────────────────────────────

// PurgeExpired runs, in ONE transaction, the six statements the port's
// contract adds up to:
//
//	DELETE FROM <oauth_codes>                 WHERE expires_at < $1;
//	DELETE FROM <oauth_device_authorizations> WHERE expires_at < $1;
//	DELETE FROM <oauth_refresh_tokens>        WHERE expires_at < $1;
//	SELECT id FROM <oauth_grants> WHERE (expires_at IS NOT NULL AND expires_at < $1)
//	                                 OR (revoked_at IS NOT NULL AND revoked_at < $1);
//	DELETE FROM <oauth_codes>          WHERE grant_id IN (<those ids>);
//	DELETE FROM <oauth_refresh_tokens> WHERE grant_id IN (<those ids>);
//	DELETE FROM <oauth_grants>         WHERE id IN (<those ids>);
//
// and returns the rows affected summed over every DELETE. The dead grants'
// dependents are deleted explicitly rather than left to ON DELETE CASCADE
// so the count is exact and the port's "no row names a grant that is gone"
// holds against a schema that dropped a constraint. The id list is read
// inside the transaction, so a grant revoked between the SELECT and the
// DELETE goes on the next pass, not this one.
func (st *OAuthStore) PurgeExpired(ctx context.Context, before time.Time) (int, error) {
	total := 0
	err := st.db.InTx(ctx, func(txdb *pg.DB) error {
		count := func(res drops.Result, err error) error {
			if err != nil {
				return err
			}
			n, err := res.RowsAffected()
			if err != nil {
				return err
			}
			total += int(n)
			return nil
		}
		for _, dep := range []struct {
			t  *pg.Table
			cs *colSet
		}{
			{st.s.Codes, st.s.codes},
			{st.s.DeviceAuthorizations, st.s.devices},
			{st.s.RefreshTokens, st.s.refresh},
		} {
			if err := count(txdb.Delete(dep.t).Where(pg.Lt(dep.cs.col("expires_at"), before)).Exec(ctx)); err != nil {
				return err
			}
		}
		expiresAt, revokedAt := st.s.grants.col("expires_at"), st.s.grants.col("revoked_at")
		var dead []struct {
			ID string `drop:"id"`
		}
		if err := txdb.Select(st.s.grants.col("id")).From(st.s.Grants).
			Where(pg.Or(
				pg.And(pg.IsNotNull(expiresAt), pg.Lt(expiresAt, before)),
				pg.And(pg.IsNotNull(revokedAt), pg.Lt(revokedAt, before)),
			)).All(ctx, &dead); err != nil {
			return err
		}
		if len(dead) == 0 {
			return nil
		}
		ids := make([]any, len(dead))
		for i, d := range dead {
			ids[i] = d.ID
		}
		if err := count(txdb.Delete(st.s.Codes).Where(pg.In(st.s.codes.col("grant_id"), ids...)).Exec(ctx)); err != nil {
			return err
		}
		if err := count(txdb.Delete(st.s.RefreshTokens).Where(pg.In(st.s.refresh.col("grant_id"), ids...)).Exec(ctx)); err != nil {
			return err
		}
		return count(txdb.Delete(st.s.Grants).Where(pg.In(st.s.grants.col("id"), ids...)).Exec(ctx))
	})
	if err != nil {
		return 0, err
	}
	return total, nil
}
