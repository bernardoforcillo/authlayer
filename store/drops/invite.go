package dropsstore

import (
	"context"
	"errors"
	"time"

	"github.com/bernardoforcillo/authlayer/invite"
	"github.com/bernardoforcillo/drops/pg"
)

// InviteNames are the two table names an InviteStore persists to. The zero
// value defaults to the organization scope's own naming — the same "no
// custom names given" convention [Names] follows — so a second scope
// instance (teams, projects) that wants its own invitation tables overrides
// them via [WithInviteNames], just as [WithNames] does for the scope tables.
type InviteNames struct {
	EmailInvites string // default "organization_invites"
	Links        string // default "organization_invite_links"
}

func (n InviteNames) withDefaults() InviteNames {
	if n.EmailInvites == "" {
		n.EmailInvites = "organization_invites"
	}
	if n.Links == "" {
		n.Links = "organization_invite_links"
	}
	return n
}

type inviteSettings struct {
	names       InviteNames
	uuidUserIDs bool
}

// InviteOption customizes an [InviteSchema] or [InviteStore] at construction.
type InviteOption func(*inviteSettings)

// WithInviteNames overrides the two table names, so a second scope instance
// (teams, projects) can persist its own invitations without colliding with
// another's.
func WithInviteNames(n InviteNames) InviteOption {
	return func(s *inviteSettings) { s.names = n }
}

// WithInviteTextUserIDs types invited_by and created_by as text rather than
// uuid. Mirrors [WithTextUserIDs] on the scope Store: use it only when
// invitations are used against an existing, non-UUID user table.
func WithInviteTextUserIDs() InviteOption {
	return func(s *inviteSettings) { s.uuidUserIDs = false }
}

// InviteSchema holds the two invitation tables and their derived columns:
//
//	<invites>       id PK, container_id, email, role_key, token_hash,
//	                invited_by, expires_at, created_at,
//	                UNIQUE (container_id, email)
//	<invite_links>  id PK, container_id, code, role_key, created_by, max_uses,
//	                use_count, expires_at, revoked_at, created_at,
//	                UNIQUE (code)
//
// Both unique constraints are load-bearing, not decoration. (container_id,
// email) is what turns a concurrent double-invite of the same address into a
// unique violation instead of two ambiguous rows — DeleteEmailInvitesFor is
// what makes an ordinary re-invite replace rather than duplicate, and this
// constraint is the backstop for the race between two such calls. code is
// what FindLinkByCode depends on to be an unambiguous lookup.
// [InviteStore.CreateSchema] emits both itself — CREATE TABLE cannot carry a
// multi-column UNIQUE, and code is registered as a one-column
// [pg.Table.AddUnique] for the same reason (the [invite.Link] struct tag
// carries no "unique" option, so nothing declares it inline) — following the
// idiom [Store.CreateSchema] already uses for the composite constraints on
// the scope tables.
//
// [invite.EmailInvite] and [invite.Link] are fixed shapes, unlike the
// generic scope Store, so unlike [Schema] this type is not parameterized by
// C, M.
type InviteSchema struct {
	// EmailInvites is the one-time, single-recipient invitation table.
	EmailInvites *pg.Table
	// Links is the reusable invitation-link table.
	Links *pg.Table

	emailInvites *colSet
	links        *colSet
}

// NewInviteSchema builds the schema for one invite store instance.
// [NewInviteStore] calls it, so use it directly only when you need the table
// definitions without a store — to generate DDL for a migration, for
// instance.
func NewInviteSchema(opts ...InviteOption) *InviteSchema {
	cfg := inviteSettings{uuidUserIDs: true}
	for _, o := range opts {
		o(&cfg)
	}
	names := cfg.names.withDefaults()

	s := &InviteSchema{
		EmailInvites: pg.NewTable(names.EmailInvites),
		Links:        pg.NewTable(names.Links),
	}
	s.emailInvites = newColSet(s.EmailInvites, invite.EmailInvite{}, cfg.uuidUserIDs)
	s.links = newColSet(s.Links, invite.Link{}, cfg.uuidUserIDs)

	s.EmailInvites.AddUnique(names.EmailInvites+"_container_email",
		s.emailInvites.col("container_id"), s.emailInvites.col("email"))
	s.Links.AddUnique(names.Links+"_code", s.links.col("code"))

	return s
}

// InviteStore is a drops-backed invite.Store. Like
// [store/memory.InviteStore] it is pure persistence and, because
// [invite.EmailInvite] and [invite.Link] are fixed shapes, it is not generic
// the way [Store] is over C and M.
type InviteStore struct {
	db *pg.DB
	s  *InviteSchema
}

// Compile-time proof the drops invite store satisfies the port.
var _ invite.Store = (*InviteStore)(nil)

// NewInviteStore returns an InviteStore over db, building a fresh
// [InviteSchema].
func NewInviteStore(db *pg.DB, opts ...InviteOption) *InviteStore {
	return &InviteStore{db: db, s: NewInviteSchema(opts...)}
}

// Schema exposes the tables so callers can build guards, join against them,
// or emit their own DDL.
func (st *InviteStore) Schema() *InviteSchema { return st.s }

// CreateSchema issues CREATE TABLE IF NOT EXISTS for both invitation tables,
// followed by the two UNIQUE constraints CREATE TABLE cannot carry — see
// [InviteSchema]'s doc for why they are load-bearing. Every statement is
// idempotent, so the call is safe to re-run; like [Store.CreateSchema] it
// adds what is missing and never alters what is already there, so production
// deployments that own these tables via their own migrations should skip it.
func (st *InviteStore) CreateSchema(ctx context.Context) error {
	for _, t := range []*pg.Table{st.s.EmailInvites, st.s.Links} {
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

// ── EmailInvite ─────────────────────────────────────────────────────────────

// CreateEmailInvite persists an already-stamped invite and returns it
// unchanged, matching store/memory's contract.
func (st *InviteStore) CreateEmailInvite(ctx context.Context, inv invite.EmailInvite) (invite.EmailInvite, error) {
	_, err := st.db.Insert(st.s.EmailInvites).Row(st.s.emailInvites.row(inv)...).Exec(ctx)
	if err != nil {
		return invite.EmailInvite{}, err
	}
	return inv, nil
}

// FindEmailInviteByTokenHash loads the invite whose TokenHash matches,
// mapping drops' ErrNoRows to invite.ErrInviteNotFound.
func (st *InviteStore) FindEmailInviteByTokenHash(ctx context.Context, tokenHash string) (invite.EmailInvite, error) {
	var inv invite.EmailInvite
	err := st.db.Select().From(st.s.EmailInvites).
		Where(st.s.emailInvites.eq("token_hash", tokenHash)).
		One(ctx, &inv)
	if err != nil {
		return invite.EmailInvite{}, mapNoRows(err, invite.ErrInviteNotFound)
	}
	return inv, nil
}

// FindEmailInvite loads an invite by id, mapping drops' ErrNoRows to
// invite.ErrInviteNotFound.
func (st *InviteStore) FindEmailInvite(ctx context.Context, id string) (invite.EmailInvite, error) {
	var inv invite.EmailInvite
	err := st.db.Select().From(st.s.EmailInvites).
		Where(st.s.emailInvites.eq("id", id)).
		One(ctx, &inv)
	if err != nil {
		return invite.EmailInvite{}, mapNoRows(err, invite.ErrInviteNotFound)
	}
	return inv, nil
}

// ListEmailInvites returns every invite in containerID, expired or not — the
// caller filters. A container with none yields an empty slice, not an error.
func (st *InviteStore) ListEmailInvites(ctx context.Context, containerID string) ([]invite.EmailInvite, error) {
	var out []invite.EmailInvite
	if err := st.db.Select().From(st.s.EmailInvites).
		Where(st.s.emailInvites.eq("container_id", containerID)).
		All(ctx, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// DeleteEmailInvite removes an invite by id, reporting
// invite.ErrInviteNotFound when no row matched.
func (st *InviteStore) DeleteEmailInvite(ctx context.Context, id string) error {
	res, err := st.db.Delete(st.s.EmailInvites).
		Where(st.s.emailInvites.eq("id", id)).
		Exec(ctx)
	return affectedOrErr(res, err, invite.ErrInviteNotFound)
}

// DeleteEmailInvitesFor removes every invite for (containerID, email).
// Deleting zero rows is not an error — paired with the (container_id,
// email) UNIQUE constraint (see [InviteSchema]), this is what makes an
// ordinary re-invite replace rather than duplicate.
func (st *InviteStore) DeleteEmailInvitesFor(ctx context.Context, containerID, email string) error {
	_, err := st.db.Delete(st.s.EmailInvites).
		Where(st.s.emailInvites.eq("container_id", containerID), st.s.emailInvites.eq("email", email)).
		Exec(ctx)
	return err
}

// ── Link ────────────────────────────────────────────────────────────────────

// CreateLink persists an already-stamped link and returns it unchanged,
// matching store/memory's contract.
func (st *InviteStore) CreateLink(ctx context.Context, l invite.Link) (invite.Link, error) {
	_, err := st.db.Insert(st.s.Links).Row(st.s.links.row(l)...).Exec(ctx)
	if err != nil {
		return invite.Link{}, err
	}
	return l, nil
}

// FindLinkByCode loads the link whose Code matches, mapping drops' ErrNoRows
// to invite.ErrLinkNotFound. Code is stored in clear (see [invite.Link]), so
// this is a plain lookup, unlike FindEmailInviteByTokenHash.
func (st *InviteStore) FindLinkByCode(ctx context.Context, code string) (invite.Link, error) {
	var l invite.Link
	err := st.db.Select().From(st.s.Links).
		Where(st.s.links.eq("code", code)).
		One(ctx, &l)
	if err != nil {
		return invite.Link{}, mapNoRows(err, invite.ErrLinkNotFound)
	}
	return l, nil
}

// FindLink loads a link by id, mapping drops' ErrNoRows to
// invite.ErrLinkNotFound.
func (st *InviteStore) FindLink(ctx context.Context, id string) (invite.Link, error) {
	var l invite.Link
	err := st.db.Select().From(st.s.Links).
		Where(st.s.links.eq("id", id)).
		One(ctx, &l)
	if err != nil {
		return invite.Link{}, mapNoRows(err, invite.ErrLinkNotFound)
	}
	return l, nil
}

// ListLinks returns every link in containerID, revoked or not, expired or
// not — the caller filters. A container with none yields an empty slice, not
// an error.
func (st *InviteStore) ListLinks(ctx context.Context, containerID string) ([]invite.Link, error) {
	var out []invite.Link
	if err := st.db.Select().From(st.s.Links).
		Where(st.s.links.eq("container_id", containerID)).
		All(ctx, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// RevokeLink stamps RevokedAt with at, reporting invite.ErrLinkNotFound when
// no row matched. Revoking an already-revoked link overwrites the timestamp
// rather than erroring — revocation is idempotent, matching store/memory.
func (st *InviteStore) RevokeLink(ctx context.Context, id string, at time.Time) error {
	res, err := st.db.Update(st.s.Links).
		Set(st.s.links.bind("revoked_at", &at)).
		Where(st.s.links.eq("id", id)).
		Exec(ctx)
	return affectedOrErr(res, err, invite.ErrLinkNotFound)
}

// ConsumeLink atomically increments UseCount in a single
//
//	UPDATE <links> SET use_count = use_count + 1
//	 WHERE id = $1
//	   AND revoked_at IS NULL
//	   AND (expires_at IS NULL OR expires_at > $2)
//	   AND (max_uses = 0 OR use_count < max_uses)
//
// exactly as invite.Store requires: ok is taken from rows-affected, which
// PostgreSQL decides under a single row lock, so no concurrent caller of
// this method can observe or act on an intermediate state — a MaxUses:1
// link can never admit two callers (see the interface's atomicity
// requirement).
//
// The expiry test uses strict ">" — a link exactly at its ExpiresAt instant
// is already expired, not admitted one tick later — matching store/memory's
// boundary convention (see its ConsumeLink doc) exactly, rather than
// PurgeExpired's looser, strictly-before one.
//
// A single UPDATE cannot say *why* it matched zero rows: "no such id" and
// "id exists but is revoked/expired/exhausted" both leave rows-affected at
// 0. Splitting that decision into a second, separate read would reintroduce
// the very check-then-act race the one-statement UPDATE exists to close.
// Instead, only on the zero-rows path, ConsumeLink re-reads the link
// purely to classify the failure for the caller: no such id becomes
// (false, invite.ErrLinkNotFound), matching the interface doc; a real row
// that failed one of the three guards becomes (false, nil). That follow-up
// read cannot reopen the atomicity gap above — the increment already did or
// did not happen by the time it runs, and this read never writes.
func (st *InviteStore) ConsumeLink(ctx context.Context, id string, now time.Time) (bool, error) {
	useCount := st.s.links.i32["use_count"]
	maxUses := st.s.links.i32["max_uses"]
	revokedAt := st.s.links.col("revoked_at")
	expiresAt := st.s.links.col("expires_at")

	res, err := st.db.Update(st.s.Links).
		Set(useCount.Expr(pg.Plus(useCount, 1))).
		Where(
			st.s.links.eq("id", id),
			pg.IsNull(revokedAt),
			pg.Or(pg.IsNull(expiresAt), pg.Gt(expiresAt, now)),
			pg.Or(pg.Eq(maxUses, int32(0)), pg.Lt(useCount, maxUses)),
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

	if _, ferr := st.FindLink(ctx, id); errors.Is(ferr, invite.ErrLinkNotFound) {
		return false, invite.ErrLinkNotFound
	} else if ferr != nil {
		return false, ferr
	}
	return false, nil
}

// PurgeExpired deletes every EmailInvite and Link expired strictly before
// before — email invites by ExpiresAt, links by a non-nil ExpiresAt — and
// returns how many rows were removed in total, across both kinds. A link
// with a nil ExpiresAt ("never") is never purged by this call, matching
// store/memory. Housekeeping, not a security boundary: unlike ConsumeLink
// this is not required to be atomic with anything else, so it is two plain
// DELETEs rather than one statement.
func (st *InviteStore) PurgeExpired(ctx context.Context, before time.Time) (int, error) {
	res1, err := st.db.Delete(st.s.EmailInvites).
		Where(pg.Lt(st.s.emailInvites.col("expires_at"), before)).
		Exec(ctx)
	if err != nil {
		return 0, err
	}
	a1, err := res1.RowsAffected()
	if err != nil {
		return 0, err
	}

	res2, err := st.db.Delete(st.s.Links).
		Where(pg.IsNotNull(st.s.links.col("expires_at")), pg.Lt(st.s.links.col("expires_at"), before)).
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
