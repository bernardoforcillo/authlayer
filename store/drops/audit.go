package dropsstore

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/bernardoforcillo/drops"
	"github.com/bernardoforcillo/drops/pg"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/bernardoforcillo/authlayer/audit"
)

// AuditStore is a drops-backed audit.Store over two tables, with the guard
// triggers of [AuditDDL] enforcing append-only at the database. It is pure
// persistence: the audit.Service stamps ids, times and redaction.
type AuditStore struct {
	db  *pg.DB
	cfg auditSettings
	ev  string // quoted events table
	sl  string // quoted seals table
}

// Compile-time proof the drops audit store satisfies the port.
var _ audit.Store = (*AuditStore)(nil)

// NewAuditStore returns an AuditStore over db, which must be a pool, not a
// handle bound to a transaction: Insert and InsertSeal each run in a READ
// COMMITTED transaction of their own, and a transaction-bound db cannot nest
// one (the database/sql driver refuses nested transactions). Write audit
// events outside the business transaction, so they survive its rollback.
func NewAuditStore(db *pg.DB, opts ...AuditOption) *AuditStore {
	cfg := newAuditSettings(opts)
	return &AuditStore{db: db, cfg: cfg, ev: quoteIdent(cfg.names.Events), sl: quoteIdent(cfg.names.Seals)}
}

// CreateSchema runs [AuditDDL] in one transaction, under an advisory lock so
// replicas booting together apply it one at a time. It creates the tables
// and indexes that are missing and replaces the guard functions and triggers
// in place, so they always match this version; it changes no table.
// Deployments that own their migrations apply AuditDDL there instead.
func (st *AuditStore) CreateSchema(ctx context.Context) error {
	return st.db.InTx(ctx, func(tx *pg.DB) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, int64(auditSchemaLock)); err != nil {
			return err
		}
		for _, stmt := range AuditDDL(func(s *auditSettings) { *s = st.cfg }) {
			if _, err := tx.Exec(ctx, stmt); err != nil {
				return err
			}
		}
		return nil
	})
}

// DropSchema drops both tables and the guard functions. It is for tests and
// teardown; the guards deliberately make nothing else able to remove an
// event.
func (st *AuditStore) DropSchema(ctx context.Context) error {
	for _, stmt := range []string{
		`DROP TABLE IF EXISTS ` + st.ev,
		`DROP TABLE IF EXISTS ` + st.sl,
		`DROP FUNCTION IF EXISTS ` + quoteIdent(st.cfg.names.Events+"_guard_update") + `()`,
		`DROP FUNCTION IF EXISTS ` + quoteIdent(st.cfg.names.Events+"_guard_delete") + `()`,
		`DROP FUNCTION IF EXISTS ` + quoteIdent(st.cfg.names.Events+"_guard_insert") + `()`,
		`DROP FUNCTION IF EXISTS ` + quoteIdent(st.cfg.names.Seals+"_guard") + `()`,
	} {
		if _, err := st.db.Exec(ctx, stmt); err != nil {
			return err
		}
	}
	return nil
}

const auditEventCols = `id, seq, occurred_at, completed_at, topic, action, source, origin, procedure,
 actor_type, actor_id, actor_display, on_behalf_of, session_id, container_id, resource_type, resource_id,
 outcome, code, reason, request, changes, ip, user_agent, client_time, duration_ms`

const auditSealCols = `topic, day, event_count, first_seq, last_seq, events_hash, prev_hash, seal_hash, sealed_at, purged_at`

func pgCode(err error) string {
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		return pe.Code
	}
	return ""
}

func jsonArg(raw []byte) any {
	if len(raw) == 0 {
		return nil
	}
	return string(raw)
}

func utcPtr(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	u := t.UTC()
	return &u
}

func scanAuditEvent(rows drops.Rows) (audit.Event, error) {
	var (
		e                audit.Event
		actorType        string
		source, outcome  string
		completed, ctime *time.Time
		req, chg         []byte
	)
	err := rows.Scan(&e.ID, &e.Seq, &e.OccurredAt, &completed, &e.Topic, &e.Action, &source, &e.Origin, &e.Procedure,
		&actorType, &e.Actor.ID, &e.Actor.Display, &e.OnBehalfOf, &e.SessionID, &e.ContainerID,
		&e.Resource.Type, &e.Resource.ID, &outcome, &e.Code, &e.Reason, &req, &chg, &e.IP, &e.UserAgent,
		&ctime, &e.DurationMS)
	if err != nil {
		return audit.Event{}, err
	}
	e.Actor.Type, e.Source, e.Outcome = actorType, audit.Source(source), audit.Outcome(outcome)
	e.OccurredAt = e.OccurredAt.UTC()
	e.CompletedAt, e.ClientTime = utcPtr(completed), utcPtr(ctime)
	if len(req) > 0 {
		e.Request = req
	}
	if len(chg) > 0 {
		e.Changes = chg
	}
	return e, nil
}

func (st *AuditStore) queryEvents(ctx context.Context, sql string, args ...any) ([]audit.Event, error) {
	return queryEvents(ctx, st.db, sql, args...)
}

func queryEvents(ctx context.Context, db *pg.DB, sql string, args ...any) ([]audit.Event, error) {
	rows, err := db.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []audit.Event
	for rows.Next() {
		e, err := scanAuditEvent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// where renders f as a conjunction over the events table and appends its
// arguments to args. It mirrors [audit.Filter.Match].
func auditWhere(f audit.Filter, args []any) (string, []any) {
	var conds []string
	arg := func(v any) string {
		args = append(args, v)
		return "$" + strconv.Itoa(len(args))
	}
	if len(f.Topics) > 0 {
		ph := make([]string, len(f.Topics))
		for i, t := range f.Topics {
			ph[i] = arg(t)
		}
		conds = append(conds, "topic IN ("+strings.Join(ph, ", ")+")")
	}
	if !f.From.IsZero() {
		conds = append(conds, "occurred_at >= "+arg(f.From.UTC()))
	}
	if !f.To.IsZero() {
		conds = append(conds, "occurred_at < "+arg(f.To.UTC()))
	}
	if f.ContainerID != "" {
		conds = append(conds, "container_id = "+arg(f.ContainerID))
	}
	if f.Member != "" {
		m := arg(f.Member)
		conds = append(conds, "(actor_id = "+m+" OR on_behalf_of = "+m+
			" OR (resource_type = '"+audit.ResourceUser+"' AND resource_id = "+m+"))")
	}
	if f.ActorID != "" {
		conds = append(conds, "actor_id = "+arg(f.ActorID))
	}
	if f.Resource.Type != "" {
		conds = append(conds, "resource_type = "+arg(f.Resource.Type))
	}
	if f.Resource.ID != "" {
		conds = append(conds, "resource_id = "+arg(f.Resource.ID))
	}
	if len(f.Outcomes) > 0 {
		ph := make([]string, len(f.Outcomes))
		for i, o := range f.Outcomes {
			ph[i] = arg(string(o))
		}
		conds = append(conds, "(completed_at IS NOT NULL AND outcome <> '' AND outcome IN ("+strings.Join(ph, ", ")+"))")
	}
	if f.Source != "" {
		conds = append(conds, "source = "+arg(string(f.Source)))
	}
	if f.ActionPrefix != "" {
		conds = append(conds, "starts_with(action, "+arg(f.ActionPrefix)+")")
	}
	if len(conds) == 0 {
		return "TRUE", args
	}
	return strings.Join(conds, " AND "), args
}

// canonicalUUID reports whether id is a UUID spelled the way the Service mints
// one: lowercase hex, hyphenated. A uuid column accepts other spellings and
// stores them canonicalized, so the stored id would not be the caller's.
func canonicalUUID(id string) bool {
	if len(id) != 36 {
		return false
	}
	for i, r := range id {
		switch {
		case i == 8 || i == 13 || i == 18 || i == 23:
			if r != '-' {
				return false
			}
		case (r < '0' || r > '9') && (r < 'a' || r > 'f'):
			return false
		}
	}
	return true
}

// storable reports whether id fits the id column: anything with
// [WithAuditTextLibraryIDs], a canonical UUID otherwise.
func (st *AuditStore) storable(id string) bool { return st.cfg.textIDs || canonicalUUID(id) }

// Insert stores e, or returns the stored row when its id exists; a sealed
// (topic, day) is audit.ErrSealed, raised by the AU004 guard so the check and
// the write are one step. On a uuid-typed table an id that is not a
// lowercase, hyphenated UUID is audit.ErrInvalidEvent.
func (st *AuditStore) Insert(ctx context.Context, e audit.Event) (audit.Event, error) {
	if !st.storable(e.ID) {
		return audit.Event{}, fmt.Errorf("%w: id %q is not a lowercase UUID", audit.ErrInvalidEvent, e.ID)
	}
	if stored, err := st.Get(ctx, e.ID); err == nil {
		return stored, nil
	} else if !errors.Is(err, audit.ErrNotFound) {
		return audit.Event{}, err
	}
	var rows []audit.Event
	err := st.readCommitted(ctx, func(tx *pg.DB) error {
		var err error
		rows, err = queryEvents(ctx, tx,
			`INSERT INTO `+st.ev+` (id, occurred_at, completed_at, topic, action, source, origin, procedure,
 actor_type, actor_id, actor_display, on_behalf_of, session_id, container_id, resource_type, resource_id,
 outcome, code, reason, request, changes, ip, user_agent, client_time, duration_ms)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19,
 $20::jsonb, $21::jsonb, $22, $23, $24, $25)
ON CONFLICT (id) DO NOTHING
RETURNING `+auditEventCols,
			e.ID, e.OccurredAt.UTC(), utcPtr(e.CompletedAt), e.Topic, e.Action, string(e.Source), e.Origin, e.Procedure,
			e.Actor.Type, e.Actor.ID, e.Actor.Display, e.OnBehalfOf, e.SessionID, e.ContainerID,
			e.Resource.Type, e.Resource.ID, string(e.Outcome), e.Code, e.Reason,
			jsonArg(e.Request), jsonArg(e.Changes), e.IP, e.UserAgent, utcPtr(e.ClientTime), e.DurationMS)
		return err
	})
	switch {
	case pgCode(err) == AuditDaySealed:
		return audit.Event{}, audit.ErrSealed
	case err != nil:
		return audit.Event{}, err
	case len(rows) == 1:
		return rows[0], nil
	}
	return st.Get(ctx, e.ID) // lost a race with a concurrent insert of the same id
}

// Complete writes c onto the open event id; see audit.Store.
func (st *AuditStore) Complete(ctx context.Context, id string, c audit.Closing) (audit.Event, error) {
	if !st.storable(id) {
		return audit.Event{}, audit.ErrNotFound
	}
	rows, err := st.queryEvents(ctx,
		`UPDATE `+st.ev+` SET completed_at = $2, outcome = $3, code = $4, reason = $5,
 changes = $6::jsonb, duration_ms = $7,
 resource_type = CASE WHEN resource_type = '' AND resource_id = '' THEN $8::text ELSE resource_type END,
 resource_id = CASE WHEN resource_type = '' AND resource_id = '' THEN $9::text ELSE resource_id END,
 container_id = CASE WHEN container_id = '' THEN $10::text ELSE container_id END
WHERE id = $1 AND completed_at IS NULL
RETURNING `+auditEventCols,
		id, c.At.UTC(), string(c.Outcome), c.Code, c.Reason, jsonArg(c.Changes), c.DurationMS,
		c.Resource.Type, c.Resource.ID, c.ContainerID)
	if err != nil {
		return audit.Event{}, err
	}
	if len(rows) == 1 {
		return rows[0], nil
	}
	e, err := st.Get(ctx, id)
	if err != nil {
		return audit.Event{}, err
	}
	if audit.SameClosing(e, c) {
		return e, nil
	}
	return audit.Event{}, audit.ErrCompleted
}

// Get loads one event, or audit.ErrNotFound.
func (st *AuditStore) Get(ctx context.Context, id string) (audit.Event, error) {
	if !st.storable(id) {
		return audit.Event{}, audit.ErrNotFound
	}
	rows, err := st.queryEvents(ctx, `SELECT `+auditEventCols+` FROM `+st.ev+` WHERE id = $1`, id)
	if err != nil {
		return audit.Event{}, err
	}
	if len(rows) == 0 {
		return audit.Event{}, audit.ErrNotFound
	}
	return rows[0], nil
}

// List returns matching events, Seq descending, below page.Before.
func (st *AuditStore) List(ctx context.Context, f audit.Filter, page audit.Page) ([]audit.Event, error) {
	limit := page.Limit
	if limit <= 0 || limit > audit.MaxPageSize {
		limit = audit.MaxPageSize
	}
	where, args := auditWhere(f, nil)
	if page.Before > 0 {
		args = append(args, page.Before)
		where += " AND seq < $" + strconv.Itoa(len(args))
	}
	args = append(args, limit)
	return st.queryEvents(ctx, `SELECT `+auditEventCols+` FROM `+st.ev+` WHERE `+where+
		` ORDER BY seq DESC LIMIT $`+strconv.Itoa(len(args)), args...)
}

// Count returns how many events match f.
func (st *AuditStore) Count(ctx context.Context, f audit.Filter) (int, error) {
	where, args := auditWhere(f, nil)
	rows, err := st.db.Query(ctx, `SELECT count(*) FROM `+st.ev+` WHERE `+where, args...)
	if err != nil {
		return 0, err
	}
	defer func() { _ = rows.Close() }()
	var n int
	if rows.Next() {
		if err := rows.Scan(&n); err != nil {
			return 0, err
		}
	}
	return n, rows.Err()
}

const auditScanChunk = 500

// Scan calls fn for every matching event, Seq ascending. It reads in keyset
// chunks, so no connection is held while fn runs and fn may call the store.
func (st *AuditStore) Scan(ctx context.Context, f audit.Filter, fn func(audit.Event) error) error {
	var after int64
	for {
		where, args := auditWhere(f, nil)
		args = append(args, after, auditScanChunk)
		n := len(args)
		chunk, err := st.queryEvents(ctx, `SELECT `+auditEventCols+` FROM `+st.ev+` WHERE `+where+
			` AND seq > $`+strconv.Itoa(n-1)+` ORDER BY seq LIMIT $`+strconv.Itoa(n), args...)
		if err != nil {
			return err
		}
		for _, e := range chunk {
			if err := fn(e); err != nil {
				return err
			}
			after = e.Seq
		}
		if len(chunk) < auditScanChunk {
			return nil
		}
	}
}

// OpenBefore returns open event ids older than before, oldest first.
func (st *AuditStore) OpenBefore(ctx context.Context, before time.Time, limit int) ([]string, error) {
	rows, err := st.db.Query(ctx, `SELECT id FROM `+st.ev+
		` WHERE completed_at IS NULL AND occurred_at < $1 ORDER BY seq LIMIT NULLIF($2::bigint, 0)`,
		before.UTC(), max(limit, 0))
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func scanAuditSeal(rows drops.Rows) (audit.Seal, error) {
	var s audit.Seal
	var purged *time.Time
	if err := rows.Scan(&s.Topic, &s.Day, &s.EventCount, &s.FirstSeq, &s.LastSeq,
		&s.EventsHash, &s.PrevHash, &s.SealHash, &s.SealedAt, &purged); err != nil {
		return audit.Seal{}, err
	}
	s.Day, s.SealedAt, s.PurgedAt = s.Day.UTC(), s.SealedAt.UTC(), utcPtr(purged)
	return s, nil
}

func (st *AuditStore) querySeals(ctx context.Context, sql string, args ...any) ([]audit.Seal, error) {
	rows, err := st.db.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []audit.Seal
	for rows.Next() {
		s, err := scanAuditSeal(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func utcDay(t time.Time) time.Time {
	y, m, d := t.UTC().Date()
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
}

// LastSeal returns the topic's latest seal, or audit.ErrNotFound.
func (st *AuditStore) LastSeal(ctx context.Context, topic string) (audit.Seal, error) {
	seals, err := st.querySeals(ctx, `SELECT `+auditSealCols+` FROM `+st.sl+
		` WHERE topic = $1 ORDER BY day DESC LIMIT 1`, topic)
	if err != nil {
		return audit.Seal{}, err
	}
	if len(seals) == 0 {
		return audit.Seal{}, audit.ErrNotFound
	}
	return seals[0], nil
}

// InsertSeal stores s; an existing (topic, day) is audit.ErrSealExists. The
// seals guard waits for the day's event inserts in flight and re-counts the
// day under the same lock, so a seal that no longer matches its day is
// audit.ErrSealStale.
func (st *AuditStore) InsertSeal(ctx context.Context, s audit.Seal) error {
	err := st.readCommitted(ctx, func(tx *pg.DB) error {
		_, err := tx.Exec(ctx, `INSERT INTO `+st.sl+` (`+auditSealCols+`)
VALUES ($1, $2::date, $3, $4, $5, $6, $7, $8, $9, $10)`,
			s.Topic, utcDay(s.Day), s.EventCount, s.FirstSeq, s.LastSeq, s.EventsHash, s.PrevHash, s.SealHash,
			s.SealedAt.UTC(), utcPtr(s.PurgedAt))
		return err
	})
	switch pgCode(err) {
	case "23505":
		return audit.ErrSealExists
	case AuditSealStale:
		return audit.ErrSealStale
	}
	return err
}

// readCommitted runs fn in a READ COMMITTED transaction, whatever the
// database's default: the sealed-day and stale-seal checks in the guards must
// see what committed while they waited for their lock.
func (st *AuditStore) readCommitted(ctx context.Context, fn func(tx *pg.DB) error) error {
	return st.db.InTx(ctx, func(tx *pg.DB) error {
		if _, err := tx.Exec(ctx, `SET TRANSACTION ISOLATION LEVEL READ COMMITTED`); err != nil {
			return err
		}
		return fn(tx)
	})
}

// Seals returns the topic's seals with Day in [from, to], ascending.
func (st *AuditStore) Seals(ctx context.Context, topic string, from, to time.Time) ([]audit.Seal, error) {
	return st.querySeals(ctx, `SELECT `+auditSealCols+` FROM `+st.sl+
		` WHERE topic = $1 AND day >= $2::date AND day <= $3::date ORDER BY day`,
		topic, utcDay(from), utcDay(to))
}

// Purge deletes at most batch events of topic older than before, oldest
// first, inside its own retention transaction ([AuditRetentionSetting]). The
// AU002 guard still refuses events of a sealed day that is not marked purged.
func (st *AuditStore) Purge(ctx context.Context, topic string, before time.Time, batch int) (int, error) {
	if batch <= 0 {
		return 0, nil
	}
	var n int64
	err := st.inRetention(ctx, func(tx *pg.DB) error {
		res, err := tx.Exec(ctx, `DELETE FROM `+st.ev+` WHERE seq IN (
 SELECT seq FROM `+st.ev+` WHERE topic = $1 AND occurred_at < $2 ORDER BY seq LIMIT $3)`,
			topic, before.UTC(), batch)
		if err != nil {
			return err
		}
		n, err = res.RowsAffected()
		return err
	})
	return int(n), err
}

// MarkPurged stamps at on the topic's unpurged seals before before, inside
// its own retention transaction.
func (st *AuditStore) MarkPurged(ctx context.Context, topic string, before, at time.Time) error {
	return st.inRetention(ctx, func(tx *pg.DB) error {
		_, err := tx.Exec(ctx, `UPDATE `+st.sl+` SET purged_at = $3
WHERE topic = $1 AND day::timestamp < ($2::timestamptz AT TIME ZONE 'UTC') AND purged_at IS NULL`,
			topic, before.UTC(), at.UTC())
		return err
	})
}

// inRetention runs fn in a transaction with [AuditRetentionSetting] on, the
// only state in which the guards let an event go or a seal be marked purged.
func (st *AuditStore) inRetention(ctx context.Context, fn func(tx *pg.DB) error) error {
	return st.db.InTx(ctx, func(tx *pg.DB) error {
		if _, err := tx.Exec(ctx, `SELECT set_config($1, 'on', true)`, AuditRetentionSetting); err != nil {
			return err
		}
		return fn(tx)
	})
}

// ScrubClientData clears ip and user_agent on at most batch events of topic
// older than before, oldest first. The AU001 guard allows exactly this
// rewrite and no other.
func (st *AuditStore) ScrubClientData(ctx context.Context, topic string, before time.Time, batch int) (int, error) {
	res, err := st.db.Exec(ctx, `UPDATE `+st.ev+` SET ip = '', user_agent = '' WHERE seq IN (
 SELECT seq FROM `+st.ev+` WHERE topic = $1 AND occurred_at < $2 AND (ip <> '' OR user_agent <> '')
 ORDER BY seq LIMIT NULLIF($3::bigint, 0))`, topic, before.UTC(), max(batch, 0))
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	return int(n), err
}

// AuditKeyStore is a drops-backed audit.KeyStore: one row per data subject
// holding the key that pseudonymizes them in the log. Erasure nulls the key
// and keeps a tombstone, so keep this table out of backups that must honour a deletion
// request, or encrypt the keys under a KMS key you can rotate.
type AuditKeyStore struct {
	db  *pg.DB
	cfg auditSettings
	tbl string
}

// Compile-time proof the drops key store satisfies the port.
var _ audit.KeyStore = (*AuditKeyStore)(nil)

// NewAuditKeyStore returns an AuditKeyStore over db.
func NewAuditKeyStore(db *pg.DB, opts ...AuditOption) *AuditKeyStore {
	cfg := newAuditSettings(opts)
	return &AuditKeyStore{db: db, cfg: cfg, tbl: quoteIdent(cfg.names.Keys)}
}

// AuditKeyDDL returns the statement creating the key table.
func AuditKeyDDL(opts ...AuditOption) []string {
	cfg := newAuditSettings(opts)
	return []string{`CREATE TABLE IF NOT EXISTS ` + quoteIdent(cfg.names.Keys) + ` (
  subject text PRIMARY KEY,
  key bytea,
  created_at timestamptz NOT NULL DEFAULT now(),
  erased_at timestamptz
)`}
}

// CreateSchema runs [AuditKeyDDL].
func (st *AuditKeyStore) CreateSchema(ctx context.Context) error {
	for _, stmt := range AuditKeyDDL(func(s *auditSettings) { *s = st.cfg }) {
		if _, err := st.db.Exec(ctx, stmt); err != nil {
			return err
		}
	}
	return nil
}

// DropSchema drops the key table.
func (st *AuditKeyStore) DropSchema(ctx context.Context) error {
	_, err := st.db.Exec(ctx, `DROP TABLE IF EXISTS `+st.tbl)
	return err
}

// Key returns the subject's key, or audit.ErrNotFound.
func (st *AuditKeyStore) Key(ctx context.Context, subject string) ([]byte, error) {
	rows, err := st.db.Query(ctx, `SELECT key, erased_at FROM `+st.tbl+` WHERE subject = $1`, subject)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return nil, err
		}
		return nil, audit.ErrNotFound
	}
	var key []byte
	var erased *time.Time
	if err := rows.Scan(&key, &erased); err != nil {
		return nil, err
	}
	if erased != nil || key == nil {
		return nil, audit.ErrForgotten
	}
	return key, rows.Err()
}

// PutKey stores key unless the subject has one, and returns the stored key.
func (st *AuditKeyStore) PutKey(ctx context.Context, subject string, key []byte) ([]byte, error) {
	if _, err := st.db.Exec(ctx, `INSERT INTO `+st.tbl+` (subject, key) VALUES ($1, $2) ON CONFLICT (subject) DO NOTHING`,
		subject, key); err != nil {
		return nil, err
	}
	return st.Key(ctx, subject)
}

// DeleteKey erases the subject's key and leaves a tombstone row (the
// subject's id and the erasure time) so a later event cannot mint a new one.
func (st *AuditKeyStore) DeleteKey(ctx context.Context, subject string) error {
	_, err := st.db.Exec(ctx, `INSERT INTO `+st.tbl+` (subject, key, erased_at) VALUES ($1, NULL, now())
ON CONFLICT (subject) DO UPDATE SET key = NULL, erased_at = COALESCE(`+st.tbl+`.erased_at, now())`, subject)
	return err
}
