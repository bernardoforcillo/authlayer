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

// SQLSTATEs the audit guard triggers raise. They are in the application
// class space (AU) so a caller can tell a refused rewrite from any other
// failure with errors.As on *pgconn.PgError.
const (
	// AuditEventImmutable (AU001): an UPDATE of an event other than the one
	// completion of an open event.
	AuditEventImmutable = "AU001"
	// AuditEventProtected (AU002): a DELETE or TRUNCATE of events that a seal
	// still vouches for — the day is sealed and retention has not marked it
	// purged.
	AuditEventProtected = "AU002"
	// AuditSealImmutable (AU003): an UPDATE of a seal other than stamping
	// purged_at once, or any DELETE or TRUNCATE of seals.
	AuditSealImmutable = "AU003"
	// AuditDaySealed (AU004): an INSERT of an event into a (topic, day) that
	// is already sealed. [AuditStore.Insert] reports it as audit.ErrSealed.
	AuditDaySealed = "AU004"
)

// AuditNames are the two table names an AuditStore persists to; the zero
// value means the defaults.
type AuditNames struct {
	Events string // default "audit_events"
	Seals  string // default "audit_seals"
}

func (n AuditNames) withDefaults() AuditNames {
	if n.Events == "" {
		n.Events = "audit_events"
	}
	if n.Seals == "" {
		n.Seals = "audit_seals"
	}
	return n
}

type auditSettings struct {
	names   AuditNames
	textIDs bool
}

// AuditOption customizes an [AuditStore] or [AuditDDL].
type AuditOption func(*auditSettings)

// WithAuditNames overrides the two table names.
func WithAuditNames(n AuditNames) AuditOption {
	return func(s *auditSettings) { s.names = n }
}

// WithAuditTextIDs types the event id column as text instead of uuid, for an
// audit.Service whose id generator does not produce UUIDs
// ([audit.WithRuntime]).
func WithAuditTextIDs() AuditOption {
	return func(s *auditSettings) { s.textIDs = true }
}

func newAuditSettings(opts []AuditOption) auditSettings {
	var cfg auditSettings
	for _, o := range opts {
		if o != nil {
			o(&cfg)
		}
	}
	cfg.names = cfg.names.withDefaults()
	return cfg
}

func quoteIdent(s string) string { return `"` + strings.ReplaceAll(s, `"`, `""`) + `"` }

// AuditDDL returns the statements that create the audit tables, their
// indexes and the guard triggers, in order, each idempotent. Run them from a
// migration, or let [AuditStore.CreateSchema] do it.
//
// The guards are what make the log append-only inside the database, so a bug
// or a stray UPDATE in the application cannot rewrite it:
//
//   - AU001: an event may only be updated by the one transition that
//     completes it (completed_at NULL to set, the completion columns
//     written, resource and container filled only when empty), or by
//     clearing its ip and user_agent on retention.
//   - AU002: an event of a sealed day may not be deleted until the seal is
//     marked purged, and the events table may not be truncated.
//   - AU003: a seal may only get purged_at stamped, once; seals are never
//     deleted or truncated.
//   - AU004: an event may not be inserted into a sealed (topic, day); the
//     check and the insert are serialized against the seal insert with an
//     advisory lock.
//
// A role with ownership of the tables can still drop a trigger: the guards
// stop mistakes and ordinary code, and the hash chain ([audit.Service.Verify])
// detects what a privileged rewrite leaves behind. Run the application as a
// role that does not own the tables.
func AuditDDL(opts ...AuditOption) []string {
	cfg := newAuditSettings(opts)
	ev, sl := quoteIdent(cfg.names.Events), quoteIdent(cfg.names.Seals)
	idType := "uuid"
	if cfg.textIDs {
		idType = "text"
	}
	q := func(suffix string) string { return quoteIdent(cfg.names.Events + suffix) }
	qs := func(suffix string) string { return quoteIdent(cfg.names.Seals + suffix) }
	const dayOf = "(%s.occurred_at AT TIME ZONE 'UTC')::date"
	oldDay := fmt.Sprintf(dayOf, "OLD")
	newDay := fmt.Sprintf(dayOf, "NEW")

	return []string{
		`CREATE TABLE IF NOT EXISTS ` + ev + ` (
  id ` + idType + ` PRIMARY KEY,
  seq bigint GENERATED ALWAYS AS IDENTITY NOT NULL UNIQUE,
  occurred_at timestamptz NOT NULL,
  completed_at timestamptz,
  topic text NOT NULL,
  action text NOT NULL,
  source text NOT NULL,
  origin text NOT NULL,
  procedure text NOT NULL DEFAULT '',
  actor_type text NOT NULL,
  actor_id text NOT NULL DEFAULT '',
  actor_display text NOT NULL DEFAULT '',
  on_behalf_of text NOT NULL DEFAULT '',
  session_id text NOT NULL DEFAULT '',
  container_id text NOT NULL DEFAULT '',
  resource_type text NOT NULL DEFAULT '',
  resource_id text NOT NULL DEFAULT '',
  outcome text NOT NULL DEFAULT '',
  code text NOT NULL DEFAULT '',
  reason text NOT NULL DEFAULT '',
  request jsonb,
  changes jsonb,
  ip text NOT NULL DEFAULT '',
  user_agent text NOT NULL DEFAULT '',
  client_time timestamptz,
  duration_ms bigint NOT NULL DEFAULT 0
)`,
		`CREATE TABLE IF NOT EXISTS ` + sl + ` (
  topic text NOT NULL,
  day date NOT NULL,
  event_count bigint NOT NULL,
  first_seq bigint NOT NULL,
  last_seq bigint NOT NULL,
  events_hash text NOT NULL,
  prev_hash text NOT NULL DEFAULT '',
  seal_hash text NOT NULL,
  sealed_at timestamptz NOT NULL,
  purged_at timestamptz,
  PRIMARY KEY (topic, day)
)`,
		`CREATE INDEX IF NOT EXISTS ` + q("_topic_time") + ` ON ` + ev + ` (topic, occurred_at)`,
		`CREATE INDEX IF NOT EXISTS ` + q("_open") + ` ON ` + ev + ` (occurred_at) WHERE completed_at IS NULL`,
		`CREATE INDEX IF NOT EXISTS ` + q("_container") + ` ON ` + ev + ` (container_id, seq DESC) WHERE container_id <> ''`,
		`CREATE INDEX IF NOT EXISTS ` + q("_client") + ` ON ` + ev + ` (topic, occurred_at) WHERE ip <> '' OR user_agent <> ''`,
		`CREATE INDEX IF NOT EXISTS ` + q("_actor") + ` ON ` + ev + ` (actor_id, seq DESC) WHERE actor_id <> ''`,

		// events: AU001 on update.
		`CREATE OR REPLACE FUNCTION ` + q("_guard_update") + `() RETURNS trigger LANGUAGE plpgsql AS $authlayer$
BEGIN
  -- Clearing the client data (IP, user agent) on retention: nothing else may differ.
  IF NEW.ip = '' AND NEW.user_agent = '' AND (OLD.ip <> '' OR OLD.user_agent <> '')
     AND NEW.id = OLD.id AND NEW.seq = OLD.seq AND NEW.occurred_at = OLD.occurred_at
     AND NEW.completed_at IS NOT DISTINCT FROM OLD.completed_at
     AND NEW.topic = OLD.topic AND NEW.action = OLD.action AND NEW.source = OLD.source
     AND NEW.origin = OLD.origin AND NEW.procedure = OLD.procedure
     AND NEW.actor_type = OLD.actor_type AND NEW.actor_id = OLD.actor_id
     AND NEW.actor_display = OLD.actor_display AND NEW.on_behalf_of = OLD.on_behalf_of
     AND NEW.session_id = OLD.session_id AND NEW.container_id = OLD.container_id
     AND NEW.resource_type = OLD.resource_type AND NEW.resource_id = OLD.resource_id
     AND NEW.outcome = OLD.outcome AND NEW.code = OLD.code AND NEW.reason = OLD.reason
     AND NEW.request IS NOT DISTINCT FROM OLD.request AND NEW.changes IS NOT DISTINCT FROM OLD.changes
     AND NEW.client_time IS NOT DISTINCT FROM OLD.client_time AND NEW.duration_ms = OLD.duration_ms
  THEN
    RETURN NEW;
  END IF;
  IF OLD.completed_at IS NULL AND NEW.completed_at IS NOT NULL
     AND NEW.id = OLD.id AND NEW.seq = OLD.seq AND NEW.occurred_at = OLD.occurred_at
     AND NEW.topic = OLD.topic AND NEW.action = OLD.action AND NEW.source = OLD.source
     AND NEW.origin = OLD.origin AND NEW.procedure = OLD.procedure
     AND NEW.actor_type = OLD.actor_type AND NEW.actor_id = OLD.actor_id
     AND NEW.actor_display = OLD.actor_display AND NEW.on_behalf_of = OLD.on_behalf_of
     AND NEW.session_id = OLD.session_id AND NEW.request IS NOT DISTINCT FROM OLD.request
     AND NEW.ip = OLD.ip AND NEW.user_agent = OLD.user_agent
     AND NEW.client_time IS NOT DISTINCT FROM OLD.client_time
     AND OLD.changes IS NULL
     AND ((NEW.resource_type = OLD.resource_type AND NEW.resource_id = OLD.resource_id)
          OR (OLD.resource_type = '' AND OLD.resource_id = ''))
     AND (NEW.container_id = OLD.container_id OR OLD.container_id = '')
  THEN
    RETURN NEW;
  END IF;
  RAISE EXCEPTION 'authlayer audit: an event is immutable once written' USING ERRCODE = '` + AuditEventImmutable + `';
END
$authlayer$`,
		`DROP TRIGGER IF EXISTS ` + q("_guard_update") + ` ON ` + ev,
		`CREATE TRIGGER ` + q("_guard_update") + ` BEFORE UPDATE ON ` + ev +
			` FOR EACH ROW EXECUTE FUNCTION ` + q("_guard_update") + `()`,

		// events: AU002 on delete and truncate.
		`CREATE OR REPLACE FUNCTION ` + q("_guard_delete") + `() RETURNS trigger LANGUAGE plpgsql AS $authlayer$
BEGIN
  IF TG_OP = 'TRUNCATE' THEN
    RAISE EXCEPTION 'authlayer audit: events cannot be truncated' USING ERRCODE = '` + AuditEventProtected + `';
  END IF;
  IF EXISTS (SELECT 1 FROM ` + sl + ` s
              WHERE s.topic = OLD.topic AND s.day = ` + oldDay + ` AND s.purged_at IS NULL) THEN
    RAISE EXCEPTION 'authlayer audit: an event of a sealed day cannot be deleted before retention purges it'
      USING ERRCODE = '` + AuditEventProtected + `';
  END IF;
  RETURN OLD;
END
$authlayer$`,
		`DROP TRIGGER IF EXISTS ` + q("_guard_delete") + ` ON ` + ev,
		`CREATE TRIGGER ` + q("_guard_delete") + ` BEFORE DELETE ON ` + ev +
			` FOR EACH ROW EXECUTE FUNCTION ` + q("_guard_delete") + `()`,
		`DROP TRIGGER IF EXISTS ` + q("_guard_truncate") + ` ON ` + ev,
		`CREATE TRIGGER ` + q("_guard_truncate") + ` BEFORE TRUNCATE ON ` + ev +
			` FOR EACH STATEMENT EXECUTE FUNCTION ` + q("_guard_delete") + `()`,

		// events: AU004 on insert into a sealed day.
		`CREATE OR REPLACE FUNCTION ` + q("_guard_insert") + `() RETURNS trigger LANGUAGE plpgsql AS $authlayer$
BEGIN
  PERFORM pg_advisory_xact_lock_shared(hashtextextended(NEW.topic || '|' || ` + newDay + `::text, 0));
  IF EXISTS (SELECT 1 FROM ` + sl + ` s WHERE s.topic = NEW.topic AND s.day = ` + newDay + `) THEN
    RAISE EXCEPTION 'authlayer audit: the day is sealed' USING ERRCODE = '` + AuditDaySealed + `';
  END IF;
  RETURN NEW;
END
$authlayer$`,
		`DROP TRIGGER IF EXISTS ` + q("_guard_insert") + ` ON ` + ev,
		`CREATE TRIGGER ` + q("_guard_insert") + ` BEFORE INSERT ON ` + ev +
			` FOR EACH ROW EXECUTE FUNCTION ` + q("_guard_insert") + `()`,

		// seals: AU003 on update, delete and truncate; the insert takes the
		// exclusive side of the lock the event insert shares.
		`CREATE OR REPLACE FUNCTION ` + qs("_guard") + `() RETURNS trigger LANGUAGE plpgsql AS $authlayer$
BEGIN
  IF TG_OP = 'INSERT' THEN
    PERFORM pg_advisory_xact_lock(hashtextextended(NEW.topic || '|' || NEW.day::text, 0));
    RETURN NEW;
  END IF;
  IF TG_OP = 'UPDATE' AND OLD.purged_at IS NULL AND NEW.purged_at IS NOT NULL
     AND NEW.topic = OLD.topic AND NEW.day = OLD.day AND NEW.event_count = OLD.event_count
     AND NEW.first_seq = OLD.first_seq AND NEW.last_seq = OLD.last_seq
     AND NEW.events_hash = OLD.events_hash AND NEW.prev_hash = OLD.prev_hash
     AND NEW.seal_hash = OLD.seal_hash AND NEW.sealed_at = OLD.sealed_at
  THEN
    RETURN NEW;
  END IF;
  RAISE EXCEPTION 'authlayer audit: a seal is immutable' USING ERRCODE = '` + AuditSealImmutable + `';
END
$authlayer$`,
		`DROP TRIGGER IF EXISTS ` + qs("_guard") + ` ON ` + sl,
		`CREATE TRIGGER ` + qs("_guard") + ` BEFORE INSERT OR UPDATE OR DELETE ON ` + sl +
			` FOR EACH ROW EXECUTE FUNCTION ` + qs("_guard") + `()`,
		`DROP TRIGGER IF EXISTS ` + qs("_guard_truncate") + ` ON ` + sl,
		`CREATE TRIGGER ` + qs("_guard_truncate") + ` BEFORE TRUNCATE ON ` + sl +
			` FOR EACH STATEMENT EXECUTE FUNCTION ` + qs("_guard") + `()`,
	}
}

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

// NewAuditStore returns an AuditStore over db.
func NewAuditStore(db *pg.DB, opts ...AuditOption) *AuditStore {
	cfg := newAuditSettings(opts)
	return &AuditStore{db: db, cfg: cfg, ev: quoteIdent(cfg.names.Events), sl: quoteIdent(cfg.names.Seals)}
}

// CreateSchema runs [AuditDDL]. Every statement is idempotent; like the other
// stores it adds what is missing and alters nothing else, so deployments that
// own their migrations should apply AuditDDL there instead.
func (st *AuditStore) CreateSchema(ctx context.Context) error {
	for _, stmt := range AuditDDL(func(s *auditSettings) { *s = st.cfg }) {
		if _, err := st.db.Exec(ctx, stmt); err != nil {
			return err
		}
	}
	return nil
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
	rows, err := st.db.Query(ctx, sql, args...)
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

// Insert stores e, or returns the stored row when its id exists; a sealed
// (topic, day) is audit.ErrSealed, raised by the AU004 guard so the check and
// the write are one step.
func (st *AuditStore) Insert(ctx context.Context, e audit.Event) (audit.Event, error) {
	if stored, err := st.Get(ctx, e.ID); err == nil {
		return stored, nil
	} else if !errors.Is(err, audit.ErrNotFound) {
		return audit.Event{}, err
	}
	rows, err := st.queryEvents(ctx,
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
		if pgCode(err) == "22P02" { // not a uuid
			return audit.Event{}, audit.ErrNotFound
		}
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
	rows, err := st.queryEvents(ctx, `SELECT `+auditEventCols+` FROM `+st.ev+` WHERE id = $1`, id)
	if err != nil {
		if pgCode(err) == "22P02" {
			return audit.Event{}, audit.ErrNotFound
		}
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

// InsertSeal stores s; an existing (topic, day) is audit.ErrSealExists.
func (st *AuditStore) InsertSeal(ctx context.Context, s audit.Seal) error {
	_, err := st.db.Exec(ctx, `INSERT INTO `+st.sl+` (`+auditSealCols+`)
VALUES ($1, $2::date, $3, $4, $5, $6, $7, $8, $9, $10)`,
		s.Topic, utcDay(s.Day), s.EventCount, s.FirstSeq, s.LastSeq, s.EventsHash, s.PrevHash, s.SealHash,
		s.SealedAt.UTC(), utcPtr(s.PurgedAt))
	if pgCode(err) == "23505" {
		return audit.ErrSealExists
	}
	return err
}

// Seals returns the topic's seals with Day in [from, to], ascending.
func (st *AuditStore) Seals(ctx context.Context, topic string, from, to time.Time) ([]audit.Seal, error) {
	return st.querySeals(ctx, `SELECT `+auditSealCols+` FROM `+st.sl+
		` WHERE topic = $1 AND day >= $2::date AND day <= $3::date ORDER BY day`,
		topic, utcDay(from), utcDay(to))
}

// Purge deletes at most batch events of topic older than before, oldest
// first. The AU002 guard refuses events of a sealed day that is not marked
// purged.
func (st *AuditStore) Purge(ctx context.Context, topic string, before time.Time, batch int) (int, error) {
	res, err := st.db.Exec(ctx, `DELETE FROM `+st.ev+` WHERE seq IN (
 SELECT seq FROM `+st.ev+` WHERE topic = $1 AND occurred_at < $2 ORDER BY seq LIMIT NULLIF($3::bigint, 0))`,
		topic, before.UTC(), max(batch, 0))
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	return int(n), err
}

// MarkPurged stamps at on the topic's unpurged seals before before.
func (st *AuditStore) MarkPurged(ctx context.Context, topic string, before, at time.Time) error {
	_, err := st.db.Exec(ctx, `UPDATE `+st.sl+` SET purged_at = $3
WHERE topic = $1 AND day::timestamp < ($2::timestamptz AT TIME ZONE 'UTC') AND purged_at IS NULL`,
		topic, before.UTC(), at.UTC())
	return err
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
