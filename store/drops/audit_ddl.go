package dropsstore

import (
	"strconv"
	"strings"
	"time"

	"github.com/bernardoforcillo/authlayer/audit"
)

// SQLSTATEs the audit guard triggers raise. They are in the application
// class space (AU) so a caller can tell a refused rewrite from any other
// failure with errors.As on *pgconn.PgError.
const (
	// AuditEventImmutable (AU001): an UPDATE of an event other than the one
	// completion of an open event.
	AuditEventImmutable = "AU001"
	// AuditEventProtected (AU002): any TRUNCATE of events, a DELETE outside a
	// retention transaction ([AuditRetentionSetting] not 'on'), and, even
	// inside one, a DELETE of an event that a seal still vouches for — its
	// day is sealed and the seal is not marked purged.
	AuditEventProtected = "AU002"
	// AuditSealImmutable (AU003): an UPDATE of a seal other than stamping
	// purged_at once inside a retention transaction, with a time not later
	// than the database clock plus [audit.PurgeClockSkew], or any DELETE or
	// TRUNCATE of seals.
	AuditSealImmutable = "AU003"
	// AuditDaySealed (AU004): an INSERT of an event into a (topic, day) that
	// is already sealed. [AuditStore.Insert] reports it as audit.ErrSealed.
	AuditDaySealed = "AU004"
	// AuditSealStale (AU005): an INSERT of a seal whose event count or first
	// and last Seq no longer match its day's events, or whose day holds an
	// open event. [AuditStore.InsertSeal] reports it as audit.ErrSealStale.
	AuditSealStale = "AU005"
	// AuditIsolation (AU006): an INSERT of an event or a seal in a
	// transaction stricter than READ COMMITTED, where the guards' checks
	// would read a snapshot taken before a concurrent seal or event committed.
	// The store runs its own writes under READ COMMITTED whatever the
	// database's default.
	AuditIsolation = "AU006"
)

// AuditRetentionSetting is the transaction-local setting that opens the
// audit tables to retention: the AU002 guard refuses every DELETE of an event,
// and the AU003 guard every purged_at stamp, unless it is 'on'.
// [AuditStore.Purge] and [AuditStore.MarkPurged] set it with set_config(...,
// true) inside their own transaction, so it never outlives them.
const AuditRetentionSetting = "authlayer.audit_retention"

// AuditNames are the table names the audit stores persist to; the zero
// value means the defaults.
type AuditNames struct {
	Events string // default "audit_events"
	Seals  string // default "audit_seals"
	Keys   string // default "audit_subject_keys", used by [AuditKeyStore]
}

func (n AuditNames) withDefaults() AuditNames {
	if n.Events == "" {
		n.Events = "audit_events"
	}
	if n.Seals == "" {
		n.Seals = "audit_seals"
	}
	if n.Keys == "" {
		n.Keys = "audit_subject_keys"
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

// WithAuditTextLibraryIDs types the event id column as text instead of uuid,
// for an audit.Service whose id generator does not produce UUIDs
// ([audit.WithRuntime]). Without it the store accepts only canonical
// lowercase UUIDs as event ids.
func WithAuditTextLibraryIDs() AuditOption {
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

func quoteLiteral(s string) string { return `'` + strings.ReplaceAll(s, `'`, `''`) + `'` }

// auditSchemaLock is the advisory lock key [AuditStore.CreateSchema] holds
// while it runs [AuditDDL], so replicas booting together apply it one at a
// time.
const auditSchemaLock = 0x617564697464646c // "auditddl"

// AuditDDL returns the statements that create the audit tables, their
// indexes and the guard triggers, in order, each idempotent. It is the
// schema for a deployment that owns its migrations: apply every statement,
// in one transaction, as the role that will own the tables, and let the
// application connect as another role. [AuditStore.CreateSchema] runs the
// same statements for development and tests. Re-applying it replaces the
// guard functions and triggers in place (CREATE OR REPLACE, PostgreSQL 14 or
// later), so an upgrade never leaves a table unguarded, even for a moment.
//
// The guards are what make the log append-only inside the database, so a bug
// or a stray UPDATE in the application cannot rewrite it:
//
//   - AU001: an event may only be updated by the one transition that
//     completes it (completed_at NULL to set, the completion columns
//     written, resource and container filled only when empty), or by
//     clearing its ip and user_agent on retention.
//   - AU002: an event may be deleted only inside a retention transaction
//     ([AuditRetentionSetting] on, as [AuditStore.Purge] sets it), and even
//     then not while its day's seal is unpurged; the events table may not be
//     truncated.
//   - AU003: a seal may only get purged_at stamped, once, inside a retention
//     transaction, and not with a time ahead of the database clock by more
//     than [audit.PurgeClockSkew]; seals are never deleted or truncated.
//   - AU004: an event may not be inserted into a sealed (topic, day).
//   - AU005: a seal may not be inserted unless the day's events still
//     match it (count, first and last seq, none open).
//   - AU006: neither an event nor a seal may be inserted in a transaction
//     stricter than READ COMMITTED.
//
// AU004 and AU005 share an advisory lock per (tables, topic, day): an event insert
// holds it shared until it commits, the seal insert takes it exclusively and
// then re-counts the day. An event in flight while Seal digested the day is
// therefore either counted, which makes the seal stale so Seal digests the
// day again, or starts after the seal committed and is refused. Both checks
// need READ COMMITTED to see what committed while they waited for the lock,
// hence AU006; [AuditStore] runs its own writes under READ COMMITTED whatever
// the database's default_transaction_isolation.
//
// The guard functions find the other table in the schema of the table they
// fire on (keep both tables in one schema) and run with a fixed search_path,
// so a caller's search_path, or a TEMP table named like an audit table,
// cannot redirect them.
//
// A role with ownership of the tables can still drop a trigger: the guards
// stop mistakes and ordinary code, and the hash chain ([audit.Service.Verify])
// detects what a privileged rewrite leaves behind. Run the application as a
// role that does not own the tables.
func AuditDDL(opts ...AuditOption) []string {
	cfg := newAuditSettings(opts)
	ev, sl := quoteIdent(cfg.names.Events), quoteIdent(cfg.names.Seals)
	evLit, slLit := quoteLiteral(cfg.names.Events), quoteLiteral(cfg.names.Seals)
	idType := "uuid"
	if cfg.textIDs {
		idType = "text"
	}
	q := func(suffix string) string { return quoteIdent(cfg.names.Events + suffix) }
	qs := func(suffix string) string { return quoteIdent(cfg.names.Seals + suffix) }
	// Every guard runs with this search_path and reaches the tables only as
	// TG_TABLE_SCHEMA-qualified names, through format('%I.%I').
	const guarded = ` LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $authlayer$`
	// dayLock is the advisory lock key of a (topic, day) of these tables,
	// shared by the event and seal insert guards: the schema-qualified events
	// table and the topic hashed, and the day as days since 1970-01-01, so
	// neither the session's DateStyle nor a second pair of audit tables in
	// the database changes which inserts it serializes.
	dayLock := func(dayExpr string) string {
		return `hashtext(TG_TABLE_SCHEMA || '.' || ` + evLit + ` || '|' || NEW.topic), ` + dayExpr + ` - date '1970-01-01'`
	}
	trigger := func(name, when, table, each, fn string) string {
		return `CREATE OR REPLACE TRIGGER ` + name + ` ` + when + ` ON ` + table +
			` FOR EACH ` + each + ` EXECUTE FUNCTION ` + fn + `()`
	}

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
		// Filter.Member ORs actor_id, on_behalf_of and the user resource: with an
		// index behind each branch the planner answers it with a BitmapOr.
		`CREATE INDEX IF NOT EXISTS ` + q("_resource") + ` ON ` + ev + ` (resource_type, resource_id, seq DESC) WHERE resource_id <> ''`,
		`CREATE INDEX IF NOT EXISTS ` + q("_on_behalf_of") + ` ON ` + ev + ` (on_behalf_of, seq DESC) WHERE on_behalf_of <> ''`,

		// events: AU001 on update.
		`CREATE OR REPLACE FUNCTION ` + q("_guard_update") + `() RETURNS trigger` + guarded + `
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
		trigger(q("_guard_update"), "BEFORE UPDATE", ev, "ROW", q("_guard_update")),

		// events: AU002 on delete and truncate.
		`CREATE OR REPLACE FUNCTION ` + q("_guard_delete") + `() RETURNS trigger` + guarded + `
DECLARE
  sealed boolean;
BEGIN
  IF TG_OP = 'TRUNCATE' THEN
    RAISE EXCEPTION 'authlayer audit: events cannot be truncated' USING ERRCODE = '` + AuditEventProtected + `';
  END IF;
  IF current_setting('` + AuditRetentionSetting + `', true) IS DISTINCT FROM 'on' THEN
    RAISE EXCEPTION 'authlayer audit: events are deleted only by retention' USING ERRCODE = '` + AuditEventProtected + `';
  END IF;
  EXECUTE format('SELECT EXISTS (SELECT 1 FROM %I.%I s WHERE s.topic = $1 AND s.day = $2 AND s.purged_at IS NULL)',
                 TG_TABLE_SCHEMA, ` + slLit + `)
     INTO sealed USING OLD.topic, (OLD.occurred_at AT TIME ZONE 'UTC')::date;
  IF sealed THEN
    RAISE EXCEPTION 'authlayer audit: an event of a sealed day cannot be deleted before retention purges it'
      USING ERRCODE = '` + AuditEventProtected + `';
  END IF;
  RETURN OLD;
END
$authlayer$`,
		trigger(q("_guard_delete"), "BEFORE DELETE", ev, "ROW", q("_guard_delete")),
		trigger(q("_guard_truncate"), "BEFORE TRUNCATE", ev, "STATEMENT", q("_guard_delete")),

		// events: AU004 and AU006 on insert.
		`CREATE OR REPLACE FUNCTION ` + q("_guard_insert") + `() RETURNS trigger` + guarded + `
DECLARE
  sealed boolean;
BEGIN
  IF current_setting('transaction_isolation') <> 'read committed' THEN
    RAISE EXCEPTION 'authlayer audit: events must be inserted under READ COMMITTED' USING ERRCODE = '` + AuditIsolation + `';
  END IF;
  PERFORM pg_advisory_xact_lock_shared(` + dayLock("(NEW.occurred_at AT TIME ZONE 'UTC')::date") + `);
  EXECUTE format('SELECT EXISTS (SELECT 1 FROM %I.%I s WHERE s.topic = $1 AND s.day = $2)', TG_TABLE_SCHEMA, ` + slLit + `)
     INTO sealed USING NEW.topic, (NEW.occurred_at AT TIME ZONE 'UTC')::date;
  IF sealed THEN
    RAISE EXCEPTION 'authlayer audit: the day is sealed' USING ERRCODE = '` + AuditDaySealed + `';
  END IF;
  RETURN NEW;
END
$authlayer$`,
		trigger(q("_guard_insert"), "BEFORE INSERT", ev, "ROW", q("_guard_insert")),

		// seals: AU005 and AU006 on insert, which takes the exclusive side of
		// the lock the event insert shares; AU003 on update, delete, truncate.
		`CREATE OR REPLACE FUNCTION ` + qs("_guard") + `() RETURNS trigger` + guarded + `
DECLARE
  n bigint; lo bigint; hi bigint; open bigint;
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF current_setting('transaction_isolation') <> 'read committed' THEN
      RAISE EXCEPTION 'authlayer audit: seals must be inserted under READ COMMITTED' USING ERRCODE = '` + AuditIsolation + `';
    END IF;
    -- Wait for every event insert in flight on the day, then check the seal
    -- still describes the day: under READ COMMITTED this statement sees them.
    PERFORM pg_advisory_xact_lock(` + dayLock("NEW.day") + `);
    EXECUTE format('SELECT count(*), coalesce(min(e.seq), 0), coalesce(max(e.seq), 0),
                           count(*) FILTER (WHERE e.completed_at IS NULL)
                      FROM %I.%I e WHERE e.topic = $1 AND e.occurred_at >= $2 AND e.occurred_at < $3',
                   TG_TABLE_SCHEMA, ` + evLit + `)
       INTO n, lo, hi, open
      USING NEW.topic, (NEW.day::timestamp AT TIME ZONE 'UTC'), ((NEW.day + 1)::timestamp AT TIME ZONE 'UTC');
    IF n <> NEW.event_count OR lo <> NEW.first_seq OR hi <> NEW.last_seq OR open > 0 THEN
      RAISE EXCEPTION 'authlayer audit: the seal no longer matches its day' USING ERRCODE = '` + AuditSealStale + `';
    END IF;
    RETURN NEW;
  END IF;
  IF TG_OP = 'UPDATE' AND OLD.purged_at IS NULL AND NEW.purged_at IS NOT NULL
     AND current_setting('` + AuditRetentionSetting + `', true) IS NOT DISTINCT FROM 'on'
     AND NEW.purged_at <= now() + interval '` + strconv.Itoa(int(audit.PurgeClockSkew/time.Second)) + ` seconds'
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
		trigger(qs("_guard"), "BEFORE INSERT OR UPDATE OR DELETE", sl, "ROW", qs("_guard")),
		trigger(qs("_guard_truncate"), "BEFORE TRUNCATE", sl, "STATEMENT", qs("_guard")),
	}
}
