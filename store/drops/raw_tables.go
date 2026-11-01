package dropsstore

import (
	"github.com/bernardoforcillo/drops"
	"github.com/bernardoforcillo/drops/pg"
)

// The audit and consent tables are not read through struct tags like the other
// stores' tables: their stores speak SQL directly, and the audit tables also
// carry guard functions and triggers drops cannot declare. Their columns,
// keys and indexes are still declared here as [pg.Table]s, so they are part of
// [Tables] and the frozen snapshot, are created and migrated by the same
// routine as every other table, and are covered by the same contract tests.
// Only the guard functions and triggers remain SQL text ([auditGuards]).

// rawExpr is a fixed SQL fragment used where DDL cannot take a bound parameter
// (a partial-index predicate, a default).
func rawExpr(sql string) drops.Expression {
	return drops.ExprFunc(func(b *drops.Builder) { b.WriteString(sql) })
}

// desc is a descending index column. drops' own Column.Desc qualifies the name
// with its table, which PostgreSQL rejects inside an index column list.
func desc(c *pg.Column) drops.Expression {
	return drops.ExprFunc(func(b *drops.Builder) {
		b.WriteIdent(c.Name())
		b.WriteString(" DESC")
	})
}

// emptyText declares a NOT NULL text column defaulting to the empty string.
func emptyText(t *pg.Table, name string) {
	pg.Add(t, pg.Text(name).NotNull().Default("''"))
}

// partialIndex declares an index limited to the rows where pred holds.
func partialIndex(t *pg.Table, name, pred string, cols ...drops.Expression) {
	t.AddIndex(pg.NewIndex(name, t, cols...).Where(rawExpr(pred)))
}

// AuditSchema holds the audit tables:
//
//	<events>  id PK, seq (identity, UNIQUE), occurred_at, completed_at, topic, ...
//	<seals>   (topic, day) PK, event_count, first_seq, last_seq, hashes, ...
//	<keys>    subject PK, key, created_at, erased_at
//
// The index names are the ones deployed since the audit store shipped
// (<events>_topic_time, ...); they predate the <table>_<cols>_idx rule and are
// kept so an existing database does not gain a duplicate of each.
type AuditSchema struct {
	Events *pg.Table
	Seals  *pg.Table
	Keys   *pg.Table
}

// NewAuditSchema builds the audit tables. It honours [WithAuditNames] and
// [TextLibraryIDs] (the event id is text instead of uuid).
func NewAuditSchema(opts ...Option) *AuditSchema {
	return newAuditSchema(newAuditSettings(opts))
}

func newAuditSchema(cfg auditSettings) *AuditSchema {
	ev := pg.NewTable(cfg.names.Events)
	if cfg.textIDs {
		pg.Add(ev, pg.Text("id").PrimaryKey())
	} else {
		pg.Add(ev, pg.UUID("id").PrimaryKey())
	}
	pg.Add(ev, pg.Custom[int64]("seq", "bigint GENERATED ALWAYS AS IDENTITY").NotNull().Unique())
	pg.Add(ev, pg.Timestamp("occurred_at", true).NotNull())
	pg.Add(ev, pg.Timestamp("completed_at", true))
	for _, c := range []string{"topic", "action", "source", "origin"} {
		pg.Add(ev, pg.Text(c).NotNull())
	}
	emptyText(ev, "procedure")
	pg.Add(ev, pg.Text("actor_type").NotNull())
	for _, c := range []string{"actor_id", "actor_display", "on_behalf_of", "session_id",
		"container_id", "resource_type", "resource_id", "outcome", "code", "reason"} {
		emptyText(ev, c)
	}
	pg.Add(ev, pg.JSONB("request"))
	pg.Add(ev, pg.JSONB("changes"))
	emptyText(ev, "ip")
	emptyText(ev, "user_agent")
	pg.Add(ev, pg.Timestamp("client_time", true))
	pg.Add(ev, pg.BigInt("duration_ms").NotNull().Default("0"))

	c := ev.Col
	t := cfg.names.Events
	ev.AddIndex(pg.NewIndex(t+"_topic_time", ev, c("topic"), c("occurred_at")))
	partialIndex(ev, t+"_open", "completed_at IS NULL", c("occurred_at"))
	partialIndex(ev, t+"_container", "container_id <> ''", c("container_id"), desc(c("seq")))
	partialIndex(ev, t+"_client", "ip <> '' OR user_agent <> ''", c("topic"), c("occurred_at"))
	partialIndex(ev, t+"_actor", "actor_id <> ''", c("actor_id"), desc(c("seq")))
	// Filter.Member ORs actor_id, on_behalf_of and the user resource: with an
	// index behind each branch the planner answers it with a BitmapOr.
	partialIndex(ev, t+"_resource", "resource_id <> ''", c("resource_type"), c("resource_id"), desc(c("seq")))
	partialIndex(ev, t+"_on_behalf_of", "on_behalf_of <> ''", c("on_behalf_of"), desc(c("seq")))

	sl := pg.NewTable(cfg.names.Seals)
	pg.Add(sl, pg.Text("topic").NotNull())
	pg.Add(sl, pg.Date("day").NotNull())
	for _, n := range []string{"event_count", "first_seq", "last_seq"} {
		pg.Add(sl, pg.BigInt(n).NotNull())
	}
	pg.Add(sl, pg.Text("events_hash").NotNull())
	emptyText(sl, "prev_hash")
	pg.Add(sl, pg.Text("seal_hash").NotNull())
	pg.Add(sl, pg.Timestamp("sealed_at", true).NotNull())
	pg.Add(sl, pg.Timestamp("purged_at", true))
	sl.PrimaryKey(sl.Col("topic"), sl.Col("day"))

	return &AuditSchema{Events: ev, Seals: sl, Keys: newAuditKeys(cfg)}
}

func newAuditKeys(cfg auditSettings) *pg.Table {
	k := pg.NewTable(cfg.names.Keys)
	pg.Add(k, pg.Text("subject").PrimaryKey())
	pg.Add(k, pg.Bytea("key"))
	pg.Add(k, pg.Timestamp("created_at", true).NotNull().Default("now()"))
	pg.Add(k, pg.Timestamp("erased_at", true))
	return k
}

// ConsentSchema holds the consent table:
//
//	<records>  id PK, subject_id, purpose, version, source, granted_at, ended_at, end_reason
//
// with a partial UNIQUE index on (subject_id, purpose) where ended_at IS NULL,
// which is what turns a second current record into consent.ErrConflict.
type ConsentSchema struct {
	Records *pg.Table
}

// NewConsentSchema builds the consent table under name ("consent_records" when
// empty).
func NewConsentSchema(name string) *ConsentSchema {
	if name == "" {
		name = "consent_records"
	}
	r := pg.NewTable(name)
	pg.Add(r, pg.Text("id").PrimaryKey())
	pg.Add(r, pg.Text("subject_id").NotNull())
	pg.Add(r, pg.Text("purpose").NotNull())
	pg.Add(r, pg.Text("version").NotNull())
	emptyText(r, "source")
	pg.Add(r, pg.Timestamp("granted_at", true).NotNull())
	pg.Add(r, pg.Timestamp("ended_at", true))
	emptyText(r, "end_reason")
	r.AddIndex(pg.NewIndex(name+"_current", r, r.Col("subject_id"), r.Col("purpose")).
		Unique().Where(rawExpr("ended_at IS NULL")))
	r.AddIndex(pg.NewIndex(name+"_subject", r, r.Col("subject_id"), r.Col("granted_at")))
	return &ConsentSchema{Records: r}
}

// tableStatements renders the DDL that creates the tables in order: for each,
// CREATE TABLE IF NOT EXISTS, its composite constraints, then its indexes. It
// is what [createTables] executes, as text, for the stores whose DDL is
// exported ([AuditDDL], [AuditKeyDDL], [ConsentDDL]) for deployments that run
// it through their own migrations.
func tableStatements(tables ...*pg.Table) []string {
	var out []string
	render := func(e drops.Expression) {
		b := drops.NewBuilder()
		e.WriteSQL(b)
		sql, _ := b.SQL()
		out = append(out, sql)
	}
	for _, t := range tables {
		render(pg.CreateTableIfNotExists(t))
		for _, ddl := range compositeConstraintDDL(t) {
			render(ddl)
		}
		for _, idx := range t.Indexes() {
			render(pg.CreateIndexIfNotExists(idx))
		}
	}
	return out
}
