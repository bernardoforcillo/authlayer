package dropsstore

import (
	"context"
	"slices"
	"strconv"
	"strings"

	"github.com/bernardoforcillo/drops"
	"github.com/bernardoforcillo/drops/pg"
)

// compositeConstraintDDL returns the statements that add t's composite
// constraints — the ones CREATE TABLE cannot carry.
//
// drops' CreateTableIfNotExists writes column definitions only; its own doc
// scopes it to "PRIMARY KEY (single-column only)" and reads the composite
// registry nowhere (drops@v0.5.0/pg/ddl.go, pg/snapshot.go). A composite key
// declared through Table.PrimaryKey or Table.AddUnique therefore lives in
// memory and never reaches the database unless something emits it. These
// constraints are load-bearing for authlayer: the engine does not pre-check
// membership or role-key uniqueness, it relies on the unique violation coming
// back from PostgreSQL, so without them a second AddMember inserts a duplicate
// row and returns nil.
//
// Each statement is wrapped in a plpgsql block that swallows the three
// "already there" SQLSTATEs — 42P07 duplicate_table (the constraint's backing
// index name is taken), 42710 duplicate_object, and 42P16
// invalid_table_definition (the table already has a primary key). PostgreSQL
// has no ADD CONSTRAINT IF NOT EXISTS, and this is the standard stand-in for
// it. Swallowing rather than replacing keeps CreateSchema's contract honest:
// it adds a missing constraint, and never alters one that is already there.
//
// Identifiers are written through the builder, so a table name containing a
// quote is escaped rather than interpolated.
func compositeConstraintDDL(t *pg.Table) []drops.Expression {
	var out []drops.Expression

	if pk := t.CompositePrimaryKey(); len(pk) > 0 {
		out = append(out, addConstraint(t, t.Name()+"_pkey", "PRIMARY KEY", pk))
	}

	// CompositeUniques is a map; sort so the emitted DDL is deterministic.
	uniques := t.CompositeUniques()
	names := make([]string, 0, len(uniques))
	for name := range uniques {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		out = append(out, addConstraint(t, name, "UNIQUE", uniques[name]))
	}

	return out
}

// addConstraint renders one idempotent ALTER TABLE ... ADD CONSTRAINT. kind is
// a fixed keyword ("PRIMARY KEY", "UNIQUE"), never caller input.
func addConstraint(t *pg.Table, name, kind string, cols []*pg.Column) drops.Expression {
	return drops.ExprFunc(func(b *drops.Builder) {
		b.WriteString("DO $authlayer$\nBEGIN\n  ALTER TABLE ")
		b.WriteQualified(t.Schema(), t.Name())
		b.WriteString(" ADD CONSTRAINT ")
		b.WriteIdent(name)
		b.WriteString(" ")
		b.WriteString(kind)
		b.WriteString(" (")
		for i, c := range cols {
			if i > 0 {
				b.WriteString(", ")
			}
			b.WriteIdent(c.Name())
		}
		b.WriteString(");\nEXCEPTION\n  WHEN duplicate_table OR duplicate_object OR " +
			"invalid_table_definition THEN NULL;\nEND;\n$authlayer$")
	})
}

// createTables is the one CreateSchema loop every store shares: for each table,
// CREATE TABLE IF NOT EXISTS, then the composite constraints CREATE TABLE
// cannot carry, then CREATE INDEX IF NOT EXISTS for every index registered on
// it. Tables are created in the order given, so a referenced table must come
// before the tables that reference it.
//
// Running the index step for tables that already exist is what lets a new
// release add an index to a deployed schema: CREATE TABLE no-ops, the index is
// created. It never alters or drops anything that is already there.
func createTables(ctx context.Context, db *pg.DB, tables ...*pg.Table) error {
	for _, t := range tables {
		if _, err := db.ExecExpr(ctx, pg.CreateTableIfNotExists(t)); err != nil {
			return err
		}
		for _, ddl := range compositeConstraintDDL(t) {
			if _, err := db.ExecExpr(ctx, ddl); err != nil {
				return err
			}
		}
		for _, idx := range t.Indexes() {
			if _, err := db.ExecExpr(ctx, pg.CreateIndexIfNotExists(idx)); err != nil {
				return err
			}
		}
	}
	return nil
}

// idxName is the single naming rule for a non-unique index declared through
// pg.NewIndex: <table>_<col>[_<col>...]_idx. Every index added after the rule
// follows it; the older ones already did, so no name changes on a deployed
// database.
func idxName(table string, cols ...string) string {
	return table + "_" + strings.Join(cols, "_") + "_idx"
}

// addIndex registers a plain btree index on cs's columns under [idxName].
func addIndex(t *pg.Table, cs *colSet, cols ...string) {
	exprs := make([]drops.Expression, len(cols))
	for i, c := range cols {
		exprs[i] = cs.col(c)
	}
	t.AddIndex(pg.NewIndex(idxName(t.Name(), cols...), t, exprs...))
}

// purgeBatchSize bounds how many rows one housekeeping DELETE removes. A
// single unbounded DELETE over a table that has accumulated a long expired
// tail holds its row locks and bloats WAL for the whole statement; batches
// keep each statement short and let autovacuum keep up.
const purgeBatchSize = 5000

// deleteBatched deletes every row of t matching where, purgeBatchSize rows per
// statement, and returns the total removed. It selects victims by ctid, so it
// needs no primary key and works for the composite-keyed tables too. Each
// batch is its own autocommit statement: like the single DELETEs it replaces,
// the purge is housekeeping and not atomic with anything.
func deleteBatched(ctx context.Context, db *pg.DB, t *pg.Table, where drops.Expression) (int, error) {
	total := 0
	for {
		res, err := db.ExecExpr(ctx, drops.ExprFunc(func(b *drops.Builder) {
			b.WriteString("DELETE FROM ")
			b.WriteQualified(t.Schema(), t.Name())
			b.WriteString(" WHERE ctid IN (SELECT ctid FROM ")
			b.WriteQualified(t.Schema(), t.Name())
			b.WriteString(" WHERE ")
			b.Append(where)
			b.WriteString(" LIMIT " + strconv.Itoa(purgeBatchSize) + ")")
		}))
		if err != nil {
			return total, err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return total, err
		}
		total += int(n)
		if n < purgeBatchSize {
			return total, nil
		}
		if err := ctx.Err(); err != nil {
			return total, err
		}
	}
}
