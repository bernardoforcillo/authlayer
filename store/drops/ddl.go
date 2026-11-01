package dropsstore

import (
	"context"
	"slices"
	"strconv"
	"strings"

	"github.com/bernardoforcillo/drops"
	"github.com/bernardoforcillo/drops/pg"
)

type constraintKind int

const (
	kindPrimaryKey constraintKind = iota
	kindUnique
	kindForeignKey
)

// constraint is one composite constraint of a table, with the statements that
// add, validate and drop it.
type constraint struct {
	kind constraintKind
	name string
	add  drops.Expression
	// validate is the strict VALIDATE CONSTRAINT, set for foreign keys only. A
	// foreign key is added NOT VALID — enforced for every new write, but not
	// checked against rows already there — and validated separately, so adding
	// it never scans or rewrites the table and never fails on old data.
	validate drops.Expression
	drop     drops.Expression
}

// constraintsOf lists t's composite constraints in the order they must be
// added: the primary key, the unique constraints (sorted by name, since
// CompositeUniques is a map), then the foreign keys, which may reference a
// unique constraint of another table.
func constraintsOf(t *pg.Table) []constraint {
	var out []constraint

	if pk := t.CompositePrimaryKey(); len(pk) > 0 {
		name := t.Name() + "_pkey"
		out = append(out, constraint{
			kind: kindPrimaryKey, name: name,
			add:  addConstraint(t, name, "PRIMARY KEY", pk),
			drop: dropConstraint(t, name),
		})
	}

	uniques := t.CompositeUniques()
	names := make([]string, 0, len(uniques))
	for name := range uniques {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		out = append(out, constraint{
			kind: kindUnique, name: name,
			add:  addConstraint(t, name, "UNIQUE", uniques[name]),
			drop: dropConstraint(t, name),
		})
	}

	for _, fk := range t.CompositeForeignKeys() {
		out = append(out, constraint{
			kind: kindForeignKey, name: fk.Name,
			add:      addForeignKey(t, fk),
			validate: validateConstraint(t, fk.Name),
			drop:     dropConstraint(t, fk.Name),
		})
	}
	return out
}

// compositeConstraintDDL returns the statements that add t's composite
// constraints — the ones CREATE TABLE cannot carry.
//
// drops' CreateTableIfNotExists writes column definitions only, so a composite
// key declared through Table.PrimaryKey, AddUnique or ForeignKeyN lives in
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
// A foreign key is followed by a lenient validation that leaves it NOT VALID,
// without error, when existing rows violate it: CreateSchema must not fail a
// deployment's startup over old data. The migrations validate strictly.
//
// Identifiers are written through the builder, so a table name containing a
// quote is escaped rather than interpolated.
func compositeConstraintDDL(t *pg.Table) []drops.Expression {
	var out []drops.Expression
	for _, c := range constraintsOf(t) {
		out = append(out, c.add)
		if c.validate != nil {
			out = append(out, lenientValidate(t, c.name))
		}
	}
	return out
}

// guarded wraps one ALTER TABLE in the block that swallows "already there".
func guarded(t *pg.Table, alter func(b *drops.Builder)) drops.Expression {
	return drops.ExprFunc(func(b *drops.Builder) {
		b.WriteString("DO $authlayer$\nBEGIN\n  ALTER TABLE ")
		b.WriteQualified(t.Schema(), t.Name())
		alter(b)
		b.WriteString(";\nEXCEPTION\n  WHEN duplicate_table OR duplicate_object OR " +
			"invalid_table_definition THEN NULL;\nEND;\n$authlayer$")
	})
}

func writeCols(b *drops.Builder, cols []*pg.Column) {
	for i, c := range cols {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteIdent(c.Name())
	}
}

// addConstraint renders one idempotent ALTER TABLE ... ADD CONSTRAINT. kind is
// a fixed keyword ("PRIMARY KEY", "UNIQUE"), never caller input.
func addConstraint(t *pg.Table, name, kind string, cols []*pg.Column) drops.Expression {
	return guarded(t, func(b *drops.Builder) {
		b.WriteString(" ADD CONSTRAINT ")
		b.WriteIdent(name)
		b.WriteString(" " + kind + " (")
		writeCols(b, cols)
		b.WriteString(")")
	})
}

// addForeignKey renders the idempotent, NOT VALID ADD CONSTRAINT ... FOREIGN
// KEY. The referential actions come from drops' own OnDelete/OnUpdate options,
// which accept a fixed set of keywords.
func addForeignKey(t *pg.Table, fk *pg.CompositeFK) drops.Expression {
	return guarded(t, func(b *drops.Builder) {
		b.WriteString(" ADD CONSTRAINT ")
		b.WriteIdent(fk.Name)
		b.WriteString(" FOREIGN KEY (")
		writeCols(b, fk.Columns)
		b.WriteString(") REFERENCES ")
		b.WriteQualified(fk.Target.Schema(), fk.Target.Name())
		b.WriteString(" (")
		writeCols(b, fk.TargetColumns)
		b.WriteString(")")
		if fk.OnDelete != "" {
			b.WriteString(" ON DELETE " + fk.OnDelete)
		}
		if fk.OnUpdate != "" {
			b.WriteString(" ON UPDATE " + fk.OnUpdate)
		}
		b.WriteString(" NOT VALID")
	})
}

// validateConstraint renders the strict VALIDATE CONSTRAINT; it fails with the
// foreign-key violation when existing rows break the constraint.
func validateConstraint(t *pg.Table, name string) drops.Expression {
	return drops.ExprFunc(func(b *drops.Builder) {
		b.WriteString("ALTER TABLE ")
		b.WriteQualified(t.Schema(), t.Name())
		b.WriteString(" VALIDATE CONSTRAINT ")
		b.WriteIdent(name)
	})
}

// lenientValidate validates the constraint and leaves it NOT VALID, silently,
// when existing rows violate it (SQLSTATE 23503).
func lenientValidate(t *pg.Table, name string) drops.Expression {
	return drops.ExprFunc(func(b *drops.Builder) {
		b.WriteString("DO $authlayer$\nBEGIN\n  ALTER TABLE ")
		b.WriteQualified(t.Schema(), t.Name())
		b.WriteString(" VALIDATE CONSTRAINT ")
		b.WriteIdent(name)
		b.WriteString(";\nEXCEPTION\n  WHEN foreign_key_violation THEN NULL;\nEND;\n$authlayer$")
	})
}

func dropConstraint(t *pg.Table, name string) drops.Expression {
	return drops.ExprFunc(func(b *drops.Builder) {
		b.WriteString("ALTER TABLE ")
		b.WriteQualified(t.Schema(), t.Name())
		b.WriteString(" DROP CONSTRAINT IF EXISTS ")
		b.WriteIdent(name)
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

// addIndex registers a plain btree index on cs's columns under [idxName] and
// records it as post-baseline: [tableMigrations] puts it in the index step, not
// the table step. Use it for every index added after 0.3.1, and give a later
// release its own step rather than editing the frozen ones.
func addIndex(t *pg.Table, cs *colSet, cols ...string) {
	exprs := make([]drops.Expression, len(cols))
	for i, c := range cols {
		exprs[i] = cs.col(c)
	}
	idx := pg.NewIndex(idxName(t.Name(), cols...), t, exprs...)
	t.AddIndex(idx)
	cs.late = append(cs.late, idx)
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

// uniqueName is the naming rule for a composite UNIQUE added through
// [addUnique]: <table>_<columns>_key.
func uniqueName(table string, cols ...string) string {
	return table + "_" + strings.Join(cols, "_") + "_key"
}

// addUnique registers a composite UNIQUE on cs's columns under [uniqueName]
// and records it as post-baseline, like [addIndex] does for indexes. It exists
// to give a composite foreign key a target: PostgreSQL requires the referenced
// columns to be unique.
func addUnique(t *pg.Table, cs *colSet, cols ...string) {
	refs := make([]pg.ColRef, len(cols))
	for i, c := range cols {
		refs[i] = cs.col(c)
	}
	name := uniqueName(t.Name(), cols...)
	t.AddUnique(name, refs...)
	if cs.lateUnique == nil {
		cs.lateUnique = map[string]bool{}
	}
	cs.lateUnique[name] = true
}

// addCompositeFK declares a composite foreign key on cols of the child table
// to targetCols of the parent. Every composite foreign key is post-baseline
// and added NOT VALID; see [constraint].
func addCompositeFK(child *pg.Table, childCS *colSet, cols []string, parent *pg.Table, parentCS *colSet, targetCols []string) {
	from := make([]pg.ColRef, len(cols))
	for i, c := range cols {
		from[i] = childCS.col(c)
	}
	to := make([]pg.ColRef, len(targetCols))
	for i, c := range targetCols {
		to[i] = parentCS.col(c)
	}
	child.ForeignKeyN(from, parent, to, pg.OnDelete("CASCADE"))
	// drops derives a camel-cased name that overruns PostgreSQL's 63-byte
	// identifier limit; name it the way PostgreSQL names its own: <table>_<cols>_fkey.
	fks := child.CompositeForeignKeys()
	fks[len(fks)-1].Name = child.Name() + "_" + strings.Join(cols, "_") + "_fkey"
}
