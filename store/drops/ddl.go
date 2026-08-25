package dropsstore

import (
	"sort"

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
	sort.Strings(names)
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
