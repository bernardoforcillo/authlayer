package dropsstore

import (
	"fmt"
	"math"
	"reflect"
	"strings"
	"time"

	"github.com/bernardoforcillo/drops"
	"github.com/bernardoforcillo/drops/pg"
)

// The id-bearing column names split by who mints the value, because only one
// half has an escape hatch.
//
// libraryIDColumns hold ids authlayer generates itself (uid.NewV7), so they are
// always uuid: there is no configuration under which they hold anything else.
//
// userIDColumns hold a *user* id. authlayer generates those too when its own
// auth owns the user table — hence the uuid default — but a consumer using only
// the RBAC half supplies them from an existing user table, which may key on
// anything. Those columns therefore follow WithTextUserIDs together: owner_id
// is stamped from the context subject (scope/scope.go, pc.SetOwner(subject)),
// exactly like organization_members.user_id, and invited_by / created_by are
// the same class of value.
var (
	libraryIDColumns = map[string]bool{
		"id":           true,
		"parent_id":    true,
		"container_id": true,
	}
	userIDColumns = map[string]bool{
		"user_id":    true,
		"owner_id":   true,
		"invited_by": true,
		"created_by": true,
	}
)

// colSet is the set of typed drops columns for one table, derived by walking a
// model struct's drop: tags.
//
// The columns are kept in four type-specific maps rather than one map of
// *pg.Column because pg.ColumnValue has unexported methods
// (drops@v0.5.0/pg/binding.go:8): authlayer cannot construct a binding itself,
// and the only constructor is (*pg.Col[T]).Val, which needs the concrete T.
// pg.UUID and pg.Text both return *pg.Col[string], so a uuid column and a text
// column live happily in the same map.
type colSet struct {
	tbl   *pg.Table
	str   map[string]*pg.Col[string]
	ts    map[string]*pg.Col[time.Time]
	bytes map[string]*pg.Col[[]byte]
	i32   map[string]*pg.Col[int32]
	// order lists every declared tag in declaration order. It exists because
	// the four typed maps above cannot be ranged over as one and Go map order
	// is not stable, so row() needs its own iteration order. It is not what
	// makes the INSERT correct: drops re-orders the bindings by Table.Columns()
	// and pairs them by column identity (pg/insert.go).
	order []string
}

// newColSet builds the columns of tbl from model's drop: tags, adding them to
// tbl in declaration order. Embedded structs are flattened, matching how drops
// scans them.
//
// It panics on a field type it cannot map: a model the store cannot persist is
// a startup programming error, and the same idiom is already used by
// access.NewRole for a mis-declared role.
func newColSet(tbl *pg.Table, model any, uuidUserIDs bool) *colSet {
	t := reflect.TypeOf(model)
	if t == nil || t.Kind() != reflect.Struct {
		panic(fmt.Sprintf(
			"authlayer/store/drops: %s is not a struct; the container and member "+
				"type parameters must be struct types (embed scope.ContainerBase / "+
				"scope.MemberBase), not pointers or interfaces", typeName(t)))
	}

	c := &colSet{
		tbl:   tbl,
		str:   map[string]*pg.Col[string]{},
		ts:    map[string]*pg.Col[time.Time]{},
		bytes: map[string]*pg.Col[[]byte]{},
		i32:   map[string]*pg.Col[int32]{},
	}
	c.walk(t, uuidUserIDs)
	return c
}

// The tags the store's own queries name. A model missing one of these builds a
// schema whose DDL renders and whose first query nil-dereferences, so they are
// checked at construction — see colSet.require.
var (
	requiredContainerColumns = []string{"id", "owner_id", "created_at", "updated_at"}
	requiredMemberColumns    = []string{"container_id", "user_id", "role_key", "joined_at"}
)

// require panics unless model tagged every column in names.
//
// Neither type parameter can carry this in its constraint: scope.Member asks
// for three accessor methods and says nothing about tags, so a member type that
// tags its container column drop:"org_id" satisfies it, builds a schema, and
// renders DDL — then dies on the first FindMember with a bare nil dereference,
// because col returns nil for an absent tag and drops stores that nil. Failing
// at construction with the type and the missing tag named is the same idiom
// newColSet already uses for an unmappable field type.
func (c *colSet) require(model any, role, base string, names []string) {
	var missing []string
	for _, n := range names {
		if c.col(n) == nil {
			missing = append(missing, n)
		}
	}
	if len(missing) == 0 {
		return
	}
	panic(fmt.Sprintf(
		"authlayer/store/drops: %s type %s has no drop: tag for %s; "+
			"a %s type must tag %s — embedding %s supplies them all",
		role, typeName(reflect.TypeOf(model)), strings.Join(missing, ", "),
		role, strings.Join(names, ", "), base))
}

// typeName renders a reflect.Type for a panic message, including the nil type a
// nil interface value yields.
func typeName(t reflect.Type) string {
	if t == nil {
		return "nil"
	}
	return t.String()
}

// walk declares a column per drop:-tagged field, recursing into embedded
// structs.
//
// The order of the three decisions — unexported, then tag, then embedded —
// mirrors drops' own fieldMap (drops@v0.5.0/pg/scan.go), because whatever the
// scanner binds on the way in is what this must declare on the way out. Two
// consequences follow from matching it rather than inventing an order:
// an unexported field is skipped, since the scanner can never fill it and
// reflection cannot even read it back out; and a drop:-tagged embedded struct
// is treated as one column, which add then rejects loudly, instead of being
// flattened here while the scanner binds it whole — a divergence that would
// corrupt reads with no panic.
func (c *colSet) walk(t reflect.Type, uuidUserIDs bool) {
	for i := range t.NumField() {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		tag := f.Tag.Get("drop")
		if tag == "-" {
			continue
		}
		if tag != "" {
			name, opts, _ := strings.Cut(tag, ",")
			c.add(name, strings.Split(opts, ","), f.Type, uuidUserIDs)
			continue
		}
		if f.Anonymous && f.Type.Kind() == reflect.Struct {
			c.walk(f.Type, uuidUserIDs)
		}
	}
}

func (c *colSet) add(name string, opts []string, ft reflect.Type, uuidUserIDs bool) {
	unique := false
	for _, o := range opts {
		if o == "unique" {
			unique = true
		}
	}

	switch {
	case ft.Kind() == reflect.String:
		def := pg.Text(name)
		if libraryIDColumns[name] || (userIDColumns[name] && uuidUserIDs) {
			def = pg.UUID(name)
		}
		def = def.NotNull()
		if name == "id" {
			def = def.PrimaryKey()
		}
		if unique {
			def = def.Unique()
		}
		c.str[name] = pg.Add(c.tbl, def)
	case ft == reflect.TypeOf((*time.Time)(nil)):
		// Nullable: no NotNull, so the column can hold SQL NULL. bind renders
		// a nil pointer as the NULL keyword rather than a parameter.
		c.ts[name] = pg.Add(c.tbl, pg.Timestamp(name, true))
	case ft == reflect.TypeOf(time.Time{}):
		c.ts[name] = pg.Add(c.tbl, pg.Timestamp(name, true).NotNull())
	case ft == reflect.TypeOf([]byte(nil)):
		c.bytes[name] = pg.Add(c.tbl, pg.Bytea(name).NotNull())
	case ft.Kind() == reflect.Int || ft.Kind() == reflect.Int32:
		c.i32[name] = pg.Add(c.tbl, pg.Integer(name).NotNull())
	default:
		panic(fmt.Sprintf(
			"authlayer/store/drops: column %q has unsupported Go type %s; supported: "+
				"string, time.Time, *time.Time (nullable), []byte, int, int32, and "+
				"named types whose underlying type is string, int or int32", name, ft))
	}
	c.order = append(c.order, name)
}

// col returns the untyped column for a tag, or nil when there is none. Use it
// for guards, DDL and joins; use bind or eq when a value is involved.
func (c *colSet) col(tag string) *pg.Column {
	switch {
	case c.str[tag] != nil:
		return c.str[tag].Column
	case c.ts[tag] != nil:
		return c.ts[tag].Column
	case c.bytes[tag] != nil:
		return c.bytes[tag].Column
	case c.i32[tag] != nil:
		return c.i32[tag].Column
	}
	return nil
}

// bind pairs a column with a value for an INSERT row or an UPDATE assignment.
//
// It classifies exactly as add does — by reflect.Kind for the string and
// integer families, by concrete type for *time.Time, time.Time and []byte —
// because the two must accept the same set. Type-switching on concrete string
// here while add accepted any Kind String meant a model with a `type Slug
// string` field built a schema, rendered DDL, and then panicked on its first
// INSERT. The *time.Time case is listed before time.Time for readability,
// not correctness: a type switch dispatches each case by exact match against
// the value's dynamic type, and *time.Time and time.Time are distinct
// concrete types, so a given value can only ever match one of them — their
// relative order has no effect on which arm runs. They are kept adjacent,
// nullable form first, so the pair reads as one decision instead of two.
func (c *colSet) bind(tag string, v any) pg.ColumnValue {
	switch x := v.(type) {
	case *time.Time:
		// Route through the same nil-column guard bindOne uses: c.ts[tag] can
		// itself be nil for an unknown tag, and Col[T] embeds *Column, so
		// calling Expr/Val directly on a nil *Col[T] would nil-pointer-panic
		// instead of reporting the missing column by name.
		col := requireCol(c.ts[tag], tag, "timestamptz")
		if x == nil {
			// (*pg.Col[T]).Val takes a concrete T and cannot express NULL;
			// Expr takes any drops.Expression, and drops.Raw is an exported
			// string type whose WriteSQL emits its text verbatim.
			return col.Expr(drops.Raw("NULL"))
		}
		return col.Val(*x)
	case time.Time:
		return bindOne(c.ts[tag], tag, x, "timestamptz")
	case []byte:
		return bindOne(c.bytes[tag], tag, x, "bytea")
	}

	if rv := reflect.ValueOf(v); rv.IsValid() {
		switch rv.Kind() {
		case reflect.String:
			return bindOne(c.str[tag], tag, rv.String(), "text/uuid")
		case reflect.Int, reflect.Int32:
			n := rv.Int()
			if n < math.MinInt32 || n > math.MaxInt32 {
				panic(fmt.Sprintf(
					"authlayer/store/drops: value %d for column %q does not fit the "+
						"integer column type", n, tag))
			}
			return bindOne(c.i32[tag], tag, int32(n), "integer")
		}
	}
	panic(fmt.Sprintf("authlayer/store/drops: cannot bind %T to column %q", v, tag))
}

// bindOne turns a typed column and a value into a binding, reporting a missing
// column rather than dereferencing nil. A nil column here means the tag names
// no column at all, or names one of a different type.
func bindOne[T any](col *pg.Col[T], tag string, v T, kind string) pg.ColumnValue {
	return requireCol(col, tag, kind).Val(v)
}

// requireCol panics with the same "no such column" message as bindOne when
// col is nil, and returns col otherwise. It exists as its own step — not
// folded into bindOne — because the *time.Time case in bind needs the guard
// but must call Expr for a nil value and Val for a non-nil one, so it cannot
// go through bindOne's single Val call. Any caller that skips this and
// dereferences col directly gets a nil-pointer panic instead of the message
// below: Col[T] embeds *Column, so a nil *Col[T] panics on field access, not
// on a Go nil-interface comparison.
func requireCol[T any](col *pg.Col[T], tag, kind string) *pg.Col[T] {
	if col == nil {
		panic(fmt.Sprintf(
			"authlayer/store/drops: no %s column %q; the model's drop: tags declare "+
				"no such column, or declare it with a different type", kind, tag))
	}
	return col
}

// eq builds a column = value predicate.
func (c *colSet) eq(tag string, v any) drops.Expression { return pg.Eq(c.col(tag), v) }

// row flattens a model value into one binding per column, in declaration order.
func (c *colSet) row(model any) []pg.ColumnValue {
	flat := map[string]any{}
	flatten(reflect.ValueOf(model), flat)

	out := make([]pg.ColumnValue, 0, len(c.order))
	for _, name := range c.order {
		out = append(out, c.bind(name, flat[name]))
	}
	return out
}

// flatten collects a model value's tagged fields by column name. It must make
// the same three decisions in the same order as walk, or row would look up a
// column walk never declared.
func flatten(v reflect.Value, out map[string]any) {
	t := v.Type()
	for i := range t.NumField() {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		tag := f.Tag.Get("drop")
		if tag == "-" {
			continue
		}
		if tag != "" {
			name, _, _ := strings.Cut(tag, ",")
			out[name] = v.Field(i).Interface()
			continue
		}
		if f.Anonymous && f.Type.Kind() == reflect.Struct {
			flatten(v.Field(i), out)
		}
	}
}
