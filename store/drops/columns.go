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

// The id-bearing column names split by who mints the value, because the two
// halves are configured independently.
//
// libraryIDColumns hold ids authlayer generates itself — UUIDv7 by default
// (internal/uid), hence the uuid default — but scope.WithIDGenerator and
// auth.WithIDGenerator can replace that generator with one producing ULIDs, a
// database sequence, or a readable prefix scheme. These columns therefore
// follow WithTextLibraryIDs (WithInviteTextLibraryIDs,
// WithAuthTextLibraryIDs), which is what makes those two options honourable
// against this backend rather than merely documented.
//
// userIDColumns hold a *user* id. authlayer generates those too when its own
// auth owns the user table — hence the same uuid default — but a consumer
// using only the RBAC half supplies them from an existing user table, which
// may key on anything. Those columns follow WithTextUserIDs together:
// owner_id is stamped from the context subject (scope/scope.go,
// pc.SetOwner(subject)), exactly like organization_members.user_id, and
// invited_by / created_by are the same class of value.
//
// The two are separate options and not one, because the two questions are
// genuinely independent on the scope and invite stores: a deployment can mint
// ULIDs of its own while pointing at a users table that is UUID keyed, or the
// reverse. The auth store is the exception and deliberately couples them —
// see [WithAuthTextLibraryIDs].
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

// idTypes records, per id-column family, whether those columns are typed
// PostgreSQL uuid (true) or text (false). It is one value rather than two
// bare bools threaded through walk and add so that a call site cannot get the
// two the wrong way round: newColSet(tbl, model, false, true) compiles and
// silently retypes the wrong family.
type idTypes struct {
	// library covers libraryIDColumns — the ids authlayer mints.
	library bool
	// user covers userIDColumns — the ids a consumer supplies.
	user bool
}

// uuidIDs is the default every schema constructor starts from: both families
// uuid, because authlayer generates UUIDv7 for everything it owns. The
// With*Text*IDs options clear one field each.
func uuidIDs() idTypes { return idTypes{library: true, user: true} }

// colSet is the set of typed drops columns for one table, derived by walking a
// model struct's drop: tags.
//
// The columns are kept in five type-specific maps rather than one map of
// *pg.Column because pg.ColumnValue has unexported methods
// (drops@v0.5.0/pg/binding.go:8): authlayer cannot construct a binding itself,
// and the only constructor is (*pg.Col[T]).Val, which needs the concrete T.
// pg.UUID and pg.Text both return *pg.Col[string], so a uuid column and a text
// column live happily in the same map — and so does a NULLABLE one, since the
// Go type a nullable string column is declared from (*string) is not the type
// its binding carries.
type colSet struct {
	tbl   *pg.Table
	str   map[string]*pg.Col[string]
	ts    map[string]*pg.Col[time.Time]
	bytes map[string]*pg.Col[[]byte]
	i32   map[string]*pg.Col[int32]
	// i64 holds bigint columns. Two independent needs put them here: the
	// pointer form is nullable, exactly as *time.Time is, for
	// auth.MFAFactor.LastStep — where nil means "this factor has
	// authenticated no TOTP step yet", a state the replay guard acts on and
	// which is distinct from any step number, zero included; and PostgreSQL
	// has no unsigned integer type, so a Go uint32 does not fit in `integer`
	// — see add's reflect.Uint32 case, and [auth.Credential.SignCount].
	i64 map[string]*pg.Col[int64]
	// nullable records which declared columns came from a POINTER field and
	// may therefore hold SQL NULL. bind consults it for the string family,
	// where the binding type (string) does not itself say whether the column
	// was declared nullable; the time family needs no equivalent because
	// *time.Time and time.Time are distinct types bind already switches on.
	nullable map[string]bool
	// order lists every declared tag in declaration order. It exists because
	// the typed maps above cannot be ranged over as one and Go map order
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
func newColSet(tbl *pg.Table, model any, ids idTypes) *colSet {
	t := reflect.TypeOf(model)
	if t == nil || t.Kind() != reflect.Struct {
		panic(fmt.Sprintf(
			"authlayer/store/drops: %s is not a struct; the container and member "+
				"type parameters must be struct types (embed scope.ContainerBase / "+
				"scope.MemberBase), not pointers or interfaces", typeName(t)))
	}

	c := &colSet{
		tbl:      tbl,
		str:      map[string]*pg.Col[string]{},
		ts:       map[string]*pg.Col[time.Time]{},
		bytes:    map[string]*pg.Col[[]byte]{},
		i32:      map[string]*pg.Col[int32]{},
		i64:      map[string]*pg.Col[int64]{},
		nullable: map[string]bool{},
	}
	c.walk(t, ids)
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
func (c *colSet) walk(t reflect.Type, ids idTypes) {
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
			c.add(name, strings.Split(opts, ","), f.Type, ids)
			continue
		}
		if f.Anonymous && f.Type.Kind() == reflect.Struct {
			c.walk(f.Type, ids)
		}
	}
}

func (c *colSet) add(name string, opts []string, ft reflect.Type, ids idTypes) {
	unique, primary := false, false
	for _, o := range opts {
		switch o {
		case "unique":
			unique = true
		case "pk":
			// "pk" declares a PRIMARY KEY on a column NOT named id — a
			// table whose natural key is a reference, such as
			// mfa_factors.user_id, where "at most one factor per user" IS
			// the key rather than a constraint bolted beside a surrogate
			// one. Without it such a table would carry no primary key at
			// all and its uniqueness rule would live only in prose.
			primary = true
		}
	}

	switch {
	case ft.Kind() == reflect.String:
		def := pg.Text(name)
		if (libraryIDColumns[name] && ids.library) || (userIDColumns[name] && ids.user) {
			def = pg.UUID(name)
		}
		def = def.NotNull()
		if name == "id" || primary {
			def = def.PrimaryKey()
		}
		if unique {
			def = def.Unique()
		}
		c.str[name] = pg.Add(c.tbl, def)
	case ft == reflect.TypeOf((*string)(nil)):
		// Nullable, exactly as the *time.Time case below is: no NotNull, so
		// the column can hold SQL NULL, and bind renders a nil pointer as the
		// NULL keyword rather than a parameter. It is never a primary key —
		// a nullable key is not a key — and the id/user-id typing decision is
		// the same one the non-nullable case makes, so a nullable reference
		// to users.id is a uuid like every other one.
		//
		// [auth.Challenge.UserID] is the field this exists for: nil is "this
		// ceremony names no account", which a login ceremony genuinely does
		// not (see that field's doc). Storing "" instead would fail the uuid
		// parser on every login challenge.
		def := pg.Text(name)
		if (libraryIDColumns[name] && ids.library) || (userIDColumns[name] && ids.user) {
			def = pg.UUID(name)
		}
		if unique {
			def = def.Unique()
		}
		c.str[name] = pg.Add(c.tbl, def)
		c.nullable[name] = true
	case ft.Kind() == reflect.Uint32:
		// bigint, not integer: PostgreSQL has no unsigned types, and the top
		// half of a uint32 does not fit in a signed 32-bit column. A
		// [auth.Credential.SignCount] above 2^31 is not hypothetical — it is
		// whatever value an authenticator reports, and this package neither
		// chooses it nor may truncate it: a truncated counter compares wrong,
		// and the comparison is the whole point of storing it.
		def := pg.BigInt(name).NotNull()
		if unique {
			def = def.Unique()
		}
		c.i64[name] = pg.Add(c.tbl, def)
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
	case ft == reflect.TypeOf((*int64)(nil)):
		// Nullable: no NotNull, so the column can hold SQL NULL, and bind
		// renders a nil pointer as the NULL keyword rather than a
		// parameter — the same treatment *time.Time gets above.
		c.i64[name] = pg.Add(c.tbl, pg.BigInt(name))
	case ft.Kind() == reflect.Int64:
		c.i64[name] = pg.Add(c.tbl, pg.BigInt(name).NotNull())
	default:
		panic(fmt.Sprintf(
			"authlayer/store/drops: column %q has unsupported Go type %s; supported: "+
				"string, *string (nullable), time.Time, *time.Time (nullable), []byte, "+
				"int, int32, int64, *int64 (nullable), uint32, and named types whose "+
				"underlying type is string, int, int32, int64 or uint32", name, ft))
	}
	if primary && c.str[name] == nil {
		// A "pk" option on a column this switch declared as anything but a
		// string is ignored above, and a silently ignored key declaration
		// is a table with no primary key and a doc comment claiming
		// otherwise. Fail at construction instead, the way an unmappable
		// field type already does.
		panic(fmt.Sprintf(
			"authlayer/store/drops: column %q carries the \"pk\" tag option but has Go "+
				"type %s; only a string column can be declared PRIMARY KEY that way", name, ft))
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
	case c.i64[tag] != nil:
		return c.i64[tag].Column
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
	case *int64:
		// The nullable-bigint twin of the *time.Time case above, taking
		// the same route for the same reason: c.i64[tag] can itself be nil
		// for an unknown tag, and Col[T] embeds *Column, so calling Expr
		// or Val on a nil *Col[T] would nil-pointer-panic instead of
		// reporting the missing column by name.
		col := requireCol(c.i64[tag], tag, "bigint")
		if x == nil {
			return col.Expr(drops.Raw("NULL"))
		}
		return col.Val(*x)
	case *string:
		// The nullable string family, handled exactly as *time.Time is above
		// and for the same reason: (*pg.Col[T]).Val takes a concrete T and
		// cannot express NULL, so a nil pointer goes through Expr with a raw
		// NULL keyword. A *string reaching a column that was NOT declared
		// nullable is a model/schema disagreement, not a value to coerce, so
		// it panics with the column named rather than writing "" into a
		// column the model says can be absent.
		col := requireCol(c.str[tag], tag, "text/uuid")
		if !c.nullable[tag] {
			panic(fmt.Sprintf(
				"authlayer/store/drops: column %q was not declared nullable, so a "+
					"*string cannot be bound to it", tag))
		}
		if x == nil {
			return col.Expr(drops.Raw("NULL"))
		}
		return col.Val(*x)
	case []byte:
		return bindOne(c.bytes[tag], tag, x, "bytea")
	}

	if rv := reflect.ValueOf(v); rv.IsValid() {
		switch rv.Kind() {
		case reflect.String:
			return bindOne(c.str[tag], tag, rv.String(), "text/uuid")
		case reflect.Uint32:
			// Widened to int64, the Go type of the bigint column add
			// declared for it — see that case. Every uint32 fits, so unlike
			// the Int case below there is no range check to make.
			return bindOne(c.i64[tag], tag, int64(rv.Uint()), "bigint")
		case reflect.Int, reflect.Int32:
			n := rv.Int()
			if n < math.MinInt32 || n > math.MaxInt32 {
				panic(fmt.Sprintf(
					"authlayer/store/drops: value %d for column %q does not fit the "+
						"integer column type", n, tag))
			}
			return bindOne(c.i32[tag], tag, int32(n), "integer")
		case reflect.Int64:
			// No range check: bigint IS int64, so every value fits. A
			// named type whose underlying type is int64 lands here too,
			// matching how add classifies it by Kind rather than by
			// concrete type.
			return bindOne(c.i64[tag], tag, rv.Int(), "bigint")
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
