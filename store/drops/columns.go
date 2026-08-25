package dropsstore

import (
	"fmt"
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
	order []string // declaration order, so row() is stable
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

func (c *colSet) walk(t reflect.Type, uuidUserIDs bool) {
	for i := range t.NumField() {
		f := t.Field(i)
		if f.Anonymous && f.Type.Kind() == reflect.Struct {
			c.walk(f.Type, uuidUserIDs)
			continue
		}
		tag := f.Tag.Get("drop")
		if tag == "" || tag == "-" {
			continue
		}
		name, opts, _ := strings.Cut(tag, ",")
		c.add(name, strings.Split(opts, ","), f.Type, uuidUserIDs)
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
	case ft == reflect.TypeOf(time.Time{}):
		c.ts[name] = pg.Add(c.tbl, pg.Timestamp(name, true).NotNull())
	case ft == reflect.TypeOf([]byte(nil)):
		c.bytes[name] = pg.Add(c.tbl, pg.Bytea(name).NotNull())
	case ft.Kind() == reflect.Int || ft.Kind() == reflect.Int32:
		c.i32[name] = pg.Add(c.tbl, pg.Integer(name).NotNull())
	default:
		panic(fmt.Sprintf(
			"authlayer/store/drops: column %q has unsupported Go type %s; "+
				"supported: string, time.Time, []byte, int, int32", name, ft))
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
func (c *colSet) bind(tag string, v any) pg.ColumnValue {
	switch x := v.(type) {
	case string:
		return c.str[tag].Val(x)
	case time.Time:
		return c.ts[tag].Val(x)
	case []byte:
		return c.bytes[tag].Val(x)
	case int:
		return c.i32[tag].Val(int32(x))
	case int32:
		return c.i32[tag].Val(x)
	}
	panic(fmt.Sprintf("authlayer/store/drops: cannot bind %T to column %q", v, tag))
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

func flatten(v reflect.Value, out map[string]any) {
	t := v.Type()
	for i := range t.NumField() {
		f := t.Field(i)
		if f.Anonymous && f.Type.Kind() == reflect.Struct {
			flatten(v.Field(i), out)
			continue
		}
		tag := f.Tag.Get("drop")
		if tag == "" || tag == "-" {
			continue
		}
		name, _, _ := strings.Cut(tag, ",")
		out[name] = v.Field(i).Interface()
	}
}
