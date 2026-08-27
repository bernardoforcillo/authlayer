package dropsstore

import (
	"fmt"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/bernardoforcillo/authlayer/org"
	"github.com/bernardoforcillo/authlayer/scope"
	"github.com/bernardoforcillo/drops/pg"
)

func TestColSetTypesIDColumnsAsUUID(t *testing.T) {
	tbl := pg.NewTable("organizations")
	cs := newColSet(tbl, org.Organization{}, true)

	for _, tag := range []string{"id", "owner_id"} {
		c := cs.col(tag)
		if c == nil {
			t.Fatalf("column %q missing", tag)
		}
		if got := c.Type().TypeSQL(); got != "uuid" {
			t.Fatalf("column %q type = %q, want uuid", tag, got)
		}
	}
}

func TestColSetTypesPlainStringsAsText(t *testing.T) {
	tbl := pg.NewTable("organizations")
	cs := newColSet(tbl, org.Organization{}, true)

	for _, tag := range []string{"name", "slug"} {
		if got := cs.col(tag).Type().TypeSQL(); got != "text" {
			t.Fatalf("column %q type = %q, want text", tag, got)
		}
	}
}

func TestColSetHonoursUniqueTagOption(t *testing.T) {
	cs := newColSet(pg.NewTable("organizations"), org.Organization{}, true)
	if !cs.col("slug").IsUnique() {
		t.Fatal(`slug carries drop:"slug,unique" but the column is not unique`)
	}
	if cs.col("name").IsUnique() {
		t.Fatal("name has no unique option but the column is unique")
	}
}

func TestColSetTypesTimestampsAndBytes(t *testing.T) {
	cs := newColSet(pg.NewTable("organizations"), org.Organization{}, true)
	if got := cs.col("created_at").Type().TypeSQL(); got != "timestamptz" {
		t.Fatalf("created_at type = %q, want timestamptz", got)
	}

	rc := newColSet(pg.NewTable("organization_roles"), scope.RoleRecord{}, true)
	if got := rc.col("permissions").Type().TypeSQL(); got != "bytea" {
		t.Fatalf("permissions type = %q, want bytea", got)
	}
}

// MemberBase tags the container column "container_id" (scope/base.go:40), so the
// generic store must use that name — not the legacy "organization_id".
func TestColSetUsesBaseTagNamesForMembers(t *testing.T) {
	cs := newColSet(pg.NewTable("organization_members"), org.Member{}, true)
	if cs.col("container_id") == nil {
		t.Fatal("members table has no container_id column")
	}
	if cs.col("organization_id") != nil {
		t.Fatal("members table still carries the legacy organization_id column")
	}
}

func TestColSetUserIDTypeFollowsTheOption(t *testing.T) {
	if got := newColSet(pg.NewTable("m1"), org.Member{}, true).col("user_id").Type().TypeSQL(); got != "uuid" {
		t.Fatalf("user_id type = %q, want uuid when uuidUserIDs is true", got)
	}
	if got := newColSet(pg.NewTable("m2"), org.Member{}, false).col("user_id").Type().TypeSQL(); got != "text" {
		t.Fatalf("user_id type = %q, want text when uuidUserIDs is false", got)
	}
}

// owner_id holds a user id — the engine stamps it from the context subject —
// so it must follow WithTextUserIDs alongside user_id. Typing it uuid
// unconditionally makes the escape hatch useless: every container insert fails
// with "invalid input syntax for type uuid".
func TestColSetOwnerIDFollowsTheUserIDOption(t *testing.T) {
	if got := newColSet(pg.NewTable("c1"), org.Organization{}, true).col("owner_id").Type().TypeSQL(); got != "uuid" {
		t.Fatalf("owner_id type = %q, want uuid when uuidUserIDs is true", got)
	}
	if got := newColSet(pg.NewTable("c2"), org.Organization{}, false).col("owner_id").Type().TypeSQL(); got != "text" {
		t.Fatalf("owner_id type = %q, want text when uuidUserIDs is false", got)
	}
}

// The whole split in one place: ids authlayer mints are always uuid, ids the
// consumer supplies follow the option.
func TestColSetSplitsLibraryIDsFromUserIDs(t *testing.T) {
	type model struct {
		ID          string `drop:"id"`
		ParentID    string `drop:"parent_id"`
		ContainerID string `drop:"container_id"`
		UserID      string `drop:"user_id"`
		OwnerID     string `drop:"owner_id"`
		InvitedBy   string `drop:"invited_by"`
		CreatedBy   string `drop:"created_by"`
	}
	library := []string{"id", "parent_id", "container_id"}
	user := []string{"user_id", "owner_id", "invited_by", "created_by"}

	uuidSet := newColSet(pg.NewTable("t1"), model{}, true)
	for _, tag := range append(append([]string{}, library...), user...) {
		if got := uuidSet.col(tag).Type().TypeSQL(); got != "uuid" {
			t.Fatalf("%s type = %q, want uuid by default", tag, got)
		}
	}

	textSet := newColSet(pg.NewTable("t2"), model{}, false)
	for _, tag := range library {
		if got := textSet.col(tag).Type().TypeSQL(); got != "uuid" {
			t.Fatalf("WithTextUserIDs leaked into library id %s: %q", tag, got)
		}
	}
	for _, tag := range user {
		if got := textSet.col(tag).Type().TypeSQL(); got != "text" {
			t.Fatalf("%s type = %q, want text under WithTextUserIDs", tag, got)
		}
	}
}

func TestColSetRowProducesOneBindingPerColumnInOrder(t *testing.T) {
	cs := newColSet(pg.NewTable("organizations"), org.Organization{}, true)
	at := time.Date(2026, 8, 25, 0, 0, 0, 0, time.UTC)
	o := org.Organization{
		ContainerBase: scope.ContainerBase{ID: "i", OwnerID: "o", CreatedAt: at, UpdatedAt: at},
		Name:          "Acme",
		Slug:          "acme",
	}
	vals := cs.row(o)
	if len(vals) != 6 {
		t.Fatalf("row() produced %d bindings, want 6", len(vals))
	}
	// The name promises order, so assert it: row() walks c.order, and c.order
	// is the tag order the walker declared.
	want := []string{"id", "owner_id", "created_at", "updated_at", "name", "slug"}
	if len(cs.order) != len(want) {
		t.Fatalf("order = %v, want %v", cs.order, want)
	}
	for i := range want {
		if cs.order[i] != want[i] {
			t.Fatalf("order = %v, want %v", cs.order, want)
		}
	}
}

func TestColSetRowPanicsOnUnsupportedFieldType(t *testing.T) {
	type bad struct {
		Ratio float64 `drop:"ratio"`
	}
	defer func() {
		if recover() == nil {
			t.Fatal("newColSet accepted an unsupported field type without panicking")
		}
	}()
	newColSet(pg.NewTable("bad"), bad{}, true)
}

// add classifies by reflect.Kind, so bind must too: a `type Slug string` field
// built a column happily and then panicked on the first INSERT with
// "cannot bind main.Slug to column". Named string and int types are ordinary Go
// domain modelling and the readme invites arbitrary container types.
func TestColSetBindsNamedStringAndIntTypes(t *testing.T) {
	type Slug string
	type Seats int
	type model struct {
		ID    string `drop:"id"`
		Slug  Slug   `drop:"slug"`
		Seats Seats  `drop:"seats"`
	}

	cs := newColSet(pg.NewTable("t"), model{}, true)
	if got := cs.col("slug").Type().TypeSQL(); got != "text" {
		t.Fatalf("slug type = %q, want text", got)
	}
	if got := cs.col("seats").Type().TypeSQL(); got != "integer" {
		t.Fatalf("seats type = %q, want integer", got)
	}

	vals := cs.row(model{ID: "i", Slug: "acme", Seats: 12})
	if len(vals) != 3 {
		t.Fatalf("row() produced %d bindings, want 3", len(vals))
	}
}

// The int -> int32 narrowing used to be unchecked, so an out-of-range value was
// silently truncated into a different number.
func TestColSetBindRejectsOutOfRangeIntegers(t *testing.T) {
	type model struct {
		ID    string `drop:"id"`
		Seats int    `drop:"seats"`
	}
	cs := newColSet(pg.NewTable("t"), model{}, true)

	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("bind silently truncated an out-of-range int")
		}
		if msg := fmt.Sprint(r); !strings.Contains(msg, "seats") {
			t.Fatalf("panic %q does not name the column", msg)
		}
	}()
	cs.row(model{ID: "i", Seats: math.MaxInt32 + 1})
}

// A tag that names no column must say so rather than dereferencing nil.
func TestColSetBindReportsAnUnknownColumn(t *testing.T) {
	cs := newColSet(pg.NewTable("organizations"), org.Organization{}, true)
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("bind accepted a tag that names no column")
		}
		if msg := fmt.Sprint(r); !strings.Contains(msg, "nope") {
			t.Fatalf("panic %q does not name the column", msg)
		}
	}()
	cs.bind("nope", "x")
}

// The *time.Time case used to call Expr/Val on c.ts[tag] directly instead of
// going through bindOne's nil-column guard. Col[T] embeds *Column, so on an
// unknown tag that nil-pointer-panicked instead of reporting the missing
// column by name — exactly the failure bindOne exists to prevent for every
// other type.
func TestColSetBindReportsAnUnknownColumnForNullableTimestamp(t *testing.T) {
	type withNullable struct {
		ExpiresAt *time.Time `drop:"expires_at"`
	}
	cs := newColSet(pg.NewTable("links"), withNullable{}, true)
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("bind accepted a *time.Time for a tag that names no column")
		}
		if msg := fmt.Sprint(r); !strings.Contains(msg, "nope") {
			t.Fatalf("panic %q does not name the column", msg)
		}
	}()
	cs.bind("nope", (*time.Time)(nil))
}

// drops' scanner skips unexported fields, so a column declared for one could
// never be filled — and flatten's Field(i).Interface() would panic reading it
// back out. walk must skip them for the same reason.
func TestColSetSkipsUnexportedFields(t *testing.T) {
	type model struct {
		ID     string `drop:"id"`
		hidden string `drop:"hidden"`
	}
	cs := newColSet(pg.NewTable("t"), model{ID: "i", hidden: "x"}, true)
	if cs.col("hidden") != nil {
		t.Fatal("declared a column for an unexported field")
	}
	if len(cs.order) != 1 {
		t.Fatalf("order = %v, want just id", cs.order)
	}
	// row() must not trip over it either.
	if vals := cs.row(model{ID: "i", hidden: "x"}); len(vals) != 1 {
		t.Fatalf("row() produced %d bindings, want 1", len(vals))
	}
}

// drops binds a drop:-tagged embedded struct to a single column. Flattening it
// here instead would declare inner columns the scanner never fills, corrupting
// reads with no panic — so it is passed to add, which rejects it loudly.
func TestColSetRejectsATaggedEmbeddedStruct(t *testing.T) {
	type model struct {
		scope.ContainerBase `drop:"base"`
	}
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("a drop:-tagged embedded struct was silently flattened")
		}
		if msg := fmt.Sprint(r); !strings.Contains(msg, "unsupported Go type") {
			t.Fatalf("panic %q is not the unsupported-type message", msg)
		}
	}()
	newColSet(pg.NewTable("t"), model{}, true)
}

// renderColumnValue returns the SQL and args a ColumnValue contributes, by
// rendering a one-row INSERT through drops' own builder (InsertBuilder.ToSQL,
// which itself just drives a drops.Builder). pg.ColumnValue's methods are
// unexported, so a value built outside the pg package cannot be asked for its
// own column; the table comes from the colSet under test instead.
func renderColumnValue(t *testing.T, cs *colSet, v pg.ColumnValue) (string, []any) {
	t.Helper()
	return pg.New(nil).Insert(cs.tbl).Row(v).ToSQL()
}

func TestColSetTypesPointerTimestampAsNullable(t *testing.T) {
	type withNullable struct {
		ID        string     `drop:"id"`
		ExpiresAt *time.Time `drop:"expires_at"`
	}
	cs := newColSet(pg.NewTable("links"), withNullable{}, true)

	c := cs.col("expires_at")
	if c == nil {
		t.Fatal("expires_at column missing")
	}
	if got := c.Type().TypeSQL(); got != "timestamptz" {
		t.Fatalf("expires_at type = %q, want timestamptz", got)
	}
	if c.IsNotNull() {
		t.Fatal("a *time.Time column was declared NOT NULL — it can never hold nil")
	}
	// A non-pointer time.Time must stay NOT NULL.
	if !cs.col("id").IsNotNull() {
		t.Fatal("id lost its NOT NULL")
	}
}

func TestColSetBindsNilPointerAsSQLNull(t *testing.T) {
	type withNullable struct {
		ExpiresAt *time.Time `drop:"expires_at"`
	}
	cs := newColSet(pg.NewTable("links"), withNullable{}, true)

	sql, args := renderColumnValue(t, cs, cs.bind("expires_at", (*time.Time)(nil)))
	if !strings.Contains(strings.ToUpper(sql), "NULL") {
		t.Fatalf("nil *time.Time did not render as NULL: %q", sql)
	}
	if len(args) != 0 {
		t.Fatalf("NULL bound %d args (%v), want none", len(args), args)
	}
}

func TestColSetBindsNonNilPointerAsAValue(t *testing.T) {
	type withNullable struct {
		ExpiresAt *time.Time `drop:"expires_at"`
	}
	cs := newColSet(pg.NewTable("links"), withNullable{}, true)
	at := time.Date(2026, 8, 27, 0, 0, 0, 0, time.UTC)

	sql, args := renderColumnValue(t, cs, cs.bind("expires_at", &at))
	if strings.Contains(strings.ToUpper(sql), "NULL") {
		t.Fatalf("a non-nil *time.Time rendered as NULL: %q", sql)
	}
	if len(args) != 1 || args[0] != at {
		t.Fatalf("args = %v, want [%v]", args, at)
	}
}

func TestColSetRowRoundTripsANilPointer(t *testing.T) {
	type withNullable struct {
		ID        string     `drop:"id"`
		ExpiresAt *time.Time `drop:"expires_at"`
	}
	cs := newColSet(pg.NewTable("links"), withNullable{}, true)

	vals := cs.row(withNullable{ID: "l1"})
	if len(vals) != 2 {
		t.Fatalf("row() produced %d bindings, want 2", len(vals))
	}
}
