package dropsstore

import (
	"fmt"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/bernardoforcillo/drops/pg"

	"github.com/bernardoforcillo/authlayer/org"
	"github.com/bernardoforcillo/authlayer/scope"
)

func TestColSetTypesIDColumnsAsUUID(t *testing.T) {
	tbl := pg.NewTable("organizations")
	cs := newColSet(tbl, org.Organization{}, uuidIDs())

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
	cs := newColSet(tbl, org.Organization{}, uuidIDs())

	for _, tag := range []string{"name", "slug"} {
		if got := cs.col(tag).Type().TypeSQL(); got != "text" {
			t.Fatalf("column %q type = %q, want text", tag, got)
		}
	}
}

func TestColSetHonoursUniqueTagOption(t *testing.T) {
	cs := newColSet(pg.NewTable("organizations"), org.Organization{}, uuidIDs())
	if !cs.col("slug").IsUnique() {
		t.Fatal(`slug carries drop:"slug,unique" but the column is not unique`)
	}
	if cs.col("name").IsUnique() {
		t.Fatal("name has no unique option but the column is unique")
	}
}

func TestColSetTypesTimestampsAndBytes(t *testing.T) {
	cs := newColSet(pg.NewTable("organizations"), org.Organization{}, uuidIDs())
	if got := cs.col("created_at").Type().TypeSQL(); got != "timestamptz" {
		t.Fatalf("created_at type = %q, want timestamptz", got)
	}

	rc := newColSet(pg.NewTable("organization_roles"), scope.RoleRecord{}, uuidIDs())
	if got := rc.col("permissions").Type().TypeSQL(); got != "bytea" {
		t.Fatalf("permissions type = %q, want bytea", got)
	}
}

// MemberBase tags the container column "container_id" (scope/base.go:40), so the
// generic store must use that name — not the legacy "organization_id".
func TestColSetUsesBaseTagNamesForMembers(t *testing.T) {
	cs := newColSet(pg.NewTable("organization_members"), org.Member{}, uuidIDs())
	if cs.col("container_id") == nil {
		t.Fatal("members table has no container_id column")
	}
	if cs.col("organization_id") != nil {
		t.Fatal("members table still carries the legacy organization_id column")
	}
}

func TestColSetUserIDTypeFollowsTheOption(t *testing.T) {
	if got := newColSet(pg.NewTable("m1"), org.Member{}, uuidIDs()).col("user_id").Type().TypeSQL(); got != "uuid" {
		t.Fatalf("user_id type = %q, want uuid when uuidUserIDs is true", got)
	}
	if got := newColSet(pg.NewTable("m2"), org.Member{}, idTypes{library: true}).col("user_id").Type().TypeSQL(); got != "text" {
		t.Fatalf("user_id type = %q, want text when uuidUserIDs is false", got)
	}
}

// owner_id holds a user id — the engine stamps it from the context subject —
// so it must follow WithTextUserIDs alongside user_id, and NOT
// WithTextLibraryIDs. Typing it uuid unconditionally makes the escape hatch
// useless: every container insert fails with "invalid input syntax for type
// uuid".
func TestColSetOwnerIDFollowsTheUserIDOption(t *testing.T) {
	if got := newColSet(pg.NewTable("c1"), org.Organization{}, uuidIDs()).col("owner_id").Type().TypeSQL(); got != "uuid" {
		t.Fatalf("owner_id type = %q, want uuid when uuidUserIDs is true", got)
	}
	if got := newColSet(pg.NewTable("c2"), org.Organization{}, idTypes{library: true}).col("owner_id").Type().TypeSQL(); got != "text" {
		t.Fatalf("owner_id type = %q, want text when uuidUserIDs is false", got)
	}
}

// The whole split in one place, across all four settings of the two flags.
// The two families are independent: the ids authlayer mints for itself follow
// WithTextLibraryIDs, the ids a consumer supplies follow WithTextUserIDs, and
// neither option may reach the other family. A single flag governing both
// would silently retype a consumer's existing user table the moment someone
// reached for a ULID generator, and vice versa.
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

	want := func(uuid bool) string {
		if uuid {
			return "uuid"
		}
		return "text"
	}

	for i, tc := range []idTypes{
		{library: true, user: true},   // the default
		{library: true, user: false},  // WithTextUserIDs
		{library: false, user: true},  // WithTextLibraryIDs
		{library: false, user: false}, // both
	} {
		cs := newColSet(pg.NewTable(fmt.Sprintf("t%d", i)), model{}, tc)
		for _, tag := range library {
			if got := cs.col(tag).Type().TypeSQL(); got != want(tc.library) {
				t.Fatalf("%+v: library id %s type = %q, want %q", tc, tag, got, want(tc.library))
			}
		}
		for _, tag := range user {
			if got := cs.col(tag).Type().TypeSQL(); got != want(tc.user) {
				t.Fatalf("%+v: user id %s type = %q, want %q", tc, tag, got, want(tc.user))
			}
		}
	}
}

// uuidIDs is the default every schema constructor starts from, so it has to
// mean "both families uuid". If it ever drifted, every caller who passes no
// option at all would silently get text columns.
func TestUUIDIDsIsBothFamiliesUUID(t *testing.T) {
	if got := uuidIDs(); !got.library || !got.user || got.extraLibrary != nil {
		t.Fatalf("uuidIDs() = %+v, want both families uuid and no extra columns", got)
	}
}

func TestColSetRowProducesOneBindingPerColumnInOrder(t *testing.T) {
	cs := newColSet(pg.NewTable("organizations"), org.Organization{}, uuidIDs())
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
	newColSet(pg.NewTable("bad"), bad{}, uuidIDs())
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

	cs := newColSet(pg.NewTable("t"), model{}, uuidIDs())
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
	cs := newColSet(pg.NewTable("t"), model{}, uuidIDs())

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
	cs := newColSet(pg.NewTable("organizations"), org.Organization{}, uuidIDs())
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
	cs := newColSet(pg.NewTable("links"), withNullable{}, uuidIDs())
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
	cs := newColSet(pg.NewTable("t"), model{ID: "i", hidden: "x"}, uuidIDs())
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
	newColSet(pg.NewTable("t"), model{}, uuidIDs())
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
	cs := newColSet(pg.NewTable("links"), withNullable{}, uuidIDs())

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
	cs := newColSet(pg.NewTable("links"), withNullable{}, uuidIDs())

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
	cs := newColSet(pg.NewTable("links"), withNullable{}, uuidIDs())
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
	cs := newColSet(pg.NewTable("links"), withNullable{}, uuidIDs())

	vals := cs.row(withNullable{ID: "l1"})
	if len(vals) != 2 {
		t.Fatalf("row() produced %d bindings, want 2", len(vals))
	}
}

// uint32 maps to BIGINT, and it is the one integer width where the Go type and
// the obvious SQL type disagree: PostgreSQL has no unsigned types, so half the
// uint32 range does not fit in `integer`. auth.Credential.SignCount is the
// field that needs it, and a counter stored wrong is a compare-and-set that
// accepts what it should refuse — so this is a correctness mapping, not a
// capacity nicety. Named uint32 types are classified by Kind here exactly as
// named string and int types are.
func TestColSetMapsUint32ToBigInt(t *testing.T) {
	type Counter uint32
	type model struct {
		ID    string  `drop:"id"`
		Count uint32  `drop:"count"`
		Named Counter `drop:"named"`
	}

	cs := newColSet(pg.NewTable("t"), model{}, uuidIDs())
	for _, tag := range []string{"count", "named"} {
		if got := cs.col(tag).Type().TypeSQL(); got != "bigint" {
			t.Fatalf("%s type = %q, want bigint", tag, got)
		}
		if !cs.col(tag).IsNotNull() {
			t.Fatalf("%s is nullable, want NOT NULL", tag)
		}
	}

	// The whole range binds, including values above math.MaxInt32 that an
	// `integer` column would have rejected or an unchecked narrowing would
	// have turned into a negative number.
	vals := cs.row(model{ID: "i", Count: math.MaxUint32, Named: 4_000_000_000})
	if len(vals) != 3 {
		t.Fatalf("row() produced %d bindings, want 3", len(vals))
	}
}

// *string is the nullable string family, declared without NOT NULL and bound
// as the NULL keyword when nil. auth.Challenge.UserID is the field that needs
// it: nil means "this ceremony names no account", which a login ceremony
// genuinely does not, and "" is not a substitute — it fails a uuid column
// outright.
//
// The id-column typing decision is the same one a non-nullable string gets, so
// a nullable reference to users.id is still uuid.
func TestColSetMapsNullableStrings(t *testing.T) {
	type model struct {
		ID     string  `drop:"id"`
		UserID *string `drop:"user_id"`
		Note   *string `drop:"note"`
	}

	cs := newColSet(pg.NewTable("t"), model{}, uuidIDs())
	if got := cs.col("user_id").Type().TypeSQL(); got != "uuid" {
		t.Fatalf("user_id type = %q, want uuid — nullability must not change the id typing", got)
	}
	if got := cs.col("note").Type().TypeSQL(); got != "text" {
		t.Fatalf("note type = %q, want text", got)
	}
	for _, tag := range []string{"user_id", "note"} {
		if cs.col(tag).IsNotNull() {
			t.Fatalf("%s is NOT NULL; a *string column must be able to hold NULL", tag)
		}
	}

	// Both the nil and the non-nil forms bind, and neither panics.
	if got := len(cs.row(model{ID: "i"})); got != 3 {
		t.Fatalf("row() with nil pointers produced %d bindings, want 3", got)
	}
	value := "01a05ba5-3d49-786e-a5e9-e492b0839ea4"
	if got := len(cs.row(model{ID: "i", UserID: &value, Note: &value})); got != 3 {
		t.Fatalf("row() with set pointers produced %d bindings, want 3", got)
	}
}

// Binding a *string to a column the model declared as a plain string is a
// model/schema disagreement, and coercing nil to "" there would write an empty
// string into a column that is NOT NULL for a reason. It names the column
// rather than nil-panicking, like every other bind failure.
func TestColSetBindRejectsANullableValueForANonNullableColumn(t *testing.T) {
	type model struct {
		ID    string `drop:"id"`
		Label string `drop:"label"`
	}
	cs := newColSet(pg.NewTable("t"), model{}, uuidIDs())

	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("bind accepted a *string for a NOT NULL column")
		}
		if msg := fmt.Sprint(r); !strings.Contains(msg, "label") {
			t.Fatalf("panic %q does not name the column", msg)
		}
	}()
	var nilPtr *string
	cs.bind("label", nilPtr)
}
