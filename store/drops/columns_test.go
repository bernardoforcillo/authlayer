package dropsstore

import (
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
