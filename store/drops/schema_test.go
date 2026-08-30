package dropsstore

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/bernardoforcillo/authlayer/org"
	"github.com/bernardoforcillo/authlayer/scope"
	"github.com/bernardoforcillo/authlayer/team"
)

func TestSchemaDefaultTableNames(t *testing.T) {
	s := NewSchema[org.Organization, org.Member]()
	if s.Containers.Name() != "organizations" ||
		s.Members.Name() != "organization_members" ||
		s.Roles.Name() != "organization_roles" {
		t.Fatalf("unexpected table names: %s %s %s",
			s.Containers.Name(), s.Members.Name(), s.Roles.Name())
	}
}

func TestSchemaHonoursCustomNames(t *testing.T) {
	s := NewSchema[org.Organization, org.Member](WithNames(Names{
		Containers: "teams", Members: "team_members", Roles: "team_roles",
	}))
	if s.Containers.Name() != "teams" || s.Members.Name() != "team_members" || s.Roles.Name() != "team_roles" {
		t.Fatalf("custom names not applied: %s %s %s",
			s.Containers.Name(), s.Members.Name(), s.Roles.Name())
	}
}

// The composite PK is load-bearing: it is what turns a concurrent double-insert
// into ErrAlreadyMember instead of a duplicate row.
func TestSchemaMembersHaveCompositePrimaryKey(t *testing.T) {
	s := NewSchema[org.Organization, org.Member]()
	pk := s.Members.CompositePrimaryKey()
	if len(pk) != 2 {
		t.Fatalf("members composite PK has %d columns, want 2", len(pk))
	}
	got := []string{pk[0].Name(), pk[1].Name()}
	want := []string{"container_id", "user_id"}
	if got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("composite PK = %v, want %v", got, want)
	}
}

func TestSchemaIDColumnsAreUUID(t *testing.T) {
	s := NewSchema[org.Organization, org.Member]()
	for tbl, col := range map[string]string{
		"containers": "id",
		"members":    "container_id",
		"roles":      "container_id",
	} {
		var got string
		switch tbl {
		case "containers":
			got = s.Containers.Col(col).Type().TypeSQL()
		case "members":
			got = s.Members.Col(col).Type().TypeSQL()
		case "roles":
			got = s.Roles.Col(col).Type().TypeSQL()
		}
		if got != "uuid" {
			t.Fatalf("%s.%s type = %q, want uuid", tbl, col, got)
		}
	}
}

func TestSchemaWithTextUserIDs(t *testing.T) {
	s := NewSchema[org.Organization, org.Member](WithTextUserIDs())
	if got := s.Members.Col("user_id").Type().TypeSQL(); got != "text" {
		t.Fatalf("user_id type = %q, want text under WithTextUserIDs", got)
	}
	// owner_id holds a user id too, so the option must reach it — otherwise
	// every CreateOrganization fails against a non-UUID user table.
	if got := s.Containers.Col("owner_id").Type().TypeSQL(); got != "text" {
		t.Fatalf("owner_id type = %q, want text under WithTextUserIDs", got)
	}
	if got := s.Members.Col("container_id").Type().TypeSQL(); got != "uuid" {
		t.Fatalf("WithTextUserIDs leaked into container_id: %q", got)
	}
	if got := s.Containers.Col("id").Type().TypeSQL(); got != "uuid" {
		t.Fatalf("WithTextUserIDs leaked into the container id: %q", got)
	}
	if got := s.Roles.Col("id").Type().TypeSQL(); got != "uuid" {
		t.Fatalf("WithTextUserIDs leaked into the role id: %q", got)
	}
}

// WithTextLibraryIDs is the other half of the pair: it types the ids
// authlayer mints for itself as text, so a caller who overrode
// scope.WithIDGenerator with a ULID (or a sequence, or a readable prefix
// scheme) can persist through this store at all. Without it those columns are
// uuid and the first CreateContainer fails with SQLSTATE 22P02.
//
// It must not reach the user-id columns: a deployment can perfectly well mint
// ULIDs of its own while pointing at a users table that is genuinely UUID
// keyed, and retyping owner_id under this option would break it.
func TestSchemaWithTextLibraryIDs(t *testing.T) {
	s := NewSchema[org.Organization, org.Member](WithTextLibraryIDs())
	for _, c := range []struct {
		tag string
		col func() string
	}{
		{"containers.id", func() string { return s.Containers.Col("id").Type().TypeSQL() }},
		{"members.container_id", func() string { return s.Members.Col("container_id").Type().TypeSQL() }},
		{"roles.id", func() string { return s.Roles.Col("id").Type().TypeSQL() }},
		{"roles.container_id", func() string { return s.Roles.Col("container_id").Type().TypeSQL() }},
	} {
		if got := c.col(); got != "text" {
			t.Fatalf("%s type = %q, want text under WithTextLibraryIDs", c.tag, got)
		}
	}
	// The user-id family is a separate decision and keeps its uuid default.
	if got := s.Members.Col("user_id").Type().TypeSQL(); got != "uuid" {
		t.Fatalf("WithTextLibraryIDs leaked into user_id: %q", got)
	}
	if got := s.Containers.Col("owner_id").Type().TypeSQL(); got != "uuid" {
		t.Fatalf("WithTextLibraryIDs leaked into owner_id: %q", got)
	}

	// parent_id is the third library id column and only exists on a nested
	// container type, so it needs its own schema to be asserted at all. A
	// nested scope whose parent_id stayed uuid while its id went text could
	// not store the link at all.
	nested := NewSchema[team.Team, team.Member](WithTextLibraryIDs())
	if got := nested.Containers.Col("parent_id").Type().TypeSQL(); got != "text" {
		t.Fatalf("parent_id type = %q, want text under WithTextLibraryIDs", got)
	}
	if got := NewSchema[team.Team, team.Member]().Containers.Col("parent_id").Type().TypeSQL(); got != "uuid" {
		t.Fatalf("parent_id type = %q, want uuid by default", got)
	}
}

// The two options compose, which is the combination an auth-integrated
// deployment on a non-UUID id scheme actually needs: its user ids come from
// the same generator as its container ids.
func TestSchemaWithBothTextIDOptions(t *testing.T) {
	s := NewSchema[org.Organization, org.Member](WithTextLibraryIDs(), WithTextUserIDs())
	for tag, got := range map[string]string{
		"containers.id":        s.Containers.Col("id").Type().TypeSQL(),
		"containers.owner_id":  s.Containers.Col("owner_id").Type().TypeSQL(),
		"members.container_id": s.Members.Col("container_id").Type().TypeSQL(),
		"members.user_id":      s.Members.Col("user_id").Type().TypeSQL(),
		"roles.id":             s.Roles.Col("id").Type().TypeSQL(),
	} {
		if got != "text" {
			t.Fatalf("%s type = %q, want text with both options", tag, got)
		}
	}
}

// The default must not move: authlayer mints UUIDv7, so a caller who passes
// no id option keeps uuid columns everywhere.
func TestSchemaDefaultsToUUIDForBothIDFamilies(t *testing.T) {
	s := NewSchema[org.Organization, org.Member]()
	for tag, got := range map[string]string{
		"containers.id":        s.Containers.Col("id").Type().TypeSQL(),
		"containers.owner_id":  s.Containers.Col("owner_id").Type().TypeSQL(),
		"members.container_id": s.Members.Col("container_id").Type().TypeSQL(),
		"members.user_id":      s.Members.Col("user_id").Type().TypeSQL(),
		"roles.id":             s.Roles.Col("id").Type().TypeSQL(),
		"roles.container_id":   s.Roles.Col("container_id").Type().TypeSQL(),
	} {
		if got != "uuid" {
			t.Fatalf("%s type = %q, want uuid by default", tag, got)
		}
	}
}

// The UNIQUE (container_id, key) constraint is load-bearing: it is what turns
// a concurrent double-insert into ErrRoleKeyTaken instead of a duplicate row.
func TestSchemaRolesHaveUniqueContainerKey(t *testing.T) {
	s := NewSchema[org.Organization, org.Member]()
	if s.Roles.Col("permissions") == nil {
		t.Fatal("roles table missing permissions column")
	}
	if s.Roles.Col("key") == nil {
		t.Fatal("roles table missing key column")
	}

	uniques := s.Roles.CompositeUniques()
	cols, ok := uniques["organization_roles_container_key"]
	if !ok {
		t.Fatalf("roles table missing UNIQUE constraint %q; have %v",
			"organization_roles_container_key", uniques)
	}
	if len(cols) != 2 {
		t.Fatalf("roles unique constraint has %d columns, want 2", len(cols))
	}
	got := []string{cols[0].Name(), cols[1].Name()}
	want := []string{"container_id", "key"}
	if got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("roles unique constraint columns = %v, want %v", got, want)
	}
}

// The constraint name is derived from the configured Roles table name, so a
// second scope instance (teams, projects) gets its own, non-colliding
// constraint rather than reusing "organization_roles_container_key".
func TestSchemaRolesUniqueConstraintNameFollowsCustomNames(t *testing.T) {
	s := NewSchema[org.Organization, org.Member](WithNames(Names{
		Containers: "teams", Members: "team_members", Roles: "team_roles",
	}))
	uniques := s.Roles.CompositeUniques()
	cols, ok := uniques["team_roles_container_key"]
	if !ok {
		t.Fatalf("roles table missing UNIQUE constraint %q; have %v",
			"team_roles_container_key", uniques)
	}
	got := []string{cols[0].Name(), cols[1].Name()}
	want := []string{"container_id", "key"}
	if got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("roles unique constraint columns = %v, want %v", got, want)
	}
}

// A second scope instance must need only table names, not a new store.
func TestSchemaSupportsASecondContainerType(t *testing.T) {
	type Team struct {
		scope.ContainerBase
		Name     string `drop:"name"`
		ParentID string `drop:"parent_id"`
	}
	type TeamMember struct {
		scope.MemberBase
	}

	s := NewSchema[Team, TeamMember](WithNames(Names{
		Containers: "teams", Members: "team_members", Roles: "team_roles",
	}))
	if s.Containers.Name() != "teams" || s.Members.Name() != "team_members" || s.Roles.Name() != "team_roles" {
		t.Fatalf("unexpected table names: %s %s %s",
			s.Containers.Name(), s.Members.Name(), s.Roles.Name())
	}
	if got := s.Containers.Col("parent_id").Type().TypeSQL(); got != "uuid" {
		t.Fatalf("parent_id type = %q, want uuid", got)
	}
	if s.Containers.Col("name") == nil {
		t.Fatal("teams table missing the custom name column")
	}
}

// A member type that satisfies scope.Member but tags its container column
// something else used to build a schema, render DDL, and then nil-deref on the
// first FindMember. Fail at construction instead, and say what is missing.
func TestNewSchemaPanicsOnMemberTypeMissingARequiredTag(t *testing.T) {
	type badMember struct {
		OrgID    string    `drop:"org_id"`
		UserID   string    `drop:"user_id"`
		RoleKey  string    `drop:"role_key"`
		JoinedAt time.Time `drop:"joined_at"`
	}

	msg := recoverPanic(t, func() { NewSchema[org.Organization, badMember]() })
	for _, want := range []string{"badMember", "scope.MemberBase"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("panic message %q does not mention %q", msg, want)
		}
	}
	// The missing list is exactly the missing tag, not every required one.
	if !strings.Contains(msg, "no drop: tag for container_id;") {
		t.Fatalf("panic message %q does not name container_id as the missing tag", msg)
	}
}

func TestNewSchemaPanicsOnContainerTypeMissingARequiredTag(t *testing.T) {
	type badContainer struct {
		ID   string `drop:"id"`
		Name string `drop:"name"`
	}

	msg := recoverPanic(t, func() { NewSchema[badContainer, org.Member]() })
	for _, want := range []string{"badContainer", "owner_id", "created_at", "updated_at"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("panic message %q does not mention %q", msg, want)
		}
	}
}

// A pointer type parameter used to die inside reflect with "NumField of
// non-struct type" instead of the package's own message.
func TestNewSchemaPanicsOnPointerContainerType(t *testing.T) {
	msg := recoverPanic(t, func() { NewSchema[*org.Organization, org.Member]() })
	if !strings.Contains(msg, "authlayer/store/drops") || !strings.Contains(msg, "not a struct") {
		t.Fatalf("pointer C panicked with %q, want the package's own message", msg)
	}
}

// A fully-tagged pair that does not embed the bases is still accepted: the
// check is on the tags, not on the embedding.
func TestNewSchemaAcceptsHandTaggedTypes(t *testing.T) {
	type container struct {
		ID        string    `drop:"id"`
		OwnerID   string    `drop:"owner_id"`
		CreatedAt time.Time `drop:"created_at"`
		UpdatedAt time.Time `drop:"updated_at"`
	}
	type member struct {
		ContainerID string    `drop:"container_id"`
		UserID      string    `drop:"user_id"`
		RoleKey     string    `drop:"role_key"`
		JoinedAt    time.Time `drop:"joined_at"`
	}
	s := NewSchema[container, member]()
	if s.Members.Col("container_id") == nil {
		t.Fatal("hand-tagged member type produced no container_id column")
	}
}

// recoverPanic runs fn and returns the panic value as a string, failing the
// test if fn returns normally.
func recoverPanic(t *testing.T, fn func()) (msg string) {
	t.Helper()
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected a panic, got none")
		}
		msg = fmt.Sprint(r)
	}()
	fn()
	return ""
}
