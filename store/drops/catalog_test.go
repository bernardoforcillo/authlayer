package dropsstore

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/bernardoforcillo/drops/pg"
)

const goldenPath = "testdata/schema.snapshot.json"

// The data model is frozen in testdata/schema.snapshot.json. Any change to a
// table, column, type, key or index shows up there as a diff in review. After
// an intended change, regenerate it with
//
//	UPDATE_GOLDEN=1 go test ./store/drops -run TestSnapshotMatchesGolden
//
// and ship a migration step for it (see migrations.go).
func TestSnapshotMatchesGolden(t *testing.T) {
	got, err := SnapshotSchema().Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	got = append(bytes.TrimRight(got, "\n"), '\n')
	if os.Getenv("UPDATE_GOLDEN") != "" {
		if err := os.MkdirAll(filepath.Dir(goldenPath), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(goldenPath, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read %s: %v (generate it with UPDATE_GOLDEN=1)", goldenPath, err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("the data model differs from %s. If the change is intended, regenerate the file with UPDATE_GOLDEN=1 and add a migration step", goldenPath)
	}
}

// The snapshot is deterministic: building it twice gives the same bytes.
func TestSnapshotIsDeterministic(t *testing.T) {
	a, _ := SnapshotSchema().Marshal()
	b, _ := SnapshotSchema().Marshal()
	if !bytes.Equal(a, b) {
		t.Fatal("two snapshots of the same model differ")
	}
}

// storeOf maps each default table name to the store that owns it.
func storeOf() map[string]string {
	out := map[string]string{}
	for _, st := range contractStores() {
		for _, sp := range st.tables {
			out[sp.t.Name()] = st.name
		}
	}
	return out
}

var snake = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// Tables() and the stores' own schemas describe the same set of tables.
func TestTablesCoverEveryStoreTable(t *testing.T) {
	want := storeOf()
	got := map[string]bool{}
	for _, tb := range Tables() {
		got[tb.Name()] = true
		if _, ok := want[tb.Name()]; !ok {
			t.Errorf("Tables() lists %s, which no store owns", tb.Name())
		}
	}
	for name := range want {
		if !got[name] {
			t.Errorf("table %s is owned by a store but missing from Tables()", name)
		}
	}
}

func leadsIndex(t *testing.T, tb *pg.Table, col string) bool {
	t.Helper()
	if c := tb.Col(col); c != nil && (c.IsPrimaryKey() || c.IsUnique()) {
		return true
	}
	if pk := tb.CompositePrimaryKey(); len(pk) > 0 && pk[0].Name() == col {
		return true
	}
	for _, cols := range tb.CompositeUniques() {
		if cols[0].Name() == col {
			return true
		}
	}
	for _, idx := range tb.Indexes() {
		if indexColumns(t, idx)[0] == col {
			return true
		}
	}
	return false
}

func uniqueAlone(tb *pg.Table, col string) bool {
	if c := tb.Col(col); c != nil && (c.IsPrimaryKey() || c.IsUnique()) {
		return true
	}
	for _, cols := range tb.CompositeUniques() {
		if len(cols) == 1 && cols[0].Name() == col {
			return true
		}
	}
	return false
}

// Naming: tables and columns are lower snake_case.
func TestContractNamesAreSnakeCase(t *testing.T) {
	for _, tb := range Tables() {
		if !snake.MatchString(tb.Name()) {
			t.Errorf("table %q is not snake_case", tb.Name())
		}
		for _, c := range tb.Columns() {
			if !snake.MatchString(c.Name()) {
				t.Errorf("%s.%q is not snake_case", tb.Name(), c.Name())
			}
		}
	}
}

// Keys: every table has a primary key; a single-column one is called id.
func TestContractEveryTableHasAKeyAndEntityKeysAreCalledID(t *testing.T) {
	// keyedByOwner lists the tables with exactly one row per owner, which are
	// keyed by that owner (a user, an audit subject) rather than by a row id of
	// their own.
	keyedByOwner := map[string]string{"mfa_factors": "user_id", "audit_subject_keys": "subject"}
	for _, tb := range Tables() {
		single := ""
		for _, c := range tb.Columns() {
			if c.IsPrimaryKey() {
				single = c.Name()
			}
		}
		if single == "" && len(tb.CompositePrimaryKey()) == 0 {
			t.Errorf("%s has no primary key", tb.Name())
		}
		if want, ok := keyedByOwner[tb.Name()]; ok {
			if single != want {
				t.Errorf("%s: primary key is %q, want %s", tb.Name(), single, want)
			}
			continue
		}
		if single != "" && single != "id" {
			t.Errorf("%s: single-column primary key is %q, want id", tb.Name(), single)
		}
	}
}

// Types: *_at is timestamptz, created_at is never null, permissions are
// NOT NULL bytea, booleans are NOT NULL, and id is uuid or text.
func TestContractColumnTypes(t *testing.T) {
	for _, tb := range Tables() {
		for _, c := range tb.Columns() {
			typ := c.Type().TypeSQL()
			name := tb.Name() + "." + c.Name()
			switch {
			case strings.HasSuffix(c.Name(), "_at") && typ != "timestamptz":
				t.Errorf("%s is %s, want timestamptz", name, typ)
			case c.Name() == "created_at" && !c.IsNotNull():
				t.Errorf("%s must be NOT NULL", name)
			case c.Name() == "permissions" && (typ != "bytea" || !c.IsNotNull()):
				t.Errorf("%s is %s (not null %v), want NOT NULL bytea", name, typ, c.IsNotNull())
			case typ == "boolean" && !c.IsNotNull():
				t.Errorf("%s is a nullable boolean", name)
			case c.Name() == "id" && typ != "uuid" && typ != "text":
				t.Errorf("%s is %s, want uuid or text", name, typ)
			}
		}
	}
}

// Security: a hash a lookup resolves a bearer secret by is unique, so one
// secret can never resolve to two rows. These three are the exceptions: a
// password hash and a client secret hash are never looked up by value, and a
// recovery code hash is matched within one user's rows.
func TestContractLookupHashesAreUnique(t *testing.T) {
	exempt := map[string]bool{
		"users.password_hash":          true,
		"oauth_clients.secret_hash":    true,
		"mfa_recovery_codes.code_hash": true,
		// Integrity hashes of the audit chain, not bearer secrets.
		"audit_seals.events_hash": true,
		"audit_seals.prev_hash":   true,
		"audit_seals.seal_hash":   true,
	}
	for _, tb := range Tables() {
		for _, c := range tb.Columns() {
			if !strings.HasSuffix(c.Name(), "_hash") || exempt[tb.Name()+"."+c.Name()] {
				continue
			}
			if !uniqueAlone(tb, c.Name()) {
				t.Errorf("%s.%s resolves a bearer secret but is not UNIQUE", tb.Name(), c.Name())
			}
		}
	}
}

// Foreign keys stay inside the store that owns both ends, and their column
// leads an index (so a cascade does not scan the child table).
func TestContractForeignKeys(t *testing.T) {
	owner := storeOf()
	for _, tb := range Tables() {
		for _, c := range tb.Columns() {
			fk := c.ForeignKey()
			if fk == nil {
				continue
			}
			target := fk.Target.Table().Name()
			if owner[target] != owner[tb.Name()] {
				t.Errorf("%s.%s references %s, owned by %s: a foreign key must not cross stores",
					tb.Name(), c.Name(), target, owner[target])
			}
			if !leadsIndex(t, tb, c.Name()) {
				t.Errorf("%s.%s is a foreign key but leads no index", tb.Name(), c.Name())
			}
		}
	}
}

func colNames(cols []*pg.Column) string {
	names := make([]string, len(cols))
	for i, c := range cols {
		names[i] = c.Name()
	}
	return strings.Join(names, ",")
}

// A composite foreign key stays inside its store, its first column leads an
// index (so a cascade does not scan the child), and it targets columns that are
// exactly a UNIQUE or primary key of the parent — PostgreSQL refuses it
// otherwise, and the test says so before a database does.
func TestContractCompositeForeignKeys(t *testing.T) {
	owner := storeOf()
	for _, tb := range Tables() {
		for _, fk := range tb.CompositeForeignKeys() {
			if owner[fk.Target.Name()] != owner[tb.Name()] {
				t.Errorf("%s.%s references %s, owned by %s: a foreign key must not cross stores",
					tb.Name(), fk.Name, fk.Target.Name(), owner[fk.Target.Name()])
			}
			if !leadsIndex(t, tb, fk.Columns[0].Name()) {
				t.Errorf("%s.%s: first column %s leads no index", tb.Name(), fk.Name, fk.Columns[0].Name())
			}
			want, found := colNames(fk.TargetColumns), false
			for _, cols := range fk.Target.CompositeUniques() {
				found = found || colNames(cols) == want
			}
			if pk := fk.Target.CompositePrimaryKey(); len(pk) > 0 && colNames(pk) == want {
				found = true
			}
			if !found {
				t.Errorf("%s.%s targets (%s) of %s, which is not a UNIQUE or primary key there", tb.Name(), fk.Name, want, fk.Target.Name())
			}
			if len(fk.Name) > 63 {
				t.Errorf("%s: constraint name %q is longer than PostgreSQL's 63-byte limit", tb.Name(), fk.Name)
			}
		}
	}
}

// Normalization: a column that repeats what a parent row already determines
// (a third-normal-form dependency through a foreign key) is either guarded by a
// composite foreign key — so the database refuses a row that disagrees with its
// parent — or listed here with the reason it is not.
func TestContractRepeatedColumnsAreGuarded(t *testing.T) {
	guarded := []struct{ table, parent, copied string }{
		{"api_keys", "service_accounts", "service_account_id,container_id"},
		{"oauth_codes", "oauth_grants", "grant_id,client_id"},
		{"oauth_refresh_tokens", "oauth_grants", "grant_id,client_id"},
	}
	byName := map[string]*pg.Table{}
	for _, tb := range Tables() {
		byName[tb.Name()] = tb
	}
	for _, g := range guarded {
		found := false
		for _, fk := range byName[g.table].CompositeForeignKeys() {
			found = found || (fk.Target.Name() == g.parent && colNames(fk.Columns) == g.copied)
		}
		if !found {
			t.Errorf("%s repeats a column of %s but has no composite foreign key on (%s)", g.table, g.parent, g.copied)
		}
	}

	// Not guarded, deliberately.
	unguarded := map[string]string{
		"oauth_device_authorizations.client_id": "grant_id is nullable until the user approves; the pair is checked in oauth.Service",
		"oauth_clients.container_id":            "service_accounts belongs to another store, and a foreign key must not cross stores",
		"sessions.user_id":                      "users are only referenced by value from every other store, by design",
		"oauth_refresh_tokens.family_id":        "a family has no table of its own; its rows are linked by value",
	}
	for k, reason := range unguarded {
		if reason == "" {
			t.Errorf("%s is listed as unguarded without a reason", k)
		}
	}
}
