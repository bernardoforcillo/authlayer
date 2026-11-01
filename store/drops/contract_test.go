package dropsstore

import (
	"regexp"
	"strings"
	"testing"

	"github.com/bernardoforcillo/drops"
	"github.com/bernardoforcillo/drops/pg"
)

// This file is the executable form of the data-layer conventions written up in
// docs/storage/conventions.mdx. A change that breaks one fails here, with the
// table and index named, before it reaches a database.

// contractStore is what the checks need from every store: its migrations and
// the tables (with their column sets) they cover.
type contractStore struct {
	name       string
	migrations []pg.TreeMigration
	tables     []tableSpec
}

func contractStores() []contractStore {
	fd := &fakeDriver{}
	sc, au, in, ak := newStore(fd), newAuthStore(fd), newInviteStore(fd), newAPIKeyStore(fd)
	id, cr, mf, oa := newIdentityStore(fd), newCredentialStore(fd), newMFAStore(fd), newOAuthStore(fd)
	return []contractStore{
		{"scope", sc.Migrations(), []tableSpec{{sc.s.Containers, sc.s.containers}, {sc.s.Members, sc.s.members}, {sc.s.Roles, sc.s.roles}}},
		{"auth", au.Migrations(), []tableSpec{{au.s.Users, au.s.users}, {au.s.Sessions, au.s.sessions}, {au.s.Verifications, au.s.verifications}}},
		{"invite", in.Migrations(), []tableSpec{{in.s.EmailInvites, in.s.emailInvites}, {in.s.Links, in.s.links}}},
		{"apikey", ak.Migrations(), []tableSpec{{ak.s.ServiceAccounts, ak.s.accounts}, {ak.s.Keys, ak.s.keys}}},
		{"identity", id.Migrations(), []tableSpec{{id.s.Identities, id.s.identities}}},
		{"credential", cr.Migrations(), []tableSpec{{cr.s.Credentials, cr.s.credentials}, {cr.s.Challenges, cr.s.challenges}}},
		{"mfa", mf.Migrations(), []tableSpec{{mf.s.Factors, mf.s.factors}, {mf.s.RecoveryCodes, mf.s.codes}, {mf.s.TrustedDevices, mf.s.devices}}},
		{"oauth", oa.Migrations(), []tableSpec{
			{oa.s.Clients, oa.s.clients}, {oa.s.Grants, oa.s.grants}, {oa.s.Codes, oa.s.codes},
			{oa.s.DeviceAuthorizations, oa.s.devices}, {oa.s.RefreshTokens, oa.s.refresh}}},
	}
}

var indexSQL = regexp.MustCompile(`ON "([^"]+)" \(([^)]*)\)`)

// indexColumns renders idx and returns its column list.
func indexColumns(t *testing.T, idx *pg.Index) []string {
	t.Helper()
	b := drops.NewBuilder()
	pg.CreateIndexIfNotExists(idx).WriteSQL(b)
	sql, _ := b.SQL()
	m := indexSQL.FindStringSubmatch(sql)
	if m == nil {
		t.Fatalf("cannot read the columns of index %s from %q", idx.Name(), sql)
	}
	var cols []string
	for _, c := range strings.Split(m[2], ",") {
		cols = append(cols, strings.Trim(strings.TrimSpace(c), `"`))
	}
	return cols
}

// Table names are unique across the default configuration of every store, so
// one database can hold them all.
func TestContractDefaultTableNamesAreUnique(t *testing.T) {
	seen := map[string]string{}
	for _, st := range contractStores() {
		for _, sp := range st.tables {
			if other, dup := seen[sp.t.Name()]; dup {
				t.Fatalf("table %q is claimed by both %s and %s", sp.t.Name(), other, st.name)
			}
			seen[sp.t.Name()] = st.name
		}
	}
}

// Every registered index is named <table>_<columns>_idx, where <columns> is
// its own column list, so a name always says what the index covers.
func TestContractIndexNamesSayWhatTheyCover(t *testing.T) {
	for _, st := range contractStores() {
		for _, sp := range st.tables {
			for _, idx := range sp.t.Indexes() {
				want := idxName(sp.t.Name(), indexColumns(t, idx)...)
				if idx.Name() != want {
					t.Errorf("%s: index %s should be named %s", sp.t.Name(), idx.Name(), want)
				}
			}
		}
	}
}

// A column a janitor deletes by must lead an index, or the purge scans the
// table. expires_at is checked on every table; revoked_at on the two tables
// whose purge also deletes by it.
func TestContractPurgedColumnsAreIndexed(t *testing.T) {
	revokedPurged := map[string]bool{"api_keys": true, "oauth_grants": true}
	for _, st := range contractStores() {
		for _, sp := range st.tables {
			leading := map[string]bool{}
			for _, idx := range sp.t.Indexes() {
				leading[indexColumns(t, idx)[0]] = true
			}
			for _, c := range sp.t.Columns() {
				purged := c.Name() == "expires_at" || (c.Name() == "revoked_at" && revokedPurged[sp.t.Name()])
				if purged && !leading[c.Name()] {
					t.Errorf("%s.%s is deleted by a janitor but leads no index", sp.t.Name(), c.Name())
				}
			}
		}
	}
}

// Migrations form one chain per store on the authlayer branch: the table step
// is a parentless root with no Down, the index step depends on it and is
// reversible, IDs are unique across stores, and every post-baseline index is
// created by an index step.
func TestContractMigrationsAreAFormalChain(t *testing.T) {
	ids := map[string]bool{}
	for _, st := range contractStores() {
		if len(st.migrations) == 0 {
			t.Fatalf("%s has no migrations", st.name)
		}
		root := st.migrations[0]
		if len(root.Parents) != 0 || root.Down != nil || !strings.HasSuffix(root.ID, "-001_tables") {
			t.Errorf("%s: first step %q must be a parentless, irreversible -001_tables", st.name, root.ID)
		}
		lateIdx, lateRel := 0, 0
		for _, sp := range st.tables {
			lateIdx += len(sp.cs.late)
			lateRel += len(sp.cs.lateUnique) + len(sp.t.CompositeForeignKeys())
		}
		var want []string
		if lateIdx > 0 {
			want = append(want, "-002_indexes")
		}
		if lateRel > 0 {
			want = append(want, "-003_relations")
		}
		if len(st.migrations) != 1+len(want) {
			t.Fatalf("%s: %d migrations, want the root plus %v", st.name, len(st.migrations), want)
		}
		for i, suffix := range want {
			step, prev := st.migrations[i+1], st.migrations[i]
			if len(step.Parents) != 1 || step.Parents[0] != prev.ID || step.Down == nil || !strings.HasSuffix(step.ID, suffix) {
				t.Errorf("%s: step %q must be %s, depend on %s and have a Down", st.name, step.ID, suffix, prev.ID)
			}
		}
		for _, m := range st.migrations {
			if m.Branch != MigrationBranch {
				t.Errorf("%s: %s is on branch %q, want %q", st.name, m.ID, m.Branch, MigrationBranch)
			}
			if ids[m.ID] {
				t.Errorf("migration id %s is used twice", m.ID)
			}
			ids[m.ID] = true
		}
	}
}

// Every post-baseline index is also in the registry, so CreateSchema and the
// migrations cannot disagree about which indexes exist.
func TestContractLateIndexesAreRegistered(t *testing.T) {
	for _, st := range contractStores() {
		for _, sp := range st.tables {
			reg := map[string]bool{}
			for _, idx := range sp.t.Indexes() {
				reg[idx.Name()] = true
			}
			for _, idx := range sp.cs.late {
				if !reg[idx.Name()] {
					t.Errorf("%s: late index %s is not registered on the table", sp.t.Name(), idx.Name())
				}
			}
		}
	}
}
