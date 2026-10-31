package dropsstore

import (
	"context"
	"slices"

	"github.com/bernardoforcillo/drops"
	"github.com/bernardoforcillo/drops/pg"
)

// MigrationBranch is the branch every authlayer migration lives on in a
// [pg.TreeMigrator], so a deployment's own migrations stay on theirs.
const MigrationBranch = "authlayer"

// MigrationSource is a store that can describe its schema as TreeMigrator
// nodes. Every constructor in this package returns one.
type MigrationSource interface {
	Migrations() []pg.TreeMigration
}

// AddMigrations registers the migrations of every source on m. Pass the stores
// the application actually uses; a store you do not construct contributes
// nothing. It panics on a duplicate ID, which means two stores were configured
// with the same table names.
//
//	m := pg.NewTreeMigrator(db)
//	dropsstore.AddMigrations(m, authStore, rbacStore, oauthStore)
//	if err := m.Up(ctx); err != nil { ... }
//
// # What the migrations are
//
// Each store contributes a chain on the "authlayer" branch, one node per step:
//
//	authlayer-<first table>-001_tables    tables, composite constraints and
//	                                      the indexes of the 0.3.1 baseline
//	authlayer-<first table>-002_indexes   indexes added since (omitted when
//	                                      a store has none)
//
// IDs embed the store's first table name, so two instances of one store type
// under [WithNames] (organizations and teams) do not collide, and every name
// follows the options the store was built with. The audit and consent stores
// contribute a single -001 step that replays their DDL.
//
// Every Up is idempotent, so adopting the migrator on a database that
// [Store.CreateSchema] already populated applies cleanly and only creates what
// is missing. The table steps have no Down: dropping a table is data loss, and
// is the application's decision. The index steps do, and drop exactly the
// indexes they created.
//
// The Up functions are Go, not SQL text, so the migrator's tamper check does
// not cover them; the statements are generated from the same schema definitions
// [Store.CreateSchema] uses, which is what keeps the two paths from drifting.
func AddMigrations(m *pg.TreeMigrator, sources ...MigrationSource) {
	for _, s := range sources {
		for _, mig := range s.Migrations() {
			m.Add(mig)
		}
	}
}

type tableSpec struct {
	t  *pg.Table
	cs *colSet
}

// tableMigrations builds the two-step chain for one store's tables, in
// dependency order.
func tableMigrations(specs ...tableSpec) []pg.TreeMigration {
	base := "authlayer-" + specs[0].t.Name()
	tables := pg.TreeMigration{
		ID:          base + "-001_tables",
		Name:        "tables of " + specs[0].t.Name(),
		Branch:      MigrationBranch,
		Description: "tables, composite constraints and baseline indexes",
		Up: func(ctx context.Context, db *pg.DB) error {
			for _, sp := range specs {
				late := map[string]bool{}
				for _, i := range sp.cs.late {
					late[i.Name()] = true
				}
				if _, err := db.ExecExpr(ctx, pg.CreateTableIfNotExists(sp.t)); err != nil {
					return err
				}
				for _, ddl := range compositeConstraintDDL(sp.t) {
					if _, err := db.ExecExpr(ctx, ddl); err != nil {
						return err
					}
				}
				for _, idx := range sp.t.Indexes() {
					if late[idx.Name()] {
						continue
					}
					if _, err := db.ExecExpr(ctx, pg.CreateIndexIfNotExists(idx)); err != nil {
						return err
					}
				}
			}
			return nil
		},
	}
	out := []pg.TreeMigration{tables}

	var late []*pg.Index
	for _, sp := range specs {
		late = append(late, sp.cs.late...)
	}
	if len(late) == 0 {
		return out
	}
	return append(out, pg.TreeMigration{
		ID:          base + "-002_indexes",
		Name:        "indexes of " + specs[0].t.Name(),
		Branch:      MigrationBranch,
		Parents:     []string{tables.ID},
		Description: "lookup and purge indexes added after 0.3.1",
		Up: func(ctx context.Context, db *pg.DB) error {
			for _, idx := range late {
				if _, err := db.ExecExpr(ctx, pg.CreateIndexIfNotExists(idx)); err != nil {
					return err
				}
			}
			return nil
		},
		Down: func(ctx context.Context, db *pg.DB) error {
			for _, idx := range slices.Backward(late) {

				if _, err := db.ExecExpr(ctx, drops.ExprFunc(func(b *drops.Builder) {
					b.WriteString("DROP INDEX IF EXISTS ")
					b.WriteQualified(idx.Table().Schema(), idx.Name())
				})); err != nil {
					return err
				}
			}
			return nil
		},
	})
}

// rawMigration is the single-step chain for the stores whose DDL is SQL text.
func rawMigration(id, name string, up func(ctx context.Context, db *pg.DB) error) []pg.TreeMigration {
	return []pg.TreeMigration{{
		ID: id, Name: name, Branch: MigrationBranch,
		Description: "replays the store's idempotent DDL",
		Up:          up,
	}}
}

// Migrations implements [MigrationSource].
func (st *Store[C, M]) Migrations() []pg.TreeMigration {
	return tableMigrations(
		tableSpec{st.s.Containers, st.s.containers},
		tableSpec{st.s.Members, st.s.members},
		tableSpec{st.s.Roles, st.s.roles})
}

// Migrations implements [MigrationSource].
func (st *AuthStore) Migrations() []pg.TreeMigration {
	return tableMigrations(
		tableSpec{st.s.Users, st.s.users},
		tableSpec{st.s.Sessions, st.s.sessions},
		tableSpec{st.s.Verifications, st.s.verifications})
}

// Migrations implements [MigrationSource].
func (st *InviteStore) Migrations() []pg.TreeMigration {
	return tableMigrations(
		tableSpec{st.s.EmailInvites, st.s.emailInvites},
		tableSpec{st.s.Links, st.s.links})
}

// Migrations implements [MigrationSource].
func (st *APIKeyStore) Migrations() []pg.TreeMigration {
	return tableMigrations(
		tableSpec{st.s.ServiceAccounts, st.s.accounts},
		tableSpec{st.s.Keys, st.s.keys})
}

// Migrations implements [MigrationSource].
func (st *IdentityStore) Migrations() []pg.TreeMigration {
	return tableMigrations(tableSpec{st.s.Identities, st.s.identities})
}

// Migrations implements [MigrationSource].
func (st *CredentialStore) Migrations() []pg.TreeMigration {
	return tableMigrations(
		tableSpec{st.s.Credentials, st.s.credentials},
		tableSpec{st.s.Challenges, st.s.challenges})
}

// Migrations implements [MigrationSource].
func (st *MFAStore) Migrations() []pg.TreeMigration {
	return tableMigrations(
		tableSpec{st.s.Factors, st.s.factors},
		tableSpec{st.s.RecoveryCodes, st.s.codes},
		tableSpec{st.s.TrustedDevices, st.s.devices})
}

// Migrations implements [MigrationSource].
func (st *OAuthStore) Migrations() []pg.TreeMigration {
	return tableMigrations(
		tableSpec{st.s.Clients, st.s.clients},
		tableSpec{st.s.Grants, st.s.grants},
		tableSpec{st.s.Codes, st.s.codes},
		tableSpec{st.s.DeviceAuthorizations, st.s.devices},
		tableSpec{st.s.RefreshTokens, st.s.refresh})
}

// Migrations implements [MigrationSource]. The step replays [AuditDDL], which
// also replaces the guard functions and triggers in place so they match this
// version, exactly as [AuditStore.CreateSchema] does.
func (st *AuditStore) Migrations() []pg.TreeMigration {
	cfg := st.cfg
	return rawMigration("authlayer-"+cfg.names.Events+"-001_tables", "audit tables and guards",
		func(ctx context.Context, db *pg.DB) error { return applyAuditDDL(ctx, db, cfg) })
}

// Migrations implements [MigrationSource].
func (st *AuditKeyStore) Migrations() []pg.TreeMigration {
	cfg := st.cfg
	return rawMigration("authlayer-"+cfg.names.Keys+"-001_tables", "audit subject keys",
		func(ctx context.Context, db *pg.DB) error {
			for _, stmt := range auditKeyDDL(cfg) {
				if _, err := db.Exec(ctx, stmt); err != nil {
					return err
				}
			}
			return nil
		})
}

// Migrations implements [MigrationSource].
func (st *ConsentStore) Migrations() []pg.TreeMigration {
	raw := st.raw
	return rawMigration("authlayer-"+raw+"-001_tables", "consent records",
		func(ctx context.Context, db *pg.DB) error {
			for _, stmt := range ConsentDDL(raw) {
				if _, err := db.Exec(ctx, stmt); err != nil {
					return err
				}
			}
			return nil
		})
}
