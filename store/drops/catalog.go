package dropsstore

import (
	"github.com/bernardoforcillo/drops/pg"

	"github.com/bernardoforcillo/authlayer/scope"
)

// Tables returns every table this package models as a [pg.Table], store by
// store, each store's tables in creation order (a referenced table before the
// tables that reference it). It is the formal definition of the data model:
// the same *pg.Table values the stores query and CreateSchema creates, built
// with opts so a deployment's own names and id types are reflected.
//
// The scope tables carry only the engine's base columns
// ([scope.ContainerBase], [scope.MemberBase]); a custom scope adds its own
// fields to them. The audit and consent tables are declared in raw_tables.go;
// the audit guard functions and triggers are SQL text, not tables, and are
// reachable only through [AuditDDL].
func Tables(opts ...Option) []*pg.Table {
	var out []*pg.Table
	sc := NewSchema[scope.ContainerBase, scope.MemberBase](opts...)
	out = append(out, sc.Containers, sc.Members, sc.Roles)
	au := NewAuthSchema(opts...)
	out = append(out, au.Users, au.Sessions, au.Verifications)
	in := NewInviteSchema(opts...)
	out = append(out, in.EmailInvites, in.Links)
	ak := NewAPIKeySchema(opts...)
	out = append(out, ak.ServiceAccounts, ak.Keys)
	id := NewIdentitySchema(opts...)
	out = append(out, id.Identities)
	cr := NewCredentialSchema(opts...)
	out = append(out, cr.Credentials, cr.Challenges)
	mf := NewMFASchema(opts...)
	out = append(out, mf.Factors, mf.RecoveryCodes, mf.TrustedDevices)
	oa := NewOAuthSchema(opts...)
	out = append(out, oa.tables()...)
	au2 := NewAuditSchema(opts...)
	out = append(out, au2.Events, au2.Seals, au2.Keys)
	out = append(out, NewConsentSchema("").Records)
	return out
}

// TableSchema wraps [Tables] in a [pg.Schema], the input drops' snapshot and
// diff tooling takes.
func TableSchema(opts ...Option) *pg.Schema { return pg.NewSchema(Tables(opts...)...) }

// SnapshotSchema returns the drops snapshot of [Tables]: every column with its
// SQL type and nullability, primary and unique keys, foreign keys and indexes,
// as a serializable value. Its ID is fixed, so two snapshots of the same model
// marshal to the same bytes; diff one release's snapshot against the next to
// see exactly what a migration has to change.
func SnapshotSchema(opts ...Option) *pg.Snapshot {
	s := pg.BuildSnapshot(TableSchema(opts...))
	s.ID = "authlayer"
	return s
}
