package dropsstore

import (
	"context"
	"time"

	"github.com/bernardoforcillo/drops"
	"github.com/bernardoforcillo/drops/pg"

	"github.com/bernardoforcillo/authlayer/consent"
)

// ConsentStore is a drops-backed consent.Store over one table:
//
//	<consent_records>  id PK, subject_id, purpose, version, source,
//	                   granted_at, ended_at, end_reason,
//	                   UNIQUE (subject_id, purpose) WHERE ended_at IS NULL
//
// The partial unique index is what makes a second concurrent grant a
// consent.ErrConflict instead of two current records.
type ConsentStore struct {
	db  *pg.DB
	tbl string
	raw string
}

// Compile-time proof the drops consent store satisfies the port.
var _ consent.Store = (*ConsentStore)(nil)

// NewConsentStore returns a ConsentStore over db. table defaults to
// "consent_records" when empty.
func NewConsentStore(db *pg.DB, table string) *ConsentStore {
	if table == "" {
		table = "consent_records"
	}
	return &ConsentStore{db: db, tbl: quoteIdent(table), raw: table}
}

// ConsentDDL returns the statements creating the table and its index.
func ConsentDDL(table string) []string {
	if table == "" {
		table = "consent_records"
	}
	t := quoteIdent(table)
	return []string{
		`CREATE TABLE IF NOT EXISTS ` + t + ` (
  id text PRIMARY KEY,
  subject_id text NOT NULL,
  purpose text NOT NULL,
  version text NOT NULL,
  source text NOT NULL DEFAULT '',
  granted_at timestamptz NOT NULL,
  ended_at timestamptz,
  end_reason text NOT NULL DEFAULT ''
)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS ` + quoteIdent(table+"_current") + ` ON ` + t + ` (subject_id, purpose) WHERE ended_at IS NULL`,
		`CREATE INDEX IF NOT EXISTS ` + quoteIdent(table+"_subject") + ` ON ` + t + ` (subject_id, granted_at)`,
	}
}

// CreateSchema runs [ConsentDDL]; idempotent.
func (st *ConsentStore) CreateSchema(ctx context.Context) error {
	for _, stmt := range ConsentDDL(st.raw) {
		if _, err := st.db.Exec(ctx, stmt); err != nil {
			return err
		}
	}
	return nil
}

// DropSchema drops the table.
func (st *ConsentStore) DropSchema(ctx context.Context) error {
	_, err := st.db.Exec(ctx, `DROP TABLE IF EXISTS `+st.tbl)
	return err
}

const consentCols = `id, subject_id, purpose, version, source, granted_at, ended_at, end_reason`

// Insert stores r; a second current record is consent.ErrConflict.
func (st *ConsentStore) Insert(ctx context.Context, r consent.Record) error {
	_, err := st.db.Exec(ctx, `INSERT INTO `+st.tbl+` (`+consentCols+`) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		r.ID, r.SubjectID, r.Purpose, r.Version, r.Source, r.GrantedAt.UTC(), utcPtr(r.EndedAt), r.EndReason)
	if pgCode(err) == "23505" {
		return consent.ErrConflict
	}
	return err
}

func scanConsent(rows drops.Rows) (consent.Record, error) {
	var r consent.Record
	var ended *time.Time
	if err := rows.Scan(&r.ID, &r.SubjectID, &r.Purpose, &r.Version, &r.Source, &r.GrantedAt, &ended, &r.EndReason); err != nil {
		return consent.Record{}, err
	}
	r.GrantedAt, r.EndedAt = r.GrantedAt.UTC(), utcPtr(ended)
	return r, nil
}

func (st *ConsentStore) query(ctx context.Context, sql string, args ...any) ([]consent.Record, error) {
	rows, err := st.db.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []consent.Record
	for rows.Next() {
		r, err := scanConsent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// Current returns the subject's record for purpose that has not ended.
func (st *ConsentStore) Current(ctx context.Context, subjectID, purpose string) (consent.Record, error) {
	rs, err := st.query(ctx, `SELECT `+consentCols+` FROM `+st.tbl+
		` WHERE subject_id = $1 AND purpose = $2 AND ended_at IS NULL`, subjectID, purpose)
	if err != nil {
		return consent.Record{}, err
	}
	if len(rs) == 0 {
		return consent.Record{}, consent.ErrNotFound
	}
	return rs[0], nil
}

// End stamps the subject's current record for purpose.
func (st *ConsentStore) End(ctx context.Context, subjectID, purpose string, at time.Time, reason string) (int, error) {
	res, err := st.db.Exec(ctx, `UPDATE `+st.tbl+` SET ended_at = $3, end_reason = $4
WHERE subject_id = $1 AND purpose = $2 AND ended_at IS NULL`, subjectID, purpose, at.UTC(), reason)
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	return int(n), err
}

// List returns the subject's records, oldest first.
func (st *ConsentStore) List(ctx context.Context, subjectID string) ([]consent.Record, error) {
	return st.query(ctx, `SELECT `+consentCols+` FROM `+st.tbl+` WHERE subject_id = $1 ORDER BY granted_at, id`, subjectID)
}

// DeleteSubject deletes every record of the subject.
func (st *ConsentStore) DeleteSubject(ctx context.Context, subjectID string) (int, error) {
	res, err := st.db.Exec(ctx, `DELETE FROM `+st.tbl+` WHERE subject_id = $1`, subjectID)
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	return int(n), err
}
