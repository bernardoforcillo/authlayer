package dropsstore

import (
	"errors"
	"strings"

	"github.com/bernardoforcillo/drops"
	"github.com/bernardoforcillo/drops/pg"
	"github.com/jackc/pgx/v5/pgconn"
)

// Helpers shared by every store in this package: error classification and
// identifier quoting. They live here, not in whichever store happened to need
// them first.

// mapNoRows converts drops' ErrNoRows into a domain not-found sentinel.
func mapNoRows(err, notFound error) error {
	if errors.Is(err, pg.ErrNoRows) {
		return notFound
	}
	return err
}

// affectedOrErr returns notFound when the statement matched no rows, else the
// original error (or nil on success).
func affectedOrErr(res drops.Result, err, notFound error) error {
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return notFound
	}
	return nil
}

// isPrimaryKeyViolation reports whether a unique-violation error was
// PostgreSQL's own primary-key constraint colliding, by reading the
// constraint name straight off the driver's own *pgconn.PgError —
// PostgreSQL auto-names a single-column inline PRIMARY KEY "<table>_pkey"
// (see [AuthSchema]'s doc on how id is declared), so that suffix reliably
// distinguishes an id collision from every other UNIQUE constraint the
// same table might carry.
//
// This reads *pgconn.PgError directly rather than drops' own
// pg.PgError.Constraint or a follow-up database read, for two reasons
// found the hard way against this store's live integration suite:
//
//   - pg.PgError.Constraint is documented as populated "when the driver
//     reports it", but jackc/pgx/v5's pgconn.PgError carries ConstraintName
//     as a plain struct FIELD, not the ConstraintName() string METHOD
//     drops' own classifyError looks for via
//     errors.As(err, &interface{ ConstraintName() string }). That
//     interface therefore never matches a real pgx error, so
//     pg.PgError.Constraint is silently "" on every genuine conflict.
//     Reaching past drops' wrapper to *pgconn.PgError directly — already in
//     the module graph via the pgx dependency this codebase already
//     requires, so this needs no go.mod change — sidesteps that gap. The
//     tradeoff is a direct dependency on pgx's concrete error type in a
//     file that otherwise only depends on drops' own abstractions; that
//     coupling is deliberate and confined to this one function.
//   - An earlier version of this function instead re-queried the table
//     ("does a row with this id exist") as a read-only follow-up after the
//     INSERT failed — safe when composed on its own, but broken when the
//     caller's INSERT runs inside its own transaction (e.g. via
//     [pg.DB.InTx]): a failed statement aborts a PostgreSQL transaction
//     immediately, so ANY further statement on that same transaction —
//     including a plain read-only SELECT — fails with SQLSTATE 25P02
//     ("current transaction is aborted"), not the row-existence answer the
//     classifier needed. Proven live: a duplicate-email CreateUser inside
//     InTx returned neither ErrEmailTaken, ErrIDTaken, nor even the
//     original pg.ErrUniqueViolation — just the 25P02 from the doomed
//     follow-up read. See TestCreateUserDuplicateEmailInsideTxReturnsErrEmailTakenLive.
//     Reading the already-in-hand error's own constraint name needs no
//     further statement at all, so it works identically whether the
//     caller composed the INSERT into a transaction or not.
func isPrimaryKeyViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && strings.HasSuffix(pgErr.ConstraintName, "_pkey")
}

func quoteIdent(s string) string { return `"` + strings.ReplaceAll(s, `"`, `""`) + `"` }
