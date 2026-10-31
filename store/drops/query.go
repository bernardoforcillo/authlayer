package dropsstore

import (
	"context"

	"github.com/bernardoforcillo/drops"
	"github.com/bernardoforcillo/drops/pg"
)

// The four statements nearly every store method reduces to. Each takes the
// *pg.DB explicitly, so the same helper serves a store's own connection and
// the transaction handle inside InTx. The store keeps writing the statements
// that carry meaning — the conditional UPDATEs, the locking SELECTs, the
// multi-step transactions — by hand.

// findOne returns the single row of t matching preds, or notFound when there
// is none.
func findOne[T any](ctx context.Context, db *pg.DB, t *pg.Table, notFound error, preds ...drops.Expression) (T, error) {
	var v T
	if err := db.Select().From(t).Where(preds...).One(ctx, &v); err != nil {
		var zero T
		return zero, mapNoRows(err, notFound)
	}
	return v, nil
}

// listWhere returns every row of t matching preds. No rows is a nil slice, not
// an error.
func listWhere[T any](ctx context.Context, db *pg.DB, t *pg.Table, preds ...drops.Expression) ([]T, error) {
	var out []T
	if err := db.Select().From(t).Where(preds...).All(ctx, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// updateOne applies set to the rows of t matching preds and reports notFound
// when none matched.
func updateOne(ctx context.Context, db *pg.DB, t *pg.Table, notFound error, set []pg.ColumnValue, preds ...drops.Expression) error {
	res, err := db.Update(t).Set(set...).Where(preds...).Exec(ctx)
	return affectedOrErr(res, err, notFound)
}

// deleteOne deletes the rows of t matching preds and reports notFound when
// none matched.
func deleteOne(ctx context.Context, db *pg.DB, t *pg.Table, notFound error, preds ...drops.Expression) error {
	res, err := db.Delete(t).Where(preds...).Exec(ctx)
	return affectedOrErr(res, err, notFound)
}
