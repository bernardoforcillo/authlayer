//go:build integration

package dropsstore_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/bernardoforcillo/drops/pg"
	"github.com/bernardoforcillo/drops/stdlib"

	"github.com/bernardoforcillo/authlayer/internal/uid"
	"github.com/bernardoforcillo/authlayer/org"
	dropsstore "github.com/bernardoforcillo/authlayer/store/drops"
)

// TestMembersUserIDIndexIsUsedLive proves the index added for
// ListUserStandings and ListUserContainers: the members primary key leads with
// container_id, so without organization_members_user_id_idx a lookup by user
// alone seq-scans every membership of every tenant. The control drops the
// index and requires the seq scan to come back, so the first assertion is
// known to measure the index.
func TestMembersUserIDIndexIsUsedLive(t *testing.T) {
	sqlDB, _ := openLiveDB(t)
	rec := &identityQueryRecorder{Driver: stdlib.New(sqlDB)}
	db := pg.New(rec)
	st := dropsstore.New[org.Organization, org.Member](db)
	ctx := context.Background()

	drop := func() {
		for _, tbl := range []*pg.Table{st.Schema().Members, st.Schema().Roles, st.Schema().Containers} {
			if _, err := db.ExecExpr(ctx, pg.DropTableIfExists(tbl)); err != nil {
				t.Fatalf("drop %s: %v", tbl.Name(), err)
			}
		}
	}
	drop()
	if err := st.CreateSchema(ctx); err != nil {
		t.Fatalf("CreateSchema: %v", err)
	}
	t.Cleanup(drop)

	table := st.Schema().Members.Name()
	// 2000 distinct users, one membership each: a user matches a single row,
	// so an index scan is the cheaper plan.
	if _, err := sqlDB.ExecContext(ctx, `INSERT INTO `+table+` (container_id, user_id, role_key, joined_at)
		SELECT gen_random_uuid(), u.id, 'member', now()
		FROM (SELECT gen_random_uuid() AS id FROM generate_series(1, 2000)) u,
		     generate_series(1, 1)`); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := sqlDB.ExecContext(ctx, `ANALYZE `+table); err != nil {
		t.Fatalf("ANALYZE: %v", err)
	}
	var probe string
	if err := sqlDB.QueryRowContext(ctx, `SELECT user_id::text FROM `+table+` LIMIT 1`).Scan(&probe); err != nil {
		t.Fatalf("probe: %v", err)
	}

	if _, err := st.ListUserStandings(ctx, uid.NewV7()); err != nil {
		t.Fatalf("ListUserStandings: %v", err)
	}
	stmt := rec.last()
	if !strings.Contains(stmt, "user_id") {
		t.Fatalf("recorded statement is not the query under test: %q", stmt)
	}

	idx := table + "_user_id_idx"
	with := explain(t, sqlDB, stmt, probe)
	if !strings.Contains(with, idx) || strings.Contains(with, "Seq Scan on "+table) {
		t.Fatalf("planner did not use %s. Plan:\n%s", idx, with)
	}
	if _, err := sqlDB.ExecContext(ctx, "DROP INDEX "+idx); err != nil {
		t.Fatalf("DROP INDEX: %v", err)
	}
	without := explain(t, sqlDB, stmt, probe)
	if !strings.Contains(without, "Seq Scan on "+table) {
		t.Fatalf("control failed: no seq scan without the index. Plan:\n%s", without)
	}

	// CreateSchema alone brings the index to a table that already exists.
	if err := st.CreateSchema(ctx); err != nil {
		t.Fatalf("CreateSchema (self-heal): %v", err)
	}
	var n int
	if err := sqlDB.QueryRowContext(ctx,
		`SELECT count(*) FROM pg_indexes WHERE tablename = $1 AND indexname = $2`, table, idx).Scan(&n); err != nil || n != 1 {
		t.Fatalf("index %s not restored by CreateSchema: n=%d err=%v", idx, n, err)
	}
}

// TestPurgeExpiredRemovesMoreThanOneBatchLive seeds more expired rows than one
// purge batch holds and requires PurgeExpired to loop until every one is gone,
// while leaving unexpired rows alone.
func TestPurgeExpiredRemovesMoreThanOneBatchLive(t *testing.T) {
	st := newLiveAuthStore(t)
	sqlDB, _ := openLiveDB(t)
	ctx := context.Background()
	sess := st.Schema().Sessions.Name()

	const expired, live = 12_345, 50
	insert := func(n int, expiresAt string) {
		t.Helper()
		if _, err := sqlDB.ExecContext(ctx, `INSERT INTO `+sess+`
			(id, user_id, token_hash, family_id, expires_at, created_at, user_agent, ip)
			SELECT gen_random_uuid(), gen_random_uuid(), md5(random()::text || g::text), gen_random_uuid(),
			       `+expiresAt+`, now(), '', ''
			FROM generate_series(1, $1) g`, n); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	insert(expired, `now() - interval '2 days'`)
	insert(live, `now() + interval '2 days'`)

	n, err := st.PurgeExpired(ctx, time.Now().UTC())
	if err != nil {
		t.Fatalf("PurgeExpired: %v", err)
	}
	if n != expired {
		t.Fatalf("PurgeExpired removed %d rows, want %d", n, expired)
	}
	var left int
	if err := sqlDB.QueryRowContext(ctx, `SELECT count(*) FROM `+sess).Scan(&left); err != nil || left != live {
		t.Fatalf("rows left = %d (err %v), want the %d unexpired", left, err, live)
	}
}
