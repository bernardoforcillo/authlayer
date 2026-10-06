//go:build integration

// Live tests for the audit store against a real PostgreSQL. Run with:
//
//	AUTHLAYER_TEST_DSN='postgres://user:pass@localhost:5432/db?sslmode=disable' \
//	    go test -tags integration ./store/drops/ -run Audit
package dropsstore_test

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/bernardoforcillo/drops/pg"
	"github.com/bernardoforcillo/drops/stdlib"
	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/bernardoforcillo/authlayer/audit"
	"github.com/bernardoforcillo/authlayer/audit/audittest"
	"github.com/bernardoforcillo/authlayer/core"
	dropsstore "github.com/bernardoforcillo/authlayer/store/drops"
)

func newLiveAuditStore(t *testing.T) (*dropsstore.AuditStore, *pg.DB) {
	t.Helper()
	dsn := os.Getenv("AUTHLAYER_TEST_DSN")
	if dsn == "" {
		t.Skip("set AUTHLAYER_TEST_DSN to run the drops audit store integration test")
	}
	sqlDB, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })
	db := pg.New(stdlib.New(sqlDB))
	st := dropsstore.NewAuditStore(db)
	ctx := context.Background()
	if err := st.DropSchema(ctx); err != nil {
		t.Fatalf("DropSchema: %v", err)
	}
	if err := st.CreateSchema(ctx); err != nil {
		t.Fatalf("CreateSchema: %v", err)
	}
	if err := st.CreateSchema(ctx); err != nil {
		t.Fatalf("CreateSchema is not idempotent: %v", err)
	}
	t.Cleanup(func() { _ = st.DropSchema(context.Background()) })
	return st, db
}

func TestAuditStoreSatisfiesTheStoreContractLive(t *testing.T) {
	audittest.RunStoreContract(t, func(t *testing.T) audit.Store {
		st, _ := newLiveAuditStore(t)
		return st
	})
}

func wantCode(t *testing.T, err error, code string) {
	t.Helper()
	var pe interface{ SQLState() string }
	if !errors.As(err, &pe) || pe.SQLState() != code {
		t.Fatalf("err = %v; want SQLSTATE %s", err, code)
	}
}

func TestAuditGuardsRefuseRewrites(t *testing.T) {
	st, db := newLiveAuditStore(t)
	ctx := context.Background()
	clock := time.Date(2026, 1, 10, 9, 0, 0, 0, time.UTC)
	svc := audit.New(st, audit.WithRuntime(core.Runtime{Clock: func() time.Time { return clock }}),
		audit.WithTopics(audit.Topic{Key: "t", Retention: 24 * time.Hour}))
	e, err := svc.Record(ctx, audit.Event{Topic: "t", Action: "a.b", Origin: "x", Outcome: audit.OutcomeOK,
		Actor: audit.Actor{Type: audit.ActorUser, ID: "u"}})
	if err != nil {
		t.Fatal(err)
	}

	// AU001: a completed event cannot change, nor a completed one be reopened.
	_, err = db.Exec(ctx, `UPDATE audit_events SET action = 'x.y' WHERE id = $1`, e.ID)
	wantCode(t, err, dropsstore.AuditEventImmutable)
	_, err = db.Exec(ctx, `UPDATE audit_events SET completed_at = NULL, outcome = '' WHERE id = $1`, e.ID)
	wantCode(t, err, dropsstore.AuditEventImmutable)

	// An open event may only be completed, not edited while open.
	open, err := svc.Begin(ctx, audit.Event{Topic: "t", Action: "a.c", Origin: "x",
		Actor: audit.Actor{Type: audit.ActorUser, ID: "u"}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(ctx, `UPDATE audit_events SET actor_id = 'someone-else' WHERE id = $1`, open.ID)
	wantCode(t, err, dropsstore.AuditEventImmutable)
	if err := svc.Complete(ctx, open.ID, audit.Completion{Outcome: audit.OutcomeFailed, Code: "boom"}); err != nil {
		t.Fatalf("Complete: %v", err)
	}

	clock = clock.Add(48 * time.Hour)
	sealed, err := svc.Seal(ctx, clock)
	if err != nil || len(sealed) == 0 {
		t.Fatalf("Seal = %v, %v", sealed, err)
	}

	// AU002: a sealed day's events outlive a plain DELETE or TRUNCATE.
	_, err = db.Exec(ctx, `DELETE FROM audit_events WHERE id = $1`, e.ID)
	wantCode(t, err, dropsstore.AuditEventProtected)
	_, err = db.Exec(ctx, `TRUNCATE audit_events`)
	wantCode(t, err, dropsstore.AuditEventProtected)

	// AU003: seals can only be marked purged, once.
	_, err = db.Exec(ctx, `UPDATE audit_seals SET events_hash = 'forged'`)
	wantCode(t, err, dropsstore.AuditSealImmutable)
	_, err = db.Exec(ctx, `DELETE FROM audit_seals`)
	wantCode(t, err, dropsstore.AuditSealImmutable)
	_, err = db.Exec(ctx, `TRUNCATE audit_seals`)
	wantCode(t, err, dropsstore.AuditSealImmutable)

	// AU004 surfaces as ErrSealed.
	clock = e.OccurredAt
	if _, err := svc.Record(ctx, audit.Event{Topic: "t", Action: "a.d", Origin: "x", Outcome: audit.OutcomeOK,
		Actor: audit.Actor{Type: audit.ActorUser, ID: "u"}}); !errors.Is(err, audit.ErrSealed) {
		t.Fatalf("Record into a sealed day err = %v; want ErrSealed", err)
	}

	// Verify is clean, retention purges through the guard, and Verify stays clean.
	clock = clock.Add(72 * time.Hour)
	checkVerify := func(want audit.DayState) {
		t.Helper()
		sts, err := svc.Verify(ctx, nil, e.OccurredAt, e.OccurredAt)
		if err != nil || len(sts) != 1 || sts[0].State != want {
			t.Fatalf("Verify = %+v, %v; want %s", sts, err, want)
		}
	}
	checkVerify(audit.DayOK)
	deleted, err := svc.ApplyRetention(ctx)
	if err != nil || deleted["t"] != 2 {
		t.Fatalf("ApplyRetention = %v, %v; want 2 deleted", deleted, err)
	}
	checkVerify(audit.DayPurged)
}

func TestAuditStoreTextIDs(t *testing.T) {
	_, db := newLiveAuditStore(t)
	ctx := context.Background()
	st := dropsstore.NewAuditStore(db, dropsstore.WithAuditNames(dropsstore.AuditNames{Events: "ae_text", Seals: "as_text"}),
		dropsstore.WithAuditTextIDs())
	_ = st.DropSchema(ctx)
	if err := st.CreateSchema(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.DropSchema(context.Background()) })
	svc := audit.New(st, audit.WithRuntime(core.Runtime{IDs: func() string { return "evt-1" }}),
		audit.WithTopics(audit.Topic{Key: "t"}))
	e, err := svc.Record(ctx, audit.Event{Topic: "t", Action: "a.b", Origin: "x", Outcome: audit.OutcomeOK,
		Actor: audit.Actor{Type: audit.ActorSystem}})
	if err != nil || e.ID != "evt-1" {
		t.Fatalf("Record = %+v, %v", e, err)
	}
}
