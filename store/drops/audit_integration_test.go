//go:build integration

// Live tests for the audit store against a real PostgreSQL. Run with:
//
//	AUTHLAYER_TEST_DSN='postgres://user:pass@localhost:5432/db?sslmode=disable' \
//	    go test -tags integration ./store/drops/ -run Audit
package dropsstore_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/bernardoforcillo/drops/pg"
	"github.com/bernardoforcillo/drops/stdlib"
	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/bernardoforcillo/authlayer/audit"
	"github.com/bernardoforcillo/authlayer/audit/audittest"
	"github.com/bernardoforcillo/authlayer/consent"
	"github.com/bernardoforcillo/authlayer/consent/consenttest"
	"github.com/bernardoforcillo/authlayer/core"
	"github.com/bernardoforcillo/authlayer/internal/uid"
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
		dropsstore.WithAuditTextLibraryIDs())
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

func TestAuditGuardAllowsOnlyClearingClientData(t *testing.T) {
	st, db := newLiveAuditStore(t)
	ctx := context.Background()
	clock := time.Date(2026, 1, 10, 9, 0, 0, 0, time.UTC)
	svc := audit.New(st, audit.WithRuntime(core.Runtime{Clock: func() time.Time { return clock }}),
		audit.WithTopics(audit.Topic{Key: "t", ClientDataRetention: time.Hour}))
	e, err := svc.Record(ctx, audit.Event{Topic: "t", Action: "a.b", Origin: "x", Outcome: audit.OutcomeOK,
		Actor: audit.Actor{Type: audit.ActorUser, ID: "u"}, IP: "203.0.113.7", UserAgent: "ua"})
	if err != nil {
		t.Fatal(err)
	}
	// A rewrite that also touches anything else is refused, even with the client data cleared.
	_, err = db.Exec(ctx, `UPDATE audit_events SET ip = '', user_agent = '', action = 'x.y' WHERE id = $1`, e.ID)
	wantCode(t, err, dropsstore.AuditEventImmutable)
	_, err = db.Exec(ctx, `UPDATE audit_events SET ip = '9.9.9.9' WHERE id = $1`, e.ID)
	wantCode(t, err, dropsstore.AuditEventImmutable)

	clock = clock.Add(48 * time.Hour)
	if _, err := svc.Seal(ctx, clock); err != nil {
		t.Fatal(err)
	}
	cleared, err := svc.ScrubClientData(ctx)
	if err != nil || cleared["t"] != 1 {
		t.Fatalf("ScrubClientData = %v, %v", cleared, err)
	}
	if got, _ := svc.Get(ctx, e.ID); got.IP != "" || got.UserAgent != "" || got.Action != "a.b" {
		t.Fatalf("event after scrub = %+v", got)
	}
	if sts, err := svc.Verify(ctx, nil, e.OccurredAt, e.OccurredAt); err != nil || sts[0].State != audit.DayOK {
		t.Fatalf("Verify after scrub = %+v, %v", sts, err)
	}
}

func TestAuditKeyStoreSatisfiesTheKeyContractLive(t *testing.T) {
	_, db := newLiveAuditStore(t)
	audittest.RunKeyStoreContract(t, func(t *testing.T) audit.KeyStore {
		ks := dropsstore.NewAuditKeyStore(db)
		_ = ks.DropSchema(context.Background())
		if err := ks.CreateSchema(context.Background()); err != nil {
			t.Fatalf("CreateSchema: %v", err)
		}
		t.Cleanup(func() { _ = ks.DropSchema(context.Background()) })
		return ks
	})
}

func TestAuditForgetErasesAPersonEndToEndLive(t *testing.T) {
	st, db := newLiveAuditStore(t)
	ks := dropsstore.NewAuditKeyStore(db)
	ctx := context.Background()
	_ = ks.DropSchema(ctx)
	if err := ks.CreateSchema(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ks.DropSchema(context.Background()) })
	clock := time.Date(2026, 1, 10, 9, 0, 0, 0, time.UTC)
	svc := audit.New(st, audit.WithSubjectKeys(ks),
		audit.WithRuntime(core.Runtime{Clock: func() time.Time { return clock }}),
		audit.WithTopics(audit.Topic{Key: "t"}))
	if _, err := svc.Record(ctx, audit.Event{Topic: "t", Action: "a.b", Origin: "x", Outcome: audit.OutcomeOK,
		Actor: audit.Actor{Type: audit.ActorUser, ID: "alice", Display: "alice@example.com"}}); err != nil {
		t.Fatal(err)
	}
	rows, err := db.Query(ctx, `SELECT actor_id, actor_display FROM audit_events`)
	if err != nil {
		t.Fatal(err)
	}
	var id, display string
	if !rows.Next() || rows.Scan(&id, &display) != nil {
		t.Fatal("no row")
	}
	_ = rows.Close()
	if id == "alice" || display != "" {
		t.Fatalf("stored actor = %q / %q; want a pseudonym and no display", id, display)
	}
	if got, _, _ := svc.List(ctx, audit.Filter{Member: "alice"}, audit.Page{}); len(got) != 1 {
		t.Fatalf("alice's trail = %d events, want 1", len(got))
	}
	if err := svc.Forget(ctx, "alice"); err != nil {
		t.Fatal(err)
	}
	if got, _, _ := svc.List(ctx, audit.Filter{Member: "alice"}, audit.Page{}); len(got) != 0 {
		t.Fatalf("alice's trail after Forget = %d events, want 0", len(got))
	}
	clock = clock.Add(48 * time.Hour)
	if _, err := svc.Seal(ctx, clock); err != nil {
		t.Fatal(err)
	}
	if sts, err := svc.Verify(ctx, nil, clock.Add(-48*time.Hour), clock.Add(-48*time.Hour)); err != nil || sts[0].State != audit.DayOK {
		t.Fatalf("Verify = %+v, %v", sts, err)
	}
}

func TestConsentStoreSatisfiesTheContractLive(t *testing.T) {
	_, db := newLiveAuditStore(t)
	consenttest.RunStoreContract(t, func(t *testing.T) consent.Store {
		st := dropsstore.NewConsentStore(db, "")
		_ = st.DropSchema(context.Background())
		if err := st.CreateSchema(context.Background()); err != nil {
			t.Fatalf("CreateSchema: %v", err)
		}
		t.Cleanup(func() { _ = st.DropSchema(context.Background()) })
		return st
	})
}

// A delete outside retention is refused whether or not the day is sealed, and
// so is stamping purged_at: both need the transaction-local retention
// setting, which only Purge and MarkPurged set. Retention itself still works.
func TestAuditDeleteAndPurgeStampNeedTheRetentionSettingLive(t *testing.T) {
	st, db := newLiveAuditStore(t)
	ctx := context.Background()
	clock := time.Date(2026, 1, 10, 9, 0, 0, 0, time.UTC)
	svc := audit.New(st, audit.WithRuntime(core.Runtime{Clock: func() time.Time { return clock }}),
		audit.WithTopics(audit.Topic{Key: "t", Retention: 24 * time.Hour}))
	record := func() audit.Event {
		t.Helper()
		e, err := svc.Record(ctx, audit.Event{Topic: "t", Action: "a.b", Origin: "x", Outcome: audit.OutcomeOK,
			Actor: audit.Actor{Type: audit.ActorUser, ID: "u"}})
		if err != nil {
			t.Fatal(err)
		}
		return e
	}
	e := record()

	// The day is not sealed yet: a plain DELETE is still refused.
	_, err := db.Exec(ctx, `DELETE FROM audit_events WHERE id = $1`, e.ID)
	wantCode(t, err, dropsstore.AuditEventProtected)
	if _, err := svc.Get(ctx, e.ID); err != nil {
		t.Fatalf("the unsealed event is gone after a refused DELETE: %v", err)
	}

	clock = clock.Add(48 * time.Hour)
	if _, err := svc.Seal(ctx, clock); err != nil {
		t.Fatal(err)
	}
	// Stamping purged_at by hand is refused, so it cannot open the day to a DELETE.
	_, err = db.Exec(ctx, `UPDATE audit_seals SET purged_at = now()`)
	wantCode(t, err, dropsstore.AuditSealImmutable)
	// Even with the setting on, a sealed day whose seal is not purged keeps its events.
	err = db.InTx(ctx, func(tx *pg.DB) error {
		if _, err := tx.Exec(ctx, `SELECT set_config($1, 'on', true)`, dropsstore.AuditRetentionSetting); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `DELETE FROM audit_events WHERE id = $1`, e.ID)
		return err
	})
	wantCode(t, err, dropsstore.AuditEventProtected)

	// Retention, which sets it, still purges.
	clock = clock.Add(72 * time.Hour)
	deleted, err := svc.ApplyRetention(ctx)
	if err != nil || deleted["t"] != 1 {
		t.Fatalf("ApplyRetention = %v, %v; want 1 deleted", deleted, err)
	}
	if sts, err := svc.Verify(ctx, nil, e.OccurredAt, e.OccurredAt); err != nil || sts[0].State != audit.DayPurged {
		t.Fatalf("Verify after retention = %+v, %v; want purged", sts, err)
	}
}

// A purge stamp dated in the future is how a holder of the application's
// credentials would make a young day pass the age check: the seals guard
// refuses one beyond the database clock plus audit.PurgeClockSkew, and Verify,
// judging by its own clock, calls any future stamp that does land
// purged_early, never purged.
func TestAuditFutureDatedPurgeStampIsRefusedLive(t *testing.T) {
	st, db := newLiveAuditStore(t)
	ctx := context.Background()
	clock := time.Date(2026, 1, 10, 9, 0, 0, 0, time.UTC)
	svc := audit.New(st, audit.WithRuntime(core.Runtime{Clock: func() time.Time { return clock }}),
		audit.WithTopics(audit.Topic{Key: "t", Retention: 90 * 24 * time.Hour}))
	e, err := svc.Record(ctx, audit.Event{Topic: "t", Action: "a.b", Origin: "x", Outcome: audit.OutcomeOK,
		Actor: audit.Actor{Type: audit.ActorUser, ID: "u"}})
	if err != nil {
		t.Fatal(err)
	}
	clock = clock.Add(24 * time.Hour)
	if _, err := svc.Seal(ctx, clock); err != nil {
		t.Fatal(err)
	}
	day := time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC)

	// The scenario of the review: retention setting on, a forged stamp, a DELETE.
	err = db.InTx(ctx, func(tx *pg.DB) error {
		if _, err := tx.Exec(ctx, `SELECT set_config($1, 'on', true)`, dropsstore.AuditRetentionSetting); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE audit_seals SET purged_at = '2099-01-01' WHERE topic = 't' AND day = $1`, day); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `DELETE FROM audit_events WHERE id = $1`, e.ID)
		return err
	})
	wantCode(t, err, dropsstore.AuditSealImmutable)
	err = st.MarkPurged(ctx, "t", day.Add(24*time.Hour), time.Now().Add(audit.PurgeClockSkew+time.Hour))
	wantCode(t, err, dropsstore.AuditSealImmutable)

	// A stamp inside the skew lands (the database cannot tell it from a
	// replica's fast clock), but Verify's clock sits on 11 January, so the day
	// reads as purged_early, not purged.
	if err := st.MarkPurged(ctx, "t", day.Add(24*time.Hour), time.Now().Add(time.Minute)); err != nil {
		t.Fatalf("MarkPurged inside the skew: %v", err)
	}
	sts, err := svc.Verify(ctx, nil, day, day)
	if err != nil || sts[0].State != audit.DayMismatch || sts[0].Detail != "purged_early" {
		t.Fatalf("Verify = %+v, %v; want mismatch purged_early", sts, err)
	}
}

const rawAuditInsert = `INSERT INTO audit_events (id, occurred_at, completed_at, topic, action, source, origin, actor_type, outcome)
VALUES ($1, $2, $2, 't', 'a.late', 'server', 'x', 'system', 'ok')`

// An event whose insert is still in flight when its day is sealed either
// makes the seal stale, so Seal digests the day again and covers it, or is
// refused; it never lands in a day its seal does not cover.
//
// The inserting session may format dates differently from the sealing one
// (DateStyle): the lock both take must not depend on it.
func TestAuditSealCoversAnInsertInFlightLive(t *testing.T) {
	for _, style := range []string{"", "SQL, DMY", "German"} {
		t.Run("datestyle "+style, func(t *testing.T) { sealCoversAnInsertInFlight(t, style) })
	}
}

func sealCoversAnInsertInFlight(t *testing.T, dateStyle string) {
	st, db := newLiveAuditStore(t)
	ctx := context.Background()
	clock := time.Date(2026, 1, 11, 0, 0, 1, 0, time.UTC)
	svc := audit.New(st, audit.WithRuntime(core.Runtime{Clock: func() time.Time { return clock }}),
		audit.WithTopics(audit.Topic{Key: "t"}))
	yesterday := time.Date(2026, 1, 10, 23, 59, 59, 0, time.UTC)

	txdb, tx, err := db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if dateStyle != "" {
		if _, err := txdb.Exec(ctx, `SELECT set_config('DateStyle', $1, true)`, dateStyle); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := txdb.Exec(ctx, rawAuditInsert, uid.NewV7(), yesterday); err != nil {
		t.Fatalf("insert in flight: %v", err)
	}
	type result struct {
		seals []audit.Seal
		err   error
	}
	done := make(chan result, 1)
	go func() {
		seals, err := svc.Seal(ctx, clock)
		done <- result{seals, err}
	}()
	time.Sleep(300 * time.Millisecond) // Seal digests the day, then waits on the insert's lock
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	r := <-done
	if r.err != nil {
		t.Fatalf("Seal: %v", r.err)
	}
	if len(r.seals) != 1 || r.seals[0].EventCount != 1 {
		t.Fatalf("Seal = %+v, want the day sealed with the event that was in flight", r.seals)
	}
	if sts, err := svc.Verify(ctx, nil, yesterday, yesterday); err != nil || sts[0].State != audit.DayOK {
		t.Fatalf("Verify = %+v, %v; want ok", sts, err)
	}
}

// The (topic, day) lock is scoped by the audit tables it guards: an insert in
// flight into one pair of tables does not hold up sealing another pair that
// uses the same topic.
func TestAuditSealLockIsScopedByTableLive(t *testing.T) {
	_, db := newLiveAuditStore(t)
	ctx := context.Background()
	other := dropsstore.NewAuditStore(db, dropsstore.WithAuditNames(dropsstore.AuditNames{
		Events: "audit_events_b", Seals: "audit_seals_b", Keys: "audit_subject_keys_b"}))
	_ = other.DropSchema(ctx)
	if err := other.CreateSchema(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = other.DropSchema(context.Background()) })
	clock := time.Date(2026, 1, 10, 12, 0, 0, 0, time.UTC)
	svc := audit.New(other, audit.WithRuntime(core.Runtime{Clock: func() time.Time { return clock }}),
		audit.WithTopics(audit.Topic{Key: "t"}))
	if _, err := svc.Record(ctx, audit.Event{Topic: "t", Action: "a.b", Origin: "x", Outcome: audit.OutcomeOK,
		Actor: audit.Actor{Type: audit.ActorSystem}}); err != nil {
		t.Fatal(err)
	}
	clock = time.Date(2026, 1, 11, 0, 0, 1, 0, time.UTC)

	txdb, tx, err := db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := txdb.Exec(ctx, rawAuditInsert, uid.NewV7(), time.Date(2026, 1, 10, 23, 59, 59, 0, time.UTC)); err != nil {
		t.Fatalf("insert in flight: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := svc.Seal(ctx, clock)
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("sealing audit_seals_b waits on an insert into audit_events")
	}
}

// Under REPEATABLE READ the sealed-day check would read a snapshot older than
// the seal, so the guard refuses such an insert outright; the store runs its
// own writes under READ COMMITTED, so it works whatever the database default.
func TestAuditGuardsHoldUnderRepeatableReadLive(t *testing.T) {
	st, db := newLiveAuditStore(t)
	ctx := context.Background()
	d := time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC)

	txdb, tx, err := db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := txdb.Exec(ctx, `SET TRANSACTION ISOLATION LEVEL REPEATABLE READ`); err != nil {
		t.Fatal(err)
	}
	if _, err := txdb.Exec(ctx, `SELECT 1`); err != nil { // takes the snapshot
		t.Fatal(err)
	}
	if err := st.InsertSeal(ctx, audit.Seal{Topic: "t", Day: d, EventsHash: "e", SealHash: "s", SealedAt: d.Add(30 * time.Hour)}); err != nil {
		t.Fatalf("InsertSeal: %v", err)
	}
	_, err = txdb.Exec(ctx, rawAuditInsert, uid.NewV7(), d.Add(time.Hour))
	if err == nil {
		t.Fatal("an insert under REPEATABLE READ landed in a day sealed after its snapshot")
	}
	wantCode(t, err, dropsstore.AuditIsolation)
	_ = tx.Rollback(ctx)

	// The store itself, on a connection whose default is REPEATABLE READ.
	rrDB, err := sql.Open("pgx", os.Getenv("AUTHLAYER_TEST_DSN")+"&default_transaction_isolation=repeatable%20read")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rrDB.Close() })
	rr := dropsstore.NewAuditStore(pg.New(stdlib.New(rrDB)))
	clock := d.Add(26 * time.Hour)
	svc := audit.New(rr, audit.WithRuntime(core.Runtime{Clock: func() time.Time { return clock }}),
		audit.WithTopics(audit.Topic{Key: "t"}, audit.Topic{Key: "u"}))
	if _, err := svc.Record(ctx, audit.Event{Topic: "u", Action: "a.b", Origin: "x", Outcome: audit.OutcomeOK,
		Actor: audit.Actor{Type: audit.ActorSystem}}); err != nil {
		t.Fatalf("Record on a REPEATABLE READ default: %v", err)
	}
	clock = clock.Add(24 * time.Hour)
	if _, err := svc.Seal(ctx, clock); err != nil {
		t.Fatalf("Seal on a REPEATABLE READ default: %v", err)
	}
}

// A TEMP table named like the seals table comes first on the session's
// search_path; the guards must still read the real one.
func TestAuditGuardsIgnoreATempShadowTableLive(t *testing.T) {
	st, db := newLiveAuditStore(t)
	ctx := context.Background()
	d := time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC)
	if err := st.InsertSeal(ctx, audit.Seal{Topic: "t", Day: d, EventsHash: "e", SealHash: "s", SealedAt: d.Add(30 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	err := db.InTx(ctx, func(tx *pg.DB) error {
		if _, err := tx.Exec(ctx, `CREATE TEMP TABLE audit_seals (topic text, day date, purged_at timestamptz) ON COMMIT DROP`); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, rawAuditInsert, uid.NewV7(), d.Add(time.Hour))
		return err
	})
	wantCode(t, err, dropsstore.AuditDaySealed)

	// The delete guard too: with the retention setting on, an event of a
	// sealed, unpurged day stays even when the shadow says nothing is sealed.
	clock := d.Add(48*time.Hour + time.Hour)
	svc := audit.New(st, audit.WithRuntime(core.Runtime{Clock: func() time.Time { return clock }}),
		audit.WithTopics(audit.Topic{Key: "u"}))
	clock = d.Add(24*time.Hour + time.Hour)
	e, err := svc.Record(ctx, audit.Event{Topic: "u", Action: "a.b", Origin: "x", Outcome: audit.OutcomeOK,
		Actor: audit.Actor{Type: audit.ActorSystem}})
	if err != nil {
		t.Fatal(err)
	}
	clock = d.Add(48*time.Hour + time.Hour)
	if _, err := svc.Seal(ctx, clock); err != nil {
		t.Fatal(err)
	}
	err = db.InTx(ctx, func(tx *pg.DB) error {
		if _, err := tx.Exec(ctx, `CREATE TEMP TABLE audit_seals (topic text, day date, purged_at timestamptz) ON COMMIT DROP`); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `SELECT set_config($1, 'on', true)`, dropsstore.AuditRetentionSetting); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `DELETE FROM audit_events WHERE id = $1`, e.ID)
		return err
	})
	wantCode(t, err, dropsstore.AuditEventProtected)
}

func TestAuditIDsLive(t *testing.T) {
	st, _ := newLiveAuditStore(t)
	ctx := context.Background()
	for _, id := range []string{"not-a-uuid", "0192A3B4-C5D6-7E8F-9A0B-1C2D3E4F5A6B", "{0192a3b4-c5d6-7e8f-9a0b-1c2d3e4f5a6b}"} {
		if _, err := st.Get(ctx, id); !errors.Is(err, audit.ErrNotFound) {
			t.Errorf("Get(%q) err = %v, want ErrNotFound", id, err)
		}
		if _, err := st.Complete(ctx, id, audit.Closing{At: time.Now(), Outcome: audit.OutcomeOK}); !errors.Is(err, audit.ErrNotFound) {
			t.Errorf("Complete(%q) err = %v, want ErrNotFound", id, err)
		}
		e := audit.Event{ID: id, OccurredAt: time.Now().UTC().Truncate(time.Microsecond), Topic: "t", Action: "a.b",
			Source: audit.SourceServer, Origin: "x", Actor: audit.Actor{Type: audit.ActorSystem}}
		if got, err := st.Insert(ctx, e); !errors.Is(err, audit.ErrInvalidEvent) {
			t.Errorf("Insert(%q) = %q, %v; want ErrInvalidEvent", id, got.ID, err)
		}
	}
}

// Begin, Complete (and its identical retry), Seal and Verify survive the jsonb
// round trip, which sorts keys and respells numbers.
func TestAuditJSONBRoundTripVerifiesLive(t *testing.T) {
	st, _ := newLiveAuditStore(t)
	ctx := context.Background()
	clock := time.Date(2026, 1, 10, 9, 0, 0, 0, time.UTC)
	svc := audit.New(st, audit.WithRuntime(core.Runtime{Clock: func() time.Time { return clock }}),
		audit.WithTopics(audit.Topic{Key: "t"}))
	open, err := svc.Begin(ctx, audit.Event{Topic: "t", Action: "a.b", Origin: "x", Actor: audit.Actor{Type: audit.ActorSystem},
		Request: json.RawMessage(`{"z":{"b":[1,{"y":2,"x":1}],"a":1.50},"a":1e-7,"m":"é"}`)})
	if err != nil {
		t.Fatal(err)
	}
	c := audit.Completion{Outcome: audit.OutcomeOK,
		Before: json.RawMessage(`{"price":1.50,"tiny":1e-7}`), After: json.RawMessage(`{"price":2.50,"tiny":2E-7}`)}
	if err := svc.Complete(ctx, open.ID, c); err != nil {
		t.Fatal(err)
	}
	if err := svc.Complete(ctx, open.ID, c); err != nil {
		t.Fatalf("identical Complete retry after the jsonb round trip: %v", err)
	}
	clock = clock.Add(24 * time.Hour)
	if _, err := svc.Seal(ctx, clock); err != nil {
		t.Fatal(err)
	}
	if sts, err := svc.Verify(ctx, nil, open.OccurredAt, open.OccurredAt); err != nil || sts[0].State != audit.DayOK {
		t.Fatalf("Verify = %+v, %v; want ok", sts, err)
	}
}

func TestAuditCompletionCannotOverwriteAResourceOrContainerLive(t *testing.T) {
	st, db := newLiveAuditStore(t)
	ctx := context.Background()
	svc := audit.New(st, audit.WithTopics(audit.Topic{Key: "t"}))
	open, err := svc.Begin(ctx, audit.Event{Topic: "t", Action: "a.b", Origin: "x", Actor: audit.Actor{Type: audit.ActorSystem},
		Resource: audit.Resource{Type: "menu", ID: "m1"}, ContainerID: "org1"})
	if err != nil {
		t.Fatal(err)
	}
	for _, set := range []string{"resource_id = 'm2'", "resource_type = 'lot'", "container_id = 'org2'"} {
		_, err := db.Exec(ctx, `UPDATE audit_events SET completed_at = now(), outcome = 'ok', `+set+` WHERE id = $1`, open.ID)
		wantCode(t, err, dropsstore.AuditEventImmutable)
	}
}

// CreateSchema may run on several replicas at once.
func TestAuditCreateSchemaConcurrentlyLive(t *testing.T) {
	st, _ := newLiveAuditStore(t)
	ctx := context.Background()
	errs := make(chan error, 8)
	for range 8 {
		go func() { errs <- st.CreateSchema(ctx) }()
	}
	for range 8 {
		if err := <-errs; err != nil {
			t.Errorf("concurrent CreateSchema: %v", err)
		}
	}
}

// One person's trail (Filter.Member) can be read from indexes alone.
func TestAuditMemberFilterUsesIndexesLive(t *testing.T) {
	_, db := newLiveAuditStore(t)
	ctx := context.Background()
	var plan []string
	err := db.InTx(ctx, func(tx *pg.DB) error {
		if _, err := tx.Exec(ctx, `SET LOCAL enable_seqscan = off`); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `EXPLAIN SELECT count(*) FROM audit_events
WHERE (actor_id = 'u' OR on_behalf_of = 'u' OR (resource_type = 'user' AND resource_id = 'u'))`)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var line string
			if err := rows.Scan(&line); err != nil {
				return err
			}
			plan = append(plan, line)
		}
		return rows.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(plan, "\n")
	for _, idx := range []string{"audit_events_actor", "audit_events_on_behalf_of", "audit_events_resource"} {
		if !strings.Contains(joined, idx) {
			t.Errorf("the Member plan does not use %s:\n%s", idx, joined)
		}
	}
}

// A filter bound with a sub-microsecond part selects what it selects on the
// memory store: the Service rounds it before the driver would truncate it.
func TestAuditFilterBoundsMatchTheMemoryStoreLive(t *testing.T) {
	st, _ := newLiveAuditStore(t)
	ctx := context.Background()
	svc := audit.New(st, audit.WithTopics(audit.Topic{Key: "t"}))
	e, err := svc.Record(ctx, audit.Event{Topic: "t", Action: "a.b", Origin: "x", Outcome: audit.OutcomeOK,
		Actor: audit.Actor{Type: audit.ActorSystem}})
	if err != nil {
		t.Fatal(err)
	}
	for name, f := range map[string]audit.Filter{
		"from": {From: e.OccurredAt.Add(500 * time.Nanosecond)},
		"to":   {To: e.OccurredAt.Add(500 * time.Nanosecond)},
	} {
		if n, err := svc.Count(ctx, f); err != nil || n != 1 {
			t.Errorf("Count with a sub-microsecond %s = %d, %v; want 1", name, n, err)
		}
	}
}
