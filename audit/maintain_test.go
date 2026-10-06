package audit_test

import (
	"context"
	"testing"
	"time"

	"github.com/bernardoforcillo/authlayer/audit"
)

func TestReconcileClosesOnlyStaleOpenEvents(t *testing.T) {
	svc, st, clk := newService(t)
	ctx := context.Background()
	clk.Set(day(1).Add(time.Hour))
	stale, err := svc.Begin(ctx, action())
	if err != nil {
		t.Fatal(err)
	}
	clk.Set(day(1).Add(3 * time.Hour))
	fresh, err := svc.Begin(ctx, action())
	if err != nil {
		t.Fatal(err)
	}
	clk.Set(day(1).Add(3*time.Hour + 5*time.Minute))
	n, err := svc.Reconcile(ctx, time.Hour)
	if err != nil || n != 1 {
		t.Fatalf("Reconcile = %d, %v; want 1, nil", n, err)
	}
	got, _ := st.Get(ctx, stale.ID)
	if got.Outcome != audit.OutcomeUnknown || got.Reason != audit.ReasonReconciled || got.CompletedAt == nil {
		t.Errorf("stale event = %+v", got)
	}
	if got, _ := st.Get(ctx, fresh.ID); got.CompletedAt != nil {
		t.Errorf("fresh event was closed: %+v", got)
	}
	if n, err := svc.Reconcile(ctx, time.Hour); err != nil || n != 0 {
		t.Errorf("second Reconcile = %d, %v; want 0, nil", n, err)
	}
}

func TestReconcileUnblocksSeal(t *testing.T) {
	svc, _, clk := newService(t)
	ctx := context.Background()
	clk.Set(day(1).Add(time.Hour))
	if _, err := svc.Begin(ctx, action()); err != nil {
		t.Fatal(err)
	}
	clk.Set(day(3))
	if _, err := svc.Seal(ctx, day(3)); err == nil {
		t.Fatal("Seal over an open event succeeded")
	}
	if _, err := svc.Reconcile(ctx, time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Seal(ctx, day(3)); err != nil {
		t.Fatalf("Seal after Reconcile: %v", err)
	}
}

func TestApplyRetentionPurgesSealedDaysAndVerifyStaysQuiet(t *testing.T) {
	svc, st, clk := newService(t)
	ctx := context.Background()
	old := threeDays(t, svc, clk) // 1 and 3 March, topic "menus" (365 days)
	// "auth" keeps 30 days.
	clk.Set(day(1).Add(time.Hour))
	oldAuth, err := svc.Record(ctx, action(func(e *audit.Event) { e.Topic = "auth"; e.Outcome = audit.OutcomeOK }))
	if err != nil {
		t.Fatal(err)
	}
	clk.Set(day(10))
	if _, err := svc.Seal(ctx, day(10)); err != nil {
		t.Fatalf("Seal: %v", err)
	}
	clk.Set(day(1).AddDate(0, 0, 40))
	deleted, err := svc.ApplyRetention(ctx)
	if err != nil {
		t.Fatalf("ApplyRetention: %v", err)
	}
	if deleted["auth"] != 1 || deleted["menus"] != 0 {
		t.Fatalf("deleted = %v; want only auth:1", deleted)
	}
	if _, err := st.Get(ctx, oldAuth.ID); err == nil {
		t.Error("auth event survived retention")
	}
	if _, err := st.Get(ctx, old[0].ID); err != nil {
		t.Errorf("menus event deleted early: %v", err)
	}
	sts, err := svc.Verify(ctx, []string{"auth"}, day(1), day(9))
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range sts {
		if s.State == audit.DayMismatch {
			t.Errorf("false alarm after retention: %+v", s)
		}
	}
	if sts[0].State != audit.DayPurged {
		t.Errorf("day 1 = %v; want purged", sts[0].State)
	}
}

func TestApplyRetentionKeepsUnsealedDays(t *testing.T) {
	svc, st, clk := newService(t)
	ctx := context.Background()
	e := recordAt(t, svc, clk, day(1).Add(time.Hour))
	clk.Set(day(1).AddDate(0, 0, 400))
	deleted, err := svc.ApplyRetention(ctx)
	if err != nil || len(deleted) != 0 {
		t.Fatalf("ApplyRetention = %v, %v; want nothing", deleted, err)
	}
	if _, err := st.Get(ctx, e.ID); err != nil {
		t.Errorf("unsealed event deleted: %v", err)
	}
}
