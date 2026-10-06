package audit_test

import (
	"context"
	"testing"
	"time"

	"github.com/bernardoforcillo/authlayer/audit"
	"github.com/bernardoforcillo/authlayer/core"
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

// replicaStore completes one event itself just before the Service's own
// Complete of it, the way another replica's Reconcile can win the race.
type replicaStore struct {
	audit.Store
	steal     string
	completed string // answers ErrCompleted for this id
}

func (s *replicaStore) Complete(ctx context.Context, id string, c audit.Closing) (audit.Event, error) {
	if id == s.completed {
		return audit.Event{}, audit.ErrCompleted
	}
	if id == s.steal {
		other := c
		other.At = c.At.Add(-time.Second)
		if _, err := s.Store.Complete(ctx, id, other); err != nil {
			return audit.Event{}, err
		}
	}
	return s.Store.Complete(ctx, id, c)
}

func TestReconcileCountsOnlyWhatItClosed(t *testing.T) {
	_, st, clk := newService(t)
	rs := &replicaStore{Store: st}
	svc := audit.New(rs, audit.WithRuntime(core.Runtime{Clock: clk.Now}), audit.WithTopics(audit.Topic{Key: "menus"}))
	ctx := context.Background()
	clk.Set(day(1).Add(time.Hour))
	var ids []string
	for range 3 {
		e, err := svc.Begin(ctx, action())
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, e.ID)
	}
	rs.steal, rs.completed = ids[0], ids[1]
	clk.Set(day(1).Add(3 * time.Hour))
	n, err := svc.Reconcile(ctx, time.Hour)
	if err != nil || n != 1 {
		t.Fatalf("Reconcile = %d, %v; want 1 (one closed by another replica, one completed differently)", n, err)
	}
	if got, _ := st.Get(ctx, ids[2]); got.Outcome != audit.OutcomeUnknown {
		t.Errorf("third event = %+v, want closed as unknown", got)
	}
}

func TestMaintenanceCrossesBatchBoundaries(t *testing.T) {
	defer audit.SetMaintainBatch(2)()
	svc, st, clk := newService(t)
	ctx := context.Background()
	clk.Set(day(1).Add(time.Hour))
	for range 5 {
		if _, err := svc.Begin(ctx, action(func(e *audit.Event) { e.Topic = "auth" })); err != nil {
			t.Fatal(err)
		}
	}
	clk.Set(day(2))
	if n, err := svc.Reconcile(ctx, time.Hour); err != nil || n != 5 {
		t.Fatalf("Reconcile = %d, %v; want all 5 across three batches", n, err)
	}
	if _, err := svc.Seal(ctx, day(2)); err != nil {
		t.Fatal(err)
	}
	clk.Set(day(1).AddDate(0, 0, 40))
	deleted, err := svc.ApplyRetention(ctx)
	if err != nil || deleted["auth"] != 5 {
		t.Fatalf("ApplyRetention = %v, %v; want auth:5 across three batches", deleted, err)
	}
	if n, _ := st.Count(ctx, audit.Filter{Topics: []string{"auth"}}); n != 0 {
		t.Errorf("auth kept %d events, want 0", n)
	}
}
