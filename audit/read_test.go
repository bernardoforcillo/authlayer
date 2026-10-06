package audit_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/bernardoforcillo/authlayer/audit"
)

func record(t *testing.T, svc *audit.Service, clk *testClock, n int) []audit.Event {
	t.Helper()
	var out []audit.Event
	for i := 0; i < n; i++ {
		e, err := svc.Record(context.Background(), action(func(e *audit.Event) { e.Outcome = audit.OutcomeOK }))
		if err != nil {
			t.Fatalf("Record: %v", err)
		}
		out = append(out, e)
		clk.Advance(time.Minute)
	}
	return out
}

func TestListPagesNewestFirst(t *testing.T) {
	svc, _, clk := newService(t)
	all := record(t, svc, clk, 5)
	var got []int64
	before := int64(0)
	for pages := 0; ; pages++ {
		events, next, err := svc.List(context.Background(), audit.Filter{}, audit.Page{Before: before, Limit: 2})
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		for _, e := range events {
			got = append(got, e.Seq)
		}
		if next == 0 {
			break
		}
		if pages > 5 {
			t.Fatal("List never returned a zero cursor")
		}
		before = next
	}
	if len(got) != 5 || got[0] != all[4].Seq || got[4] != all[0].Seq {
		t.Errorf("pages = %v, want the five events newest first", got)
	}
}

func TestListClampsTheLimit(t *testing.T) {
	svc, _, clk := newService(t)
	record(t, svc, clk, 3)
	for _, limit := range []int{0, -1, audit.MaxPageSize + 1} {
		events, next, err := svc.List(context.Background(), audit.Filter{}, audit.Page{Limit: limit})
		if err != nil || len(events) != 3 || next != 0 {
			t.Errorf("Limit %d: %d events, next %d, %v; want 3, 0", limit, len(events), next, err)
		}
	}
}

func TestExportYieldsOldestFirst(t *testing.T) {
	svc, _, clk := newService(t)
	all := record(t, svc, clk, 3)
	var got []string
	err := svc.Export(context.Background(), audit.Filter{}, 10, func(e audit.Event) error {
		got = append(got, e.ID)
		return nil
	})
	if err != nil || len(got) != 3 || got[0] != all[0].ID || got[2] != all[2].ID {
		t.Errorf("Export = %v, %v; want the three ids oldest first", got, err)
	}
}

func TestExportRefusesAboveTheLimitBeforeYielding(t *testing.T) {
	svc, _, clk := newService(t)
	record(t, svc, clk, 3)
	calls := 0
	err := svc.Export(context.Background(), audit.Filter{}, 2, func(audit.Event) error { calls++; return nil })
	if !errors.Is(err, audit.ErrExportTooLarge) || calls != 0 {
		t.Errorf("Export = %v after %d yields, want ErrExportTooLarge after none", err, calls)
	}
}

// Stores keep microseconds: a bound with a sub-microsecond part is rounded
// the same way for every store, From down and To up.
func TestFilterBoundsAreNormalisedToMicroseconds(t *testing.T) {
	svc, _, clk := newService(t)
	ctx := context.Background()
	e := record(t, svc, clk, 1)[0]
	for name, f := range map[string]audit.Filter{
		"from": {From: e.OccurredAt.Add(500 * time.Nanosecond)},
		"to":   {To: e.OccurredAt.Add(500 * time.Nanosecond)},
	} {
		events, _, err := svc.List(ctx, f, audit.Page{})
		if err != nil || len(events) != 1 {
			t.Errorf("List with a sub-microsecond %s = %d events, %v; want the event", name, len(events), err)
		}
		if n, err := svc.Count(ctx, f); err != nil || n != 1 {
			t.Errorf("Count with a sub-microsecond %s = %d, %v; want 1", name, n, err)
		}
		got := 0
		if err := svc.Export(ctx, f, 0, func(audit.Event) error { got++; return nil }); err != nil || got != 1 {
			t.Errorf("Export with a sub-microsecond %s = %d, %v; want 1", name, got, err)
		}
	}
}
