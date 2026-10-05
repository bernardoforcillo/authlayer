package audit_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/bernardoforcillo/authlayer/audit"
	"github.com/bernardoforcillo/authlayer/core"
)

const emptyDayHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

func day(n int) time.Time { return time.Date(2026, 3, n, 0, 0, 0, 0, time.UTC) }

func sealHashOf(prev, topic string, d time.Time, count int64, events string) string {
	sum := sha256.Sum256([]byte(prev + "|" + topic + "|" + d.Format(time.DateOnly) + "|" +
		strconv.FormatInt(count, 10) + "|" + events))
	return hex.EncodeToString(sum[:])
}

func recordAt(t *testing.T, svc *audit.Service, clk *testClock, at time.Time) audit.Event {
	t.Helper()
	clk.Set(at)
	e, err := svc.Record(context.Background(), action(func(e *audit.Event) { e.Outcome = audit.OutcomeOK }))
	if err != nil {
		t.Fatalf("Record: %v", err)
	}
	return e
}

// threeDays records two "menus" events on 1 March and one on 3 March.
func threeDays(t *testing.T, svc *audit.Service, clk *testClock) []audit.Event {
	t.Helper()
	return []audit.Event{
		recordAt(t, svc, clk, day(1).Add(9*time.Hour)),
		recordAt(t, svc, clk, day(1).Add(10*time.Hour)),
		recordAt(t, svc, clk, day(3).Add(10*time.Hour)),
	}
}

func menusSeals(t *testing.T, st audit.Store, from, to time.Time) []audit.Seal {
	t.Helper()
	seals, err := st.Seals(context.Background(), "menus", from, to)
	if err != nil {
		t.Fatalf("Seals: %v", err)
	}
	return seals
}

func TestSealChainsEveryDayIncludingEmptyOnes(t *testing.T) {
	svc, st, clk := newService(t)
	events := threeDays(t, svc, clk)
	sealed, err := svc.Seal(context.Background(), day(4))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if len(sealed) != 4 { // auth: 3 March (no events yet); menus: 1, 2, 3 March
		t.Fatalf("Seal returned %d seals, want 4: %+v", len(sealed), sealed)
	}
	seals := menusSeals(t, st, day(1), day(3))
	if len(seals) != 3 {
		t.Fatalf("menus seals = %d, want 3", len(seals))
	}
	for i, want := range []int64{2, 0, 1} {
		s := seals[i]
		if s.EventCount != want {
			t.Errorf("day %d EventCount = %d, want %d", i+1, s.EventCount, want)
		}
		prev := ""
		if i > 0 {
			prev = seals[i-1].SealHash
		}
		if s.PrevHash != prev || s.SealHash != sealHashOf(prev, "menus", s.Day, s.EventCount, s.EventsHash) {
			t.Errorf("day %d does not chain: %+v", i+1, s)
		}
	}
	if seals[1].EventsHash != emptyDayHash || seals[1].FirstSeq != 0 {
		t.Errorf("empty day = %+v, want the empty hash and no seq", seals[1])
	}
	if seals[0].FirstSeq != events[0].Seq || seals[0].LastSeq != events[1].Seq {
		t.Errorf("1 March seqs = %d..%d, want %d..%d", seals[0].FirstSeq, seals[0].LastSeq, events[0].Seq, events[1].Seq)
	}
}

func TestSealResumesWhereItStopped(t *testing.T) {
	svc, st, clk := newService(t)
	threeDays(t, svc, clk)
	if _, err := svc.Seal(context.Background(), day(4)); err != nil {
		t.Fatalf("Seal: %v", err)
	}
	recordAt(t, svc, clk, day(4).Add(12*time.Hour))
	sealed, err := svc.Seal(context.Background(), day(5))
	if err != nil || len(sealed) != 2 {
		t.Fatalf("second Seal = %d seals, %v; want 2 (auth and menus, 4 March)", len(sealed), err)
	}
	seals := menusSeals(t, st, day(3), day(4))
	if len(seals) != 2 || seals[1].PrevHash != seals[0].SealHash || seals[1].EventCount != 1 {
		t.Errorf("4 March seal = %+v, want it chained to 3 March with one event", seals)
	}
}

func TestSealRefusesADayWithOpenEvents(t *testing.T) {
	svc, st, clk := newService(t)
	ctx := context.Background()
	clk.Set(day(1).Add(9 * time.Hour))
	open, err := svc.Begin(ctx, action())
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if _, err := svc.Seal(ctx, day(2)); !errors.Is(err, audit.ErrOpenEvents) {
		t.Fatalf("Seal err = %v, want ErrOpenEvents", err)
	}
	if _, err := st.LastSeal(ctx, "menus"); !errors.Is(err, audit.ErrNotFound) {
		t.Errorf("menus was sealed over an open event: %v", err)
	}
	if err := svc.Complete(ctx, open.ID, audit.Completion{Outcome: audit.OutcomeOK}); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if _, err := svc.Seal(ctx, day(2)); err != nil {
		t.Errorf("Seal after completion: %v", err)
	}
}

func TestSealOnTwoReplicasAtOnce(t *testing.T) {
	svc, st, clk := newService(t)
	threeDays(t, svc, clk)
	other := audit.New(st, audit.WithRuntime(core.Runtime{Clock: clk.Now}),
		audit.WithTopics(audit.Topic{Key: "menus"}, audit.Topic{Key: "auth", Retention: thirtyDays}))
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i, s := range []*audit.Service{svc, other} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, errs[i] = s.Seal(context.Background(), day(4))
		}()
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Errorf("replica %d: %v", i, err)
		}
	}
	if seals := menusSeals(t, st, day(1), day(3)); len(seals) != 3 {
		t.Errorf("menus seals = %d, want 3", len(seals))
	}
	days, err := svc.Verify(context.Background(), []string{"menus"}, day(1), day(3))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	for _, d := range days {
		if d.State != audit.DayOK {
			t.Errorf("%s: %s %s", d.Day.Format(time.DateOnly), d.State, d.Detail)
		}
	}
}

func TestVerifyReportsOKAndUnsealedDays(t *testing.T) {
	svc, _, clk := newService(t)
	threeDays(t, svc, clk)
	if _, err := svc.Seal(context.Background(), day(4)); err != nil {
		t.Fatalf("Seal: %v", err)
	}
	days, err := svc.Verify(context.Background(), []string{"menus"}, day(1), day(4))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	want := []audit.DayState{audit.DayOK, audit.DayOK, audit.DayOK, audit.DayUnsealed}
	if len(days) != len(want) {
		t.Fatalf("Verify = %+v", days)
	}
	for i, d := range days {
		if d.State != want[i] {
			t.Errorf("%s = %s, want %s", d.Day.Format(time.DateOnly), d.State, want[i])
		}
	}
}

// tamperStore rewrites what a store returns, the way someone with database
// access could rewrite the rows themselves.
type tamperStore struct {
	audit.Store
	scan  func(audit.Event) (audit.Event, bool)
	extra []audit.Event
	seals func([]audit.Seal) []audit.Seal
}

func (s tamperStore) Scan(ctx context.Context, f audit.Filter, fn func(audit.Event) error) error {
	err := s.Store.Scan(ctx, f, func(e audit.Event) error {
		if s.scan != nil {
			var keep bool
			if e, keep = s.scan(e); !keep {
				return nil
			}
		}
		return fn(e)
	})
	if err != nil {
		return err
	}
	for _, e := range s.extra {
		if f.Match(e) {
			if err := fn(e); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s tamperStore) Seals(ctx context.Context, topic string, from, to time.Time) ([]audit.Seal, error) {
	out, err := s.Store.Seals(ctx, topic, from, to)
	if err != nil || s.seals == nil {
		return out, err
	}
	return s.seals(out), nil
}

func TestVerifyDetectsTampering(t *testing.T) {
	forged := func(seals []audit.Seal) []audit.Seal {
		for i := range seals {
			if seals[i].Day.Equal(day(2)) {
				seals[i].PrevHash = "forged"
				seals[i].SealHash = sealHashOf("forged", "menus", day(2), seals[i].EventCount, seals[i].EventsHash)
			}
		}
		return seals
	}
	cases := []struct {
		name   string
		tamper func(events []audit.Event) tamperStore
		want   map[int]string // day of March → Detail; other days must be OK
	}{
		{"altered event", func(events []audit.Event) tamperStore {
			return tamperStore{scan: func(e audit.Event) (audit.Event, bool) {
				if e.ID == events[0].ID {
					e.Action = "menu.delete"
				}
				return e, true
			}}
		}, map[int]string{1: "events_hash"}},
		{"deleted event", func(events []audit.Event) tamperStore {
			return tamperStore{scan: func(e audit.Event) (audit.Event, bool) { return e, e.ID != events[2].ID }}
		}, map[int]string{3: "events_hash"}},
		{"inserted event", func(events []audit.Event) tamperStore {
			fake := events[0]
			fake.ID, fake.Seq, fake.OccurredAt = "fake", 99, day(2).Add(12*time.Hour)
			return tamperStore{extra: []audit.Event{fake}}
		}, map[int]string{2: "events_hash"}},
		{"altered seal", func([]audit.Event) tamperStore {
			return tamperStore{seals: func(seals []audit.Seal) []audit.Seal {
				for i := range seals {
					if seals[i].Day.Equal(day(2)) {
						seals[i].EventsHash = "x"
					}
				}
				return seals
			}}
		}, map[int]string{2: "seal_hash"}},
		{"broken chain", func([]audit.Event) tamperStore {
			return tamperStore{seals: forged}
		}, map[int]string{2: "chain", 3: "chain"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc, st, clk := newService(t)
			events := threeDays(t, svc, clk)
			if _, err := svc.Seal(context.Background(), day(4)); err != nil {
				t.Fatalf("Seal: %v", err)
			}
			ts := tc.tamper(events)
			ts.Store = st
			auditor := audit.New(ts, audit.WithRuntime(core.Runtime{Clock: clk.Now}),
				audit.WithTopics(audit.Topic{Key: "menus"}))
			days, err := auditor.Verify(context.Background(), []string{"menus"}, day(1), day(3))
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			for _, d := range days {
				want, bad := tc.want[d.Day.Day()]
				switch {
				case bad && (d.State != audit.DayMismatch || d.Detail != want):
					t.Errorf("%s = %s %q, want mismatch %q", d.Day.Format(time.DateOnly), d.State, d.Detail, want)
				case !bad && d.State != audit.DayOK:
					t.Errorf("%s = %s %q, want ok", d.Day.Format(time.DateOnly), d.State, d.Detail)
				}
			}
		})
	}
}
