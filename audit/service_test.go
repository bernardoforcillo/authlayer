package audit_test

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/bernardoforcillo/authlayer/audit"
	"github.com/bernardoforcillo/authlayer/core"
	"github.com/bernardoforcillo/authlayer/store/memory"
)

type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.now }

func (c *testClock) Advance(d time.Duration) { c.mu.Lock(); c.now = c.now.Add(d); c.mu.Unlock() }

func (c *testClock) Set(t time.Time) { c.mu.Lock(); c.now = t; c.mu.Unlock() }

var t0 = time.Date(2026, 3, 1, 9, 30, 0, 123456789, time.UTC)

const thirtyDays = 30 * 24 * time.Hour

// newService returns a Service over an empty memory store with the topics
// "menus" (default retention) and "auth" (30 days), on a clock at t0.
func newService(t *testing.T, opts ...audit.Option) (*audit.Service, *memory.AuditStore, *testClock) {
	t.Helper()
	st := memory.NewAuditStore()
	clk := &testClock{now: t0}
	base := []audit.Option{
		audit.WithRuntime(core.Runtime{Clock: clk.Now}),
		audit.WithTopics(audit.Topic{Key: "menus"}, audit.Topic{Key: "auth", Retention: thirtyDays}),
	}
	return audit.New(st, append(base, opts...)...), st, clk
}

func action(mods ...func(*audit.Event)) audit.Event {
	e := audit.Event{Topic: "menus", Action: "menu.update", Origin: "test",
		Actor: audit.Actor{Type: audit.ActorUser, ID: "alice"}}
	for _, m := range mods {
		m(&e)
	}
	return e
}

func TestBeginStampsAndRedacts(t *testing.T) {
	svc, _, _ := newService(t)
	ctx := context.Background()
	e, err := svc.Begin(ctx, action(func(e *audit.Event) {
		e.Request = json.RawMessage(`{"password":"p","name":"n"}`)
	}))
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if e.ID == "" || e.Seq == 0 || e.Source != audit.SourceServer || e.CompletedAt != nil {
		t.Errorf("Begin = %+v, want an id, a seq, server source, open", e)
	}
	if !e.OccurredAt.Equal(t0.Truncate(time.Microsecond)) || e.OccurredAt.Location() != time.UTC {
		t.Errorf("OccurredAt = %v, want %v in UTC", e.OccurredAt, t0.Truncate(time.Microsecond))
	}
	if !audit.EqualJSON(e.Request, json.RawMessage(`{"password":"[REDACTED]","name":"n"}`)) {
		t.Errorf("Request = %s, want the password redacted", e.Request)
	}
	back, err := svc.Get(ctx, e.ID)
	if err != nil || back.Seq != e.Seq {
		t.Errorf("Get = %+v, %v", back, err)
	}
}

func TestBeginNormalisesAnyClockToUTCMicroseconds(t *testing.T) {
	cet := time.FixedZone("CET", 3600)
	local := time.Date(2026, 3, 2, 0, 30, 0, 999, cet) // 1 March, 23:30 UTC
	svc, _, _ := newService(t, audit.WithRuntime(core.Runtime{Clock: func() time.Time { return local }}))
	e, err := svc.Begin(context.Background(), action())
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if e.OccurredAt.Location() != time.UTC || e.OccurredAt.Day() != 1 || e.OccurredAt.Nanosecond() != 0 {
		t.Errorf("OccurredAt = %v, want 1 March 23:30 UTC with no sub-microsecond part", e.OccurredAt)
	}
}

func TestBeginRefusesInvalidEvents(t *testing.T) {
	svc, _, _ := newService(t)
	tests := []struct {
		name string
		e    audit.Event
		want error
	}{
		{"unknown topic", action(func(e *audit.Event) { e.Topic = "nope" }), audit.ErrUnknownTopic},
		{"no action", action(func(e *audit.Event) { e.Action = "" }), audit.ErrInvalidEvent},
		{"no origin", action(func(e *audit.Event) { e.Origin = "" }), audit.ErrInvalidEvent},
		{"no actor type", action(func(e *audit.Event) { e.Actor.Type = "" }), audit.ErrInvalidEvent},
		{"bad source", action(func(e *audit.Event) { e.Source = "elsewhere" }), audit.ErrInvalidEvent},
		{"already completed", action(func(e *audit.Event) { e.Outcome = audit.OutcomeOK }), audit.ErrInvalidEvent},
	}
	for _, tt := range tests {
		if _, err := svc.Begin(context.Background(), tt.e); !errors.Is(err, tt.want) {
			t.Errorf("%s: err = %v, want %v", tt.name, err, tt.want)
		}
	}
}

// PostgreSQL text and jsonb cannot hold a NUL character, so the Service
// refuses one everywhere a store would have to, whichever store it runs on.
func TestNULCharactersAreInvalidEverywhere(t *testing.T) {
	svc, _, _ := newService(t)
	ctx := context.Background()
	for name, mod := range map[string]func(*audit.Event){
		"action":       func(e *audit.Event) { e.Action = "menu.\x00update" },
		"actor id":     func(e *audit.Event) { e.Actor.ID = "al\x00ice" },
		"resource":     func(e *audit.Event) { e.Resource = audit.Resource{Type: "menu", ID: "m\x001"} },
		"user agent":   func(e *audit.Event) { e.UserAgent = "ua\x00" },
		"request":      func(e *audit.Event) { e.Request = json.RawMessage(`{"name":"a\u0000b"}`) },
		"request key":  func(e *audit.Event) { e.Request = json.RawMessage(`{"a\u0000":1}`) },
		"id":           func(e *audit.Event) { e.ID = "id\x00" },
		"display":      func(e *audit.Event) { e.Actor.Display = "\x00" },
		"on behalf of": func(e *audit.Event) { e.OnBehalfOf = "\x00" },
	} {
		if _, err := svc.Begin(ctx, action(mod)); !errors.Is(err, audit.ErrInvalidEvent) {
			t.Errorf("Begin with a NUL in the %s: err = %v, want ErrInvalidEvent", name, err)
		}
	}
	if _, err := svc.Record(ctx, action(func(e *audit.Event) {
		e.Outcome, e.Changes = audit.OutcomeOK, json.RawMessage(`{"x":{"before":"\u0000","after":1}}`)
	})); !errors.Is(err, audit.ErrInvalidEvent) {
		t.Errorf("Record with a NUL in Changes: err = %v, want ErrInvalidEvent", err)
	}
	// An escaped backslash before u0000 is plain text, not a NUL.
	if _, err := svc.Begin(ctx, action(func(e *audit.Event) { e.Request = json.RawMessage(`{"path":"C:\\u0000"}`) })); err != nil {
		t.Errorf("Begin with an escaped backslash: %v", err)
	}
	open, err := svc.Begin(ctx, action())
	if err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]audit.Completion{
		"reason":   {Outcome: audit.OutcomeOK, Reason: "\x00"},
		"code":     {Outcome: audit.OutcomeOK, Code: "\x00"},
		"resource": {Outcome: audit.OutcomeOK, Resource: audit.Resource{Type: "menu", ID: "\x00"}},
		"after":    {Outcome: audit.OutcomeOK, After: json.RawMessage(`{"a":"\u0000"}`)},
	} {
		if err := svc.Complete(ctx, open.ID, c); !errors.Is(err, audit.ErrInvalidEvent) {
			t.Errorf("Complete with a NUL in the %s: err = %v, want ErrInvalidEvent", name, err)
		}
	}
}

func TestBeginIsIdempotentOnTheCallersID(t *testing.T) {
	svc, st, _ := newService(t)
	ctx := context.Background()
	e := action(func(e *audit.Event) { e.ID = "0192a3b4-c5d6-7e8f-9a0b-1c2d3e4f5a6b" })
	first, err := svc.Begin(ctx, e)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	second, err := svc.Begin(ctx, e)
	if err != nil || second.Seq != first.Seq {
		t.Errorf("retried Begin = seq %d, %v; want seq %d", second.Seq, err, first.Seq)
	}
	if n, _ := st.Count(ctx, audit.Filter{}); n != 1 {
		t.Errorf("events = %d, want 1", n)
	}
}

func TestCompleteStoresTheRedactedDiff(t *testing.T) {
	svc, _, clk := newService(t)
	ctx := context.Background()
	e, err := svc.Begin(ctx, action())
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	clk.Advance(time.Second)
	err = svc.Complete(ctx, e.ID, audit.Completion{
		Outcome: audit.OutcomeOK, DurationMS: 40,
		Before: json.RawMessage(`{"role":"viewer","password":"a"}`),
		After:  json.RawMessage(`{"role":"editor","password":"b"}`),
	})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	got, _ := svc.Get(ctx, e.ID)
	if !audit.EqualJSON(got.Changes, json.RawMessage(`{"role":{"before":"viewer","after":"editor"},"password":"[REDACTED]"}`)) {
		t.Errorf("Changes = %s, want the role change and the password change with its values withheld", got.Changes)
	}
	if got.CompletedAt == nil || !got.CompletedAt.Equal(clk.Now().Truncate(time.Microsecond)) || got.DurationMS != 40 {
		t.Errorf("completion = %v / %d", got.CompletedAt, got.DurationMS)
	}
}

func TestCompleteWritesOnce(t *testing.T) {
	svc, _, _ := newService(t)
	ctx := context.Background()
	e, _ := svc.Begin(ctx, action())
	c := audit.Completion{Outcome: audit.OutcomeDenied, Code: "permission_denied"}
	if err := svc.Complete(ctx, e.ID, c); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if err := svc.Complete(ctx, e.ID, c); err != nil {
		t.Errorf("identical retry err = %v, want nil", err)
	}
	if err := svc.Complete(ctx, e.ID, audit.Completion{Outcome: audit.OutcomeOK}); !errors.Is(err, audit.ErrCompleted) {
		t.Errorf("conflicting Complete err = %v, want ErrCompleted", err)
	}
	if err := svc.Complete(ctx, e.ID, audit.Completion{}); !errors.Is(err, audit.ErrInvalidEvent) {
		t.Errorf("Complete without outcome err = %v, want ErrInvalidEvent", err)
	}
	if err := svc.Complete(ctx, "0192a3b4-0000-7000-8000-000000000000", c); !errors.Is(err, audit.ErrNotFound) {
		t.Errorf("Complete(unknown) err = %v, want ErrNotFound", err)
	}
}

func TestRecordStoresACompletedEvent(t *testing.T) {
	svc, _, _ := newService(t)
	ctx := context.Background()
	e, err := svc.Record(ctx, action(func(e *audit.Event) {
		e.Topic, e.Action, e.Outcome, e.Reason = "auth", "auth.login_failed", audit.OutcomeDenied, "wrong_password"
		e.Request = json.RawMessage(`{"token":"t"}`)
	}))
	if err != nil {
		t.Fatalf("Record: %v", err)
	}
	if e.CompletedAt == nil || !e.CompletedAt.Equal(e.OccurredAt) || e.Outcome != audit.OutcomeDenied {
		t.Errorf("Record = %+v, want completed at OccurredAt", e)
	}
	if !audit.EqualJSON(e.Request, json.RawMessage(`{"token":"[REDACTED]"}`)) {
		t.Errorf("Request = %s", e.Request)
	}
	if _, err := svc.Record(ctx, action()); !errors.Is(err, audit.ErrInvalidEvent) {
		t.Errorf("Record without outcome err = %v, want ErrInvalidEvent", err)
	}
}

func TestTopicsReportEffectiveRetention(t *testing.T) {
	svc, _, _ := newService(t, audit.WithDefaultRetention(90*24*time.Hour))
	got := svc.Topics()
	want := []audit.Topic{{Key: "auth", Retention: thirtyDays}, {Key: "menus", Retention: 90 * 24 * time.Hour}}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("Topics = %+v, want %+v", got, want)
	}
}

func TestBeginAndRecordRefuseAnIDTakenByAnotherEvent(t *testing.T) {
	svc, st, _ := newService(t)
	ctx := context.Background()
	const id = "0192a3b4-c5d6-7e8f-9a0b-1c2d3e4f5a6c"
	if _, err := svc.Begin(ctx, action(func(e *audit.Event) { e.ID = id })); err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if _, err := svc.Begin(ctx, action(func(e *audit.Event) { e.ID, e.Action, e.Actor.ID = id, "menu.delete", "mallory" })); !errors.Is(err, audit.ErrInvalidEvent) {
		t.Errorf("Begin of another event under a taken id err = %v, want ErrInvalidEvent", err)
	}
	if _, err := svc.Record(ctx, action(func(e *audit.Event) { e.ID, e.Outcome = id, audit.OutcomeFailed })); !errors.Is(err, audit.ErrInvalidEvent) {
		t.Errorf("Record over an open event's id err = %v, want ErrInvalidEvent", err)
	}
	if n, _ := st.Count(ctx, audit.Filter{}); n != 1 {
		t.Errorf("events = %d, want 1", n)
	}
}
