// Package audittest is the executable contract for
// [github.com/bernardoforcillo/authlayer/audit.Store].
//
// Write one test per backend:
//
//	func TestMyStoreSatisfiesTheAuditContract(t *testing.T) {
//	    audittest.RunStoreContract(t, func(t *testing.T) audit.Store {
//	        return myStoreWithEmptyTables(t)
//	    })
//	}
//
// The factory is called once per check and MUST return an EMPTY store: the
// checks count rows. Register teardown with t.Cleanup inside the factory; a
// factory may t.Skip. Event ids are UUIDv7, so the suite runs against a
// backend that types ids as uuid; every other reference is an opaque string.
// Times are UTC and truncated to the microsecond, as the Service writes
// them.
package audittest

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/bernardoforcillo/authlayer/audit"
	"github.com/bernardoforcillo/authlayer/internal/uid"
)

// tb is the subset of *testing.T the checks use, so this package's own tests
// can run a check against a broken store and assert that it fails.
type tb interface {
	Helper()
	Errorf(format string, args ...any)
	Fatalf(format string, args ...any)
}

type check struct {
	name string
	fn   func(t tb, st audit.Store)
}

// RunStoreContract runs every check against a fresh store from newStore.
func RunStoreContract(t *testing.T, newStore func(t *testing.T) audit.Store) {
	t.Helper()
	for _, c := range checks {
		t.Run(c.name, func(t *testing.T) { c.fn(t, newStore(t)) })
	}
}

var checks = []check{
	{"Insert/AssignsIncreasingSeq", insertAssignsIncreasingSeq},
	{"Insert/ExistingIDReturnsTheStoredRow", insertExistingIDReturnsStoredRow},
	{"Insert/RefusesASealedDay", insertRefusesASealedDay},
	{"Insert/RoundTripsEveryField", insertRoundTripsEveryField},
	{"Get/UnknownIsErrNotFound", getUnknownIsErrNotFound},
	{"Complete/WritesOnce", completeWritesOnce},
	{"Complete/IdenticalRetryIsNil", completeIdenticalRetryIsNil},
	{"Complete/FillsOnlyEmptyResourceAndContainer", completeFillsOnlyEmpty},
	{"Complete/UnknownIsErrNotFound", completeUnknownIsErrNotFound},
	{"List/NewestFirstWithCursor", listNewestFirstWithCursor},
	{"Filter/FollowsTheReferenceSemantics", filterFollowsReference},
	{"Scan/AscendingAndStopsOnError", scanAscendingAndStops},
	{"OpenBefore/OldestOpenFirst", openBeforeOldestOpenFirst},
	{"Seals/InsertOnceListAndLast", sealsInsertOnceListAndLast},
	{"Purge/DeletesOnlyTheTopicBeforeInBatches", purgeDeletesOnlyTopicBefore},
	{"MarkPurged/StampsOnlyEarlierUnpurged", markPurgedStampsOnlyEarlier},
}

var day0 = time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC)

func ev(topic string, at time.Time, mods ...func(*audit.Event)) audit.Event {
	e := audit.Event{
		ID: uid.NewV7(), OccurredAt: at.UTC().Truncate(time.Microsecond),
		Topic: topic, Action: "thing.do", Source: audit.SourceServer, Origin: "audittest",
		Actor: audit.Actor{Type: audit.ActorUser, ID: "u1"},
	}
	for _, m := range mods {
		m(&e)
	}
	return e
}

func closeAs(o audit.Outcome) func(*audit.Event) {
	return func(e *audit.Event) {
		at := e.OccurredAt
		e.CompletedAt, e.Outcome, e.DurationMS = &at, o, 7
	}
}

func mustInsert(t tb, st audit.Store, e audit.Event) audit.Event {
	t.Helper()
	got, err := st.Insert(context.Background(), e)
	if err != nil {
		t.Fatalf("Insert(%s): %v", e.Action, err)
	}
	return got
}

func ids(events []audit.Event) []string {
	out := make([]string, len(events))
	for i, e := range events {
		out[i] = e.ID
	}
	return out
}

func timesEqual(a, b *time.Time) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Equal(*b)
}

// diffEvent names the first field where got differs from want; Seq is not
// compared.
func diffEvent(got, want audit.Event) string {
	switch {
	case got.ID != want.ID:
		return "ID"
	case !got.OccurredAt.Equal(want.OccurredAt):
		return "OccurredAt"
	case !timesEqual(got.CompletedAt, want.CompletedAt):
		return "CompletedAt"
	case got.Topic != want.Topic || got.Action != want.Action || got.Source != want.Source ||
		got.Origin != want.Origin || got.Procedure != want.Procedure:
		return "Topic/Action/Source/Origin/Procedure"
	case got.Actor != want.Actor || got.OnBehalfOf != want.OnBehalfOf || got.SessionID != want.SessionID:
		return "Actor/OnBehalfOf/SessionID"
	case got.ContainerID != want.ContainerID || got.Resource != want.Resource:
		return "ContainerID/Resource"
	case got.Outcome != want.Outcome || got.Code != want.Code || got.Reason != want.Reason ||
		got.DurationMS != want.DurationMS:
		return "Outcome/Code/Reason/DurationMS"
	case !audit.EqualJSON(got.Request, want.Request) || !audit.EqualJSON(got.Changes, want.Changes):
		return "Request/Changes"
	case got.IP != want.IP || got.UserAgent != want.UserAgent || !timesEqual(got.ClientTime, want.ClientTime):
		return "IP/UserAgent/ClientTime"
	}
	return ""
}

func insertAssignsIncreasingSeq(t tb, st audit.Store) {
	a := mustInsert(t, st, ev("t", day0))
	b := mustInsert(t, st, ev("t", day0.Add(time.Minute)))
	if a.Seq <= 0 || b.Seq <= a.Seq {
		t.Errorf("Seq = %d then %d, want positive and increasing", a.Seq, b.Seq)
	}
}

func insertExistingIDReturnsStoredRow(t tb, st audit.Store) {
	ctx := context.Background()
	e := ev("t", day0)
	first := mustInsert(t, st, e)
	again := e
	again.Action = "other.action"
	got, err := st.Insert(ctx, again)
	if err != nil {
		t.Fatalf("second Insert: %v", err)
	}
	if got.Seq != first.Seq || got.Action != first.Action {
		t.Errorf("second Insert = seq %d action %q, want the stored seq %d action %q", got.Seq, got.Action, first.Seq, first.Action)
	}
	if n, err := st.Count(ctx, audit.Filter{}); err != nil || n != 1 {
		t.Errorf("Count = %d, %v; want 1", n, err)
	}
}

func insertRefusesASealedDay(t tb, st audit.Store) {
	ctx := context.Background()
	if err := st.InsertSeal(ctx, audit.Seal{Topic: "t", Day: day0, EventsHash: "e", SealHash: "s", SealedAt: day0.Add(48 * time.Hour)}); err != nil {
		t.Fatalf("InsertSeal: %v", err)
	}
	for _, at := range []time.Time{day0, day0.Add(5 * time.Hour), day0.Add(24*time.Hour - time.Microsecond)} {
		refused := ev("t", at)
		if _, err := st.Insert(ctx, refused); !errors.Is(err, audit.ErrSealed) {
			t.Errorf("Insert at %s into a sealed day err = %v, want ErrSealed", at.Format(time.RFC3339Nano), err)
		}
		if _, err := st.Get(ctx, refused.ID); !errors.Is(err, audit.ErrNotFound) {
			t.Errorf("the event refused at %s was stored anyway: Get err = %v, want ErrNotFound", at.Format(time.RFC3339Nano), err)
		}
	}
	mustInsert(t, st, ev("other", day0.Add(5*time.Hour)))
	mustInsert(t, st, ev("t", day0.Add(-time.Microsecond)))
	mustInsert(t, st, ev("t", day0.Add(24*time.Hour)))
}

func insertRoundTripsEveryField(t tb, st audit.Store) {
	ctx := context.Background()
	clientAt := day0.Add(-time.Second)
	full := ev("t", day0, closeAs(audit.OutcomeDenied), func(e *audit.Event) {
		e.Source, e.Procedure = audit.SourceClient, "/svc/Do"
		e.Actor = audit.Actor{Type: audit.ActorUser, ID: "u1", Display: "u1@example.com"}
		e.OnBehalfOf, e.SessionID, e.ContainerID = "u2", "s1", "org1"
		e.Resource = audit.Resource{Type: "menu", ID: "m1"}
		e.Code, e.Reason = "permission_denied", "nope"
		e.Request = json.RawMessage(`{"a":1,"b":[true,null],"n":12345678901234567890}`)
		e.Changes = json.RawMessage(`{"x":{"before":1,"after":2}}`)
		e.IP, e.UserAgent, e.ClientTime = "203.0.113.7", "agent/1", &clientAt
	})
	bare := ev("t", day0.Add(time.Minute))
	for _, want := range []audit.Event{full, bare} {
		got := mustInsert(t, st, want)
		back, err := st.Get(ctx, want.ID)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		for name, e := range map[string]audit.Event{"Insert": got, "Get": back} {
			if field := diffEvent(e, want); field != "" {
				t.Errorf("%s of %s: %s differs: got %+v want %+v", name, want.Action, field, e, want)
			}
		}
	}
}

func getUnknownIsErrNotFound(t tb, st audit.Store) {
	if _, err := st.Get(context.Background(), uid.NewV7()); !errors.Is(err, audit.ErrNotFound) {
		t.Errorf("Get(unknown) err = %v, want ErrNotFound", err)
	}
}

func completeWritesOnce(t tb, st audit.Store) {
	ctx := context.Background()
	e := mustInsert(t, st, ev("t", day0))
	c := audit.Closing{At: day0.Add(time.Second), Outcome: audit.OutcomeOK, Code: "c1", Reason: "r",
		Changes: json.RawMessage(`{"k":{"before":null,"after":1}}`), DurationMS: 12}
	got, err := st.Complete(ctx, e.ID, c)
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	want := e
	at := c.At
	want.CompletedAt, want.Outcome, want.Code, want.Reason, want.Changes, want.DurationMS = &at, c.Outcome, c.Code, c.Reason, c.Changes, c.DurationMS
	back, err := st.Get(ctx, e.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	for name, x := range map[string]audit.Event{"Complete": got, "Get": back} {
		if field := diffEvent(x, want); field != "" {
			t.Errorf("%s after Complete: %s differs: got %+v want %+v", name, field, x, want)
		}
	}
	if _, err := st.Complete(ctx, e.ID, audit.Closing{At: day0.Add(time.Hour), Outcome: audit.OutcomeFailed}); !errors.Is(err, audit.ErrCompleted) {
		t.Errorf("conflicting Complete err = %v, want ErrCompleted", err)
	}
	after, err := st.Get(ctx, e.ID)
	if err != nil {
		t.Fatalf("Get after the conflicting Complete: %v", err)
	}
	if field := diffEvent(after, want); field != "" {
		t.Errorf("a conflicting Complete changed %s: got %+v want %+v", field, after, want)
	}
}

func completeIdenticalRetryIsNil(t tb, st audit.Store) {
	ctx := context.Background()
	e := mustInsert(t, st, ev("t", day0))
	c := audit.Closing{At: day0.Add(time.Second), Outcome: audit.OutcomeDenied, Code: "permission_denied", Reason: "r",
		Changes: json.RawMessage(`{"k":{"before":1,"after":2}}`), DurationMS: 3}
	first, err := st.Complete(ctx, e.ID, c)
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	retry := c
	retry.At = day0.Add(time.Minute)
	retry.Changes = json.RawMessage(`{ "k": { "after": 2, "before": 1 } }`) // the same JSON value, spelled differently
	got, err := st.Complete(ctx, e.ID, retry)
	if err != nil {
		t.Fatalf("identical retry err = %v, want nil", err)
	}
	if field := diffEvent(got, first); field != "" {
		t.Errorf("identical retry changed %s: got %+v want %+v", field, got, first)
	}
}

func completeFillsOnlyEmpty(t tb, st audit.Store) {
	ctx := context.Background()
	named := mustInsert(t, st, ev("t", day0, func(e *audit.Event) {
		e.Resource, e.ContainerID = audit.Resource{Type: "menu", ID: "m1"}, "org1"
	}))
	bare := mustInsert(t, st, ev("t", day0))
	c := audit.Closing{At: day0.Add(time.Second), Outcome: audit.OutcomeOK,
		Resource: audit.Resource{Type: "lot", ID: "l9"}, ContainerID: "org9"}
	a, err := st.Complete(ctx, named.ID, c)
	if err != nil {
		t.Fatalf("Complete(named): %v", err)
	}
	if a.Resource != (audit.Resource{Type: "menu", ID: "m1"}) || a.ContainerID != "org1" {
		t.Errorf("named event = %+v / %q, want its own resource and container kept", a.Resource, a.ContainerID)
	}
	b, err := st.Complete(ctx, bare.ID, c)
	if err != nil {
		t.Fatalf("Complete(bare): %v", err)
	}
	if b.Resource != c.Resource || b.ContainerID != "org9" {
		t.Errorf("bare event = %+v / %q, want the closing's resource and container", b.Resource, b.ContainerID)
	}
}

func completeUnknownIsErrNotFound(t tb, st audit.Store) {
	_, err := st.Complete(context.Background(), uid.NewV7(), audit.Closing{At: day0, Outcome: audit.OutcomeOK})
	if !errors.Is(err, audit.ErrNotFound) {
		t.Errorf("Complete(unknown) err = %v, want ErrNotFound", err)
	}
}

func listNewestFirstWithCursor(t tb, st audit.Store) {
	ctx := context.Background()
	// Times out of insertion order, so Seq order and time order differ.
	var seqs []int64
	for _, m := range []int{3, 1, 4, 0, 2} {
		seqs = append(seqs, mustInsert(t, st, ev("t", day0.Add(time.Duration(m)*time.Minute))).Seq)
	}
	want := slices.Clone(seqs)
	slices.Reverse(want)
	var got []int64
	before := int64(0)
	for range len(seqs) + 1 {
		page, err := st.List(ctx, audit.Filter{}, audit.Page{Before: before, Limit: 2})
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		if len(page) > 2 {
			t.Fatalf("List with Limit 2 returned %d events", len(page))
		}
		for _, e := range page {
			got = append(got, e.Seq)
		}
		if len(page) < 2 {
			break
		}
		before = page[len(page)-1].Seq
	}
	if !slices.Equal(got, want) {
		t.Errorf("pages = %v, want %v (Seq descending)", got, want)
	}
	for _, limit := range []int{0, -1, audit.MaxPageSize + 1} {
		all, err := st.List(ctx, audit.Filter{}, audit.Page{Limit: limit})
		if err != nil || len(all) != len(seqs) {
			t.Errorf("List with Limit %d = %d events, %v; want all %d (MaxPageSize applies)", limit, len(all), err, len(seqs))
		}
	}
}

func filterFixture(t tb, st audit.Store) []audit.Event {
	ok := audit.OutcomeOK
	specs := []audit.Event{
		ev("a", day0.Add(1*time.Hour), closeAs(ok), func(e *audit.Event) {
			e.ContainerID, e.Actor.ID, e.Action = "org1", "u1", "menu.update"
		}),
		ev("a", day0.Add(2*time.Hour), closeAs(audit.OutcomeDenied), func(e *audit.Event) {
			e.ContainerID, e.Actor.ID, e.Action = "org2", "u2", "menu.delete"
		}),
		ev("b", day0.Add(3*time.Hour), func(e *audit.Event) {
			e.ContainerID, e.Actor, e.OnBehalfOf, e.Action = "org1", audit.Actor{Type: audit.ActorUser, ID: "admin"}, "u2", "lot.create"
		}),
		ev("b", day0.Add(4*time.Hour), closeAs(audit.OutcomeDenied), func(e *audit.Event) {
			e.Actor, e.Action = audit.Actor{Type: audit.ActorAnonymous}, "auth.login_failed"
			e.Resource = audit.Resource{Type: audit.ResourceUser, ID: "u2"}
		}),
		ev("c", day0.Add(5*time.Hour), closeAs(audit.OutcomeUnknown), func(e *audit.Event) {
			e.Resource, e.Source, e.Action = audit.Resource{Type: "menu", ID: "m1"}, audit.SourceClient, "a_b%c.x"
		}),
		ev("c", day0.Add(26*time.Hour), closeAs(ok), func(e *audit.Event) {
			e.Resource, e.Action = audit.Resource{Type: "menu", ID: "m2"}, "axb%c.x"
		}),
		ev("c", day0.Add(27*time.Hour), closeAs(audit.OutcomeFailed), func(e *audit.Event) { e.Action = "a_bzc" }),
	}
	out := make([]audit.Event, 0, len(specs))
	for _, e := range specs {
		out = append(out, mustInsert(t, st, e))
	}
	return out
}

var filters = []struct {
	name string
	f    audit.Filter
}{
	{"all", audit.Filter{}},
	{"topic", audit.Filter{Topics: []string{"a"}}},
	{"topics", audit.Filter{Topics: []string{"a", "c"}}},
	{"from", audit.Filter{From: day0.Add(3 * time.Hour)}},
	{"to", audit.Filter{To: day0.Add(3 * time.Hour)}},
	{"from-to", audit.Filter{From: day0.Add(2 * time.Hour), To: day0.Add(26 * time.Hour)}},
	{"container", audit.Filter{ContainerID: "org1"}},
	{"member", audit.Filter{Member: "u2"}},
	{"actor", audit.Filter{ActorID: "u2"}},
	{"resource-type", audit.Filter{Resource: audit.Resource{Type: "menu"}}},
	{"resource", audit.Filter{Resource: audit.Resource{Type: "menu", ID: "m1"}}},
	{"outcome", audit.Filter{Outcomes: []audit.Outcome{audit.OutcomeDenied}}},
	{"outcomes", audit.Filter{Outcomes: []audit.Outcome{audit.OutcomeOK, audit.OutcomeUnknown}}},
	{"source", audit.Filter{Source: audit.SourceClient}},
	{"action-prefix", audit.Filter{ActionPrefix: "menu."}},
	{"action-prefix-is-literal", audit.Filter{ActionPrefix: "a_b%"}},
	{"combined", audit.Filter{Topics: []string{"a", "b"}, ContainerID: "org1", Member: "u2"}},
}

func filterFollowsReference(t tb, st audit.Store) {
	ctx := context.Background()
	stored := filterFixture(t, st)
	for _, tc := range filters {
		var want []audit.Event
		for _, e := range stored {
			if tc.f.Match(e) {
				want = append(want, e)
			}
		}
		slices.SortFunc(want, func(a, b audit.Event) int { return int(b.Seq - a.Seq) })
		got, err := st.List(ctx, tc.f, audit.Page{Limit: audit.MaxPageSize})
		if err != nil {
			t.Fatalf("%s: List: %v", tc.name, err)
		}
		if !slices.Equal(ids(got), ids(want)) {
			t.Errorf("%s: List = %v, want %v", tc.name, ids(got), ids(want))
		}
		if n, err := st.Count(ctx, tc.f); err != nil || n != len(want) {
			t.Errorf("%s: Count = %d, %v; want %d", tc.name, n, err, len(want))
		}
	}
}

func scanAscendingAndStops(t tb, st audit.Store) {
	ctx := context.Background()
	for _, at := range []time.Duration{3 * time.Hour, time.Hour, 2 * time.Hour} {
		mustInsert(t, st, ev("t", day0.Add(at)))
	}
	var seqs []int64
	if err := st.Scan(ctx, audit.Filter{}, func(e audit.Event) error { seqs = append(seqs, e.Seq); return nil }); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(seqs) != 3 || !slices.IsSorted(seqs) {
		t.Errorf("Scan seqs = %v, want 3 ascending", seqs)
	}
	stop := errors.New("stop")
	calls := 0
	err := st.Scan(ctx, audit.Filter{}, func(audit.Event) error { calls++; return stop })
	// The port returns fn's error unwrapped, so compare by identity.
	if err != stop || calls != 1 {
		t.Errorf("Scan with a failing fn = %v after %d calls, want stop after 1", err, calls)
	}
}

func openBeforeOldestOpenFirst(t tb, st audit.Store) {
	ctx := context.Background()
	old1 := mustInsert(t, st, ev("t", day0))
	old2 := mustInsert(t, st, ev("t", day0.Add(time.Minute)))
	mustInsert(t, st, ev("t", day0.Add(2*time.Minute), closeAs(audit.OutcomeOK)))
	mustInsert(t, st, ev("t", day0.Add(10*time.Hour)))
	got, err := st.OpenBefore(ctx, day0.Add(time.Hour), 10)
	if err != nil {
		t.Fatalf("OpenBefore: %v", err)
	}
	if !slices.Equal(got, []string{old1.ID, old2.ID}) {
		t.Errorf("OpenBefore = %v, want [%s %s]", got, old1.ID, old2.ID)
	}
	if got, _ := st.OpenBefore(ctx, day0.Add(time.Hour), 1); !slices.Equal(got, []string{old1.ID}) {
		t.Errorf("OpenBefore limit 1 = %v, want [%s]", got, old1.ID)
	}
}

func seal(topic string, d time.Time, prev, hash string) audit.Seal {
	return audit.Seal{Topic: topic, Day: d, EventCount: 2, FirstSeq: 1, LastSeq: 2,
		EventsHash: "e-" + hash, PrevHash: prev, SealHash: hash, SealedAt: d.Add(30 * time.Hour)}
}

func sealsInsertOnceListAndLast(t tb, st audit.Store) {
	ctx := context.Background()
	s1, s2 := seal("t", day0, "", "s1"), seal("t", day0.Add(24*time.Hour), "s1", "s2")
	for _, s := range []audit.Seal{s1, s2} {
		if err := st.InsertSeal(ctx, s); err != nil {
			t.Fatalf("InsertSeal: %v", err)
		}
	}
	if err := st.InsertSeal(ctx, s1); !errors.Is(err, audit.ErrSealExists) {
		t.Errorf("duplicate InsertSeal err = %v, want ErrSealExists", err)
	}
	if _, err := st.LastSeal(ctx, "other"); !errors.Is(err, audit.ErrNotFound) {
		t.Errorf("LastSeal(other) err = %v, want ErrNotFound", err)
	}
	last, err := st.LastSeal(ctx, "t")
	if err != nil || last.SealHash != "s2" || !last.Day.Equal(s2.Day) || last.PrevHash != "s1" || last.EventCount != 2 {
		t.Errorf("LastSeal = %+v, %v; want s2", last, err)
	}
	all, err := st.Seals(ctx, "t", day0, day0.Add(24*time.Hour))
	if err != nil || len(all) != 2 || all[0].SealHash != "s1" || all[1].SealHash != "s2" {
		t.Errorf("Seals = %+v, %v; want [s1 s2]", all, err)
	}
	if one, _ := st.Seals(ctx, "t", day0.Add(24*time.Hour), day0.Add(24*time.Hour)); len(one) != 1 || one[0].SealHash != "s2" {
		t.Errorf("Seals(day1) = %+v, want [s2]", one)
	}
}

func purgeDeletesOnlyTopicBefore(t tb, st audit.Store) {
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		mustInsert(t, st, ev("t", day0.Add(time.Duration(i)*time.Hour), closeAs(audit.OutcomeOK)))
	}
	mustInsert(t, st, ev("t", day0.Add(25*time.Hour), closeAs(audit.OutcomeOK)))
	mustInsert(t, st, ev("u", day0.Add(time.Hour), closeAs(audit.OutcomeOK)))
	before := day0.Add(24 * time.Hour)
	for _, want := range []int{2, 3, 0} {
		batch := 2
		if want != 2 {
			batch = 10
		}
		n, err := st.Purge(ctx, "t", before, batch)
		if err != nil || n != want {
			t.Fatalf("Purge(batch %d) = %d, %v; want %d", batch, n, err, want)
		}
	}
	if n, _ := st.Count(ctx, audit.Filter{Topics: []string{"t"}}); n != 1 {
		t.Errorf("topic t left %d events, want 1 (the next day's)", n)
	}
	if n, _ := st.Count(ctx, audit.Filter{Topics: []string{"u"}}); n != 1 {
		t.Errorf("topic u left %d events, want 1", n)
	}
}

func markPurgedStampsOnlyEarlier(t tb, st audit.Store) {
	ctx := context.Background()
	for i, h := range []string{"s1", "s2", "s3"} {
		if err := st.InsertSeal(ctx, seal("t", day0.Add(time.Duration(i)*24*time.Hour), "", h)); err != nil {
			t.Fatalf("InsertSeal: %v", err)
		}
	}
	if err := st.InsertSeal(ctx, seal("u", day0, "", "u1")); err != nil {
		t.Fatalf("InsertSeal: %v", err)
	}
	first, second := day0.Add(100*time.Hour), day0.Add(200*time.Hour)
	for _, at := range []time.Time{first, second} {
		if err := st.MarkPurged(ctx, "t", day0.Add(48*time.Hour), at); err != nil {
			t.Fatalf("MarkPurged: %v", err)
		}
	}
	seals, err := st.Seals(ctx, "t", day0, day0.Add(48*time.Hour))
	if err != nil || len(seals) != 3 {
		t.Fatalf("Seals = %d, %v; want 3", len(seals), err)
	}
	for i, s := range seals[:2] {
		if s.PurgedAt == nil || !s.PurgedAt.Equal(first) {
			t.Errorf("seal %d PurgedAt = %v, want the first stamp %v", i, s.PurgedAt, first)
		}
	}
	if seals[2].PurgedAt != nil {
		t.Errorf("day 2 PurgedAt = %v, want nil", seals[2].PurgedAt)
	}
	if u, _ := st.Seals(ctx, "u", day0, day0); len(u) != 1 || u[0].PurgedAt != nil {
		t.Errorf("topic u seal = %+v, want unpurged", u)
	}
}
