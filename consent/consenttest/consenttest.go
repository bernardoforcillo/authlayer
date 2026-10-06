// Package consenttest is the executable contract for
// [github.com/bernardoforcillo/authlayer/consent.Store]:
//
//	func TestMyStoreSatisfiesTheConsentContract(t *testing.T) {
//	    consenttest.RunStoreContract(t, func(t *testing.T) consent.Store {
//	        return myStoreWithEmptyTables(t)
//	    })
//	}
//
// The factory is called once per check and MUST return an EMPTY store.
package consenttest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/bernardoforcillo/authlayer/consent"
)

var t0 = time.Date(2026, 3, 1, 9, 0, 0, 0, time.UTC)

func rec(id, subject, purpose, version string, at time.Time) consent.Record {
	return consent.Record{ID: id, SubjectID: subject, Purpose: purpose, Version: version, Source: "test", GrantedAt: at}
}

// RunStoreContract runs every check against a fresh store from newStore.
func RunStoreContract(t *testing.T, newStore func(t *testing.T) consent.Store) {
	t.Helper()
	for _, c := range []struct {
		name string
		fn   func(t *testing.T, st consent.Store)
	}{
		{"Current/UnknownIsErrNotFound", currentUnknown},
		{"Insert/RoundTripsEveryField", roundTrip},
		{"Insert/RefusesASecondCurrentRecord", insertConflict},
		{"End/EndsOnlyTheCurrentRecordOfThatSubjectAndPurpose", endScope},
		{"List/OldestFirstAndOnlyThatSubject", listOrder},
		{"DeleteSubject/DeletesOnlyThatSubject", deleteSubject},
	} {
		t.Run(c.name, func(t *testing.T) { c.fn(t, newStore(t)) })
	}
}

func currentUnknown(t *testing.T, st consent.Store) {
	if _, err := st.Current(context.Background(), "u1", "terms"); !errors.Is(err, consent.ErrNotFound) {
		t.Errorf("Current(unknown) err = %v, want ErrNotFound", err)
	}
}

func roundTrip(t *testing.T, st consent.Store) {
	ctx := context.Background()
	r := rec("r1", "u1", "terms", "v1", t0)
	if err := st.Insert(ctx, r); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	got, err := st.Current(ctx, "u1", "terms")
	if err != nil || got.ID != "r1" || got.Version != "v1" || got.Source != "test" || !got.GrantedAt.Equal(t0) || got.EndedAt != nil || got.EndReason != "" {
		t.Errorf("Current = %+v, %v; want %+v", got, err, r)
	}
}

func endScope(t *testing.T, st consent.Store) {
	ctx := context.Background()
	for _, r := range []consent.Record{
		rec("a", "u1", "terms", "v1", t0), rec("b", "u1", "marketing", "v1", t0), rec("c", "u2", "terms", "v1", t0),
	} {
		if err := st.Insert(ctx, r); err != nil {
			t.Fatalf("Insert: %v", err)
		}
	}
	end := t0.Add(time.Hour)
	if n, err := st.End(ctx, "u1", "terms", end, consent.EndWithdrawn); err != nil || n != 1 {
		t.Fatalf("End = %d, %v; want 1", n, err)
	}
	if n, err := st.End(ctx, "u1", "terms", end, consent.EndWithdrawn); err != nil || n != 0 {
		t.Errorf("second End = %d, %v; want 0", n, err)
	}
	if _, err := st.Current(ctx, "u1", "terms"); !errors.Is(err, consent.ErrNotFound) {
		t.Errorf("Current after End err = %v, want ErrNotFound", err)
	}
	for _, other := range [][2]string{{"u1", "marketing"}, {"u2", "terms"}} {
		if _, err := st.Current(ctx, other[0], other[1]); err != nil {
			t.Errorf("Current(%v) after an unrelated End: %v", other, err)
		}
	}
	all, _ := st.List(ctx, "u1")
	for _, r := range all {
		if r.ID == "a" && (r.EndedAt == nil || !r.EndedAt.Equal(end) || r.EndReason != consent.EndWithdrawn) {
			t.Errorf("ended record = %+v", r)
		}
	}
}

func listOrder(t *testing.T, st consent.Store) {
	ctx := context.Background()
	ended := t0.Add(time.Hour)
	early := rec("early", "u1", "terms", "v1", t0)
	early.EndedAt, early.EndReason = &ended, consent.EndSuperseded
	for _, r := range []consent.Record{
		rec("late", "u1", "terms", "v2", t0.Add(2*time.Hour)), early,
		rec("other", "u2", "terms", "v1", t0),
	} {
		if err := st.Insert(ctx, r); err != nil {
			t.Fatalf("Insert: %v", err)
		}
	}
	got, err := st.List(ctx, "u1")
	if err != nil || len(got) != 2 || got[0].ID != "early" || got[1].ID != "late" {
		t.Errorf("List = %+v, %v; want [early late]", got, err)
	}
	if none, err := st.List(ctx, "nobody"); err != nil || len(none) != 0 {
		t.Errorf("List(nobody) = %+v, %v", none, err)
	}
}

func deleteSubject(t *testing.T, st consent.Store) {
	ctx := context.Background()
	for _, r := range []consent.Record{rec("a", "u1", "terms", "v1", t0), rec("b", "u1", "marketing", "v1", t0), rec("c", "u2", "terms", "v1", t0)} {
		if err := st.Insert(ctx, r); err != nil {
			t.Fatalf("Insert: %v", err)
		}
	}
	if n, err := st.DeleteSubject(ctx, "u1"); err != nil || n != 2 {
		t.Fatalf("DeleteSubject = %d, %v; want 2", n, err)
	}
	if got, _ := st.List(ctx, "u1"); len(got) != 0 {
		t.Errorf("u1 still has %d records", len(got))
	}
	if got, _ := st.List(ctx, "u2"); len(got) != 1 {
		t.Errorf("u2 has %d records, want 1", len(got))
	}
}

func insertConflict(t *testing.T, st consent.Store) {
	ctx := context.Background()
	if err := st.Insert(ctx, rec("a", "u1", "terms", "v1", t0)); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	if err := st.Insert(ctx, rec("b", "u1", "terms", "v2", t0)); !errors.Is(err, consent.ErrConflict) {
		t.Errorf("second current Insert err = %v, want ErrConflict", err)
	}
	if err := st.Insert(ctx, rec("c", "u1", "marketing", "v1", t0)); err != nil {
		t.Errorf("another purpose: %v", err)
	}
	if _, err := st.End(ctx, "u1", "terms", t0, consent.EndSuperseded); err != nil {
		t.Fatal(err)
	}
	if err := st.Insert(ctx, rec("d", "u1", "terms", "v2", t0)); err != nil {
		t.Errorf("Insert after the first ended: %v", err)
	}
}
