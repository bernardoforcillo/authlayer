package audittest

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/bernardoforcillo/authlayer/audit"
	"github.com/bernardoforcillo/authlayer/store/memory"
)

type recorder struct{ failed bool }

var errFatal = errors.New("fatal")

func (r *recorder) Helper()                   {}
func (r *recorder) Errorf(string, ...any)     { r.failed = true }
func (r *recorder) Fatalf(f string, a ...any) { r.Errorf(f, a...); panic(errFatal) }

func runCheck(t *testing.T, name string, st audit.Store) (rec *recorder) {
	t.Helper()
	rec = &recorder{}
	var c *check
	for i := range checks {
		if checks[i].name != name {
			continue
		}
		c = &checks[i]
		break
	}
	if c == nil {
		panic(fmt.Sprintf("no check named %q", name))
	}
	defer func() {
		if p := recover(); p != nil && p != errFatal {
			panic(p)
		}
	}()
	c.fn(rec, st)
	return rec
}

// sealBlind forgets every seal, so it never refuses a sealed day.
type sealBlind struct{ audit.Store }

func (sealBlind) InsertSeal(context.Context, audit.Seal) error { return nil }

// completeBlind ignores completions.
type completeBlind struct{ audit.Store }

func (s completeBlind) Complete(ctx context.Context, id string, _ audit.Closing) (audit.Event, error) {
	return s.Get(ctx, id)
}

// scrubBlind clears nothing.
type scrubBlind struct{ audit.Store }

func (scrubBlind) ScrubClientData(context.Context, string, time.Time, int) (int, error) {
	return 0, nil
}

func TestChecksBiteNonCompliantStores(t *testing.T) {
	cases := []struct {
		check string
		store audit.Store
	}{
		{"Insert/RefusesASealedDay", sealBlind{memory.NewAuditStore()}},
		{"Complete/WritesOnce", completeBlind{memory.NewAuditStore()}},
		{"ScrubClientData/ClearsOnlyTheTopicBeforeAndNothingElse", scrubBlind{memory.NewAuditStore()}},
	}
	for _, c := range cases {
		if !runCheck(t, c.check, c.store).failed {
			t.Errorf("check %s passed against a store that breaks it", c.check)
		}
	}
}
