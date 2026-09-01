package authtest

import (
	"context"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/bernardoforcillo/authlayer/auth"
)

// ── The reference store ─────────────────────────────────────────────────

// refMFAStore is a correct, minimal [auth.MFAStore]: two maps behind one
// mutex, with every method holding it for its whole body so no
// check-then-write can be split by a concurrent call. It is the baseline
// the non-compliant doubles below are each ONE defect away from, which is
// what makes "this check failed" evidence about that defect and nothing
// else.
//
// It is a second in-memory implementation beside store/memory's, on
// purpose and for the same reason [refStore] is: a control that shared code
// with the backend it is validating would pass whatever that backend
// happened to do.
type refMFAStore struct {
	mu sync.Mutex
	// factors is keyed by user id — the port's "at most one factor per
	// user" rule, expressed as the data structure rather than checked.
	factors map[string]auth.MFAFactor
	// codes is keyed by recovery-code id. Locating a user's codes is a
	// linear scan rather than a second index: a reference store trades
	// speed for having exactly one copy of the data and therefore no way
	// for two indexes to disagree.
	codes map[string]auth.RecoveryCode
}

func newRefMFAStore() *refMFAStore {
	return &refMFAStore{
		factors: map[string]auth.MFAFactor{},
		codes:   map[string]auth.RecoveryCode{},
	}
}

func (s *refMFAStore) UpsertFactor(_ context.Context, f auth.MFAFactor) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Whole-row replacement, deliberately: see UpsertFactor's MUST.
	s.factors[f.UserID] = f
	return nil
}

func (s *refMFAStore) FindFactor(_ context.Context, userID string) (auth.MFAFactor, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, ok := s.factors[userID]
	if !ok {
		return auth.MFAFactor{}, auth.ErrFactorNotFound
	}
	return f, nil
}

func (s *refMFAStore) ConfirmFactor(_ context.Context, userID string, now time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, ok := s.factors[userID]
	if !ok {
		return false, auth.ErrFactorNotFound
	}
	if f.ConfirmedAt != nil {
		return false, nil
	}
	f.ConfirmedAt = &now
	s.factors[userID] = f
	return true, nil
}

func (s *refMFAStore) AdvanceStep(_ context.Context, userID string, step int64) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, ok := s.factors[userID]
	if !ok {
		return false, auth.ErrFactorNotFound
	}
	if f.LastStep != nil && step <= *f.LastStep {
		return false, nil
	}
	f.LastStep = &step
	s.factors[userID] = f
	return true, nil
}

func (s *refMFAStore) DeleteFactor(_ context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.factors[userID]; !ok {
		return auth.ErrFactorNotFound
	}
	delete(s.factors, userID)
	return nil
}

func (s *refMFAStore) ReplaceRecoveryCodes(_ context.Context, userID string, codes []auth.RecoveryCode) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.validateCodes(userID, codes); err != nil {
		return err
	}
	s.dropCodesOf(userID)
	for _, c := range codes {
		s.codes[c.ID] = c
	}
	return nil
}

// validateCodes runs both refusals BEFORE anything is removed, which is
// what makes a refused call write nothing.
func (s *refMFAStore) validateCodes(userID string, codes []auth.RecoveryCode) error {
	seen := make(map[string]bool, len(codes))
	for _, c := range codes {
		if c.UserID != userID {
			return auth.ErrRecoveryCodeUserMismatch
		}
		if seen[c.ID] {
			return auth.ErrIDTaken
		}
		seen[c.ID] = true
		// An id held by a row this call is itself removing is free to
		// reuse; one held by another user's row is not.
		if existing, ok := s.codes[c.ID]; ok && existing.UserID != userID {
			return auth.ErrIDTaken
		}
	}
	return nil
}

func (s *refMFAStore) dropCodesOf(userID string) {
	for id, c := range s.codes {
		if c.UserID == userID {
			delete(s.codes, id)
		}
	}
}

func (s *refMFAStore) ConsumeRecoveryCode(_ context.Context, userID, codeHash string, now time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	burnt := false
	for id, c := range s.codes {
		if c.UserID != userID || c.CodeHash != codeHash || c.UsedAt != nil {
			continue
		}
		c.UsedAt = &now
		s.codes[id] = c
		burnt = true
	}
	return burnt, nil
}

func (s *refMFAStore) ListRecoveryCodes(_ context.Context, userID string) ([]auth.RecoveryCode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]auth.RecoveryCode, 0)
	for _, c := range s.codes {
		if c.UserID == userID {
			out = append(out, c)
		}
	}
	return out, nil
}

// ── The non-compliant doubles ───────────────────────────────────────────
//
// Each is exactly one defect away from [refMFAStore]. The split-lock ones
// hold their check-then-write window open for [gap] — see that constant's
// doc for why a control's window is widened to milliseconds: it makes the
// control DETERMINISTIC, so "this check failed" is evidence the check
// detects the defect, not evidence about how the scheduler felt.

// mergingUpsertFactor merges the new factor over the stored one, keeping a
// previous ConfirmedAt and LastStep — the shape UpsertFactor's MUST
// forbids, and the one that leaves a brand-new secret already confirmed.
type mergingUpsertFactor struct{ *refMFAStore }

func (s mergingUpsertFactor) UpsertFactor(_ context.Context, f auth.MFAFactor) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if old, ok := s.factors[f.UserID]; ok {
		if f.ConfirmedAt == nil {
			f.ConfirmedAt = old.ConfirmedAt
		}
		if f.LastStep == nil {
			f.LastStep = old.LastStep
		}
	}
	s.factors[f.UserID] = f
	return nil
}

// silentFindFactor answers a missing factor with the zero value and a nil
// error, so "not enrolled" is indistinguishable from "enrolled with an
// empty secret".
type silentFindFactor struct{ *refMFAStore }

func (s silentFindFactor) FindFactor(_ context.Context, userID string) (auth.MFAFactor, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.factors[userID], nil
}

// everyConfirmerWins has no compare-and-set at all: it stamps and reports
// true for every caller, however often the factor has already been
// confirmed.
type everyConfirmerWins struct{ *refMFAStore }

func (s everyConfirmerWins) ConfirmFactor(_ context.Context, userID string, now time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, ok := s.factors[userID]
	if !ok {
		return false, auth.ErrFactorNotFound
	}
	f.ConfirmedAt = &now
	s.factors[userID] = f
	return true, nil
}

// splitConfirmFactor decides under one acquisition of the lock and stamps
// under another. Sequentially correct; two concurrent callers both see it
// unconfirmed and both win.
type splitConfirmFactor struct{ *refMFAStore }

func (s splitConfirmFactor) ConfirmFactor(_ context.Context, userID string, now time.Time) (bool, error) {
	s.mu.Lock()
	f, ok := s.factors[userID]
	s.mu.Unlock()
	if !ok {
		return false, auth.ErrFactorNotFound
	}
	if f.ConfirmedAt != nil {
		return false, nil
	}

	time.Sleep(gap)

	s.mu.Lock()
	defer s.mu.Unlock()
	f = s.factors[userID]
	f.ConfirmedAt = &now
	s.factors[userID] = f
	return true, nil
}

// stepAcceptsAnything drops the replay guard's comparison: every step is
// accepted and recorded, including one already spent. This is the defect
// the whole method exists to prevent — a shoulder-surfed code stays valid
// for its entire skew window.
type stepAcceptsAnything struct{ *refMFAStore }

func (s stepAcceptsAnything) AdvanceStep(_ context.Context, userID string, step int64) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, ok := s.factors[userID]
	if !ok {
		return false, auth.ErrFactorNotFound
	}
	f.LastStep = &step
	s.factors[userID] = f
	return true, nil
}

// splitAdvanceStep compares against a LastStep read under one acquisition
// of the lock and writes under another. Sequentially correct; two
// concurrent presentations of the same code both read the old value, both
// find their step greater, and both win.
type splitAdvanceStep struct{ *refMFAStore }

func (s splitAdvanceStep) AdvanceStep(_ context.Context, userID string, step int64) (bool, error) {
	s.mu.Lock()
	f, ok := s.factors[userID]
	s.mu.Unlock()
	if !ok {
		return false, auth.ErrFactorNotFound
	}
	if f.LastStep != nil && step <= *f.LastStep {
		return false, nil
	}

	time.Sleep(gap)

	s.mu.Lock()
	defer s.mu.Unlock()
	f = s.factors[userID]
	f.LastStep = &step
	s.factors[userID] = f
	return true, nil
}

// cascadingDeleteFactor takes the user's recovery codes down with the
// factor row, widening a cascade whose extent belongs to the caller.
type cascadingDeleteFactor struct{ *refMFAStore }

func (s cascadingDeleteFactor) DeleteFactor(_ context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.factors[userID]; !ok {
		return auth.ErrFactorNotFound
	}
	delete(s.factors, userID)
	s.dropCodesOf(userID)
	return nil
}

// silentDeleteFactor answers a missing factor with nil, so a caller
// cannot tell a removal from a no-op.
type silentDeleteFactor struct{ *refMFAStore }

func (s silentDeleteFactor) DeleteFactor(_ context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.factors, userID)
	return nil
}

// partialReplaceRecoveryCodes removes the old set and writes whatever it
// can before noticing a code it must refuse — so a refused call has
// already destroyed the user's working codes and stored an incomplete
// replacement.
type partialReplaceRecoveryCodes struct{ *refMFAStore }

func (s partialReplaceRecoveryCodes) ReplaceRecoveryCodes(_ context.Context, userID string, codes []auth.RecoveryCode) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dropCodesOf(userID)
	seen := map[string]bool{}
	for _, c := range codes {
		if c.UserID != userID {
			return auth.ErrRecoveryCodeUserMismatch
		}
		if seen[c.ID] {
			return auth.ErrIDTaken
		}
		if existing, ok := s.codes[c.ID]; ok && existing.UserID != userID {
			return auth.ErrIDTaken
		}
		seen[c.ID] = true
		s.codes[c.ID] = c
	}
	return nil
}

// everyConsumerWins burns without checking UsedAt, so a single-use code
// can be spent as often as it is presented.
type everyConsumerWins struct{ *refMFAStore }

func (s everyConsumerWins) ConsumeRecoveryCode(_ context.Context, userID, codeHash string, now time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, c := range s.codes {
		if c.UserID != userID || c.CodeHash != codeHash {
			continue
		}
		c.UsedAt = &now
		s.codes[id] = c
		return true, nil
	}
	return false, nil
}

// splitConsumeRecoveryCode finds the unused code under one acquisition of
// the lock and stamps it under another. Sequentially correct; two
// concurrent consumers both find it unused and both win.
type splitConsumeRecoveryCode struct{ *refMFAStore }

func (s splitConsumeRecoveryCode) ConsumeRecoveryCode(_ context.Context, userID, codeHash string, now time.Time) (bool, error) {
	s.mu.Lock()
	var found string
	for id, c := range s.codes {
		if c.UserID == userID && c.CodeHash == codeHash && c.UsedAt == nil {
			found = id
			break
		}
	}
	s.mu.Unlock()
	if found == "" {
		return false, nil
	}

	time.Sleep(gap)

	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.codes[found]
	c.UsedAt = &now
	s.codes[found] = c
	return true, nil
}

// crossUserConsume matches a code by its hash alone, so one user's
// recovery code is spendable against another's account.
type crossUserConsume struct{ *refMFAStore }

func (s crossUserConsume) ConsumeRecoveryCode(_ context.Context, _, codeHash string, now time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, c := range s.codes {
		if c.CodeHash != codeHash || c.UsedAt != nil {
			continue
		}
		c.UsedAt = &now
		s.codes[id] = c
		return true, nil
	}
	return false, nil
}

// leakyListRecoveryCodes returns every user's codes rather than the one
// asked for.
type leakyListRecoveryCodes struct{ *refMFAStore }

func (s leakyListRecoveryCodes) ListRecoveryCodes(context.Context, string) ([]auth.RecoveryCode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]auth.RecoveryCode, 0, len(s.codes))
	for _, c := range s.codes {
		out = append(out, c)
	}
	return out, nil
}

// ── The harness ─────────────────────────────────────────────────────────

// runMFACheck runs one check against st and reports what it complained
// about. The check runs in its own goroutine so the recorder's Fatalf can
// end it with runtime.Goexit the way testing.T.Fatalf would.
func runMFACheck(c mfaCheck, st auth.MFAStore) []string {
	r := &recorder{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		c.fn(r, st)
	}()
	<-done
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.failures...)
}

func allMFAChecks() []mfaCheck { return mfaStoreContractChecks() }

func findMFACheck(t *testing.T, name string) mfaCheck {
	t.Helper()
	for _, c := range allMFAChecks() {
		if c.name == name {
			return c
		}
	}
	t.Fatalf("no MFA check named %q — the negative-control table names a check that does not exist", name)
	return mfaCheck{}
}

// TestTheReferenceMFAStorePassesTheContract is the control on the controls
// below: [refMFAStore] is correct, so the whole suite must pass it end to
// end. If it did not, a non-compliant double failing a check would prove
// nothing about the defect injected into it.
func TestTheReferenceMFAStorePassesTheContract(t *testing.T) {
	RunMFAStoreContract(t, func(*testing.T) auth.MFAStore { return newRefMFAStore() })
}

// TestTheMFAContractRejectsNonCompliantStores is what makes the suite
// worth having. Each row is a store exactly one defect away from
// [refMFAStore], paired with the check that must catch that defect. The
// whole suite runs against each one, the named check is required to have
// failed, and every check that failed is logged so the blast radius of
// each defect is on the record rather than inferred.
//
// All eight methods of the port appear here at least once: a check nobody
// has watched fail is a check nobody knows works.
func TestTheMFAContractRejectsNonCompliantStores(t *testing.T) {
	cases := []struct {
		defect   string
		check    string
		newStore func() auth.MFAStore
	}{
		{
			defect:   "UpsertFactor merges over the stored factor instead of replacing it",
			check:    "UpsertFactor/ReplacesTheWholeRowRatherThanMerging",
			newStore: func() auth.MFAStore { return mergingUpsertFactor{newRefMFAStore()} },
		},
		{
			defect:   "FindFactor answers a missing factor with the zero value and nil",
			check:    "FindFactor/UnknownUserReturnsErrFactorNotFound",
			newStore: func() auth.MFAStore { return silentFindFactor{newRefMFAStore()} },
		},
		{
			defect:   "ConfirmFactor lets every caller win",
			check:    "ConfirmFactor/StampsOnceThenReportsFalse",
			newStore: func() auth.MFAStore { return everyConfirmerWins{newRefMFAStore()} },
		},
		{
			defect:   "ConfirmFactor lets every caller win (concurrently, too)",
			check:    "ConfirmFactor/ConcurrentCallersAdmitExactlyOneWinner",
			newStore: func() auth.MFAStore { return everyConfirmerWins{newRefMFAStore()} },
		},
		{
			defect:   "ConfirmFactor decides under one lock and stamps under another",
			check:    "ConfirmFactor/ConcurrentCallersAdmitExactlyOneWinner",
			newStore: func() auth.MFAStore { return splitConfirmFactor{newRefMFAStore()} },
		},
		{
			defect:   "AdvanceStep accepts any step, replay included",
			check:    "AdvanceStep/RefusesAStepAtOrBelowLastStep",
			newStore: func() auth.MFAStore { return stepAcceptsAnything{newRefMFAStore()} },
		},
		{
			defect:   "AdvanceStep compares under one lock and writes under another",
			check:    "AdvanceStep/ConcurrentCallersWithOneStepAdmitExactlyOneWinner",
			newStore: func() auth.MFAStore { return splitAdvanceStep{newRefMFAStore()} },
		},
		{
			defect:   "DeleteFactor cascades to the user's recovery codes",
			check:    "DeleteFactor/RemovesTheFactorRowOnly",
			newStore: func() auth.MFAStore { return cascadingDeleteFactor{newRefMFAStore()} },
		},
		{
			defect:   "DeleteFactor answers a missing factor with nil",
			check:    "DeleteFactor/UnknownUserReturnsErrFactorNotFound",
			newStore: func() auth.MFAStore { return silentDeleteFactor{newRefMFAStore()} },
		},
		{
			defect:   "ReplaceRecoveryCodes removes the old set before deciding whether it can write the new one",
			check:    "ReplaceRecoveryCodes/AForeignCodeIsRefusedAndWritesNothing",
			newStore: func() auth.MFAStore { return partialReplaceRecoveryCodes{newRefMFAStore()} },
		},
		{
			defect:   "ReplaceRecoveryCodes writes part of a set it then refuses (duplicate id)",
			check:    "ReplaceRecoveryCodes/ADuplicateIDIsRefusedAndWritesNothing",
			newStore: func() auth.MFAStore { return partialReplaceRecoveryCodes{newRefMFAStore()} },
		},
		{
			defect:   "ConsumeRecoveryCode burns a code that is already used",
			check:    "ConsumeRecoveryCode/BurnsOnceThenReportsFalse",
			newStore: func() auth.MFAStore { return everyConsumerWins{newRefMFAStore()} },
		},
		{
			defect:   "ConsumeRecoveryCode finds under one lock and stamps under another",
			check:    "ConsumeRecoveryCode/ConcurrentConsumersAdmitExactlyOneWinner",
			newStore: func() auth.MFAStore { return splitConsumeRecoveryCode{newRefMFAStore()} },
		},
		{
			defect:   "ConsumeRecoveryCode matches on the hash alone, ignoring the user",
			check:    "ConsumeRecoveryCode/IsBoundToTheUser",
			newStore: func() auth.MFAStore { return crossUserConsume{newRefMFAStore()} },
		},
		{
			defect:   "ListRecoveryCodes returns every user's codes",
			check:    "ListRecoveryCodes/ReturnsUsedAndUnusedForThatUserOnly",
			newStore: func() auth.MFAStore { return leakyListRecoveryCodes{newRefMFAStore()} },
		},
	}

	for _, tc := range cases {
		t.Run(tc.defect, func(t *testing.T) {
			want := findMFACheck(t, tc.check)

			var caught []string
			var firstMessage string
			for _, c := range allMFAChecks() {
				failures := runMFACheck(c, tc.newStore())
				if len(failures) == 0 {
					continue
				}
				caught = append(caught, c.name)
				if c.name == want.name {
					firstMessage = failures[0]
				}
			}
			sort.Strings(caught)

			if firstMessage == "" {
				t.Fatalf("%s PASSED %s — the check does not catch this defect. Checks that did fail: %v", tc.defect, tc.check, caught)
			}
			t.Logf("%s\n  caught by %s: %s\n  all checks that failed: %v", tc.defect, tc.check, firstMessage, caught)
		})
	}
}
