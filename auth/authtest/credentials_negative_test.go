package authtest

import (
	"context"
	"testing"
	"time"

	"github.com/bernardoforcillo/authlayer/auth"
)

// ── The non-compliant doubles ───────────────────────────────────────────
//
// Each is exactly one defect away from [refCredentialStore]: it embeds one
// and overrides a single method with a deliberately wrong shape. That is what
// makes "this check failed" evidence about the defect and nothing else — see
// TestTheReferenceCredentialStorePassesTheContract.
//
// The ones that inject a WINDOW hold it open for [gap] rather than relying on
// the scheduler, for the reason that constant's doc gives: a real split-lock
// window is sub-microsecond and is caught only a few percent of the time, far
// too unreliable for a control whose whole job is to prove a check bites.

// everyCounterWins has no compare-and-set at all: UpdateSignCount stores
// whatever it is handed and reports true, for every caller and every value.
// It is the grossly non-atomic shape
// [auth.CredentialStore.UpdateSignCount]'s MUST forbids, and it is what a
// backend that "just updates the row" looks like — after which a replayed
// assertion is accepted forever and the package has no clone detection at
// all.
type everyCounterWins struct{ *refCredentialStore }

func (s everyCounterWins) UpdateSignCount(_ context.Context, id string, newCount uint32, now time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.credentials[id]
	if !ok {
		return false, auth.ErrCredentialNotFound
	}
	c.SignCount = newCount
	c.LastUsedAt = &now
	s.credentials[id] = c
	return true, nil
}

// splitSignCountCAS keeps the comparison but splits it from the write: it
// reads the stored counter, releases the lock for [gap], then writes if the
// value it read was lower. Sequentially it is indistinguishable from a
// correct store — it refuses an equal or lower counter every time — so only
// the concurrent check can catch it, which is exactly why that check exists.
type splitSignCountCAS struct{ *refCredentialStore }

func (s splitSignCountCAS) UpdateSignCount(_ context.Context, id string, newCount uint32, now time.Time) (bool, error) {
	s.mu.Lock()
	c, ok := s.credentials[id]
	s.mu.Unlock()
	if !ok {
		return false, auth.ErrCredentialNotFound
	}
	if newCount <= c.SignCount {
		return false, nil
	}

	time.Sleep(gap) // the window a single UPDATE ... WHERE would not have

	s.mu.Lock()
	defer s.mu.Unlock()
	c.SignCount = newCount
	c.LastUsedAt = &now
	s.credentials[id] = c
	return true, nil
}

// duplicateCredentialIDs drops the credential-id uniqueness scan, keeping the
// surrogate-id one. It is a backend whose table has no UNIQUE (credential_id)
// constraint: two rows can then name one authenticator credential against two
// different users, and which of them a login resolves to is decided by row
// order.
type duplicateCredentialIDs struct{ *refCredentialStore }

func (s duplicateCredentialIDs) CreateCredential(_ context.Context, c auth.Credential) (auth.Credential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.credentials[c.ID]; exists {
		return auth.Credential{}, auth.ErrIDTaken
	}
	s.credentials[c.ID] = c
	return c, nil
}

// splitIfNotLast is the read-then-write removal
// [auth.CredentialStore.DeleteCredentialIfNotLast]'s "It MUST be atomic"
// section forbids: it decides against a snapshot, releases the lock for
// [gap], then deletes. Two concurrent removals of a user's last two passkeys
// each see the other and both proceed — the permanent, silent lockout.
type splitIfNotLast struct{ *refCredentialStore }

func (s splitIfNotLast) DeleteCredentialIfNotLast(_ context.Context, userID, id string, userHasOtherCredential bool) error {
	s.mu.Lock()
	doomed, ok := s.credentials[id]
	survivors := 0
	for otherID, c := range s.credentials {
		if c.UserID == userID && otherID != id {
			survivors++
		}
	}
	s.mu.Unlock()

	if !ok || doomed.UserID != userID {
		return auth.ErrCredentialNotFound
	}
	if survivors == 0 && !userHasOtherCredential {
		return auth.ErrLastCredential
	}

	time.Sleep(gap) // the window one transaction would not have

	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.credentials, id)
	return nil
}

// unclaimableChallenge reports success for a challenge it did not remove: it
// deletes and returns nil whether or not a row was there. That is a claim
// that claims nothing — every concurrent presentation of one challenge is
// told it won, and two callers finishing one ceremony both get a session.
type unclaimableChallenge struct{ *refCredentialStore }

func (s unclaimableChallenge) DeleteChallenge(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.challenges, id)
	return nil
}

// challengeLosesTheNullUser coerces a nil Challenge.UserID to a zero string,
// which is what a backend with a NOT NULL user_id column does when it makes
// the column fit rather than making the model fit. A login ceremony then
// looks like a registration ceremony bound to the user whose id is the empty
// string.
type challengeLosesTheNullUser struct{ *refCredentialStore }

func (s challengeLosesTheNullUser) CreateChallenge(ctx context.Context, c auth.Challenge) (auth.Challenge, error) {
	if c.UserID == nil {
		empty := ""
		c.UserID = &empty
	}
	return s.refCredentialStore.CreateChallenge(ctx, c)
}

// touchMovesTheCounter folds TouchCredential into the counter update, which
// is the tempting simplification: one "record a use" method. It destroys the
// baseline every later comparison is made against — the counter now tracks
// whatever the last caller said rather than the highest value accepted.
type touchMovesTheCounter struct{ *refCredentialStore }

func (s touchMovesTheCounter) TouchCredential(_ context.Context, id string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.credentials[id]
	if !ok {
		return auth.ErrCredentialNotFound
	}
	c.SignCount++
	c.LastUsedAt = &now
	s.credentials[id] = c
	return nil
}

// ── Driving a credential check and capturing its verdict ────────────────

// runCredentialCheck runs one check against st and reports what it complained
// about. It mirrors [runCheck] exactly, including the goroutine that lets the
// recorder's Fatalf end the check with runtime.Goexit the way testing.T's
// would.
func runCredentialCheck(c credentialCheck, st auth.CredentialStore) []string {
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

func findCredentialCheck(t *testing.T, name string) credentialCheck {
	t.Helper()
	for _, c := range credentialContractChecks() {
		if c.name == name {
			return c
		}
	}
	t.Fatalf("no credential check named %q — the negative-control table names a check that does not exist", name)
	return credentialCheck{}
}

// TestTheReferenceCredentialStorePassesTheContract is the control on the
// controls below. [refCredentialStore] is a correct store, so
// [RunCredentialStoreContract] must pass it end to end; if it did not, a
// non-compliant double failing a check would prove nothing about the defect
// injected into it.
func TestTheReferenceCredentialStorePassesTheContract(t *testing.T) {
	RunCredentialStoreContract(t, func(*testing.T) auth.CredentialStore { return newRefCredentialStore() })
}

// TestTheCredentialContractRejectsNonCompliantStores is what makes the
// passkey suite worth having: a contract suite that passes everything is
// worthless, and that failure mode is invisible without controls. Each row is
// a store exactly one defect away from [refCredentialStore], paired with the
// check that must catch that defect. The whole suite runs against each one,
// the named check is required to have failed, and every check that failed is
// logged so the blast radius of each defect is on the record rather than
// inferred.
func TestTheCredentialContractRejectsNonCompliantStores(t *testing.T) {
	cases := []struct {
		name  string
		store func() auth.CredentialStore
		check string
		why   string
	}{
		{
			name:  "UpdateSignCount accepts any counter",
			store: func() auth.CredentialStore { return everyCounterWins{newRefCredentialStore()} },
			check: "UpdateSignCount/RefusesACountThatDidNotIncrease",
			why:   "a replayed assertion is accepted forever; the package has no clone detection left",
		},
		{
			name:  "UpdateSignCount splits its compare from its set",
			store: func() auth.CredentialStore { return splitSignCountCAS{newRefCredentialStore()} },
			check: "UpdateSignCount/ConcurrentReplayAdmitsExactlyOneWinner",
			why:   "concurrent presentations of one captured assertion all win",
		},
		{
			name:  "CreateCredential allows two rows for one credential id",
			store: func() auth.CredentialStore { return duplicateCredentialIDs{newRefCredentialStore()} },
			check: "CreateCredential/DuplicateCredentialIDIsRefused",
			why:   "one authenticator can sign in as either of two accounts, decided by row order",
		},
		{
			name:  "DeleteCredentialIfNotLast decides, then deletes",
			store: func() auth.CredentialStore { return splitIfNotLast{newRefCredentialStore()} },
			check: "DeleteCredentialIfNotLast/ConcurrentRemovalsLeaveOneWayIn",
			why:   "two concurrent removals leave an account with no way in, both reporting success",
		},
		{
			name:  "DeleteChallenge reports success for a row it did not remove",
			store: func() auth.CredentialStore { return unclaimableChallenge{newRefCredentialStore()} },
			check: "DeleteChallenge/BurnsTheChallengeExactlyOnce",
			why:   "a challenge stops being single-use, so two callers finish one ceremony",
		},
		{
			name:  "CreateChallenge cannot store a login ceremony's absent user",
			store: func() auth.CredentialStore { return challengeLosesTheNullUser{newRefCredentialStore()} },
			check: "CreateChallenge/RoundTripsBothCeremonies",
			why:   "a login challenge comes back bound to the empty-string account",
		},
		{
			name:  "TouchCredential moves the counter",
			store: func() auth.CredentialStore { return touchMovesTheCounter{newRefCredentialStore()} },
			check: "TouchCredential/StampsLastUsedAtWithoutMovingTheCounter",
			why:   "the baseline every later comparison is made against is invented rather than observed",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			target := findCredentialCheck(t, tc.check)
			var failedNames []string
			targetFailed := false
			for _, c := range credentialContractChecks() {
				failures := runCredentialCheck(c, tc.store())
				if len(failures) == 0 {
					continue
				}
				failedNames = append(failedNames, c.name)
				if c.name == target.name {
					targetFailed = true
					t.Logf("%s caught it: %s", c.name, failures[0])
				}
			}
			if !targetFailed {
				t.Fatalf("%s PASSED %s — the check does not catch the defect it exists for (%s)",
					tc.check, tc.name, tc.why)
			}
			t.Logf("checks that failed against %q: %v", tc.name, failedNames)
		})
	}
}
