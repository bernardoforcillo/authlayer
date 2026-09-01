package authtest

import (
	"context"
	"errors"
	"sort"
	"time"

	"github.com/bernardoforcillo/authlayer/auth"
)

func sessionChecks() []check {
	return []check{
		{"CreateSession/RoundTrip", checkCreateSessionRoundTrip},
		{"CreateSession/DuplicateIDReturnsErrIDTakenAndKeepsTheRow", checkCreateSessionDuplicateID},
		{"CreateSession/TokenHashIsUnique", checkSessionTokenHashUnique},
		{"CreateSession/RoundTripsTheMFAStamp", checkSessionMFAAtRoundTrip},
		{"FindSessionByHash/UnknownHashReturnsErrSessionNotFound", checkFindSessionByHashNotFound},
		{"ListSessionsByUser/ReturnsEveryStateAndOnlyThatUser", checkListSessionsByUser},
		{"ListSessionsByUser/UnknownUserIsEmptyNotAnError", checkListSessionsByUserEmpty},
		{"DeleteSession/RemovesExactlyOneRow", checkDeleteSession},
		{"DeleteSession/UnknownIDReturnsErrSessionNotFound", checkDeleteSessionNotFound},
		{"DeleteSessionsByFamily/RemovesTheFamilyAndNothingElse", checkDeleteSessionsByFamily},
		{"DeleteSessionsByFamily/ZeroRowsIsNotAnError", checkDeleteSessionsByFamilyEmpty},
		{"DeleteSessionsByUser/RemovesEveryFamilyAndOnlyThatUser", checkDeleteSessionsByUser},
		{"DeleteSessionsByUser/ZeroRowsIsNotAnError", checkDeleteSessionsByUserEmpty},
		{"MarkRotated/WinsOnceThenReportsTheRotatedSession", checkMarkRotated},
		{"MarkRotated/UnknownHashReturnsErrSessionNotFound", checkMarkRotatedNotFound},
		{"MarkRotated/IgnoresExpiry", checkMarkRotatedIgnoresExpiry},
		{"CreateSuccessorSession/InsertsWhenThePredecessorExists", checkCreateSuccessorSession},
		{"CreateSuccessorSession/RefusesWhenThePredecessorIsGone", checkCreateSuccessorSessionRefuses},
		{"CreateSuccessorSession/DuplicateIDReturnsErrIDTaken", checkCreateSuccessorSessionDuplicateID},
		{"CreateSuccessorSession/DuplicateIDIsCheckedEvenWithoutThePredecessor", checkCreateSuccessorSessionDuplicateIDNoPredecessor},
	}
}

// sortedIDs returns the ids of sessions, sorted, so a comparison never
// depends on the order a store returns them in — the port says that order is
// unspecified.
func sortedIDs(sessions []auth.Session) []string {
	out := make([]string, len(sessions))
	for i, s := range sessions {
		out[i] = s.ID
	}
	sort.Strings(out)
	return out
}

func sameIDs(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

// checkCreateSessionRoundTrip asserts CreateSession returns what it stored
// and FindSessionByHash reads the same record back, field for field. A
// freshly minted session is current, so RotatedAt must be nil.
func checkCreateSessionRoundTrip(t tb, st auth.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	s := newSession(newID(), newID(), at)

	created := mustCreateSession(t, st, s)
	if created.ID != s.ID || created.TokenHash != s.TokenHash || created.FamilyID != s.FamilyID || created.UserID != s.UserID {
		t.Fatalf("CreateSession returned %+v, want the record it was given, %+v", created, s)
	}

	got, err := st.FindSessionByHash(ctx, s.TokenHash)
	wantNoErr(t, "FindSessionByHash", err)
	if got.ID != s.ID || got.UserID != s.UserID || got.FamilyID != s.FamilyID {
		t.Fatalf("FindSessionByHash returned %+v, want %+v", got, s)
	}
	if got.RotatedAt != nil {
		t.Fatalf("RotatedAt = %v on a freshly created session, want nil — nil is what marks it current", got.RotatedAt)
	}
	if got.UserAgent != s.UserAgent || got.IP != s.IP {
		t.Fatalf("UserAgent/IP = %q/%q, want %q/%q", got.UserAgent, got.IP, s.UserAgent, s.IP)
	}
	wantTimeEqual(t, "ExpiresAt", got.ExpiresAt, s.ExpiresAt)
	wantTimeEqual(t, "CreatedAt", got.CreatedAt, s.CreatedAt)
}

// checkSessionMFAAtRoundTrip asserts [auth.Session.MFAAt] survives a store
// round trip in BOTH states, through both read paths: a nil stamp comes back
// nil, and a set one comes back equal to what was given.
//
// It is a check of its own rather than a line inside the round-trip check
// above because the two failure directions are not symmetric and neither is
// a cosmetic loss of a field. A backend that drops a SET stamp fails every
// [github.com/bernardoforcillo/authlayer/auth.Service.RequireFreshMFA] — so
// every account with a second factor is locked out of changing its own
// password. A backend that returns a non-nil stamp for a session that never
// proved a factor PASSES every step-up check, which is the direction that
// hands a stolen session the account.
func checkSessionMFAAtRoundTrip(t tb, st auth.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()

	never := mustCreateSession(t, st, newSession(newID(), newID(), at))
	if never.MFAAt != nil {
		t.Fatalf("CreateSession returned MFAAt = %v for a session created with none, want nil", never.MFAAt)
	}
	read, err := st.FindSessionByHash(ctx, never.TokenHash)
	wantNoErr(t, "FindSessionByHash", err)
	if read.MFAAt != nil {
		t.Fatalf("MFAAt = %v after a round trip, want nil — a session that never proved a second factor must not read back as one that did", read.MFAAt)
	}

	proven := newSession(newID(), newID(), at)
	provenAt := at.Add(time.Minute)
	proven.MFAAt = &provenAt
	created := mustCreateSession(t, st, proven)
	if created.MFAAt == nil {
		t.Fatalf("CreateSession dropped MFAAt; RequireFreshMFA reads nothing else, so a session that proved a factor would never be fresh")
	}
	wantTimeEqual(t, "CreateSession MFAAt", *created.MFAAt, provenAt)

	back, err := st.FindSessionByHash(ctx, proven.TokenHash)
	wantNoErr(t, "FindSessionByHash", err)
	if back.MFAAt == nil {
		t.Fatalf("FindSessionByHash dropped MFAAt")
	}
	wantTimeEqual(t, "FindSessionByHash MFAAt", *back.MFAAt, provenAt)

	listed, err := st.ListSessionsByUser(ctx, proven.UserID)
	wantNoErr(t, "ListSessionsByUser", err)
	if len(listed) != 1 || listed[0].MFAAt == nil {
		t.Fatalf("ListSessionsByUser returned %d row(s) with MFAAt = %v; RequireFreshMFA reads the stamp through THIS method", len(listed), listedMFAAt(listed))
	}
	wantTimeEqual(t, "ListSessionsByUser MFAAt", *listed[0].MFAAt, provenAt)
}

// listedMFAAt is a nil-safe accessor for the failure message above.
func listedMFAAt(sessions []auth.Session) *time.Time {
	if len(sessions) == 0 {
		return nil
	}
	return sessions[0].MFAAt
}

// checkCreateSessionDuplicateID asserts a second CreateSession under an id
// that already identifies a session returns ErrIDTaken and never silently
// replaces the row: the original token hash still resolves, and the second
// call's own hash does not.
func checkCreateSessionDuplicateID(t tb, st auth.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	first := mustCreateSession(t, st, newSession(newID(), newID(), at))

	clash := newSession(newID(), newID(), at)
	clash.ID = first.ID
	_, err := st.CreateSession(ctx, clash)
	wantErrIs(t, "CreateSession with an id already taken", err, auth.ErrIDTaken)

	got, err := st.FindSessionByHash(ctx, first.TokenHash)
	wantNoErr(t, "FindSessionByHash(the original hash)", err)
	if got.ID != first.ID {
		t.Fatalf("the original session's hash resolves to id %q, want %q", got.ID, first.ID)
	}
	if _, err := st.FindSessionByHash(ctx, clash.TokenHash); !errors.Is(err, auth.ErrSessionNotFound) {
		t.Fatalf("FindSessionByHash(the rejected session's hash) error = %v, want ErrSessionNotFound — the row must not have been replaced", err)
	}
}

// checkFindSessionByHashNotFound asserts a hash no session holds is
// ErrSessionNotFound.
func checkFindSessionByHashNotFound(t tb, st auth.Store) {
	t.Helper()
	_, err := st.FindSessionByHash(context.Background(), "sh-"+newID())
	wantErrIs(t, "FindSessionByHash(unknown hash)", err, auth.ErrSessionNotFound)
}

// checkListSessionsByUser asserts the port's "every session belonging to
// userID, rotated or not, expired or not — the caller filters": a current
// session, a rotated one, and an already-expired one all come back, sessions
// belonging to another user do not, and the order is not relied on.
func checkListSessionsByUser(t tb, st auth.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	userID := newID()
	familyID := newID()

	current := mustCreateSession(t, st, newSession(userID, familyID, at))

	rotatedSession := newSession(userID, familyID, at)
	rotatedAt := at
	rotatedSession.RotatedAt = &rotatedAt
	rotated := mustCreateSession(t, st, rotatedSession)

	expiredSession := newSession(userID, newID(), at)
	expiredSession.ExpiresAt = at.Add(-time.Hour)
	expired := mustCreateSession(t, st, expiredSession)

	other := mustCreateSession(t, st, newSession(newID(), newID(), at))

	got, err := st.ListSessionsByUser(ctx, userID)
	wantNoErr(t, "ListSessionsByUser", err)
	want := []string{current.ID, rotated.ID, expired.ID}
	sort.Strings(want)
	if !sameIDs(sortedIDs(got), want) {
		t.Fatalf("ListSessionsByUser returned %v, want %v (rotated and expired sessions are included; %s belongs to another user)", sortedIDs(got), want, other.ID)
	}
}

// checkListSessionsByUserEmpty asserts a user with no sessions is not an
// error. Whether the store returns nil or an empty slice is deliberately not
// distinguished — the port says len and range treat them alike.
func checkListSessionsByUserEmpty(t tb, st auth.Store) {
	t.Helper()
	got, err := st.ListSessionsByUser(context.Background(), newID())
	wantNoErr(t, "ListSessionsByUser(a user with no sessions)", err)
	if len(got) != 0 {
		t.Fatalf("ListSessionsByUser returned %d session(s) for a user with none, want 0", len(got))
	}
}

// checkDeleteSession asserts DeleteSession removes exactly the row named and
// leaves the rest of the family alone, and that deleting the same id twice
// reports ErrSessionNotFound the second time.
func checkDeleteSession(t tb, st auth.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	userID := newID()
	familyID := newID()
	target := mustCreateSession(t, st, newSession(userID, familyID, at))
	sibling := mustCreateSession(t, st, newSession(userID, familyID, at))

	wantNoErr(t, "DeleteSession", st.DeleteSession(ctx, target.ID))

	if _, err := st.FindSessionByHash(ctx, target.TokenHash); !errors.Is(err, auth.ErrSessionNotFound) {
		t.Fatalf("FindSessionByHash(the deleted session) error = %v, want ErrSessionNotFound", err)
	}
	if _, err := st.FindSessionByHash(ctx, sibling.TokenHash); err != nil {
		t.Fatalf("FindSessionByHash(a sibling in the same family) error = %v, want nil — DeleteSession removes one row", err)
	}

	err := st.DeleteSession(ctx, target.ID)
	wantErrIs(t, "DeleteSession(the same id twice)", err, auth.ErrSessionNotFound)
}

// checkDeleteSessionNotFound asserts an id no session holds is
// ErrSessionNotFound.
func checkDeleteSessionNotFound(t tb, st auth.Store) {
	t.Helper()
	err := st.DeleteSession(context.Background(), newID())
	wantErrIs(t, "DeleteSession(unknown id)", err, auth.ErrSessionNotFound)
}

// checkDeleteSessionsByFamily asserts every session sharing the family goes
// — current and rotated alike, however many there are — and that a session
// in a different family belonging to the same user survives.
func checkDeleteSessionsByFamily(t tb, st auth.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	userID := newID()
	doomed := newID()

	for i := 0; i < 3; i++ {
		s := newSession(userID, doomed, at)
		if i > 0 {
			rotatedAt := at
			s.RotatedAt = &rotatedAt
		}
		mustCreateSession(t, st, s)
	}
	survivor := mustCreateSession(t, st, newSession(userID, newID(), at))

	wantNoErr(t, "DeleteSessionsByFamily", st.DeleteSessionsByFamily(ctx, doomed))

	got, err := st.ListSessionsByUser(ctx, userID)
	wantNoErr(t, "ListSessionsByUser", err)
	if !sameIDs(sortedIDs(got), []string{survivor.ID}) {
		t.Fatalf("ListSessionsByUser returned %v after revoking family %s, want only %v", sortedIDs(got), doomed, []string{survivor.ID})
	}
}

// checkDeleteSessionsByFamilyEmpty asserts deleting a family with no rows in
// it is not an error — the port says so explicitly, and the service layer
// relies on it when a revocation races another.
func checkDeleteSessionsByFamilyEmpty(t tb, st auth.Store) {
	t.Helper()
	err := st.DeleteSessionsByFamily(context.Background(), newID())
	wantNoErr(t, "DeleteSessionsByFamily(a family with no sessions)", err)
}

// checkDeleteSessionsByUser asserts [auth.Store.DeleteSessionsByUser]'s
// "every family": three families belonging to one user — one holding a
// current session, one holding a rotated session, one holding an already
// expired session — all go in a single call, while a session belonging to a
// DIFFERENT user survives untouched.
//
// Three families rather than one is the point of the check. This method's
// whole reason to exist on the port is that its caller cannot get the same
// effect by enumerating families and looping over
// [auth.Store.DeleteSessionsByFamily] (see its doc), so an implementation
// that quietly revokes only one family — the first it finds, the newest, the
// one whose id sorts first — is exactly the defect worth catching, and it is
// invisible against a fixture with a single family. Rotated and expired
// sessions are included because they are still rows: a superseded session is
// the tripwire reuse detection reads, and leaving one behind for an account
// that is being deleted or anonymized leaves a live row keyed to a user that
// is about to stop existing.
func checkDeleteSessionsByUser(t tb, st auth.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	userID := newID()

	current := mustCreateSession(t, st, newSession(userID, newID(), at))

	rotatedSession := newSession(userID, newID(), at)
	rotatedAt := at
	rotatedSession.RotatedAt = &rotatedAt
	rotated := mustCreateSession(t, st, rotatedSession)

	expiredSession := newSession(userID, newID(), at)
	expiredSession.ExpiresAt = at.Add(-time.Hour)
	expired := mustCreateSession(t, st, expiredSession)

	otherUser := newID()
	survivor := mustCreateSession(t, st, newSession(otherUser, newID(), at))

	wantNoErr(t, "DeleteSessionsByUser", st.DeleteSessionsByUser(ctx, userID))

	for _, s := range []auth.Session{current, rotated, expired} {
		if _, err := st.FindSessionByHash(ctx, s.TokenHash); !errors.Is(err, auth.ErrSessionNotFound) {
			t.Fatalf("FindSessionByHash(session %s, family %s) error = %v, want ErrSessionNotFound — every family belonging to the user goes, not just one", s.ID, s.FamilyID, err)
		}
	}
	left, err := st.ListSessionsByUser(ctx, userID)
	wantNoErr(t, "ListSessionsByUser(the swept user)", err)
	if len(left) != 0 {
		t.Fatalf("ListSessionsByUser returned %v after DeleteSessionsByUser, want none", sortedIDs(left))
	}

	if _, err := st.FindSessionByHash(ctx, survivor.TokenHash); err != nil {
		t.Fatalf("FindSessionByHash(another user's session) error = %v, want nil — the sweep is scoped to one user", err)
	}
}

// checkDeleteSessionsByUserEmpty asserts sweeping a user with no sessions is
// not an error — the port says so explicitly, and it is the ordinary case
// for an account that has never logged in or has already been logged out
// everywhere.
func checkDeleteSessionsByUserEmpty(t tb, st auth.Store) {
	t.Helper()
	err := st.DeleteSessionsByUser(context.Background(), newID())
	wantNoErr(t, "DeleteSessionsByUser(a user with no sessions)", err)
}

// checkMarkRotated asserts the sequential half of the compare-and-set: the
// first caller wins with RotatedAt stamped to the instant it passed, and a
// second call against the same hash loses — returning ok=false and a nil
// error, with the session as stored (RotatedAt still the FIRST caller's
// instant, not the second's). The port distinguishes that outcome from
// ErrSessionNotFound deliberately: the caller needs it to tell a replay from
// an unknown token.
func checkMarkRotated(t tb, st auth.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	s := mustCreateSession(t, st, newSession(newID(), newID(), at))

	firstNow := at.Add(time.Minute)
	got, ok, err := st.MarkRotated(ctx, s.TokenHash, firstNow)
	wantNoErr(t, "MarkRotated (first)", err)
	if !ok {
		t.Fatalf("MarkRotated ok = false on a current, unrotated session, want true")
	}
	if got.ID != s.ID {
		t.Fatalf("MarkRotated returned session id %q, want %q", got.ID, s.ID)
	}
	if got.RotatedAt == nil {
		t.Fatalf("the winner's returned RotatedAt = nil, want the instant it passed")
	} else {
		wantTimeEqual(t, "the winner's returned RotatedAt", *got.RotatedAt, firstNow)
	}

	secondNow := firstNow.Add(time.Minute)
	again, ok, err := st.MarkRotated(ctx, s.TokenHash, secondNow)
	wantNoErr(t, "MarkRotated (second, already rotated)", err)
	if ok {
		t.Fatalf("MarkRotated ok = true on an already-rotated session, want false — exactly one caller may win the transition")
	}
	if again.ID != s.ID {
		t.Fatalf("the loser's returned session id = %q, want the already-rotated session %q", again.ID, s.ID)
	}
	if again.RotatedAt == nil {
		t.Fatalf("the loser's returned RotatedAt = nil, want the first caller's instant")
	} else {
		wantTimeEqual(t, "the loser's returned RotatedAt", *again.RotatedAt, firstNow)
	}

	stored, err := st.FindSessionByHash(ctx, s.TokenHash)
	wantNoErr(t, "FindSessionByHash", err)
	if stored.RotatedAt == nil {
		t.Fatalf("the stored RotatedAt = nil after a winning MarkRotated")
	}
	wantTimeEqual(t, "the stored RotatedAt", *stored.RotatedAt, firstNow)
}

// checkMarkRotatedNotFound asserts a hash matching no session at all is
// (Session{}, false, ErrSessionNotFound) — the port spells out the zero
// Session on this path, unlike CreateSuccessorSession's ok=false path, so it
// is asserted here.
func checkMarkRotatedNotFound(t tb, st auth.Store) {
	t.Helper()
	got, ok, err := st.MarkRotated(context.Background(), "sh-"+newID(), stamp())
	wantErrIs(t, "MarkRotated(unknown hash)", err, auth.ErrSessionNotFound)
	if ok {
		t.Fatalf("MarkRotated ok = true for a hash matching no session")
	}
	if got != (auth.Session{}) {
		t.Fatalf("MarkRotated returned %+v for a hash matching no session, want the zero Session", got)
	}
}

// checkMarkRotatedIgnoresExpiry asserts expiry is not part of the predicate:
// an expired-but-unrotated session still rotates successfully. An expired
// token is ordinary end-of-life, not a replay, and a store that folded an
// ExpiresAt check in here would make every expired refresh look like one —
// revoking the whole family.
func checkMarkRotatedIgnoresExpiry(t tb, st auth.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	s := newSession(newID(), newID(), at)
	s.ExpiresAt = at.Add(-time.Hour)
	mustCreateSession(t, st, s)

	_, ok, err := st.MarkRotated(ctx, s.TokenHash, at)
	wantNoErr(t, "MarkRotated(an expired but unrotated session)", err)
	if !ok {
		t.Fatalf("MarkRotated ok = false on an expired but unrotated session, want true — expiry is deliberately not part of the predicate")
	}
}

// checkCreateSuccessorSession asserts the ordinary rotation path: with the
// predecessor still present, the successor is persisted and reported ok, and
// it is reachable by its own hash afterwards.
func checkCreateSuccessorSession(t tb, st auth.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	userID := newID()
	familyID := newID()
	predSession := newSession(userID, familyID, at)
	rotatedAt := at
	predSession.RotatedAt = &rotatedAt
	pred := mustCreateSession(t, st, predSession)

	succ := newSession(userID, familyID, at)
	got, ok, err := st.CreateSuccessorSession(ctx, pred.ID, succ)
	wantNoErr(t, "CreateSuccessorSession", err)
	if !ok {
		t.Fatalf("CreateSuccessorSession ok = false with the predecessor still present, want true")
	}
	if got.ID != succ.ID {
		t.Fatalf("CreateSuccessorSession returned session id %q, want %q", got.ID, succ.ID)
	}

	stored, err := st.FindSessionByHash(ctx, succ.TokenHash)
	wantNoErr(t, "FindSessionByHash(the successor)", err)
	if stored.FamilyID != familyID {
		t.Fatalf("the successor's FamilyID = %q, want the predecessor's %q", stored.FamilyID, familyID)
	}
}

// checkCreateSuccessorSessionRefuses asserts the sequential half of the
// no-resurrection MUST: once the family is gone, a successor must not be
// persisted, and that is reported as ok=false with a NIL error — a lost race
// is an expected outcome, not a failure the method experienced.
//
// The returned Session is deliberately not asserted on this path: the port
// specifies only that s was not persisted.
func checkCreateSuccessorSessionRefuses(t tb, st auth.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	userID := newID()
	familyID := newID()
	pred := mustCreateSession(t, st, newSession(userID, familyID, at))
	wantNoErr(t, "DeleteSessionsByFamily", st.DeleteSessionsByFamily(ctx, familyID))

	succ := newSession(userID, familyID, at)
	_, ok, err := st.CreateSuccessorSession(ctx, pred.ID, succ)
	wantNoErr(t, "CreateSuccessorSession(after the family was revoked)", err)
	if ok {
		t.Fatalf("CreateSuccessorSession ok = true after the predecessor was deleted — this resurrects a revoked family")
	}
	if _, err := st.FindSessionByHash(ctx, succ.TokenHash); !errors.Is(err, auth.ErrSessionNotFound) {
		t.Fatalf("FindSessionByHash(the successor) error = %v, want ErrSessionNotFound — ok=false means the row was NOT persisted", err)
	}
}

// checkCreateSuccessorSessionDuplicateID asserts s.ID's own collision is
// reported as ErrIDTaken, the same condition CreateSession reports it under,
// even though the predecessor exists and the call would otherwise succeed.
func checkCreateSuccessorSessionDuplicateID(t tb, st auth.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	userID := newID()
	familyID := newID()
	pred := mustCreateSession(t, st, newSession(userID, familyID, at))
	taken := mustCreateSession(t, st, newSession(userID, newID(), at))

	succ := newSession(userID, familyID, at)
	succ.ID = taken.ID
	_, ok, err := st.CreateSuccessorSession(ctx, pred.ID, succ)
	wantErrIs(t, "CreateSuccessorSession with an id already taken", err, auth.ErrIDTaken)
	if ok {
		t.Fatalf("CreateSuccessorSession ok = true alongside ErrIDTaken")
	}
	if _, err := st.FindSessionByHash(ctx, succ.TokenHash); !errors.Is(err, auth.ErrSessionNotFound) {
		t.Fatalf("FindSessionByHash(the rejected successor's hash) error = %v, want ErrSessionNotFound", err)
	}
}

// checkCreateSuccessorSessionDuplicateIDNoPredecessor asserts the id
// collision is checked as part of the same atomic step, independent of the
// predecessor's own existence: with BOTH conditions failing, ErrIDTaken is
// what comes back, not a silent ok=false.
func checkCreateSuccessorSessionDuplicateIDNoPredecessor(t tb, st auth.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	userID := newID()
	taken := mustCreateSession(t, st, newSession(userID, newID(), at))

	succ := newSession(userID, newID(), at)
	succ.ID = taken.ID
	_, ok, err := st.CreateSuccessorSession(ctx, newID(), succ)
	wantErrIs(t, "CreateSuccessorSession with an id already taken and no predecessor", err, auth.ErrIDTaken)
	if ok {
		t.Fatalf("CreateSuccessorSession ok = true alongside ErrIDTaken")
	}
}

// checkSessionTokenHashUnique asserts [auth.Session.TokenHash]'s uniqueness
// MUST: a second session under a hash another row already holds must not be
// stored. Without it MarkRotated's single-winner contract breaks with no
// atomicity defect at all — two concurrent callers each atomically win a
// different one of the colliding rows — and FindSessionByHash resolves to
// whichever row the backend happens to return first.
//
// Which error the rejection carries is not asserted: the port classifies
// only ErrIDTaken on this method and leaves token-hash uniqueness to the
// backend's own constraint, so an unwrapped driver error is a compliant
// answer.
func checkSessionTokenHashUnique(t tb, st auth.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	userID := newID()
	first := mustCreateSession(t, st, newSession(userID, newID(), at))

	clash := newSession(userID, newID(), at)
	clash.TokenHash = first.TokenHash
	if _, err := st.CreateSession(ctx, clash); err == nil {
		t.Fatalf("CreateSession with a token hash another session already holds returned nil — auth.Session.TokenHash's uniqueness MUST is not enforced")
	}

	got, err := st.FindSessionByHash(ctx, first.TokenHash)
	wantNoErr(t, "FindSessionByHash", err)
	if got.ID != first.ID {
		t.Fatalf("FindSessionByHash returned id %q, want the only row that should hold the hash, %q", got.ID, first.ID)
	}
}
