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
		{"FindSessionByHash/UnknownHashReturnsErrSessionNotFound", checkFindSessionByHashNotFound},
		{"ListSessionsByUser/ReturnsEveryStateAndOnlyThatUser", checkListSessionsByUser},
		{"ListSessionsByUser/UnknownUserIsEmptyNotAnError", checkListSessionsByUserEmpty},
		{"DeleteSession/RemovesExactlyOneRow", checkDeleteSession},
		{"DeleteSession/UnknownIDReturnsErrSessionNotFound", checkDeleteSessionNotFound},
		{"DeleteSessionsByFamily/RemovesTheFamilyAndNothingElse", checkDeleteSessionsByFamily},
		{"DeleteSessionsByFamily/ZeroRowsIsNotAnError", checkDeleteSessionsByFamilyEmpty},
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
