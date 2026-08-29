package authtest

import (
	"context"
	"errors"
	"sort"
	"time"

	"github.com/bernardoforcillo/authlayer/auth"
)

// purposes is the closed set the service layer uses. The port keeps Purpose
// a plain string and validates nothing, but [auth.Verification.Email]'s doc
// requires the address to be populated and normalized for EVERY purpose —
// the field used to be conditional, and that made MarkEmailVerified's
// email-match check compare a signup's current address to itself and always
// pass. Every purpose is therefore exercised rather than one standing in for
// the rest.
var purposes = []string{"signup", "email_change", "password_reset"}

func verificationChecks() []check {
	return []check{
		{"CreateVerification/RoundTripAndNormalizesForEveryPurpose", checkCreateVerification},
		{"CreateVerification/DuplicateIDReturnsErrIDTakenAndKeepsTheRow", checkCreateVerificationDuplicateID},
		{"CreateVerification/TokenHashIsUnique", checkVerificationTokenHashUnique},
		{"FindVerificationByHash/UnknownHashReturnsErrVerificationNotFound", checkFindVerificationByHashNotFound},
		{"DeleteVerification/RemovesExactlyOneRow", checkDeleteVerification},
		{"DeleteVerification/UnknownIDReturnsErrVerificationNotFound", checkDeleteVerificationNotFound},
		{"DeleteVerificationsByUserAndPurpose/RemovesOnlyThatPair", checkDeleteVerificationsByUserAndPurpose},
		{"DeleteVerificationsByUserAndPurpose/ZeroRowsIsNotAnError", checkDeleteVerificationsByUserAndPurposeEmpty},
	}
}

func housekeepingChecks() []check {
	return []check{
		{"PurgeExpired/CutoffIsStrictAcrossBothKinds", checkPurgeExpired},
	}
}

// checkCreateVerification asserts a verification round-trips by hash for
// every purpose, and that Email is normalized on the write path
// unconditionally — never conditionally on Purpose.
func checkCreateVerification(t tb, st auth.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	userID := newID()

	for _, purpose := range purposes {
		email := newEmail()
		v := newVerification(userID, purpose, mixedCase(email), at)

		created := mustCreateVerification(t, st, v)
		if created.Email != email {
			t.Fatalf("CreateVerification(purpose %q) returned Email %q, want the normalized %q — normalization must not be conditional on Purpose", purpose, created.Email, email)
		}

		got, err := st.FindVerificationByHash(ctx, v.TokenHash)
		wantNoErr(t, "FindVerificationByHash(purpose "+purpose+")", err)
		if got.ID != v.ID || got.UserID != userID || got.Purpose != purpose {
			t.Fatalf("FindVerificationByHash returned %+v, want the record CreateVerification stored for purpose %q", got, purpose)
		}
		if got.Email != email {
			t.Fatalf("stored Email = %q for purpose %q, want the normalized %q", got.Email, purpose, email)
		}
		wantTimeEqual(t, "ExpiresAt", got.ExpiresAt, v.ExpiresAt)
		wantTimeEqual(t, "CreatedAt", got.CreatedAt, v.CreatedAt)
	}
}

// checkCreateVerificationDuplicateID asserts a second CreateVerification
// under an id that already identifies a verification returns ErrIDTaken and
// never silently replaces the row.
func checkCreateVerificationDuplicateID(t tb, st auth.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	userID := newID()
	first := mustCreateVerification(t, st, newVerification(userID, "signup", newEmail(), at))

	clash := newVerification(userID, "password_reset", newEmail(), at)
	clash.ID = first.ID
	_, err := st.CreateVerification(ctx, clash)
	wantErrIs(t, "CreateVerification with an id already taken", err, auth.ErrIDTaken)

	got, err := st.FindVerificationByHash(ctx, first.TokenHash)
	wantNoErr(t, "FindVerificationByHash(the original hash)", err)
	if got.Purpose != first.Purpose || got.Email != first.Email {
		t.Fatalf("FindVerificationByHash returned %+v after an ErrIDTaken, want the original row %+v", got, first)
	}
	if _, err := st.FindVerificationByHash(ctx, clash.TokenHash); !errors.Is(err, auth.ErrVerificationNotFound) {
		t.Fatalf("FindVerificationByHash(the rejected row's hash) error = %v, want ErrVerificationNotFound", err)
	}
}

// checkFindVerificationByHashNotFound asserts a hash no verification holds
// is ErrVerificationNotFound.
func checkFindVerificationByHashNotFound(t tb, st auth.Store) {
	t.Helper()
	_, err := st.FindVerificationByHash(context.Background(), "vh-"+newID())
	wantErrIs(t, "FindVerificationByHash(unknown hash)", err, auth.ErrVerificationNotFound)
}

// checkDeleteVerification asserts redemption removes exactly the row named —
// so the same token cannot be redeemed twice — and leaves a sibling alone.
func checkDeleteVerification(t tb, st auth.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	userID := newID()
	target := mustCreateVerification(t, st, newVerification(userID, "signup", newEmail(), at))
	sibling := mustCreateVerification(t, st, newVerification(userID, "signup", newEmail(), at))

	wantNoErr(t, "DeleteVerification", st.DeleteVerification(ctx, target.ID))

	if _, err := st.FindVerificationByHash(ctx, target.TokenHash); !errors.Is(err, auth.ErrVerificationNotFound) {
		t.Fatalf("FindVerificationByHash(the redeemed token) error = %v, want ErrVerificationNotFound", err)
	}
	if _, err := st.FindVerificationByHash(ctx, sibling.TokenHash); err != nil {
		t.Fatalf("FindVerificationByHash(a sibling) error = %v, want nil — DeleteVerification removes one row", err)
	}
	err := st.DeleteVerification(ctx, target.ID)
	wantErrIs(t, "DeleteVerification(the same id twice)", err, auth.ErrVerificationNotFound)
}

// checkDeleteVerificationNotFound asserts an id no verification holds is
// ErrVerificationNotFound.
func checkDeleteVerificationNotFound(t tb, st auth.Store) {
	t.Helper()
	err := st.DeleteVerification(context.Background(), newID())
	wantErrIs(t, "DeleteVerification(unknown id)", err, auth.ErrVerificationNotFound)
}

// checkDeleteVerificationsByUserAndPurpose asserts the sweep re-issuing a
// verification performs first is scoped to exactly (userID, purpose): every
// row for that pair goes, and rows for the same user under another purpose,
// or for another user under the same purpose, survive.
func checkDeleteVerificationsByUserAndPurpose(t tb, st auth.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	userID := newID()
	otherUser := newID()

	doomedA := mustCreateVerification(t, st, newVerification(userID, "password_reset", newEmail(), at))
	doomedB := mustCreateVerification(t, st, newVerification(userID, "password_reset", newEmail(), at))
	otherPurpose := mustCreateVerification(t, st, newVerification(userID, "email_change", newEmail(), at))
	otherUsers := mustCreateVerification(t, st, newVerification(otherUser, "password_reset", newEmail(), at))

	wantNoErr(t, "DeleteVerificationsByUserAndPurpose", st.DeleteVerificationsByUserAndPurpose(ctx, userID, "password_reset"))

	for _, v := range []auth.Verification{doomedA, doomedB} {
		if _, err := st.FindVerificationByHash(ctx, v.TokenHash); !errors.Is(err, auth.ErrVerificationNotFound) {
			t.Fatalf("FindVerificationByHash(%s, a swept row) error = %v, want ErrVerificationNotFound", v.ID, err)
		}
	}
	for _, v := range []auth.Verification{otherPurpose, otherUsers} {
		if _, err := st.FindVerificationByHash(ctx, v.TokenHash); err != nil {
			t.Fatalf("FindVerificationByHash(%s, outside the swept pair) error = %v, want nil", v.ID, err)
		}
	}
}

// checkDeleteVerificationsByUserAndPurposeEmpty asserts sweeping a pair with
// no rows is not an error.
func checkDeleteVerificationsByUserAndPurposeEmpty(t tb, st auth.Store) {
	t.Helper()
	err := st.DeleteVerificationsByUserAndPurpose(context.Background(), newID(), "signup")
	wantNoErr(t, "DeleteVerificationsByUserAndPurpose(a pair with no rows)", err)
}

// checkPurgeExpired asserts the cutoff is STRICT and applies to both kinds:
// a session and a verification expiring an hour before the cutoff go, a
// session and a verification whose ExpiresAt is exactly the cutoff stay
// (`strictly before`, so the boundary survives), and later ones stay. The
// returned count is the total across both kinds, so it must be exactly 2.
//
// Users are never purged, however old — the port says so — so a user created
// long before the cutoff must still be there afterwards.
func checkPurgeExpired(t tb, st auth.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	cutoff := at
	userID := newID()

	u := mustCreateUser(t, st, newUser(newEmail(), at.Add(-24*time.Hour)))

	mk := func(offset time.Duration) (auth.Session, auth.Verification) {
		s := newSession(userID, newID(), at)
		s.ExpiresAt = cutoff.Add(offset)
		v := newVerification(userID, "signup", newEmail(), at)
		v.ExpiresAt = cutoff.Add(offset)
		return mustCreateSession(t, st, s), mustCreateVerification(t, st, v)
	}
	expiredSession, expiredVerification := mk(-time.Hour)
	boundarySession, boundaryVerification := mk(0)
	futureSession, futureVerification := mk(time.Hour)

	n, err := st.PurgeExpired(ctx, cutoff)
	wantNoErr(t, "PurgeExpired", err)
	if n != 2 {
		t.Fatalf("PurgeExpired returned %d, want 2 — one session and one verification expired strictly before the cutoff, counted together", n)
	}

	if _, err := st.FindSessionByHash(ctx, expiredSession.TokenHash); !errors.Is(err, auth.ErrSessionNotFound) {
		t.Fatalf("the expired session survived PurgeExpired: error = %v, want ErrSessionNotFound", err)
	}
	if _, err := st.FindVerificationByHash(ctx, expiredVerification.TokenHash); !errors.Is(err, auth.ErrVerificationNotFound) {
		t.Fatalf("the expired verification survived PurgeExpired: error = %v, want ErrVerificationNotFound", err)
	}

	for _, s := range []auth.Session{boundarySession, futureSession} {
		if _, err := st.FindSessionByHash(ctx, s.TokenHash); err != nil {
			t.Fatalf("session expiring at %v was purged by a cutoff of %v: error = %v — the cutoff is strictly before", s.ExpiresAt, cutoff, err)
		}
	}
	for _, v := range []auth.Verification{boundaryVerification, futureVerification} {
		if _, err := st.FindVerificationByHash(ctx, v.TokenHash); err != nil {
			t.Fatalf("verification expiring at %v was purged by a cutoff of %v: error = %v — the cutoff is strictly before", v.ExpiresAt, cutoff, err)
		}
	}

	if _, err := st.FindUserByID(ctx, u.ID); err != nil {
		t.Fatalf("FindUserByID after PurgeExpired: error = %v, want nil — users do not expire and are never purged", err)
	}

	left, err := st.ListSessionsByUser(ctx, userID)
	wantNoErr(t, "ListSessionsByUser", err)
	want := []string{boundarySession.ID, futureSession.ID}
	sort.Strings(want)
	if !sameIDs(sortedIDs(left), want) {
		t.Fatalf("ListSessionsByUser after PurgeExpired returned %v, want %v", sortedIDs(left), want)
	}
}

// checkVerificationTokenHashUnique asserts
// [auth.Verification.TokenHash]'s uniqueness MUST, for the reason that
// field's doc gives: FindVerificationByHash assumes at most one row can
// match, and without the constraint its result depends on row order rather
// than being well-defined.
func checkVerificationTokenHashUnique(t tb, st auth.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	userID := newID()
	first := mustCreateVerification(t, st, newVerification(userID, "signup", newEmail(), at))

	clash := newVerification(userID, "password_reset", newEmail(), at)
	clash.TokenHash = first.TokenHash
	if _, err := st.CreateVerification(ctx, clash); err == nil {
		t.Fatalf("CreateVerification with a token hash another verification already holds returned nil — auth.Verification.TokenHash's uniqueness MUST is not enforced")
	}

	got, err := st.FindVerificationByHash(ctx, first.TokenHash)
	wantNoErr(t, "FindVerificationByHash", err)
	if got.ID != first.ID {
		t.Fatalf("FindVerificationByHash returned id %q, want the only row that should hold the hash, %q", got.ID, first.ID)
	}
}
