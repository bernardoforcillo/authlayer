package authtest

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/bernardoforcillo/authlayer/auth"
)

// mixedCase returns email with its case flipped and surrounding whitespace
// added — a variant that [auth.NormalizeEmail] collapses back to email, and
// therefore one that must resolve to the same row on every read and write
// path.
func mixedCase(email string) string { return "  " + strings.ToUpper(email) + "\t" }

func userChecks() []check {
	return []check{
		{"CreateUser/RoundTrip", checkCreateUserRoundTrip},
		{"CreateUser/NormalizesTheAddress", checkCreateUserNormalizes},
		{"CreateUser/DuplicateAddressReturnsErrEmailTaken", checkCreateUserDuplicateAddress},
		{"CreateUser/DuplicateIDReturnsErrIDTakenAndKeepsTheRow", checkCreateUserDuplicateID},
		{"CreateUser/RoundTripsDeletedAt", checkCreateUserDeletedAt},
		{"FindUserByID/UnknownIDReturnsErrUserNotFound", checkFindUserByIDNotFound},
		{"FindUserByEmail/NormalizesTheAddress", checkFindUserByEmailNormalizes},
		{"FindUserByEmail/UnknownAddressReturnsErrUserNotFound", checkFindUserByEmailNotFound},
		{"FindUserByEmail/ReadsItsOwnWrites", checkFindUserByEmailReadsItsOwnWrites},
		{"MarkEmailVerified/StampsWhenTheAddressMatches", checkMarkEmailVerifiedStamps},
		{"MarkEmailVerified/NormalizesTheAddressArgument", checkMarkEmailVerifiedNormalizes},
		{"MarkEmailVerified/IsIdempotent", checkMarkEmailVerifiedIdempotent},
		{"MarkEmailVerified/MismatchCertifiesNothing", checkMarkEmailVerifiedMismatch},
		{"MarkEmailVerified/UnknownUserReturnsErrUserNotFound", checkMarkEmailVerifiedUnknownUser},
		{"UpdateUserPassword/OverwritesAndStamps", checkUpdateUserPassword},
		{"UpdateUserPassword/EmptyHashRemovesTheCredential", checkUpdateUserPasswordEmpty},
		{"UpdateUserPassword/UnknownUserReturnsErrUserNotFound", checkUpdateUserPasswordUnknownUser},
		{"UpdateUserEmail/NormalizesClearsVerificationAndStamps", checkUpdateUserEmail},
		{"UpdateUserEmail/SameAddressIsNotASelfConflict", checkUpdateUserEmailSameAddress},
		{"UpdateUserEmail/AnotherUsersAddressReturnsErrEmailTaken", checkUpdateUserEmailTaken},
		{"UpdateUserEmail/UnknownUserReturnsErrUserNotFound", checkUpdateUserEmailUnknownUser},
		{"DeleteUser/RemovesTheUserRowOnly", checkDeleteUser},
		{"DeleteUser/UnknownIDReturnsErrUserNotFound", checkDeleteUserUnknownUser},
	}
}

// checkCreateUserRoundTrip asserts CreateUser returns what it stored and
// that FindUserByID reads the same record back: every field of
// [auth.UserBase] survives, a freshly created user is unverified, and the
// two timestamps come back as they were written.
func checkCreateUserRoundTrip(t tb, st auth.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	u := newUser(newEmail(), at)

	created := mustCreateUser(t, st, u)
	if created.ID != u.ID {
		t.Fatalf("CreateUser returned ID %q, want %q", created.ID, u.ID)
	}
	if created.Email != u.Email {
		t.Fatalf("CreateUser returned Email %q, want %q", created.Email, u.Email)
	}
	if created.PasswordHash != u.PasswordHash {
		t.Fatalf("CreateUser returned PasswordHash %q, want %q", created.PasswordHash, u.PasswordHash)
	}
	if created.EmailVerifiedAt != nil {
		t.Fatalf("CreateUser returned EmailVerifiedAt %v, want nil — a fresh user is unverified", created.EmailVerifiedAt)
	}
	wantTimeEqual(t, "CreateUser returned CreatedAt", created.CreatedAt, at)
	wantTimeEqual(t, "CreateUser returned UpdatedAt", created.UpdatedAt, at)

	got, err := st.FindUserByID(ctx, u.ID)
	wantNoErr(t, "FindUserByID", err)
	if got.ID != u.ID || got.Email != u.Email || got.PasswordHash != u.PasswordHash {
		t.Fatalf("FindUserByID returned %+v, want the record CreateUser stored, %+v", got, created)
	}
	if got.EmailVerifiedAt != nil {
		t.Fatalf("FindUserByID returned EmailVerifiedAt %v, want nil", got.EmailVerifiedAt)
	}
	wantTimeEqual(t, "FindUserByID CreatedAt", got.CreatedAt, at)
	wantTimeEqual(t, "FindUserByID UpdatedAt", got.UpdatedAt, at)
}

// checkCreateUserNormalizes asserts CreateUser applies [auth.NormalizeEmail]
// on the write path: a record created from an upper-cased, whitespace-padded
// address is stored — and returned — under the normalized form, and is
// reachable by it.
func checkCreateUserNormalizes(t tb, st auth.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	email := newEmail()
	u := newUser(mixedCase(email), at)

	created := mustCreateUser(t, st, u)
	if created.Email != email {
		t.Fatalf("CreateUser(%q) returned Email %q, want the normalized %q", u.Email, created.Email, email)
	}

	got, err := st.FindUserByEmail(ctx, email)
	wantNoErr(t, "FindUserByEmail(normalized form of a raw-written address)", err)
	if got.ID != u.ID {
		t.Fatalf("FindUserByEmail(%q) returned id %q, want %q", email, got.ID, u.ID)
	}
	if got.Email != email {
		t.Fatalf("stored Email = %q, want the normalized %q", got.Email, email)
	}
}

// checkCreateUserDuplicateAddress asserts a second CreateUser for an address
// an existing user already holds returns ErrEmailTaken — including when the
// second call spells the address in a different case, since the comparison
// is on the normalized form. It also asserts nothing was written: the
// address still resolves to the first user.
func checkCreateUserDuplicateAddress(t tb, st auth.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	email := newEmail()
	first := mustCreateUser(t, st, newUser(email, at))

	_, err := st.CreateUser(ctx, newUser(mixedCase(email), at))
	wantErrIs(t, "CreateUser with a case variant of an address already held", err, auth.ErrEmailTaken)

	got, err := st.FindUserByEmail(ctx, email)
	wantNoErr(t, "FindUserByEmail after the rejected duplicate", err)
	if got.ID != first.ID {
		t.Fatalf("FindUserByEmail(%q) returned id %q, want the original %q — the rejected create wrote anyway", email, got.ID, first.ID)
	}
}

// checkCreateUserDuplicateID asserts a second CreateUser under an id that
// already identifies a user returns ErrIDTaken and, per the port, never
// silently replaces the existing row: the original address and password hash
// are still what FindUserByID returns.
func checkCreateUserDuplicateID(t tb, st auth.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	first := mustCreateUser(t, st, newUser(newEmail(), at))

	clash := newUser(newEmail(), at)
	clash.ID = first.ID
	_, err := st.CreateUser(ctx, clash)
	wantErrIs(t, "CreateUser with an id already taken", err, auth.ErrIDTaken)

	got, err := st.FindUserByID(ctx, first.ID)
	wantNoErr(t, "FindUserByID after the rejected duplicate id", err)
	if got.Email != first.Email || got.PasswordHash != first.PasswordHash {
		t.Fatalf("FindUserByID returned %+v after an ErrIDTaken, want the original row %+v — an existing row must never be replaced", got, first)
	}
	if _, err := st.FindUserByEmail(ctx, clash.Email); !errors.Is(err, auth.ErrUserNotFound) {
		t.Fatalf("FindUserByEmail(%q) error = %v, want ErrUserNotFound — the rejected create's address must not exist", clash.Email, err)
	}
}

// checkCreateUserDeletedAt asserts [auth.UserBase.DeletedAt] survives a
// round trip in both of its states. A freshly created user is not
// anonymized, so it comes back nil; a user created with the field set comes
// back holding the same instant, through FindUserByID and FindUserByEmail
// alike.
//
// It is the only obligation in this suite that reaches the column at all —
// no Store method writes DeletedAt, so a backend that never declares it
// (store/drops' CREATE TABLE IF NOT EXISTS cannot add a column to a table
// that already exists; see that store's CreateSchema doc) would otherwise
// look compliant right up until an anonymized account failed to be
// recognised as one. The field's doc makes recognising it the business of
// every authentication entry point, so silently dropping it is an
// authentication defect, not a missing convenience field.
func checkCreateUserDeletedAt(t tb, st auth.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()

	fresh := mustCreateUser(t, st, newUser(newEmail(), at))
	if fresh.DeletedAt != nil {
		t.Fatalf("CreateUser returned DeletedAt %v for a fresh user, want nil — a new account is not anonymized", fresh.DeletedAt)
	}
	got, err := st.FindUserByID(ctx, fresh.ID)
	wantNoErr(t, "FindUserByID(a fresh user)", err)
	if got.DeletedAt != nil {
		t.Fatalf("FindUserByID returned DeletedAt %v for a fresh user, want nil", got.DeletedAt)
	}

	stampedAt := at.Add(time.Minute)
	u := newUser(newEmail(), at)
	u.DeletedAt = &stampedAt
	created := mustCreateUser(t, st, u)
	if created.DeletedAt == nil {
		t.Fatalf("CreateUser returned DeletedAt = nil for a user created with it set, want %v", stampedAt)
	}
	wantTimeEqual(t, "CreateUser returned DeletedAt", *created.DeletedAt, stampedAt)

	byID, err := st.FindUserByID(ctx, u.ID)
	wantNoErr(t, "FindUserByID(a stamped user)", err)
	if byID.DeletedAt == nil {
		t.Fatalf("FindUserByID returned DeletedAt = nil, want the stored %v — the column is not persisted", stampedAt)
	}
	wantTimeEqual(t, "FindUserByID DeletedAt", *byID.DeletedAt, stampedAt)

	byEmail, err := st.FindUserByEmail(ctx, u.Email)
	wantNoErr(t, "FindUserByEmail(a stamped user)", err)
	if byEmail.DeletedAt == nil {
		t.Fatalf("FindUserByEmail returned DeletedAt = nil, want the stored %v", stampedAt)
	}
	wantTimeEqual(t, "FindUserByEmail DeletedAt", *byEmail.DeletedAt, stampedAt)
}

// checkFindUserByIDNotFound asserts an id no user holds is reported as
// ErrUserNotFound rather than a zero value with a nil error.
func checkFindUserByIDNotFound(t tb, st auth.Store) {
	t.Helper()
	_, err := st.FindUserByID(context.Background(), newID())
	wantErrIs(t, "FindUserByID(unknown id)", err, auth.ErrUserNotFound)
}

// checkFindUserByEmailNormalizes asserts [auth.NormalizeEmail] is applied on
// the read path too: a user stored under a normalized address is found by an
// upper-cased, whitespace-padded spelling of it.
func checkFindUserByEmailNormalizes(t tb, st auth.Store) {
	t.Helper()
	ctx := context.Background()
	email := newEmail()
	u := mustCreateUser(t, st, newUser(email, stamp()))

	got, err := st.FindUserByEmail(ctx, mixedCase(email))
	wantNoErr(t, "FindUserByEmail(case variant)", err)
	if got.ID != u.ID {
		t.Fatalf("FindUserByEmail(%q) returned id %q, want %q", mixedCase(email), got.ID, u.ID)
	}
}

// checkFindUserByEmailNotFound asserts an address no user holds is reported
// as ErrUserNotFound.
func checkFindUserByEmailNotFound(t tb, st auth.Store) {
	t.Helper()
	_, err := st.FindUserByEmail(context.Background(), newEmail())
	wantErrIs(t, "FindUserByEmail(unknown address)", err, auth.ErrUserNotFound)
}

// checkFindUserByEmailReadsItsOwnWrites is [auth.Store.FindUserByEmail]'s
// MUST: a row CreateUser has already returned successfully for must be
// visible to a FindUserByEmail call that follows it immediately, not merely
// to one running later. auth.Service.SignUp calls CreateUser and then
// unconditionally reads back what it just wrote, on every invocation
// regardless of new-versus-duplicate, so a backend answering reads from a
// lagging replica turns the new-address branch into an enumeration oracle:
// the read-back misses only for addresses that were genuinely new.
//
// The check creates and immediately reads back several distinct addresses in
// sequence, with no delay and no intervening call. One round would be enough
// for a replica that always lags; several make a backend that lags only
// until its next write visible too.
func checkFindUserByEmailReadsItsOwnWrites(t tb, st auth.Store) {
	t.Helper()
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		u := mustCreateUser(t, st, newUser(newEmail(), stamp()))
		got, err := st.FindUserByEmail(ctx, u.Email)
		if err != nil {
			t.Fatalf("FindUserByEmail(%q) immediately after CreateUser returned it: error %v — FindUserByEmail must read its own writes", u.Email, err)
		}
		if got.ID != u.ID {
			t.Fatalf("FindUserByEmail(%q) returned id %q, want the just-created %q", u.Email, got.ID, u.ID)
		}
	}
}

// checkMarkEmailVerifiedStamps asserts the ordinary success path: given the
// user's current address, MarkEmailVerified stamps both EmailVerifiedAt and
// UpdatedAt with now, and leaves the address itself alone.
func checkMarkEmailVerifiedStamps(t tb, st auth.Store) {
	t.Helper()
	ctx := context.Background()
	u := mustCreateUser(t, st, newUser(newEmail(), stamp()))

	verifiedAt := stamp().Add(time.Minute)
	wantNoErr(t, "MarkEmailVerified", st.MarkEmailVerified(ctx, u.ID, u.Email, verifiedAt))

	got, err := st.FindUserByID(ctx, u.ID)
	wantNoErr(t, "FindUserByID", err)
	if got.EmailVerifiedAt == nil {
		t.Fatalf("EmailVerifiedAt = nil after MarkEmailVerified, want the instant it was given")
	}
	wantTimeEqual(t, "EmailVerifiedAt", *got.EmailVerifiedAt, verifiedAt)
	wantTimeEqual(t, "UpdatedAt", got.UpdatedAt, verifiedAt)
	if got.Email != u.Email {
		t.Fatalf("Email = %q after MarkEmailVerified, want %q — verifying must not change the address", got.Email, u.Email)
	}
}

// checkMarkEmailVerifiedNormalizes asserts the email argument is normalized
// before it is compared with the user's current address, so a case or
// whitespace variant of the same address certifies rather than being
// rejected as a mismatch.
func checkMarkEmailVerifiedNormalizes(t tb, st auth.Store) {
	t.Helper()
	ctx := context.Background()
	u := mustCreateUser(t, st, newUser(newEmail(), stamp()))

	verifiedAt := stamp().Add(time.Minute)
	err := st.MarkEmailVerified(ctx, u.ID, mixedCase(u.Email), verifiedAt)
	wantNoErr(t, "MarkEmailVerified(case variant of the current address)", err)

	got, ferr := st.FindUserByID(ctx, u.ID)
	wantNoErr(t, "FindUserByID", ferr)
	if got.EmailVerifiedAt == nil {
		t.Fatalf("EmailVerifiedAt = nil after MarkEmailVerified with a case variant of the current address")
	}
}

// checkMarkEmailVerifiedIdempotent asserts calling it again with the same,
// still-current address after the address is already verified re-stamps both
// timestamps rather than returning an error — the port says so explicitly.
func checkMarkEmailVerifiedIdempotent(t tb, st auth.Store) {
	t.Helper()
	ctx := context.Background()
	u := mustCreateUser(t, st, newUser(newEmail(), stamp()))

	first := stamp().Add(time.Minute)
	wantNoErr(t, "MarkEmailVerified (first)", st.MarkEmailVerified(ctx, u.ID, u.Email, first))
	second := first.Add(time.Minute)
	wantNoErr(t, "MarkEmailVerified (second, already verified)", st.MarkEmailVerified(ctx, u.ID, u.Email, second))

	got, err := st.FindUserByID(ctx, u.ID)
	wantNoErr(t, "FindUserByID", err)
	if got.EmailVerifiedAt == nil {
		t.Fatalf("EmailVerifiedAt = nil after two MarkEmailVerified calls")
	}
	wantTimeEqual(t, "EmailVerifiedAt after the second call", *got.EmailVerifiedAt, second)
	wantTimeEqual(t, "UpdatedAt after the second call", got.UpdatedAt, second)
}

// checkMarkEmailVerifiedMismatch asserts an address that is not the user's
// current one is refused with ErrEmailMismatch and certifies nothing. This
// is the sequential half of [auth.Store.MarkEmailVerified]'s MUST; the race
// the MUST exists to close is driven by
// "MarkEmailVerified/NeverCertifiesAnAddressBeingChangedAway" in
// concurrency.go.
//
// UpdatedAt is deliberately not asserted on this path: the port states what
// must NOT happen (the address must not be certified), not whether the
// rejected call re-stamps the row's modification time.
func checkMarkEmailVerifiedMismatch(t tb, st auth.Store) {
	t.Helper()
	ctx := context.Background()
	u := mustCreateUser(t, st, newUser(newEmail(), stamp()))

	err := st.MarkEmailVerified(ctx, u.ID, newEmail(), stamp().Add(time.Minute))
	wantErrIs(t, "MarkEmailVerified(an address the user does not hold)", err, auth.ErrEmailMismatch)

	got, ferr := st.FindUserByID(ctx, u.ID)
	wantNoErr(t, "FindUserByID", ferr)
	if got.EmailVerifiedAt != nil {
		t.Fatalf("EmailVerifiedAt = %v after an ErrEmailMismatch, want nil — a refused call must certify nothing", got.EmailVerifiedAt)
	}
	if got.Email != u.Email {
		t.Fatalf("Email = %q after an ErrEmailMismatch, want the unchanged %q", got.Email, u.Email)
	}
}

// checkMarkEmailVerifiedUnknownUser asserts a userID no user holds is
// ErrUserNotFound, distinct from the ErrEmailMismatch a real user with a
// different address gets.
func checkMarkEmailVerifiedUnknownUser(t tb, st auth.Store) {
	t.Helper()
	err := st.MarkEmailVerified(context.Background(), newID(), newEmail(), stamp())
	wantErrIs(t, "MarkEmailVerified(unknown user)", err, auth.ErrUserNotFound)
}

// checkUpdateUserPassword asserts PasswordHash is overwritten and UpdatedAt
// stamped, and that neither the address nor its verification state moves.
func checkUpdateUserPassword(t tb, st auth.Store) {
	t.Helper()
	ctx := context.Background()
	u := mustCreateUser(t, st, newUser(newEmail(), stamp()))
	verifiedAt := stamp().Add(time.Minute)
	wantNoErr(t, "MarkEmailVerified", st.MarkEmailVerified(ctx, u.ID, u.Email, verifiedAt))

	changedAt := verifiedAt.Add(time.Minute)
	wantNoErr(t, "UpdateUserPassword", st.UpdateUserPassword(ctx, u.ID, "new-hash", changedAt))

	got, err := st.FindUserByID(ctx, u.ID)
	wantNoErr(t, "FindUserByID", err)
	if got.PasswordHash != "new-hash" {
		t.Fatalf("PasswordHash = %q, want %q", got.PasswordHash, "new-hash")
	}
	wantTimeEqual(t, "UpdatedAt", got.UpdatedAt, changedAt)
	if got.Email != u.Email {
		t.Fatalf("Email = %q after UpdateUserPassword, want the unchanged %q", got.Email, u.Email)
	}
	if got.EmailVerifiedAt == nil {
		t.Fatalf("EmailVerifiedAt = nil after UpdateUserPassword, want it left alone — a password change proves nothing about the address either way")
	}
}

// checkUpdateUserPasswordEmpty asserts an empty passwordHash is a supported
// state, not an error: it is how a caller removes the password credential
// entirely (see [auth.UserBase]'s doc).
func checkUpdateUserPasswordEmpty(t tb, st auth.Store) {
	t.Helper()
	ctx := context.Background()
	u := mustCreateUser(t, st, newUser(newEmail(), stamp()))

	at := stamp().Add(time.Minute)
	wantNoErr(t, "UpdateUserPassword(empty hash)", st.UpdateUserPassword(ctx, u.ID, "", at))

	got, err := st.FindUserByID(ctx, u.ID)
	wantNoErr(t, "FindUserByID", err)
	if got.PasswordHash != "" {
		t.Fatalf("PasswordHash = %q after an empty update, want \"\" — removing the credential is a supported state", got.PasswordHash)
	}
}

// checkUpdateUserPasswordUnknownUser asserts a userID no user holds is
// ErrUserNotFound.
func checkUpdateUserPasswordUnknownUser(t tb, st auth.Store) {
	t.Helper()
	err := st.UpdateUserPassword(context.Background(), newID(), "hash", stamp())
	wantErrIs(t, "UpdateUserPassword(unknown user)", err, auth.ErrUserNotFound)
}

// checkUpdateUserEmail asserts the three things the port requires of the
// success path at once: the new address is normalized before it is written,
// EmailVerifiedAt is cleared unconditionally (moving an address proves
// nothing about the new one), and UpdatedAt is stamped. It also asserts the
// old address stops resolving.
func checkUpdateUserEmail(t tb, st auth.Store) {
	t.Helper()
	ctx := context.Background()
	u := mustCreateUser(t, st, newUser(newEmail(), stamp()))
	verifiedAt := stamp().Add(time.Minute)
	wantNoErr(t, "MarkEmailVerified", st.MarkEmailVerified(ctx, u.ID, u.Email, verifiedAt))

	next := newEmail()
	changedAt := verifiedAt.Add(time.Minute)
	wantNoErr(t, "UpdateUserEmail", st.UpdateUserEmail(ctx, u.ID, mixedCase(next), changedAt))

	got, err := st.FindUserByID(ctx, u.ID)
	wantNoErr(t, "FindUserByID", err)
	if got.Email != next {
		t.Fatalf("Email = %q, want the normalized %q", got.Email, next)
	}
	if got.EmailVerifiedAt != nil {
		t.Fatalf("EmailVerifiedAt = %v after UpdateUserEmail, want nil — it is cleared unconditionally", got.EmailVerifiedAt)
	}
	wantTimeEqual(t, "UpdatedAt", got.UpdatedAt, changedAt)

	if _, err := st.FindUserByEmail(ctx, u.Email); !errors.Is(err, auth.ErrUserNotFound) {
		t.Fatalf("FindUserByEmail(the old address) error = %v, want ErrUserNotFound", err)
	}
	byNew, err := st.FindUserByEmail(ctx, next)
	wantNoErr(t, "FindUserByEmail(the new address)", err)
	if byNew.ID != u.ID {
		t.Fatalf("FindUserByEmail(%q) returned id %q, want %q", next, byNew.ID, u.ID)
	}
}

// checkUpdateUserEmailSameAddress asserts the uniqueness check excludes the
// row being updated: re-setting a user to the address it already holds is
// not a self-conflict. It still clears EmailVerifiedAt and re-stamps
// UpdatedAt, which the port describes as unconditional.
func checkUpdateUserEmailSameAddress(t tb, st auth.Store) {
	t.Helper()
	ctx := context.Background()
	u := mustCreateUser(t, st, newUser(newEmail(), stamp()))
	verifiedAt := stamp().Add(time.Minute)
	wantNoErr(t, "MarkEmailVerified", st.MarkEmailVerified(ctx, u.ID, u.Email, verifiedAt))

	changedAt := verifiedAt.Add(time.Minute)
	err := st.UpdateUserEmail(ctx, u.ID, u.Email, changedAt)
	wantNoErr(t, "UpdateUserEmail(the address the user already holds)", err)

	got, ferr := st.FindUserByID(ctx, u.ID)
	wantNoErr(t, "FindUserByID", ferr)
	if got.Email != u.Email {
		t.Fatalf("Email = %q, want the unchanged %q", got.Email, u.Email)
	}
	if got.EmailVerifiedAt != nil {
		t.Fatalf("EmailVerifiedAt = %v after re-setting the same address, want nil — the clear is unconditional", got.EmailVerifiedAt)
	}
}

// checkUpdateUserEmailTaken asserts an address a DIFFERENT user already
// holds is refused with ErrEmailTaken — including as a case variant, since
// the comparison is on the normalized form — and that the refused call left
// the row's own address alone. The concurrent form of this obligation, which
// is what the port's MUST is actually about, is driven by
// "UpdateUserEmail/ConcurrentSameAddressAdmitsOneWinner" in concurrency.go.
func checkUpdateUserEmailTaken(t tb, st auth.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	held := mustCreateUser(t, st, newUser(newEmail(), at))
	mover := mustCreateUser(t, st, newUser(newEmail(), at))

	err := st.UpdateUserEmail(ctx, mover.ID, mixedCase(held.Email), stamp().Add(time.Minute))
	wantErrIs(t, "UpdateUserEmail(a case variant of another user's address)", err, auth.ErrEmailTaken)

	got, ferr := st.FindUserByID(ctx, mover.ID)
	wantNoErr(t, "FindUserByID", ferr)
	if got.Email != mover.Email {
		t.Fatalf("Email = %q after an ErrEmailTaken, want the unchanged %q", got.Email, mover.Email)
	}
	stillHeld, ferr := st.FindUserByEmail(ctx, held.Email)
	wantNoErr(t, "FindUserByEmail(the contested address)", ferr)
	if stillHeld.ID != held.ID {
		t.Fatalf("the contested address resolves to id %q, want the original holder %q", stillHeld.ID, held.ID)
	}
}

// checkUpdateUserEmailUnknownUser asserts a userID no user holds is
// ErrUserNotFound.
func checkUpdateUserEmailUnknownUser(t tb, st auth.Store) {
	t.Helper()
	err := st.UpdateUserEmail(context.Background(), newID(), newEmail(), stamp())
	wantErrIs(t, "UpdateUserEmail(unknown user)", err, auth.ErrUserNotFound)
}

// checkDeleteUser asserts [auth.Store.DeleteUser]'s "the user row, and
// nothing else": the id and the address both stop resolving, another user is
// untouched, and — the half that is easy to get wrong in a SQL backend that
// declares ON DELETE CASCADE — the deleted user's own sessions and
// verifications are still there afterwards.
//
// That last part is not fastidiousness about scope. The port makes the
// service layer order the cascade, and the order is fail-safe: sessions
// first, so access stops before anything irreversible happens, then
// verifications, then the user row last. A DeleteUser that quietly took the
// other two with it would make that ordering unobservable — a store could
// then satisfy every test in this suite while performing the cascade in
// whatever order its foreign keys happened to impose, including one that
// destroys the account's data before its access.
//
// It also asserts the deleted account's address can be signed up under
// again — hard deletion is the posture that gives an address back — and that
// deleting the same id twice reports ErrUserNotFound the second time, the
// same shape [auth.Store.DeleteSession] and [auth.Store.DeleteVerification]
// use for their own by-id deletes.
func checkDeleteUser(t tb, st auth.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()

	target := mustCreateUser(t, st, newUser(newEmail(), at))
	bystander := mustCreateUser(t, st, newUser(newEmail(), at))
	sess := mustCreateSession(t, st, newSession(target.ID, newID(), at))
	ver := mustCreateVerification(t, st, newVerification(target.ID, "password_reset", newEmail(), at))

	wantNoErr(t, "DeleteUser", st.DeleteUser(ctx, target.ID))

	if _, err := st.FindUserByID(ctx, target.ID); !errors.Is(err, auth.ErrUserNotFound) {
		t.Fatalf("FindUserByID(the deleted user) error = %v, want ErrUserNotFound", err)
	}
	if _, err := st.FindUserByEmail(ctx, target.Email); !errors.Is(err, auth.ErrUserNotFound) {
		t.Fatalf("FindUserByEmail(the deleted user's address) error = %v, want ErrUserNotFound — the address must be free again", err)
	}
	if _, err := st.FindUserByID(ctx, bystander.ID); err != nil {
		t.Fatalf("FindUserByID(another user) error = %v, want nil — DeleteUser removes one row", err)
	}

	if _, err := st.FindSessionByHash(ctx, sess.TokenHash); err != nil {
		t.Fatalf("FindSessionByHash(the deleted user's session) error = %v, want nil — DeleteUser removes the user row ONLY; the caller orders the cascade", err)
	}
	if _, err := st.FindVerificationByHash(ctx, ver.TokenHash); err != nil {
		t.Fatalf("FindVerificationByHash(the deleted user's verification) error = %v, want nil — DeleteUser removes the user row ONLY; the caller orders the cascade", err)
	}

	// The address is genuinely free again, not merely unresolvable: a new
	// sign-up under it must succeed. Hard deletion is the posture that gives
	// an address back, and a backend whose unique index still held the old
	// row's entry would refuse this with ErrEmailTaken.
	reused := mustCreateUser(t, st, newUser(target.Email, at))
	if reused.ID == target.ID {
		t.Fatalf("fixture error: the reusing account must be a different id than the deleted one")
	}

	err := st.DeleteUser(ctx, target.ID)
	wantErrIs(t, "DeleteUser(the same id twice)", err, auth.ErrUserNotFound)
}

// checkDeleteUserUnknownUser asserts an id no user holds is ErrUserNotFound
// rather than a silent nil. The port distinguishes it from the two
// by-user sweeps deliberately — see [auth.Store.DeleteUser]'s doc — because
// a caller deleting an account by id needs to know the account was there.
func checkDeleteUserUnknownUser(t tb, st auth.Store) {
	t.Helper()
	err := st.DeleteUser(context.Background(), newID())
	wantErrIs(t, "DeleteUser(unknown id)", err, auth.ErrUserNotFound)
}
