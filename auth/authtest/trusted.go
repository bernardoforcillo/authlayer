package authtest

import (
	"context"
	"errors"
	"time"

	"github.com/bernardoforcillo/authlayer/auth"
)

// This file is the trusted-device half of [RunMFAStoreContract]: the seven
// [auth.MFAStore] methods that persist [auth.TrustedDevice].
//
// They are part of the MFA suite rather than a third entry point because
// they are part of the MFA PORT — a backend implementing auth.MFAStore
// implements all fifteen methods or none, and a suite that let a backend
// skip these would let it ship a Service on which "trust this device"
// silently does nothing.
//
// # What these checks are guarding
//
// A trusted device is a long-lived bearer token that skips the SECOND
// factor, so three of the obligations below are security properties rather
// than data-shape ones, and each says so in its own failure message:
//
//   - CreateTrustedDevice refuses a duplicate token hash. Two rows sharing
//     one would make FindTrustedDeviceByHash return whichever the backend
//     reached first, so which ACCOUNT a token skips the factor for would be
//     decided by row order.
//   - ListTrustedDevices and DeleteTrustedDevicesByUser touch one user's
//     rows only. A leaky list hands one user another's device ids to revoke;
//     a leaky by-user delete makes one account's password change revoke a
//     stranger's devices.
//   - TouchTrustedDevice reports false for a row that is gone, which is what
//     lets [auth.Service.LoginWithTrustedDevice] refuse to skip a factor on
//     the strength of a device revoked a moment earlier.
//
// There are no concurrency checks here, and that is not an omission: none of
// the seven methods is a compare-and-set. TouchTrustedDevice comes closest,
// and its contract is only "stamp it if it is there" — a lost update on
// last_used_at is a display field written twice, not a credential spent
// twice.

// newTrustedDevice builds one unexpired device for userID.
func newTrustedDevice(userID string, at time.Time) auth.TrustedDevice {
	return auth.TrustedDevice{
		ID:        newID(),
		UserID:    userID,
		TokenHash: "td-" + newID(),
		Label:     "Ada's laptop",
		CreatedAt: at,
		ExpiresAt: at.Add(30 * 24 * time.Hour),
	}
}

// mustCreateTrustedDevice persists d, failing the check if the store refuses
// it. Used for fixtures, never as the assertion itself.
func mustCreateTrustedDevice(t tb, st auth.MFAStore, d auth.TrustedDevice) auth.TrustedDevice {
	t.Helper()
	got, err := st.CreateTrustedDevice(context.Background(), d)
	if err != nil {
		t.Fatalf("fixture CreateTrustedDevice(%s): unexpected error %v", d.ID, err)
	}
	return got
}

// deviceIDs returns the ids of userID's stored devices as a set, so a check
// can compare membership without depending on the unspecified order.
func deviceIDs(t tb, st auth.MFAStore, userID string) map[string]auth.TrustedDevice {
	t.Helper()
	list, err := st.ListTrustedDevices(context.Background(), userID)
	if err != nil {
		t.Fatalf("ListTrustedDevices(%s): unexpected error %v", userID, err)
	}
	out := make(map[string]auth.TrustedDevice, len(list))
	for _, d := range list {
		out[d.ID] = d
	}
	return out
}

func trustedDeviceChecks() []mfaCheck {
	return []mfaCheck{
		{"CreateTrustedDevice/RoundTripsEveryFieldAndIsFoundByHash", checkCreateTrustedDeviceRoundTrip},
		{"CreateTrustedDevice/ADuplicateIDIsRefusedWithErrIDTaken", checkCreateTrustedDeviceDuplicateID},
		{"CreateTrustedDevice/ADuplicateTokenHashIsRefused", checkCreateTrustedDeviceDuplicateHash},
		{"FindTrustedDeviceByHash/UnknownHashReturnsErrTrustedDeviceNotFound", checkFindTrustedDeviceUnknown},
		{"ListTrustedDevices/ReturnsThatUsersDevicesOnly", checkListTrustedDevicesIsPerUser},
		{"DeleteTrustedDevice/RemovesOneRowThenReportsNotFound", checkDeleteTrustedDevice},
		{"DeleteTrustedDevicesByUser/RemovesEveryDeviceOfThatUserOnly", checkDeleteTrustedDevicesByUser},
		{"DeleteTrustedDevicesByUser/MatchingNoRowsIsSuccess", checkDeleteTrustedDevicesByUserOnNothing},
		{"TouchTrustedDevice/StampsLastUsedAtAndReportsTrue", checkTouchTrustedDevice},
		{"TouchTrustedDevice/UnknownIDIsFalseAndNotAnError", checkTouchTrustedDeviceUnknown},
		{"PurgeExpiredTrustedDevices/RemovesOnlyRowsExpiredBeforeTheCutoff", checkPurgeExpiredTrustedDevices},
	}
}

// checkCreateTrustedDeviceRoundTrip stores a device and requires every field
// back through FindTrustedDeviceByHash, LastUsedAt's nil included. nil is
// the state a device leaves once ("this machine has never skipped a
// challenge"), and a backend that returned the zero time instead would make
// every freshly trusted device look used.
func checkCreateTrustedDeviceRoundTrip(t tb, st auth.MFAStore) {
	t.Helper()
	at := stamp()
	d := newTrustedDevice(newID(), at)

	created := mustCreateTrustedDevice(t, st, d)
	if created.ID != d.ID || created.TokenHash != d.TokenHash {
		t.Fatalf("CreateTrustedDevice returned {ID:%q TokenHash:%q}, want {%q %q}", created.ID, created.TokenHash, d.ID, d.TokenHash)
	}

	got, err := st.FindTrustedDeviceByHash(context.Background(), d.TokenHash)
	if err != nil {
		t.Fatalf("FindTrustedDeviceByHash: unexpected error %v", err)
	}
	if got.ID != d.ID || got.UserID != d.UserID || got.Label != d.Label {
		t.Fatalf("FindTrustedDeviceByHash = {ID:%q UserID:%q Label:%q}, want {%q %q %q}", got.ID, got.UserID, got.Label, d.ID, d.UserID, d.Label)
	}
	wantTimeEqual(t, "CreatedAt", got.CreatedAt, d.CreatedAt)
	wantTimeEqual(t, "ExpiresAt", got.ExpiresAt, d.ExpiresAt)
	if got.LastUsedAt != nil {
		t.Fatalf("LastUsedAt = %v for a freshly trusted device, want nil — nil is how a caller tells \"never skipped a challenge\" from \"skipped one at the epoch\"", *got.LastUsedAt)
	}
}

// checkCreateTrustedDeviceDuplicateID pins that an id already in use is
// auth.ErrIDTaken and does not overwrite the row that holds it.
func checkCreateTrustedDeviceDuplicateID(t tb, st auth.MFAStore) {
	t.Helper()
	ctx := context.Background()
	at := stamp()

	first := mustCreateTrustedDevice(t, st, newTrustedDevice(newID(), at))

	clash := newTrustedDevice(newID(), at)
	clash.ID = first.ID
	if _, err := st.CreateTrustedDevice(ctx, clash); !errors.Is(err, auth.ErrIDTaken) {
		t.Fatalf("CreateTrustedDevice with a taken id = %v, want auth.ErrIDTaken", err)
	}

	got, err := st.FindTrustedDeviceByHash(ctx, first.TokenHash)
	if err != nil || got.UserID != first.UserID {
		t.Fatalf("after the refused create, the original row is {%+v} (err %v) — a refused insert must not disturb the row it collided with", got, err)
	}
}

// checkCreateTrustedDeviceDuplicateHash is [auth.TrustedDevice.TokenHash]'s
// MUST. The sentinel is deliberately unspecified — the port says so — so
// this asserts only that the second create FAILS and that the stored row is
// still the first one's.
//
// Two rows sharing a token hash would make FindTrustedDeviceByHash return
// whichever the backend reached first, so which account a token skips the
// second factor for would be decided by row order.
func checkCreateTrustedDeviceDuplicateHash(t tb, st auth.MFAStore) {
	t.Helper()
	ctx := context.Background()
	at := stamp()

	first := mustCreateTrustedDevice(t, st, newTrustedDevice(newID(), at))

	clash := newTrustedDevice(newID(), at)
	clash.TokenHash = first.TokenHash
	if _, err := st.CreateTrustedDevice(ctx, clash); err == nil {
		t.Fatalf("CreateTrustedDevice with a token hash another row already holds returned nil — two devices sharing a hash means WHICH ACCOUNT that token skips the second factor for is decided by row order")
	}

	got, err := st.FindTrustedDeviceByHash(ctx, first.TokenHash)
	if err != nil {
		t.Fatalf("FindTrustedDeviceByHash after the refused create: %v", err)
	}
	if got.ID != first.ID || got.UserID != first.UserID {
		t.Fatalf("the hash now resolves to {ID:%q UserID:%q}, want the original {%q %q} — the refused insert replaced or re-pointed the row it collided with", got.ID, got.UserID, first.ID, first.UserID)
	}
}

// checkFindTrustedDeviceUnknown pins the sentinel for a hash no row holds.
// A backend answering with the zero value and a nil error would hand
// [auth.Service.trustedDeviceAtSignIn] a device whose UserID is "" — which
// it compares against the account it just authenticated, so the miss is
// caught — but which every other caller would read as a real row.
func checkFindTrustedDeviceUnknown(t tb, st auth.MFAStore) {
	t.Helper()
	if _, err := st.FindTrustedDeviceByHash(context.Background(), "td-no-such-hash"); !errors.Is(err, auth.ErrTrustedDeviceNotFound) {
		t.Fatalf("FindTrustedDeviceByHash on an unknown hash = %v, want auth.ErrTrustedDeviceNotFound", err)
	}
}

// checkListTrustedDevicesIsPerUser pins that the listing is scoped to its
// user. A leaky one hands a "your devices" screen somebody else's device
// ids, which [auth.Service.RevokeTrustedDevice] would then accept as the
// caller's own — the ownership check it performs is exactly this listing.
func checkListTrustedDevicesIsPerUser(t tb, st auth.MFAStore) {
	t.Helper()
	at := stamp()
	alice, bob := newID(), newID()

	a1 := mustCreateTrustedDevice(t, st, newTrustedDevice(alice, at))
	a2 := mustCreateTrustedDevice(t, st, newTrustedDevice(alice, at))
	b1 := mustCreateTrustedDevice(t, st, newTrustedDevice(bob, at))

	got := deviceIDs(t, st, alice)
	if len(got) != 2 || got[a1.ID].ID == "" || got[a2.ID].ID == "" {
		t.Fatalf("ListTrustedDevices(alice) returned %d rows, want exactly her two", len(got))
	}
	if _, leaked := got[b1.ID]; leaked {
		t.Fatalf("ListTrustedDevices(alice) included bob's device %s — a caller reading this listing would be handed another account's device id to revoke", b1.ID)
	}
}

// checkDeleteTrustedDevice pins the single-row delete and its sentinel: the
// named row goes, the user's other one stays, and a second delete of the
// same id reports auth.ErrTrustedDeviceNotFound.
func checkDeleteTrustedDevice(t tb, st auth.MFAStore) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	userID := newID()

	doomed := mustCreateTrustedDevice(t, st, newTrustedDevice(userID, at))
	keep := mustCreateTrustedDevice(t, st, newTrustedDevice(userID, at))

	if err := st.DeleteTrustedDevice(ctx, doomed.ID); err != nil {
		t.Fatalf("DeleteTrustedDevice: unexpected error %v", err)
	}
	got := deviceIDs(t, st, userID)
	if _, still := got[doomed.ID]; still {
		t.Fatalf("the deleted device %s is still listed", doomed.ID)
	}
	if _, gone := got[keep.ID]; !gone {
		t.Fatalf("DeleteTrustedDevice removed %s as well — it must remove the one row it names", keep.ID)
	}

	if err := st.DeleteTrustedDevice(ctx, doomed.ID); !errors.Is(err, auth.ErrTrustedDeviceNotFound) {
		t.Fatalf("DeleteTrustedDevice on an already-removed id = %v, want auth.ErrTrustedDeviceNotFound", err)
	}
}

// checkDeleteTrustedDevicesByUser is the sweep primitive every remediation
// path in [auth.Service.ChangePassword]'s matrix calls. It must take every
// one of that user's devices and none of anybody else's: leaving one behind
// leaves a live second-factor bypass after a password change, and taking a
// stranger's makes one account's remediation sign another account's laptop
// out of its convenience.
func checkDeleteTrustedDevicesByUser(t tb, st auth.MFAStore) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	alice, bob := newID(), newID()

	mustCreateTrustedDevice(t, st, newTrustedDevice(alice, at))
	mustCreateTrustedDevice(t, st, newTrustedDevice(alice, at))
	b1 := mustCreateTrustedDevice(t, st, newTrustedDevice(bob, at))

	if err := st.DeleteTrustedDevicesByUser(ctx, alice); err != nil {
		t.Fatalf("DeleteTrustedDevicesByUser: unexpected error %v", err)
	}
	if n := len(deviceIDs(t, st, alice)); n != 0 {
		t.Fatalf("alice has %d devices after the sweep, want 0 — a device left behind is a live second-factor bypass surviving the remediation that was supposed to end it", n)
	}
	bobs := deviceIDs(t, st, bob)
	if _, ok := bobs[b1.ID]; !ok || len(bobs) != 1 {
		t.Fatalf("bob has %d devices after alice's sweep, want exactly his one", len(bobs))
	}
}

// checkDeleteTrustedDevicesByUserOnNothing pins that sweeping an account
// with no devices is SUCCESS. The port says so for a reason: this call sits
// inside [auth.Service.ChangePassword], and an error here would make every
// password change fail for the majority of users, who have never trusted a
// device.
func checkDeleteTrustedDevicesByUserOnNothing(t tb, st auth.MFAStore) {
	t.Helper()
	if err := st.DeleteTrustedDevicesByUser(context.Background(), newID()); err != nil {
		t.Fatalf("DeleteTrustedDevicesByUser on a user with no devices = %v, want nil — this is the sweep every password change performs", err)
	}
}

// checkTouchTrustedDevice pins the stamp and the true beside it, and that
// the row is otherwise unchanged.
func checkTouchTrustedDevice(t tb, st auth.MFAStore) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	d := mustCreateTrustedDevice(t, st, newTrustedDevice(newID(), at))

	used := at.Add(2 * time.Hour)
	switch ok, err := st.TouchTrustedDevice(ctx, d.ID, used); {
	case err != nil:
		t.Fatalf("TouchTrustedDevice: unexpected error %v", err)
	case !ok:
		t.Fatalf("TouchTrustedDevice on a live device = false, want true")
	}

	got, err := st.FindTrustedDeviceByHash(ctx, d.TokenHash)
	if err != nil {
		t.Fatalf("FindTrustedDeviceByHash: %v", err)
	}
	if got.LastUsedAt == nil {
		t.Fatalf("LastUsedAt = nil after TouchTrustedDevice reported true")
	}
	wantTimeEqual(t, "LastUsedAt", *got.LastUsedAt, used)
	wantTimeEqual(t, "ExpiresAt after a touch", got.ExpiresAt, d.ExpiresAt)
}

// checkTouchTrustedDeviceUnknown pins the false-not-error answer for a row
// that is gone, which is the answer [auth.Service.LoginWithTrustedDevice]
// reads as "this device was revoked while I was signing in" — and refuses to
// skip a second factor on. A backend that returned an error instead would
// turn a concurrent revocation into a failed login, and one that returned
// true would let a revoked device skip a factor.
func checkTouchTrustedDeviceUnknown(t tb, st auth.MFAStore) {
	t.Helper()
	switch ok, err := st.TouchTrustedDevice(context.Background(), newID(), stamp()); {
	case err != nil:
		t.Fatalf("TouchTrustedDevice on an unknown id = (_, %v), want (false, nil)", err)
	case ok:
		t.Fatalf("TouchTrustedDevice on an unknown id = true — a caller reads that as \"the device is still there\" and skips a second factor for a row that does not exist")
	}
}

// checkPurgeExpiredTrustedDevices pins the cutoff's strictness and its
// scope: rows expiring before it go, a row expiring exactly AT it stays
// (`ExpiresAt < before`, matching [auth.Store.PurgeExpired]), and the count
// is the number actually removed.
func checkPurgeExpiredTrustedDevices(t tb, st auth.MFAStore) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	userID := newID()

	cutoff := at.Add(time.Hour)

	old := newTrustedDevice(userID, at)
	old.ExpiresAt = cutoff.Add(-time.Minute)
	mustCreateTrustedDevice(t, st, old)

	boundary := newTrustedDevice(userID, at)
	boundary.ExpiresAt = cutoff
	mustCreateTrustedDevice(t, st, boundary)

	live := newTrustedDevice(userID, at)
	live.ExpiresAt = cutoff.Add(time.Minute)
	mustCreateTrustedDevice(t, st, live)

	n, err := st.PurgeExpiredTrustedDevices(ctx, cutoff)
	if err != nil {
		t.Fatalf("PurgeExpiredTrustedDevices: unexpected error %v", err)
	}
	if n != 1 {
		t.Fatalf("PurgeExpiredTrustedDevices removed %d rows, want 1 — only the row expiring strictly before the cutoff", n)
	}

	got := deviceIDs(t, st, userID)
	if _, still := got[old.ID]; still {
		t.Fatalf("the expired device %s survived the purge", old.ID)
	}
	if _, ok := got[boundary.ID]; !ok {
		t.Fatalf("the device expiring exactly AT the cutoff was purged — the comparison is `ExpiresAt < before`, matching every other purge in this package")
	}
	if _, ok := got[live.ID]; !ok {
		t.Fatalf("a device expiring after the cutoff was purged")
	}
}
