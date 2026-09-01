package authtest

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/bernardoforcillo/authlayer/auth"
)

// This file is the executable contract for [auth.MFAStore], the OPTIONAL
// second-factor port. It is a second entry point beside [RunStoreContract]
// rather than more checks inside it, because the port itself is optional:
// a backend that implements auth.Store and no MFA is a conforming backend
// (see auth/mfa.go's package doc for which rule decides that), and a suite
// that demanded both would say otherwise.
//
// # What the concurrent checks can and cannot prove
//
// Three of the eight methods are compare-and-set, and each is checked
// TWICE, deliberately:
//
//   - A SEQUENTIAL check pins the semantics — a second confirmer sees
//     false, a step at or below LastStep is refused, a burnt code cannot be
//     burnt again. These are deterministic: they catch a store with no
//     compare-and-set at all on every run, with no interleaving to hope
//     for.
//   - A CONCURRENT check pins the atomicity, which is unreachable
//     sequentially: [RaceGoroutines] goroutines released together must
//     produce exactly one winner.
//
// The concurrent ones are mass races rather than two-party races on
// purpose. This package's own [pair] documents why a fixed-role two-party
// race explores essentially one interleaving — closing a channel readies
// its waiters in an order that makes the last-started goroutine run first,
// measured at 198 rounds in 200 — and the answer there is to swap the
// roles between rounds. Here there are no roles to swap: every goroutine
// runs the SAME call, so the assertion ("exactly one of them won") is
// independent of the order they run in, and the bias has nothing to bite
// on.
//
// What a mass race cannot promise is that it will FORCE a subtly
// non-atomic backend into its window; a split-lock in-process store's
// window is sub-microsecond, and a database-backed store with a cold pool
// lets goroutines trickle in across a window wider than the race. It
// catches a grossly non-atomic implementation every time. The
// deterministic evidence that each check bites lives in
// mfa_negative_test.go, where the split-lock doubles hold their window
// open for [gap].

// mfaCheck is one named obligation of [auth.MFAStore]. It mirrors [check]
// rather than reusing it because the two ports are different types; the
// runner, the recorder and the fixtures are shared.
type mfaCheck struct {
	name string
	fn   func(t tb, st auth.MFAStore)
}

// mfaStoreContractChecks is every check [RunMFAStoreContract] runs, in
// order: the factor record, then the recovery codes, then the trusted
// devices (trusted.go), then the obligations that only appear under
// concurrency.
func mfaStoreContractChecks() []mfaCheck {
	var all []mfaCheck
	all = append(all, mfaFactorChecks()...)
	all = append(all, recoveryCodeChecks()...)
	all = append(all, trustedDeviceChecks()...)
	all = append(all, mfaConcurrencyChecks()...)
	return all
}

// RunMFAStoreContract exercises every documented obligation of
// [auth.MFAStore] against the implementation newStore returns, as one
// sub-test per obligation.
//
// newStore is called once per sub-test and must return a store with no
// factors and no recovery codes in it. Every check builds its own
// fixtures, so a store carrying rows from a previous check will produce
// spurious failures. Register whatever teardown the backend needs with
// t.Cleanup inside the factory; the *testing.T handed to it is the
// sub-check's own. A factory is free to t.Skip.
//
// Ids are UUIDv7, so the suite runs against a backend that types its id
// columns as uuid (which store/drops does) as well as one that accepts any
// string.
//
// # What it deliberately does not assert
//
// The port leaves three things to the implementation and so does this
// suite: ListRecoveryCodes' order (results are sorted before comparison)
// and its empty-versus-nil result (read through len only), and the exact
// error a backend returns for anything the port does not classify into a
// sentinel.
//
// It also cannot see whether a backend decided ErrIDTaken from a separate
// read rather than from the write attempt — the same limit
// [RunStoreContract] documents for [auth.Store.CreateUser]. What IS
// observable is the consequence when a check and a write are not one step,
// and that is what the concurrent checks assert.
func RunMFAStoreContract(t *testing.T, newStore func(t *testing.T) auth.MFAStore) {
	t.Helper()
	if newStore == nil {
		t.Fatalf("authtest: newStore must not be nil")
	}
	for _, c := range mfaStoreContractChecks() {
		t.Run(c.name, func(t *testing.T) {
			st := newStore(t)
			if st == nil {
				t.Fatalf("authtest: newStore returned a nil auth.MFAStore")
			}
			c.fn(t, st)
		})
	}
}

// --- shared fixtures ---

// newFactor builds an UNCONFIRMED factor for userID with no step history —
// the state [auth.Service.BeginMFAEnrolment] leaves behind, and the one
// whose nil fields carry the most weight.
func newFactor(userID string, at time.Time) auth.MFAFactor {
	return auth.MFAFactor{
		UserID:    userID,
		SecretEnc: "enc-" + newID(),
		CreatedAt: at,
	}
}

// newRecoveryCode builds one unused recovery code for userID.
func newRecoveryCode(userID string, at time.Time) auth.RecoveryCode {
	return auth.RecoveryCode{
		ID:        newID(),
		UserID:    userID,
		CodeHash:  "rc-" + newID(),
		CreatedAt: at,
	}
}

// newRecoveryCodes builds n unused recovery codes for userID.
func newRecoveryCodes(userID string, at time.Time, n int) []auth.RecoveryCode {
	out := make([]auth.RecoveryCode, n)
	for i := range out {
		out[i] = newRecoveryCode(userID, at)
	}
	return out
}

// mustUpsertFactor persists f, failing the check if the store refuses it.
// Used for fixtures, never as the assertion itself.
func mustUpsertFactor(t tb, st auth.MFAStore, f auth.MFAFactor) auth.MFAFactor {
	t.Helper()
	if err := st.UpsertFactor(context.Background(), f); err != nil {
		t.Fatalf("fixture UpsertFactor(%s): unexpected error %v", f.UserID, err)
	}
	return f
}

// mustFindFactor loads userID's factor, failing the check if it is absent.
func mustFindFactor(t tb, st auth.MFAStore, userID string) auth.MFAFactor {
	t.Helper()
	got, err := st.FindFactor(context.Background(), userID)
	if err != nil {
		t.Fatalf("FindFactor(%s): unexpected error %v", userID, err)
	}
	return got
}

// mustReplaceRecoveryCodes writes codes as userID's whole set.
func mustReplaceRecoveryCodes(t tb, st auth.MFAStore, userID string, codes []auth.RecoveryCode) {
	t.Helper()
	if err := st.ReplaceRecoveryCodes(context.Background(), userID, codes); err != nil {
		t.Fatalf("fixture ReplaceRecoveryCodes(%s): unexpected error %v", userID, err)
	}
}

// codeHashes returns the hashes of userID's stored codes, so a check can
// compare sets without depending on the unspecified order.
func codeHashes(t tb, st auth.MFAStore, userID string) map[string]auth.RecoveryCode {
	t.Helper()
	list, err := st.ListRecoveryCodes(context.Background(), userID)
	if err != nil {
		t.Fatalf("ListRecoveryCodes(%s): unexpected error %v", userID, err)
	}
	out := make(map[string]auth.RecoveryCode, len(list))
	for _, c := range list {
		out[c.CodeHash] = c
	}
	return out
}

// --- the factor record ---

func mfaFactorChecks() []mfaCheck {
	return []mfaCheck{
		{"UpsertFactor/RoundTripsEveryFieldIncludingTheNilOnes", checkUpsertRoundTrip},
		{"UpsertFactor/ReplacesTheWholeRowRatherThanMerging", checkUpsertReplacesWholeRow},
		{"UpsertFactor/TouchesOnlyThatUsersFactor", checkUpsertIsPerUser},
		{"FindFactor/UnknownUserReturnsErrFactorNotFound", checkFindFactorUnknown},
		{"ConfirmFactor/StampsOnceThenReportsFalse", checkConfirmFactorOnce},
		{"ConfirmFactor/UnknownUserReturnsErrFactorNotFound", checkConfirmFactorUnknown},
		{"AdvanceStep/AcceptsTheFirstStepAndRecordsIt", checkAdvanceStepFirst},
		{"AdvanceStep/RefusesAStepAtOrBelowLastStep", checkAdvanceStepRefusesReplay},
		{"AdvanceStep/UnknownUserReturnsErrFactorNotFound", checkAdvanceStepUnknown},
		{"AdvanceStep/TouchesOnlyThatUsersFactor", checkAdvanceStepIsPerUser},
		{"DeleteFactor/RemovesTheFactorRowOnly", checkDeleteFactorRowOnly},
		{"DeleteFactor/UnknownUserReturnsErrFactorNotFound", checkDeleteFactorUnknown},
	}
}

// checkUpsertRoundTrip stores a factor in each of its two shapes — the
// unconfirmed, step-less one enrolment writes, and a fully populated one —
// and requires every field back unchanged. A backend that drops
// ConfirmedAt or LastStep on the way in or out silently disables both the
// confirmation gate and the replay guard.
func checkUpsertRoundTrip(t tb, st auth.MFAStore) {
	t.Helper()
	at := stamp()
	userID := newID()

	fresh := newFactor(userID, at)
	mustUpsertFactor(t, st, fresh)

	got := mustFindFactor(t, st, userID)
	if got.UserID != fresh.UserID || got.SecretEnc != fresh.SecretEnc {
		t.Fatalf("FindFactor = {UserID:%q SecretEnc:%q}, want {%q %q}", got.UserID, got.SecretEnc, fresh.UserID, fresh.SecretEnc)
	}
	wantTimeEqual(t, "CreatedAt", got.CreatedAt, fresh.CreatedAt)
	if got.ConfirmedAt != nil {
		t.Fatalf("FindFactor ConfirmedAt = %v for a freshly enrolled factor, want nil — an unconfirmed factor must be distinguishable, or a half-finished enrolment locks the account out", *got.ConfirmedAt)
	}
	if got.LastStep != nil {
		t.Fatalf("FindFactor LastStep = %d for a freshly enrolled factor, want nil", *got.LastStep)
	}

	confirmed := at.Add(time.Minute)
	step := int64(56789012)
	full := newFactor(userID, at)
	full.ConfirmedAt = &confirmed
	full.LastStep = &step
	mustUpsertFactor(t, st, full)

	got = mustFindFactor(t, st, userID)
	if got.ConfirmedAt == nil {
		t.Fatalf("FindFactor ConfirmedAt = nil after storing one")
	}
	wantTimeEqual(t, "ConfirmedAt", *got.ConfirmedAt, confirmed)
	if got.LastStep == nil || *got.LastStep != step {
		t.Fatalf("FindFactor LastStep = %v, want %d", got.LastStep, step)
	}
	if got.SecretEnc != full.SecretEnc {
		t.Fatalf("FindFactor SecretEnc = %q, want the second write's %q", got.SecretEnc, full.SecretEnc)
	}
}

// checkUpsertReplacesWholeRow is [auth.MFAStore.UpsertFactor]'s MUST: a
// second upsert REPLACES, it does not merge. It confirms a factor and
// advances its step, then re-enrols with a fresh unconfirmed factor and
// requires both fields back at nil.
//
// A merging upsert leaves a brand-new secret carrying the OLD
// confirmation, so an enrolment the user abandoned half way still gates
// every login with a secret no authenticator holds — the permanent lockout
// [auth.MFAFactor.ConfirmedAt]'s nil state exists to prevent, reached
// through the write path. It also leaves the old LastStep in place, which
// refuses the user's first genuine code from the new secret.
func checkUpsertReplacesWholeRow(t tb, st auth.MFAStore) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	userID := newID()

	mustUpsertFactor(t, st, newFactor(userID, at))
	if ok, err := st.ConfirmFactor(ctx, userID, at.Add(time.Minute)); err != nil || !ok {
		t.Fatalf("fixture ConfirmFactor = (%v, %v), want (true, nil)", ok, err)
	}
	if ok, err := st.AdvanceStep(ctx, userID, 4242); err != nil || !ok {
		t.Fatalf("fixture AdvanceStep = (%v, %v), want (true, nil)", ok, err)
	}

	reEnrolled := newFactor(userID, at.Add(time.Hour))
	mustUpsertFactor(t, st, reEnrolled)

	got := mustFindFactor(t, st, userID)
	if got.SecretEnc != reEnrolled.SecretEnc {
		t.Fatalf("FindFactor SecretEnc = %q, want the re-enrolled %q", got.SecretEnc, reEnrolled.SecretEnc)
	}
	if got.ConfirmedAt != nil {
		t.Fatalf("re-enrolment left ConfirmedAt = %v, want nil — the upsert merged instead of replacing, so a new secret nobody has scanned is already gating login", *got.ConfirmedAt)
	}
	if got.LastStep != nil {
		t.Fatalf("re-enrolment left LastStep = %d, want nil — the upsert merged instead of replacing, so the new secret's first genuine code is refused as a replay", *got.LastStep)
	}
	wantTimeEqual(t, "CreatedAt after re-enrolment", got.CreatedAt, reEnrolled.CreatedAt)
}

// checkUpsertIsPerUser pins that one user's enrolment does not disturb
// another's factor — the "at most one row per user" key is per user, not
// global.
func checkUpsertIsPerUser(t tb, st auth.MFAStore) {
	t.Helper()
	at := stamp()
	alice, bob := newID(), newID()

	aliceFactor := mustUpsertFactor(t, st, newFactor(alice, at))
	bobFactor := mustUpsertFactor(t, st, newFactor(bob, at))

	if got := mustFindFactor(t, st, alice); got.SecretEnc != aliceFactor.SecretEnc {
		t.Fatalf("alice's SecretEnc = %q after bob enrolled, want %q", got.SecretEnc, aliceFactor.SecretEnc)
	}
	if got := mustFindFactor(t, st, bob); got.SecretEnc != bobFactor.SecretEnc {
		t.Fatalf("bob's SecretEnc = %q, want %q", got.SecretEnc, bobFactor.SecretEnc)
	}
}

// checkFindFactorUnknown pins that "not enrolled" is ErrFactorNotFound and
// a ZERO factor, never a zero factor with a nil error — a caller that read
// an empty SecretEnc as a factor would decrypt nothing and refuse every
// code, or worse, treat the account as having no second factor at all.
func checkFindFactorUnknown(t tb, st auth.MFAStore) {
	t.Helper()
	got, err := st.FindFactor(context.Background(), newID())
	wantErrIs(t, "FindFactor of an unenrolled user", err, auth.ErrFactorNotFound)
	if got.UserID != "" || got.SecretEnc != "" {
		t.Fatalf("FindFactor returned %#v alongside ErrFactorNotFound, want the zero factor", got)
	}
}

// checkConfirmFactorOnce is the sequential half of ConfirmFactor's
// compare-and-set: the first caller stamps and reports true, the second
// reports false and leaves the ORIGINAL stamp alone. The moment of
// confirmation is a fact about the account, not a value the latest caller
// overwrites.
func checkConfirmFactorOnce(t tb, st auth.MFAStore) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	userID := newID()
	mustUpsertFactor(t, st, newFactor(userID, at))

	first := at.Add(time.Minute)
	ok, err := st.ConfirmFactor(ctx, userID, first)
	wantNoErr(t, "first ConfirmFactor", err)
	if !ok {
		t.Fatalf("first ConfirmFactor reported false on an unconfirmed factor")
	}
	got := mustFindFactor(t, st, userID)
	if got.ConfirmedAt == nil {
		t.Fatalf("ConfirmFactor reported true but ConfirmedAt is nil")
	}
	wantTimeEqual(t, "ConfirmedAt", *got.ConfirmedAt, first)

	second := at.Add(time.Hour)
	ok, err = st.ConfirmFactor(ctx, userID, second)
	wantNoErr(t, "second ConfirmFactor", err)
	if ok {
		t.Fatalf("second ConfirmFactor reported true on an already-confirmed factor — every caller wins, so the compare-and-set is not one")
	}
	got = mustFindFactor(t, st, userID)
	wantTimeEqual(t, "ConfirmedAt after a losing ConfirmFactor", *got.ConfirmedAt, first)
}

func checkConfirmFactorUnknown(t tb, st auth.MFAStore) {
	t.Helper()
	ok, err := st.ConfirmFactor(context.Background(), newID(), stamp())
	wantErrIs(t, "ConfirmFactor of an unenrolled user", err, auth.ErrFactorNotFound)
	if ok {
		t.Fatalf("ConfirmFactor reported true for a user with no factor")
	}
}

// checkAdvanceStepFirst pins the nil-LastStep case: a factor that has
// authenticated nothing accepts any step, and records it. Refusing here
// would refuse the user's very first code.
func checkAdvanceStepFirst(t tb, st auth.MFAStore) {
	t.Helper()
	ctx := context.Background()
	userID := newID()
	mustUpsertFactor(t, st, newFactor(userID, stamp()))

	const step = int64(58023700)
	ok, err := st.AdvanceStep(ctx, userID, step)
	wantNoErr(t, "first AdvanceStep", err)
	if !ok {
		t.Fatalf("AdvanceStep refused the first step of a factor whose LastStep is nil")
	}
	got := mustFindFactor(t, st, userID)
	if got.LastStep == nil || *got.LastStep != step {
		t.Fatalf("LastStep = %v after a winning AdvanceStep, want %d", got.LastStep, step)
	}
}

// checkAdvanceStepRefusesReplay is the sequential half of the replay
// guard, and the check the whole method exists for: after step N is
// spent, N and everything below it are refused, and the stored LastStep
// does not move.
//
// Without it, a code read over a user's shoulder stays usable for the rest
// of the skew window — a minute and a half during which the second factor
// buys nothing against an attacker who is watching.
func checkAdvanceStepRefusesReplay(t tb, st auth.MFAStore) {
	t.Helper()
	ctx := context.Background()
	userID := newID()
	mustUpsertFactor(t, st, newFactor(userID, stamp()))

	const spent = int64(58023700)
	if ok, err := st.AdvanceStep(ctx, userID, spent); err != nil || !ok {
		t.Fatalf("fixture AdvanceStep(%d) = (%v, %v), want (true, nil)", spent, ok, err)
	}

	for _, replay := range []int64{spent, spent - 1, spent - 1000, 0, -1} {
		ok, err := st.AdvanceStep(ctx, userID, replay)
		wantNoErr(t, "replaying AdvanceStep", err)
		if ok {
			t.Fatalf("AdvanceStep(%d) reported true against LastStep %d — a step at or below the last one used is a REPLAY, and accepting it leaves a shoulder-surfed code valid for its whole skew window", replay, spent)
		}
		got := mustFindFactor(t, st, userID)
		if got.LastStep == nil || *got.LastStep != spent {
			t.Fatalf("LastStep = %v after a refused AdvanceStep(%d), want it untouched at %d", got.LastStep, replay, spent)
		}
	}

	next := spent + 1
	ok, err := st.AdvanceStep(ctx, userID, next)
	wantNoErr(t, "AdvanceStep to the next step", err)
	if !ok {
		t.Fatalf("AdvanceStep(%d) refused a step above LastStep %d — the guard is refusing legitimate logins", next, spent)
	}
	got := mustFindFactor(t, st, userID)
	if got.LastStep == nil || *got.LastStep != next {
		t.Fatalf("LastStep = %v, want %d", got.LastStep, next)
	}
}

func checkAdvanceStepUnknown(t tb, st auth.MFAStore) {
	t.Helper()
	ok, err := st.AdvanceStep(context.Background(), newID(), 1)
	wantErrIs(t, "AdvanceStep for an unenrolled user", err, auth.ErrFactorNotFound)
	if ok {
		t.Fatalf("AdvanceStep reported true for a user with no factor")
	}
}

// checkAdvanceStepIsPerUser pins that the replay guard is per account.
// A shared LastStep would let one user's login refuse another's, and —
// the dangerous direction — one user's spent step raise the floor for
// everyone, or fail to.
func checkAdvanceStepIsPerUser(t tb, st auth.MFAStore) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	alice, bob := newID(), newID()
	mustUpsertFactor(t, st, newFactor(alice, at))
	mustUpsertFactor(t, st, newFactor(bob, at))

	const step = int64(58023700)
	if ok, err := st.AdvanceStep(ctx, alice, step); err != nil || !ok {
		t.Fatalf("fixture AdvanceStep(alice) = (%v, %v), want (true, nil)", ok, err)
	}

	ok, err := st.AdvanceStep(ctx, bob, step)
	wantNoErr(t, "AdvanceStep(bob)", err)
	if !ok {
		t.Fatalf("AdvanceStep(bob, %d) reported false after alice used that step — the replay guard is shared between accounts", step)
	}
	if got := mustFindFactor(t, st, alice); got.LastStep == nil || *got.LastStep != step {
		t.Fatalf("alice's LastStep = %v after bob advanced, want %d", got.LastStep, step)
	}
}

// checkDeleteFactorRowOnly pins DeleteFactor's scope: the factor row, and
// nothing beside it — not the user's recovery codes, and not another
// user's factor. It mirrors [auth.Store.DeleteUser]'s own "the user row
// ONLY" check, and rests on the same reasoning: the extent of a cascade is
// a policy decision belonging to the caller, so a store that helpfully
// widens it takes that decision away.
func checkDeleteFactorRowOnly(t tb, st auth.MFAStore) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	alice, bob := newID(), newID()
	mustUpsertFactor(t, st, newFactor(alice, at))
	mustUpsertFactor(t, st, newFactor(bob, at))
	codes := newRecoveryCodes(alice, at, 3)
	mustReplaceRecoveryCodes(t, st, alice, codes)

	wantNoErr(t, "DeleteFactor", st.DeleteFactor(ctx, alice))

	if _, err := st.FindFactor(ctx, alice); !errors.Is(err, auth.ErrFactorNotFound) {
		t.Fatalf("FindFactor after DeleteFactor: err = %v, want ErrFactorNotFound", err)
	}
	if got := codeHashes(t, st, alice); len(got) != len(codes) {
		t.Fatalf("DeleteFactor left %d of %d recovery codes — it removed rows it does not own; the caller decides whether the codes go too", len(got), len(codes))
	}
	if _, err := st.FindFactor(ctx, bob); err != nil {
		t.Fatalf("DeleteFactor(alice) disturbed bob's factor: %v", err)
	}
}

func checkDeleteFactorUnknown(t tb, st auth.MFAStore) {
	t.Helper()
	err := st.DeleteFactor(context.Background(), newID())
	wantErrIs(t, "DeleteFactor of an unenrolled user", err, auth.ErrFactorNotFound)
}

// --- recovery codes ---

func recoveryCodeChecks() []mfaCheck {
	return []mfaCheck{
		{"ReplaceRecoveryCodes/RoundTripsTheSetAndReplacesItWholly", checkReplaceRecoveryCodes},
		{"ReplaceRecoveryCodes/EmptyClearsTheSet", checkReplaceRecoveryCodesEmpty},
		{"ReplaceRecoveryCodes/TouchesOnlyThatUsersCodes", checkReplaceRecoveryCodesIsPerUser},
		{"ReplaceRecoveryCodes/AForeignCodeIsRefusedAndWritesNothing", checkReplaceRecoveryCodesForeignUser},
		{"ReplaceRecoveryCodes/ADuplicateIDIsRefusedAndWritesNothing", checkReplaceRecoveryCodesDuplicateID},
		{"ConsumeRecoveryCode/BurnsOnceThenReportsFalse", checkConsumeRecoveryCodeOnce},
		{"ConsumeRecoveryCode/AnUnknownCodeIsFalseNotAnError", checkConsumeRecoveryCodeUnknown},
		{"ConsumeRecoveryCode/IsBoundToTheUser", checkConsumeRecoveryCodeIsPerUser},
		{"ListRecoveryCodes/ReturnsUsedAndUnusedForThatUserOnly", checkListRecoveryCodes},
		{"ListRecoveryCodes/UnknownUserIsEmptyNotAnError", checkListRecoveryCodesUnknown},
	}
}

// checkReplaceRecoveryCodes stores a set, reads every field back, then
// replaces it with a different set and requires the first set to be GONE.
// Regeneration replaces; a backend that appended would leave every code
// the user has ever been issued live at once.
func checkReplaceRecoveryCodes(t tb, st auth.MFAStore) {
	t.Helper()
	at := stamp()
	userID := newID()

	first := newRecoveryCodes(userID, at, 3)
	mustReplaceRecoveryCodes(t, st, userID, first)

	got := codeHashes(t, st, userID)
	if len(got) != 3 {
		t.Fatalf("ListRecoveryCodes returned %d codes, want 3", len(got))
	}
	for _, want := range first {
		stored, ok := got[want.CodeHash]
		if !ok {
			t.Fatalf("code %s is missing after ReplaceRecoveryCodes", want.ID)
		}
		if stored.ID != want.ID || stored.UserID != want.UserID {
			t.Fatalf("stored code = {ID:%q UserID:%q}, want {%q %q}", stored.ID, stored.UserID, want.ID, want.UserID)
		}
		if stored.UsedAt != nil {
			t.Fatalf("a freshly issued code came back used at %v, want nil", *stored.UsedAt)
		}
		wantTimeEqual(t, "recovery code CreatedAt", stored.CreatedAt, want.CreatedAt)
	}

	second := newRecoveryCodes(userID, at.Add(time.Hour), 2)
	mustReplaceRecoveryCodes(t, st, userID, second)

	got = codeHashes(t, st, userID)
	if len(got) != 2 {
		t.Fatalf("ListRecoveryCodes returned %d codes after replacing a set of 3 with 2, want 2 — the set is REPLACED, not appended to", len(got))
	}
	for _, gone := range first {
		if _, ok := got[gone.CodeHash]; ok {
			t.Fatalf("code %s survived the replacement — every code from a superseded set must be gone", gone.ID)
		}
	}
}

// An empty set is how a caller REVOKES recovery codes without issuing new
// ones — the sweep [auth.Service.DisableMFA] owes alongside DeleteFactor.
// A backend that treated it as a no-op would leave every code live.
func checkReplaceRecoveryCodesEmpty(t tb, st auth.MFAStore) {
	t.Helper()
	at := stamp()
	userID := newID()
	mustReplaceRecoveryCodes(t, st, userID, newRecoveryCodes(userID, at, 3))

	mustReplaceRecoveryCodes(t, st, userID, nil)
	if got := codeHashes(t, st, userID); len(got) != 0 {
		t.Fatalf("ListRecoveryCodes returned %d codes after replacing the set with none, want 0 — an empty set is a revocation, not a no-op", len(got))
	}
}

func checkReplaceRecoveryCodesIsPerUser(t tb, st auth.MFAStore) {
	t.Helper()
	at := stamp()
	alice, bob := newID(), newID()
	mustReplaceRecoveryCodes(t, st, alice, newRecoveryCodes(alice, at, 3))
	bobCodes := newRecoveryCodes(bob, at, 2)
	mustReplaceRecoveryCodes(t, st, bob, bobCodes)

	mustReplaceRecoveryCodes(t, st, alice, newRecoveryCodes(alice, at, 1))

	got := codeHashes(t, st, bob)
	if len(got) != len(bobCodes) {
		t.Fatalf("bob holds %d codes after alice regenerated hers, want %d — the removal reached rows it does not own", len(got), len(bobCodes))
	}
}

// A code naming another user must be refused OUTRIGHT, with the previous
// set left intact. Writing it as given would file a live credential under
// an account the caller never named; rewriting its UserID would mint one.
func checkReplaceRecoveryCodesForeignUser(t tb, st auth.MFAStore) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	alice, bob := newID(), newID()

	original := newRecoveryCodes(alice, at, 2)
	mustReplaceRecoveryCodes(t, st, alice, original)

	mixed := newRecoveryCodes(alice, at, 2)
	mixed = append(mixed, newRecoveryCode(bob, at))
	err := st.ReplaceRecoveryCodes(ctx, alice, mixed)
	wantErrIs(t, "ReplaceRecoveryCodes with a foreign code", err, auth.ErrRecoveryCodeUserMismatch)

	got := codeHashes(t, st, alice)
	if len(got) != len(original) {
		t.Fatalf("alice holds %d codes after a refused replacement, want her original %d — the call must write NOTHING", len(got), len(original))
	}
	for _, want := range original {
		if _, ok := got[want.CodeHash]; !ok {
			t.Fatalf("a refused ReplaceRecoveryCodes removed the previous set")
		}
	}
	if bobCodes := codeHashes(t, st, bob); len(bobCodes) != 0 {
		t.Fatalf("a refused ReplaceRecoveryCodes wrote %d codes for the foreign user", len(bobCodes))
	}
}

// An id already held by ANOTHER user's row, or repeated inside the same
// call, is ErrIDTaken and writes nothing. An id held by a row this very
// call removes is free to reuse, since it is gone by the time the new set
// lands.
func checkReplaceRecoveryCodesDuplicateID(t tb, st auth.MFAStore) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	alice, bob := newID(), newID()

	bobCodes := newRecoveryCodes(bob, at, 1)
	mustReplaceRecoveryCodes(t, st, bob, bobCodes)
	original := newRecoveryCodes(alice, at, 2)
	mustReplaceRecoveryCodes(t, st, alice, original)

	stolen := newRecoveryCodes(alice, at, 2)
	stolen[1].ID = bobCodes[0].ID
	wantErrIs(t, "ReplaceRecoveryCodes with another user's id",
		st.ReplaceRecoveryCodes(ctx, alice, stolen), auth.ErrIDTaken)

	repeated := newRecoveryCodes(alice, at, 2)
	repeated[1].ID = repeated[0].ID
	wantErrIs(t, "ReplaceRecoveryCodes with a repeated id",
		st.ReplaceRecoveryCodes(ctx, alice, repeated), auth.ErrIDTaken)

	got := codeHashes(t, st, alice)
	if len(got) != len(original) {
		t.Fatalf("alice holds %d codes after two refused replacements, want her original %d — a refused call must write NOTHING", len(got), len(original))
	}
	for _, want := range original {
		if _, ok := got[want.CodeHash]; !ok {
			t.Fatalf("a refused ReplaceRecoveryCodes removed the previous set")
		}
	}
	if len(codeHashes(t, st, bob)) != 1 {
		t.Fatalf("a refused ReplaceRecoveryCodes disturbed the user whose id was taken")
	}

	reused := newRecoveryCodes(alice, at, 1)
	reused[0].ID = original[0].ID
	wantNoErr(t, "ReplaceRecoveryCodes reusing an id from the set it replaces",
		st.ReplaceRecoveryCodes(ctx, alice, reused))
}

// checkConsumeRecoveryCodeOnce is the sequential half of the burn: the
// first caller wins and the code is stamped used, the second loses and the
// stamp does not move. A code that can be spent twice is not a single-use
// credential.
func checkConsumeRecoveryCodeOnce(t tb, st auth.MFAStore) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	userID := newID()
	codes := newRecoveryCodes(userID, at, 3)
	mustReplaceRecoveryCodes(t, st, userID, codes)

	used := at.Add(time.Minute)
	ok, err := st.ConsumeRecoveryCode(ctx, userID, codes[1].CodeHash, used)
	wantNoErr(t, "first ConsumeRecoveryCode", err)
	if !ok {
		t.Fatalf("ConsumeRecoveryCode reported false for an unused code")
	}

	stored := codeHashes(t, st, userID)
	burnt := stored[codes[1].CodeHash]
	if burnt.UsedAt == nil {
		t.Fatalf("ConsumeRecoveryCode reported true but left UsedAt nil")
	}
	wantTimeEqual(t, "UsedAt", *burnt.UsedAt, used)
	for _, other := range []auth.RecoveryCode{codes[0], codes[2]} {
		if stored[other.CodeHash].UsedAt != nil {
			t.Fatalf("consuming one code burnt %s as well", other.ID)
		}
	}

	again := at.Add(time.Hour)
	ok, err = st.ConsumeRecoveryCode(ctx, userID, codes[1].CodeHash, again)
	wantNoErr(t, "second ConsumeRecoveryCode", err)
	if ok {
		t.Fatalf("ConsumeRecoveryCode reported true for an already-used code — a single-use credential just worked twice")
	}
	stored = codeHashes(t, st, userID)
	wantTimeEqual(t, "UsedAt after a losing consume", *stored[codes[1].CodeHash].UsedAt, used)
}

// A hash that matches nothing — and a user who has no codes at all — is
// (false, nil). An error here would invite a caller to treat a mistyped
// code as a system failure, and a distinct sentinel would tell an attacker
// which half of (user, code) they got wrong.
func checkConsumeRecoveryCodeUnknown(t tb, st auth.MFAStore) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	userID := newID()
	mustReplaceRecoveryCodes(t, st, userID, newRecoveryCodes(userID, at, 2))

	ok, err := st.ConsumeRecoveryCode(ctx, userID, "rc-no-such-hash", at)
	wantNoErr(t, "ConsumeRecoveryCode with an unknown hash", err)
	if ok {
		t.Fatalf("ConsumeRecoveryCode reported true for a hash matching no code")
	}

	ok, err = st.ConsumeRecoveryCode(ctx, newID(), "rc-no-such-hash", at)
	wantNoErr(t, "ConsumeRecoveryCode for a user with no codes", err)
	if ok {
		t.Fatalf("ConsumeRecoveryCode reported true for a user holding no codes")
	}
}

// checkConsumeRecoveryCodeIsPerUser pins the (user, hash) pair: another
// user's hash must not burn under this user's id. A store that matched on
// the hash alone would let a leaked code be spent by whoever presents it,
// against the account it was never issued for.
func checkConsumeRecoveryCodeIsPerUser(t tb, st auth.MFAStore) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	alice, bob := newID(), newID()
	mustReplaceRecoveryCodes(t, st, alice, newRecoveryCodes(alice, at, 2))
	bobCodes := newRecoveryCodes(bob, at, 2)
	mustReplaceRecoveryCodes(t, st, bob, bobCodes)

	ok, err := st.ConsumeRecoveryCode(ctx, alice, bobCodes[0].CodeHash, at)
	wantNoErr(t, "ConsumeRecoveryCode of another user's hash", err)
	if ok {
		t.Fatalf("ConsumeRecoveryCode(alice, bob's hash) reported true — the code is matched by hash alone, so one user's recovery code works against another's account")
	}
	if stored := codeHashes(t, st, bob); stored[bobCodes[0].CodeHash].UsedAt != nil {
		t.Fatalf("consuming under the wrong user still burnt bob's code")
	}
}

func checkListRecoveryCodes(t tb, st auth.MFAStore) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	alice, bob := newID(), newID()
	aliceCodes := newRecoveryCodes(alice, at, 3)
	mustReplaceRecoveryCodes(t, st, alice, aliceCodes)
	mustReplaceRecoveryCodes(t, st, bob, newRecoveryCodes(bob, at, 2))

	if ok, err := st.ConsumeRecoveryCode(ctx, alice, aliceCodes[0].CodeHash, at); err != nil || !ok {
		t.Fatalf("fixture ConsumeRecoveryCode = (%v, %v), want (true, nil)", ok, err)
	}

	got := codeHashes(t, st, alice)
	if len(got) != 3 {
		t.Fatalf("ListRecoveryCodes returned %d codes, want 3 — a USED code stays listed, so an application can say how many remain and the service can tell a spent code from a wrong one", len(got))
	}
	if got[aliceCodes[0].CodeHash].UsedAt == nil {
		t.Fatalf("the consumed code came back with UsedAt nil")
	}
	for _, c := range got {
		if c.UserID != alice {
			t.Fatalf("ListRecoveryCodes(alice) returned a code belonging to %q", c.UserID)
		}
	}
}

func checkListRecoveryCodesUnknown(t tb, st auth.MFAStore) {
	t.Helper()
	got, err := st.ListRecoveryCodes(context.Background(), newID())
	wantNoErr(t, "ListRecoveryCodes for a user with none", err)
	if len(got) != 0 {
		t.Fatalf("ListRecoveryCodes returned %d codes for a user with none", len(got))
	}
}

// --- the compare-and-set races ---

func mfaConcurrencyChecks() []mfaCheck {
	return []mfaCheck{
		{"ConfirmFactor/ConcurrentCallersAdmitExactlyOneWinner", checkConfirmFactorOneWinner},
		{"AdvanceStep/ConcurrentCallersWithOneStepAdmitExactlyOneWinner", checkAdvanceStepOneWinner},
		{"ConsumeRecoveryCode/ConcurrentConsumersAdmitExactlyOneWinner", checkConsumeRecoveryCodeOneWinner},
	}
}

// tally counts the winners and errors of n identical concurrent calls,
// released together. Every goroutine runs the same call, so the result is
// independent of the order they happen to run in — see this file's header
// for why that matters here and why [pair]'s role-swapping does not apply.
func tally(n int, call func() (bool, error)) (winners, failures int, firstErr error) {
	var mu sync.Mutex
	release(n, func(int) {
		ok, err := call()
		mu.Lock()
		defer mu.Unlock()
		switch {
		case err != nil:
			failures++
			if firstErr == nil {
				firstErr = err
			}
		case ok:
			winners++
		}
	})
	return winners, failures, firstErr
}

// checkConfirmFactorOneWinner is ConfirmFactor's MUST under contention.
// The winner is the caller that gets to hand the user their recovery
// codes, and generating a set replaces any previous set — so two winners
// means two sets generated and shown, with the second write silently
// invalidating every code the user was just told to write down.
func checkConfirmFactorOneWinner(t tb, st auth.MFAStore) {
	t.Helper()
	ctx := context.Background()

	for round := range massRaceRounds {
		at := stamp()
		userID := newID()
		mustUpsertFactor(t, st, newFactor(userID, at))
		shared := at.Add(time.Duration(round+1) * time.Minute)

		winners, failures, firstErr := tally(RaceGoroutines, func() (bool, error) {
			return st.ConfirmFactor(ctx, userID, shared)
		})
		if failures != 0 {
			t.Fatalf("round %d: %d of %d concurrent ConfirmFactor calls returned an error, first: %v — losing the race is (false, nil), not an error", round, failures, RaceGoroutines, firstErr)
		}
		if winners != 1 {
			t.Fatalf("round %d: %d of %d concurrent ConfirmFactor calls reported true against one factor, want exactly 1 — the compare-and-set is not atomic", round, winners, RaceGoroutines)
		}

		got := mustFindFactor(t, st, userID)
		if got.ConfirmedAt == nil {
			t.Fatalf("round %d: ConfirmedAt = nil after a winning ConfirmFactor", round)
		}
		wantTimeEqual(t, "stored ConfirmedAt", *got.ConfirmedAt, shared)
	}
}

// checkAdvanceStepOneWinner is the replay guard under contention:
// [RaceGoroutines] callers present the SAME step at once — the shape of
// an attacker replaying a captured code alongside the user's own
// submission — and exactly one may be told it advanced.
//
// A read-then-write AdvanceStep lets several callers all read the old
// LastStep, all find their step greater, and all succeed, which is the
// replay this method exists to refuse arriving as a race instead of a
// sequence.
func checkAdvanceStepOneWinner(t tb, st auth.MFAStore) {
	t.Helper()
	ctx := context.Background()

	for round := range massRaceRounds {
		userID := newID()
		mustUpsertFactor(t, st, newFactor(userID, stamp()))
		step := int64(58023700 + round)

		winners, failures, firstErr := tally(RaceGoroutines, func() (bool, error) {
			return st.AdvanceStep(ctx, userID, step)
		})
		if failures != 0 {
			t.Fatalf("round %d: %d of %d concurrent AdvanceStep calls returned an error, first: %v — losing the race is (false, nil), not an error", round, failures, RaceGoroutines, firstErr)
		}
		if winners != 1 {
			t.Fatalf("round %d: %d of %d concurrent AdvanceStep calls reported true for one step, want exactly 1 — the replay guard is not atomic, so a captured code replayed alongside the user's own submission is accepted twice", round, winners, RaceGoroutines)
		}

		got := mustFindFactor(t, st, userID)
		if got.LastStep == nil || *got.LastStep != step {
			t.Fatalf("round %d: LastStep = %v after the race, want %d", round, got.LastStep, step)
		}
	}
}

// checkConsumeRecoveryCodeOneWinner is the burn under contention: one
// code, [RaceGoroutines] consumers, exactly one winner. Two winners is a
// single-use credential spent twice.
func checkConsumeRecoveryCodeOneWinner(t tb, st auth.MFAStore) {
	t.Helper()
	ctx := context.Background()

	for round := range massRaceRounds {
		at := stamp()
		userID := newID()
		codes := newRecoveryCodes(userID, at, 2)
		mustReplaceRecoveryCodes(t, st, userID, codes)
		used := at.Add(time.Duration(round+1) * time.Minute)

		winners, failures, firstErr := tally(RaceGoroutines, func() (bool, error) {
			return st.ConsumeRecoveryCode(ctx, userID, codes[0].CodeHash, used)
		})
		if failures != 0 {
			t.Fatalf("round %d: %d of %d concurrent ConsumeRecoveryCode calls returned an error, first: %v — losing the race is (false, nil), not an error", round, failures, RaceGoroutines, firstErr)
		}
		if winners != 1 {
			t.Fatalf("round %d: %d of %d concurrent ConsumeRecoveryCode calls reported true for one code, want exactly 1 — the burn is not atomic, so a single-use recovery code is usable more than once", round, winners, RaceGoroutines)
		}

		stored := codeHashes(t, st, userID)
		burnt := stored[codes[0].CodeHash]
		if burnt.UsedAt == nil {
			t.Fatalf("round %d: UsedAt = nil after a winning ConsumeRecoveryCode", round)
		}
		wantTimeEqual(t, "stored UsedAt", *burnt.UsedAt, used)
		if stored[codes[1].CodeHash].UsedAt != nil {
			t.Fatalf("round %d: the race burnt the user's other code as well", round)
		}
	}
}
