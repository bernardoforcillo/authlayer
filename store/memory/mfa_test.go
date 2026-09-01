package memory_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/bernardoforcillo/authlayer/auth"
	"github.com/bernardoforcillo/authlayer/auth/authtest"
	"github.com/bernardoforcillo/authlayer/store/memory"
)

// Compile-time proof the memory store satisfies auth.MFAStore.
var _ auth.MFAStore = (*memory.MFAStore)(nil)

// TestMFAStoreSatisfiesTheContract runs the whole executable contract —
// every documented obligation of auth.MFAStore, the three compare-and-set
// races included — against this backend. It is the primary test for this
// type; the ones below cover only what the port deliberately leaves to the
// implementation and therefore cannot assert.
func TestMFAStoreSatisfiesTheContract(t *testing.T) {
	authtest.RunMFAStoreContract(t, func(*testing.T) auth.MFAStore { return memory.NewMFAStore() })
}

// The port leaves "empty slice or nil" unspecified and the contract reads
// the result through len only. This backend answers with an empty non-nil
// slice, and that is worth pinning HERE precisely because a caller who
// develops against it must not learn the wrong lesson: store/drops returns
// nil for the same case, so code that compares against nil works in
// development and breaks in production.
func TestMFAStoreListRecoveryCodesReturnsEmptyNotNil(t *testing.T) {
	st := memory.NewMFAStore()

	got, err := st.ListRecoveryCodes(context.Background(), "nobody")
	if err != nil {
		t.Fatalf("ListRecoveryCodes: %v", err)
	}
	if got == nil {
		t.Fatalf("ListRecoveryCodes returned nil; this backend answers empty — the PORT leaves the choice open, so callers must use len()")
	}
	if len(got) != 0 {
		t.Fatalf("ListRecoveryCodes returned %d codes for a user with none", len(got))
	}
}

// The stored factor must not alias the caller's value: a caller that
// mutates the struct it passed in, or the *time.Time inside it, must not
// be able to reach into the store afterwards. Go's map-of-values copies
// the struct, but the pointer fields are shared, so this pins the one
// consequence that matters — the stored ConfirmedAt is the instant the
// store was given, whatever the caller does to its own copy afterwards.
func TestMFAStoreDoesNotFollowACallersPointerAfterTheWrite(t *testing.T) {
	ctx := context.Background()
	st := memory.NewMFAStore()

	at := time.Date(2026, 4, 1, 9, 0, 0, 0, time.UTC)
	confirmed := at.Add(time.Minute)
	f := auth.MFAFactor{
		UserID:      "u1",
		SecretEnc:   "enc",
		CreatedAt:   at,
		ConfirmedAt: &confirmed,
	}
	if err := st.UpsertFactor(ctx, f); err != nil {
		t.Fatalf("UpsertFactor: %v", err)
	}

	// The caller's own copy moves on.
	f.SecretEnc = "rewritten by the caller"

	got, err := st.FindFactor(ctx, "u1")
	if err != nil {
		t.Fatalf("FindFactor: %v", err)
	}
	if got.SecretEnc != "enc" {
		t.Fatalf("stored SecretEnc = %q, want %q — the store followed the caller's later mutation", got.SecretEnc, "enc")
	}
	if got.ConfirmedAt == nil || !got.ConfirmedAt.Equal(confirmed) {
		t.Fatalf("stored ConfirmedAt = %v, want %v", got.ConfirmedAt, confirmed)
	}
}

// A factor and a recovery code are independent records. The contract pins
// that DeleteFactor leaves the codes; this pins the other direction, which
// the contract has no reason to state: clearing the codes leaves the
// factor.
func TestMFAStoreClearingCodesLeavesTheFactor(t *testing.T) {
	ctx := context.Background()
	st := memory.NewMFAStore()
	at := time.Date(2026, 4, 1, 9, 0, 0, 0, time.UTC)

	if err := st.UpsertFactor(ctx, auth.MFAFactor{UserID: "u1", SecretEnc: "enc", CreatedAt: at}); err != nil {
		t.Fatalf("UpsertFactor: %v", err)
	}
	codes := []auth.RecoveryCode{{ID: "c1", UserID: "u1", CodeHash: "h1", CreatedAt: at}}
	if err := st.ReplaceRecoveryCodes(ctx, "u1", codes); err != nil {
		t.Fatalf("ReplaceRecoveryCodes: %v", err)
	}

	if err := st.ReplaceRecoveryCodes(ctx, "u1", nil); err != nil {
		t.Fatalf("ReplaceRecoveryCodes(nil): %v", err)
	}
	if _, err := st.FindFactor(ctx, "u1"); err != nil {
		t.Fatalf("FindFactor after clearing the codes: %v, want the factor to survive", err)
	}
}

func TestMFAStoreUnknownUserSentinels(t *testing.T) {
	ctx := context.Background()
	st := memory.NewMFAStore()

	if _, err := st.FindFactor(ctx, "nobody"); !errors.Is(err, auth.ErrFactorNotFound) {
		t.Fatalf("FindFactor err = %v, want ErrFactorNotFound", err)
	}
	if _, err := st.ConfirmFactor(ctx, "nobody", time.Now()); !errors.Is(err, auth.ErrFactorNotFound) {
		t.Fatalf("ConfirmFactor err = %v, want ErrFactorNotFound", err)
	}
	if _, err := st.AdvanceStep(ctx, "nobody", 1); !errors.Is(err, auth.ErrFactorNotFound) {
		t.Fatalf("AdvanceStep err = %v, want ErrFactorNotFound", err)
	}
	if err := st.DeleteFactor(ctx, "nobody"); !errors.Is(err, auth.ErrFactorNotFound) {
		t.Fatalf("DeleteFactor err = %v, want ErrFactorNotFound", err)
	}
}
