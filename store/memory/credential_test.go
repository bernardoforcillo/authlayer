package memory_test

import (
	"context"
	"testing"
	"time"

	"github.com/bernardoforcillo/authlayer/auth"
	"github.com/bernardoforcillo/authlayer/auth/authtest"
	"github.com/bernardoforcillo/authlayer/internal/uid"
	"github.com/bernardoforcillo/authlayer/store/memory"
)

// TestCredentialStoreSatisfiesTheCredentialContract runs the executable
// contract for the optional passkey port against this backend. It is the
// same arrangement TestAuthStoreSatisfiesTheStoreContract has for auth.Store:
// every obligation the port documents, including the three that only appear
// under concurrency, checked by the suite that also proves — through its own
// deliberately non-compliant doubles — that each check bites.
func TestCredentialStoreSatisfiesTheCredentialContract(t *testing.T) {
	authtest.RunCredentialStoreContract(t, func(*testing.T) auth.CredentialStore {
		return memory.NewCredentialStore()
	})
}

// TestCredentialStoreListReturnsEmptyNotNil pins this backend's own choice
// where the port leaves one open. auth.CredentialStore says only that callers
// MUST use len(); store/drops returns nil for the same case. Pinning it here
// is what keeps the two backends' difference deliberate rather than
// accidental — a caller who develops against this one and compares to nil
// meets the other in production.
func TestCredentialStoreListReturnsEmptyNotNil(t *testing.T) {
	got, err := memory.NewCredentialStore().ListCredentialsByUser(context.Background(), uid.NewV7())
	if err != nil {
		t.Fatalf("ListCredentialsByUser: %v", err)
	}
	if got == nil {
		t.Fatal("ListCredentialsByUser returned nil; this backend returns an empty non-nil slice")
	}
	if len(got) != 0 {
		t.Fatalf("ListCredentialsByUser returned %d rows for an unknown user", len(got))
	}
}

// TestCredentialStoreRefusesADuplicateChallengeHash pins the uniqueness
// auth.Challenge.Hash requires of a backend. Like the two TokenHash columns,
// a collision is this store's own ErrTokenHashTaken rather than one of the
// port's sentinels — see that error's doc.
func TestCredentialStoreRefusesADuplicateChallengeHash(t *testing.T) {
	st := memory.NewCredentialStore()
	ctx := context.Background()
	at := time.Now().UTC()

	first := auth.Challenge{
		ID: uid.NewV7(), Ceremony: auth.CeremonyLogin, Hash: "shared-hash",
		ExpiresAt: at.Add(time.Minute), CreatedAt: at,
	}
	if _, err := st.CreateChallenge(ctx, first); err != nil {
		t.Fatalf("CreateChallenge: %v", err)
	}

	second := first
	second.ID = uid.NewV7()
	if _, err := st.CreateChallenge(ctx, second); err != memory.ErrTokenHashTaken {
		t.Fatalf("CreateChallenge with a duplicate hash = %v, want ErrTokenHashTaken — FindChallengeByHash assumes at most one row can match", err)
	}
}
