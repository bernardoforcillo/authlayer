package memory_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/bernardoforcillo/authlayer/apikey"
	"github.com/bernardoforcillo/authlayer/apikey/apikeytest"
	"github.com/bernardoforcillo/authlayer/store/memory"
)

// Compile-time proof the memory store satisfies apikey.Store.
var _ apikey.Store = (*memory.APIKeyStore)(nil)

// TestAPIKeyStoreSatisfiesTheStoreContract runs the exported
// [github.com/bernardoforcillo/authlayer/apikey/apikeytest] suite against
// this package's store: every documented obligation of apikey.Store, the
// token-hash uniqueness, the atomic cascade and the orphan refusal included.
// The suite is the one implementation of the contract, shared with
// store/drops' live-PostgreSQL lane; what remains below is what the suite
// deliberately does NOT assert — which error this backend answers a rejected
// duplicate hash with.
func TestAPIKeyStoreSatisfiesTheStoreContract(t *testing.T) {
	apikeytest.RunStoreContract(t, func(*testing.T) apikey.Store { return memory.NewAPIKeyStore() })
}

// TestCreateKeyDuplicateTokenHashReturnsErrTokenHashTaken pins both halves of
// the refusal: the sentinel is memory.ErrTokenHashTaken — the same error a
// colliding session, verification or invitation hash gets here, since it is
// the same column with the same meaning — and the row that already held the
// hash is left exactly as it was. The clash names another account, so only
// the hash collides.
func TestCreateKeyDuplicateTokenHashReturnsErrTokenHashTaken(t *testing.T) {
	st := memory.NewAPIKeyStore()
	ctx := context.Background()
	now := time.Now().UTC()
	for _, id := range []string{"sa1", "sa2"} {
		if _, err := st.CreateServiceAccount(ctx, apikey.ServiceAccount{ID: id, ContainerID: "acme", Name: id, CreatedBy: "alice", CreatedAt: now, UpdatedAt: now}); err != nil {
			t.Fatalf("CreateServiceAccount(%s): %v", id, err)
		}
	}
	first := apikey.Key{ID: "k1", ServiceAccountID: "sa1", ContainerID: "acme", Name: "a", Prefix: "sk_aaaaaaaa", TokenHash: "shared-hash", CreatedBy: "alice", CreatedAt: now}
	if _, err := st.CreateKey(ctx, first); err != nil {
		t.Fatalf("CreateKey(first): %v", err)
	}
	clash := first
	clash.ID, clash.ServiceAccountID, clash.Name = "k2", "sa2", "b"
	_, err := st.CreateKey(ctx, clash)
	if !errors.Is(err, memory.ErrTokenHashTaken) {
		t.Fatalf("CreateKey(duplicate token hash) err = %v, want ErrTokenHashTaken", err)
	}
	if errors.Is(err, apikey.ErrIDTaken) {
		t.Fatalf("CreateKey(duplicate token hash) err = %v, want it NOT to be ErrIDTaken — the ids differ, only the hash collides", err)
	}
	got, err := st.FindKeyByHash(ctx, "shared-hash")
	if err != nil {
		t.Fatalf("FindKeyByHash: %v", err)
	}
	if got.ID != first.ID || got.ServiceAccountID != first.ServiceAccountID {
		t.Fatalf("FindKeyByHash = %+v, want the original row %+v — the refused write must not have disturbed it", got, first)
	}
	if _, err := st.FindKey(ctx, clash.ID); !errors.Is(err, apikey.ErrKeyNotFound) {
		t.Fatalf("FindKey(the refused row) err = %v, want ErrKeyNotFound", err)
	}
}
