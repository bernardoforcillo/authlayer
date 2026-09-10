package memory_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/bernardoforcillo/authlayer/oauth"
	"github.com/bernardoforcillo/authlayer/oauth/oauthtest"
	"github.com/bernardoforcillo/authlayer/store/memory"
)

// Compile-time proof the memory store satisfies oauth.Store.
var _ oauth.Store = (*memory.OAuthStore)(nil)

// TestOAuthStoreSatisfiesTheStoreContract runs the exported
// [github.com/bernardoforcillo/authlayer/oauth/oauthtest] suite against this
// package's store: every documented obligation of oauth.Store, the four
// uniqueness MUSTs, the three compare-and-sets and the two cascades
// included. The suite is the one implementation of the contract, shared
// with store/drops' live-PostgreSQL lane; what remains below is what the
// suite deliberately does NOT assert — which error this backend answers a
// rejected duplicate hash or user code with.
func TestOAuthStoreSatisfiesTheStoreContract(t *testing.T) {
	oauthtest.RunStoreContract(t, func(*testing.T) oauth.Store { return memory.NewOAuthStore() })
}

// TestOAuthStoreDuplicatesReturnThePackageLocalErrors pins both halves of
// each refusal: a colliding code, device-code or refresh-token hash is
// memory.ErrTokenHashTaken — the same error every other hashed credential
// gets here — and a colliding user code is memory.ErrUserCodeTaken; and in
// every case the row that already held the value is left as it was.
func TestOAuthStoreDuplicatesReturnThePackageLocalErrors(t *testing.T) {
	st := memory.NewOAuthStore()
	ctx := context.Background()
	now := time.Now().UTC()
	c := oauth.Client{ID: "c1", ContainerID: "acme", Name: "bot", GrantTypes: []string{oauth.GrantDeviceCode}, CreatedAt: now, UpdatedAt: now}
	if _, err := st.CreateClient(ctx, c); err != nil {
		t.Fatalf("CreateClient: %v", err)
	}
	g := oauth.Grant{ID: "g1", ClientID: "c1", UserID: "alice", ContainerID: "acme", CreatedAt: now}
	if _, err := st.CreateGrant(ctx, g); err != nil {
		t.Fatalf("CreateGrant: %v", err)
	}

	code := oauth.AuthorizationCode{ID: "k1", CodeHash: "shared", ClientID: "c1", GrantID: "g1", CodeChallenge: "x", ExpiresAt: now.Add(time.Minute), CreatedAt: now}
	if _, err := st.CreateCode(ctx, code); err != nil {
		t.Fatalf("CreateCode: %v", err)
	}
	clash := code
	clash.ID = "k2"
	if _, err := st.CreateCode(ctx, clash); !errors.Is(err, memory.ErrTokenHashTaken) || errors.Is(err, oauth.ErrIDTaken) {
		t.Fatalf("CreateCode(duplicate hash) err = %v, want ErrTokenHashTaken and not ErrIDTaken", err)
	}
	if got, _, err := st.RedeemCode(ctx, "shared", now); err != nil || got.ID != "k1" {
		t.Fatalf("RedeemCode after the refused write = %+v, %v; want the original row", got, err)
	}

	rt := oauth.RefreshToken{ID: "r1", TokenHash: "rshared", GrantID: "g1", ClientID: "c1", FamilyID: "r1", ExpiresAt: now.Add(time.Hour), CreatedAt: now}
	if _, err := st.CreateRefreshToken(ctx, rt); err != nil {
		t.Fatalf("CreateRefreshToken: %v", err)
	}
	rt.ID, rt.FamilyID = "r2", "r2"
	if _, err := st.CreateRefreshToken(ctx, rt); !errors.Is(err, memory.ErrTokenHashTaken) {
		t.Fatalf("CreateRefreshToken(duplicate hash) err = %v, want ErrTokenHashTaken", err)
	}

	d := oauth.DeviceAuthorization{ID: "d1", DeviceCodeHash: "dshared", UserCode: "BCDFGHJK", ClientID: "c1", Status: oauth.DeviceStatusPending, Interval: 5, ExpiresAt: now.Add(time.Minute), CreatedAt: now}
	if _, err := st.CreateDeviceAuthorization(ctx, d); err != nil {
		t.Fatalf("CreateDeviceAuthorization: %v", err)
	}
	sameHash := d
	sameHash.ID, sameHash.UserCode = "d2", "LMNPQRST"
	if _, err := st.CreateDeviceAuthorization(ctx, sameHash); !errors.Is(err, memory.ErrTokenHashTaken) {
		t.Fatalf("CreateDeviceAuthorization(duplicate hash) err = %v, want ErrTokenHashTaken", err)
	}
	sameCode := d
	sameCode.ID, sameCode.DeviceCodeHash = "d3", "other"
	if _, err := st.CreateDeviceAuthorization(ctx, sameCode); !errors.Is(err, memory.ErrUserCodeTaken) {
		t.Fatalf("CreateDeviceAuthorization(duplicate user code) err = %v, want ErrUserCodeTaken", err)
	}
	if got, err := st.FindDeviceByUserCode(ctx, "BCDFGHJK"); err != nil || got.ID != "d1" {
		t.Fatalf("FindDeviceByUserCode after the refused writes = %+v, %v; want the original row", got, err)
	}
}
