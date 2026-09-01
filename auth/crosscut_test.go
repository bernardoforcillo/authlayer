package auth_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/bernardoforcillo/authlayer/auth"
	"github.com/bernardoforcillo/authlayer/store/memory"
)

// ============================================================
// The four entry points that owed an anonymized-account refusal
// ============================================================
//
// Magic links (Plan 7) and account deletion (Plan 8) were built on branches
// that could not see each other, and OAuth identities landed before both.
// Each shipped an honest "the other side owes this" note. These are the
// tests for the cells those notes described: SignInWith (BOTH rungs),
// LinkIdentity, RequestMagicLink and RedeemMagicLink.
//
// Every one of them runs against stampedStore — a row whose DeletedAt is set
// and whose every other field is untouched — for the reason that type's own
// doc gives: a genuinely anonymized account has no password and no resolvable
// address either, so a test against one could not tell the DeletedAt CHECK
// apart from the scrub. Here the check is the only thing that can refuse.

// stampedOAuthFixture is stampedFixture's sibling for the two entry points
// that need the optional identity port: one seeded account, one identity
// store, and two Services over the same rows — live, which sees the account
// as it is, and stamped, which sees it with DeletedAt set.
type stampedOAuthFixture struct {
	store   *memory.AuthStore
	ids     *memory.IdentityStore
	live    *auth.Service
	stamped *auth.Service
	user    auth.UserBase
}

func newStampedOAuthFixture(t *testing.T, email string, opts ...auth.Option) stampedOAuthFixture {
	t.Helper()
	store := memory.NewAuthStore()
	ids := memory.NewIdentityStore()
	base := append([]auth.Option{auth.WithIdentityStore(ids)}, opts...)
	live := newServiceOver(t, store, base...)
	user := signUpVerified(t, live, email, validPassword)
	stamped := newServiceOver(t, stampedStore{
		AuthStore: store,
		userID:    user.ID,
		at:        time.Now().UTC().Add(-time.Hour),
	}, base...)
	return stampedOAuthFixture{store: store, ids: ids, live: live, stamped: stamped, user: user}
}

func (f stampedOAuthFixture) identityCount(t *testing.T) int {
	t.Helper()
	rows, err := f.ids.ListIdentitiesByUser(context.Background(), f.user.ID)
	if err != nil {
		t.Fatalf("ListIdentitiesByUser: %v", err)
	}
	return len(rows)
}

// TestSignInWithRefusesAnAnonymizedAccountOnTheLinkedRung is rung 1: the
// (provider, subject) pair resolves an existing link, so the address is
// never consulted and only a DeletedAt check on the loaded account can
// refuse. AnonymizeAccount sweeps identities before it stamps, so this rung
// is defence in depth — for the two-Services-one-users-table configuration
// sweepIdentities discloses, where the sweep cannot reach the rows.
func TestSignInWithRefusesAnAnonymizedAccountOnTheLinkedRung(t *testing.T) {
	f := newStampedOAuthFixture(t, "nadia@example.com")
	ctx := context.Background()

	linked, err := f.live.LinkIdentity(ctx, f.user.ID, googleExt("nadia@example.com", true))
	if err != nil {
		t.Fatalf("LinkIdentity (seeding): %v", err)
	}

	_, err = f.stamped.SignInWith(ctx, signInReq(googleExt("nadia@example.com", true)))
	if !errors.Is(err, auth.ErrUserNotFound) {
		t.Fatalf("SignInWith through a linked identity on a stamped account = %v, want ErrUserNotFound — a linked social account is a way IN that needs no password at all", err)
	}
	if n := sessionCount(t, f.store, f.user.ID); n != 0 {
		t.Errorf("sessions after the refused sign-in = %d, want 0 — a refusal that still minted a session is an authentication bypass wearing an error's clothes", n)
	}

	// The refusal is placed above TouchIdentity, so nothing records a use
	// that did not happen.
	after, err := f.ids.FindIdentityByProviderSubject(ctx, "google", linked.Subject)
	if err != nil {
		t.Fatalf("FindIdentityByProviderSubject: %v", err)
	}
	if after.LastUsedAt != nil {
		t.Errorf("Identity.LastUsedAt = %v after a REFUSED sign-in, want nil — a use this package refused is not a use", after.LastUsedAt)
	}
}

// TestSignInWithRefusesAnAnonymizedAccountOnTheAddressRung is rung 2, and it
// is the genuinely reachable one: an anonymized row still holds the derived
// scrubbed address, so a provider willing to assert that address would
// otherwise link to it and sign in. LinkAlways is deliberate — the check
// must sit ABOVE the policy, so the most permissive setting cannot get past
// it.
func TestSignInWithRefusesAnAnonymizedAccountOnTheAddressRung(t *testing.T) {
	f := newStampedOAuthFixture(t, "oren@example.com", auth.WithLinking(auth.LinkAlways))
	ctx := context.Background()

	_, err := f.stamped.SignInWith(ctx, signInReq(auth.ExternalIdentity{
		Provider:      "google",
		Subject:       "google-subject-never-linked",
		Email:         "oren@example.com",
		EmailVerified: true,
	}))
	if !errors.Is(err, auth.ErrUserNotFound) {
		t.Fatalf("SignInWith matching a stamped account by ADDRESS under LinkAlways = %v, want ErrUserNotFound", err)
	}
	if n := f.identityCount(t); n != 0 {
		t.Errorf("identities on the stamped account = %d, want 0 — a refused sign-in must not leave a link behind", n)
	}
	if n := sessionCount(t, f.store, f.user.ID); n != 0 {
		t.Errorf("sessions after the refused sign-in = %d, want 0", n)
	}
}

// TestLinkIdentityRefusesAnAnonymizedAccount pins the entry point that ARMS
// a way in rather than using one. Anonymization clears the password, so an
// identity linked afterwards would be the account's only credential.
func TestLinkIdentityRefusesAnAnonymizedAccount(t *testing.T) {
	f := newStampedOAuthFixture(t, "pia@example.com")
	ctx := context.Background()

	_, err := f.stamped.LinkIdentity(ctx, f.user.ID, googleExt("pia@example.com", true))
	if !errors.Is(err, auth.ErrUserNotFound) {
		t.Fatalf("LinkIdentity against a stamped account = %v, want ErrUserNotFound", err)
	}
	if n := f.identityCount(t); n != 0 {
		t.Errorf("identities on the stamped account = %d, want 0 — a stamped row must never acquire a fresh credential", n)
	}
}

// TestLinkIdentityRefusesAStampedAccountEvenWhenAlreadyLinked pins that the
// refusal sits ABOVE the (provider, subject) lookup, so not even the
// idempotent "already linked to this user, here it is unchanged" return is
// reachable. That return hands back an [auth.Identity] the caller may treat
// as proof the link is live.
func TestLinkIdentityRefusesAStampedAccountEvenWhenAlreadyLinked(t *testing.T) {
	f := newStampedOAuthFixture(t, "quinn@example.com")
	ctx := context.Background()

	if _, err := f.live.LinkIdentity(ctx, f.user.ID, googleExt("quinn@example.com", true)); err != nil {
		t.Fatalf("LinkIdentity (seeding): %v", err)
	}

	_, err := f.stamped.LinkIdentity(ctx, f.user.ID, googleExt("quinn@example.com", true))
	if !errors.Is(err, auth.ErrUserNotFound) {
		t.Fatalf("LinkIdentity re-linking an existing pair on a stamped account = %v, want ErrUserNotFound — the check must precede the pair lookup", err)
	}
}

// TestRequestMagicLinkStaysIndistinguishableForAnAnonymizedAccount is the
// refusal that must NOT become an error, for exactly the reason
// RequestPasswordReset's must not: this method's whole shape is a promise
// that a caller cannot learn whether an address is registered.
func TestRequestMagicLinkStaysIndistinguishableForAnAnonymizedAccount(t *testing.T) {
	f := newStampedFixture(t, "rhea@example.com")
	ctx := context.Background()

	tok, ok, err := f.stamped.RequestMagicLink(ctx, "rhea@example.com", "203.0.113.5")
	if err != nil {
		t.Fatalf("RequestMagicLink against a stamped account = %v, want nil — a refusal here must never become a new error, or it is an existence oracle", err)
	}
	if ok || tok != "" {
		t.Fatalf("RequestMagicLink against a stamped account = (%q, %v, nil), want (\"\", false, nil)", tok, ok)
	}

	unknownTok, unknownOK, unknownErr := f.stamped.RequestMagicLink(ctx, "nobody-here@example.com", "203.0.113.5")
	if unknownTok != tok || unknownOK != ok || unknownErr != err {
		t.Errorf("a stamped account answers (%q, %v, %v) while an unknown address answers (%q, %v, %v) — the two must be identical", tok, ok, err, unknownTok, unknownOK, unknownErr)
	}
}

// TestRequestMagicLinkMintsNothingForAnAnonymizedAccount is the half the
// indistinguishability test cannot see: the return shape would be identical
// whether or not a token had been written to the store.
func TestRequestMagicLinkMintsNothingForAnAnonymizedAccount(t *testing.T) {
	store := memory.NewAuthStore()
	live := newServiceOver(t, store)
	acct := seedDeletableAccount(t, live, store, "sander@example.com")
	rec := &deletionRecorder{AuthStore: store, fail: map[string]error{}}
	stamped := newServiceOver(t, stampedRecorder{rec, acct.user.ID})

	rec.reset()
	if _, ok, err := stamped.RequestMagicLink(context.Background(), "sander@example.com", "203.0.113.5"); ok || err != nil {
		t.Fatalf("RequestMagicLink = (_, %v, %v), want (\"\", false, nil)", ok, err)
	}
	mustNotHaveMinted(t, rec, "RequestMagicLink")
}

// TestRequestMagicLinkProvisioningDoesNotResurrectAnAnonymizedAccount pins
// the interaction between the two features: with provisioning ON an
// unregistered address is REGISTERED, so a check placed below the
// provisioning branch would hand a stamped row a brand-new account, or
// collide with it. The refusal sits above that branch.
func TestRequestMagicLinkProvisioningDoesNotResurrectAnAnonymizedAccount(t *testing.T) {
	store := memory.NewAuthStore()
	live := newServiceOver(t, store, auth.WithMagicLinkProvisioning(true))
	user := mustSignUp(t, live, "tess@example.com", validPassword)
	rec := &deletionRecorder{AuthStore: store, fail: map[string]error{}}
	stamped := newServiceOver(t, stampedRecorder{rec, user.ID}, auth.WithMagicLinkProvisioning(true))
	ctx := context.Background()

	rec.reset()
	tok, ok, err := stamped.RequestMagicLink(ctx, "tess@example.com", "203.0.113.5")
	if err != nil || ok || tok != "" {
		t.Fatalf("RequestMagicLink with provisioning ON against a stamped account = (%q, %v, %v), want (\"\", false, nil)", tok, ok, err)
	}
	mustNotHaveMinted(t, rec, "RequestMagicLink (provisioning on)")
	for _, ev := range rec.snapshot() {
		if ev == "CreateUser" {
			t.Fatalf("RequestMagicLink with provisioning ON created a user for a stamped address: %v", rec.snapshot())
		}
	}
}

// TestRedeemMagicLinkRefusesAnAnonymizedAccountAndBurnsTheToken pins both
// halves of this one's deliberate ordering: the refusal, and the fact that
// it happens AFTER the claim. A magic-link token IS a session credential, so
// destroying one aimed at a closed account is remediation rather than a cost.
func TestRedeemMagicLinkRefusesAnAnonymizedAccountAndBurnsTheToken(t *testing.T) {
	f := newStampedFixture(t, "ulf@example.com")
	ctx := context.Background()

	link, ok, err := f.live.RequestMagicLink(ctx, "ulf@example.com", "203.0.113.5")
	if err != nil || !ok {
		t.Fatalf("RequestMagicLink (seeding) = (_, %v, %v), want a token", ok, err)
	}

	if _, err := f.stamped.RedeemMagicLink(ctx, link, "203.0.113.5", "ua"); !errors.Is(err, auth.ErrUserNotFound) {
		t.Fatalf("RedeemMagicLink against a stamped account = %v, want ErrUserNotFound", err)
	}
	if n := sessionCount(t, f.store, f.acct.user.ID); n != 2 {
		t.Errorf("session families after the refused redemption = %d, want the 2 the fixture seeded — a refusal must mint nothing", n)
	}

	// Burned on the way out: even the Service that sees the account as live
	// cannot redeem it now.
	if _, err := f.live.RedeemMagicLink(ctx, link, "203.0.113.5", "ua"); !errors.Is(err, auth.ErrVerificationNotFound) {
		t.Fatalf("re-redeeming through the live Service = %v, want ErrVerificationNotFound — the claim runs before the refusal, so the link is burned either way", err)
	}
}

// mustNotHaveMinted fails when a [deletionRecorder] saw a CreateVerification
// since its last reset. [auth.Store] has no by-user verification read, so
// "nothing was minted" is asserted the way the password-reset half of this
// suite already asserts it: by watching the write.
func mustNotHaveMinted(t *testing.T, rec *deletionRecorder, what string) {
	t.Helper()
	for _, ev := range rec.snapshot() {
		if ev == "CreateVerification" {
			t.Fatalf("%s minted a verification for a stamped account: %v", what, rec.snapshot())
		}
	}
}
