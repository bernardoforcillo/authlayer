// Command oauth is a runnable, database-free tour of authlayer's external
// ("sign in with Google/GitHub/…") identities: the resolution ladder, the
// linking policy, the explicit link that is the remedy when that policy
// refuses, and the edges — the account's last credential, an account that has
// no password at all, and what a password reset does to every connected
// account on the way through.
//
//	go run ./examples/oauth
//
// Everything runs against store/memory, so there is no database and no setup.
//
// # What is deliberately NOT here
//
// The OAuth dance. authlayer never talks to a provider: it exchanges no
// authorization code, it stores no provider access or refresh token, and it
// is not an API client. Your application runs the dance with whatever client
// library it likes, validates the response, and hands the result over as an
// auth.ExternalIdentity — which is the whole of what the fakeProvider below
// stands in for. An identity row is (provider, subject, email) plus two
// timestamps, and that is all of it: a dump of that table cannot be replayed
// against Google or GitHub on a user's behalf, because it holds nothing to
// replay.
//
// A transport is missing too, as in every other example here: authlayer
// returns tokens and never writes an HTTP response.
package main

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/bernardoforcillo/authlayer/auth"
	"github.com/bernardoforcillo/authlayer/store/memory"
)

// The passwords the two local accounts in this program sign up with. Alice
// gets hers only in step 8, and only through a reset — she never had one.
const (
	bobPassword        = "Correct-Horse-Battery-8!"
	carolPassword      = "Correct-Horse-Battery-7!"
	aliceFirstPassword = "First-Password-Ever-4!"
)

// externalAccount is one account AT a provider: an address the person can
// change there, and whether the provider claims to have verified it.
type externalAccount struct {
	email    string
	verified bool
}

// fakeProvider stands in for a real OAuth/OIDC client. Its authorize method
// is the only part of a provider authlayer ever sees: the assertion that
// comes back once your code has finished the dance and validated the
// response. The subject — the provider's own opaque, stable identifier for
// the account — is what authlayer keys on, and this type is deliberately
// built so the subject and the email can move independently, because that is
// the distinction steps 3 and 4 turn on.
type fakeProvider struct {
	name     string
	accounts map[string]*externalAccount
}

func newProvider(name string) *fakeProvider {
	return &fakeProvider{name: name, accounts: map[string]*externalAccount{}}
}

// register creates an account at the provider. It writes nothing to
// authlayer: nobody has signed in yet.
func (p *fakeProvider) register(subject, email string, verified bool) {
	p.accounts[subject] = &externalAccount{email: email, verified: verified}
}

// changeEmail is the person editing their address AT THE PROVIDER — the
// event step 4 exists to show authlayer surviving. The subject is untouched,
// because a provider does not reissue one when an address changes.
func (p *fakeProvider) changeEmail(subject, email string) {
	p.accounts[subject].email = email
}

// authorize returns what a completed dance yields: the provider's assertion,
// not its tokens.
func (p *fakeProvider) authorize(subject string) auth.ExternalIdentity {
	a, ok := p.accounts[subject]
	if !ok {
		panic("authlayer/examples/oauth: no account " + subject + " at " + p.name)
	}
	return auth.ExternalIdentity{
		Provider: p.name,
		Subject:  subject,
		Email:    a.email,
		// The provider's claim about ITS OWN verification of that address,
		// and nothing more. A provider that does not report this at all must
		// be mapped to false, never defaulted to true.
		EmailVerified: a.verified,
	}
}

func main() {
	ctx := context.Background()

	// -- 1. Wire the service ---------------------------------------------
	//
	// WithIdentityStore is what turns the four external-identity methods on.
	// It is a SEPARATE, optional port from auth.Store — an application that
	// offers no external sign-in wires none, and every one of those four
	// methods then fails with ErrOAuthNotConfigured rather than a nil
	// dereference.
	//
	// No WithLinking call: LinkVerified is Linking's zero value, so the safe
	// policy is the one you get by saying nothing. `strict` below is the
	// same two stores under LinkNever, which is how step 6 shows that
	// LinkIdentity is not gated by the policy at all.
	step("wire")
	key := []byte("32-bytes-or-more-from-your-vault") // the HS256 floor, RFC 7518 3.2
	authStore := memory.NewAuthStore()
	identityStore := memory.NewIdentityStore()

	svc := auth.New(authStore,
		auth.WithIdentityStore(identityStore),
		auth.WithJWT([][]byte{key}, 15*time.Minute))
	strict := auth.New(authStore,
		auth.WithIdentityStore(identityStore),
		auth.WithJWT([][]byte{key}, 15*time.Minute),
		auth.WithLinking(auth.LinkNever))

	google := newProvider("google")
	github := newProvider("github")
	google.register("google|1001", "alice@example.com", true)
	github.register("github|2002", "bob@example.com", false)
	github.register("github|3003", "carol@example.com", true)
	fmt.Println("  auth.Service over store/memory, with an identity store; policy = LinkVerified (the zero value)")
	fmt.Println("  a second Service over the SAME stores with LinkNever, for step 6")

	// -- 2. The first sign-in provisions an account ----------------------
	//
	// Nothing here knows alice yet. Rung 1 — (provider, subject) — misses,
	// so rung 2 resolves the address, finds no local account holding it, and
	// creates one: no password, and EmailVerifiedAt stamped only because the
	// provider asserted the address verified.
	step("first sign-in provisions")
	first, err := svc.SignInWith(ctx, auth.SignInRequest{
		Identity:  google.authorize("google|1001"),
		IP:        "203.0.113.9",
		UserAgent: "demo",
	})
	must(err)
	alice := first.User.ID
	fmt.Printf("  created=%v  id=%s  email=%q  verified=%v\n",
		first.Created, short(alice), first.User.Email, first.User.EmailVerifiedAt != nil)
	fmt.Printf("  access token %s...  refresh token %s...\n",
		short(first.AccessToken), short(first.RefreshToken))
	printIdentities(ctx, svc, "alice", alice)

	// -- 3. The same subject signs the SAME user in ----------------------
	//
	// Rung 1 hits this time, so no address is consulted at all and nothing is
	// provisioned. Created is false, and the identity's LastUsedAt moves.
	step("the same subject signs the same user in")
	second, err := svc.SignInWith(ctx, auth.SignInRequest{
		Identity:  google.authorize("google|1001"),
		IP:        "203.0.113.9",
		UserAgent: "demo",
	})
	must(err)
	expect(second.User.ID == alice, "the same (provider, subject) must resolve to the same account")
	expect(!second.Created, "an existing link must not provision a second account")
	fmt.Printf("  created=%v  id=%s (same account)\n", second.Created, short(second.User.ID))
	fmt.Printf("  identity rows for alice: %d (still one link, not two)\n",
		len(list(ctx, svc, alice)))

	// -- 4. The provider changes its reported email ----------------------
	//
	// THE REASON THE SUBJECT RUNG COMES FIRST. Alice edits her address at
	// Google. The subject does not change, so the link does not move: she
	// lands on the same local account, and neither her account's address nor
	// the identity's audit copy is rewritten from the new assertion.
	//
	// The security half is the same fact from the other side. If the address
	// decided first, anyone who could make a provider assert someone else's
	// address could re-route a link they already control onto that person's
	// account.
	step("the provider changes its reported email")
	google.changeEmail("google|1001", "alice@newmail.example")
	moved, err := svc.SignInWith(ctx, auth.SignInRequest{
		Identity:  google.authorize("google|1001"),
		IP:        "203.0.113.9",
		UserAgent: "demo",
	})
	must(err)
	expect(moved.User.ID == alice, "changing the address at the provider must not re-route the link")
	expect(!moved.Created, "changing the address at the provider must not split the account in two")
	fmt.Printf("  provider now asserts %q\n", google.accounts["google|1001"].email)
	fmt.Printf("  signed in as %s (same account), created=%v\n", short(moved.User.ID), moved.Created)
	fmt.Printf("  the account's own email is still %q\n", moved.User.Email)
	printIdentities(ctx, svc, "alice", alice)
	fmt.Println("  Identity.Email records what the PROVIDER asserted at link time: an audit field,")
	fmt.Println("  never an authentication input once the link exists.")

	// -- 5. An unverified identity claiming an existing address ----------
	//
	// THE ATTACK THE POLICY EXISTS TO STOP. Bob has a real, verified,
	// password-holding account here. An unknown GitHub subject now asserts
	// his address, and GitHub does not claim to have verified it. Under a
	// naive "the addresses match, so sign them in", whoever holds that
	// GitHub account owns bob's account without ever learning his password.
	//
	// LinkVerified requires BOTH sides verified, so the sign-in is refused.
	// The refusal is total: no identity row, no session, nothing written.
	step("an unverified identity claiming an existing account")
	bobSignup, err := svc.SignUp(ctx, "bob@example.com", bobPassword)
	must(err)
	bob := bobSignup.User.ID
	_, err = svc.VerifyEmail(ctx, bobSignup.VerifyToken)
	must(err)
	fmt.Printf("  bob   id=%s  password + verified address\n", short(bob))

	before := len(list(ctx, svc, bob))
	_, err = svc.SignInWith(ctx, auth.SignInRequest{
		Identity:  github.authorize("github|2002"), // asserts bob@example.com, EmailVerified=false
		IP:        "198.51.100.66",
		UserAgent: "attacker",
	})
	expect(errors.Is(err, auth.ErrLinkRequiresVerification), "an unverified assertion must not claim a verified account")
	fmt.Printf("  github asserts bob@example.com, EmailVerified=false -> %v\n", err)
	fmt.Printf("  identity rows for bob: %d (was %d)   sessions for bob: %d\n",
		len(list(ctx, svc, bob)), before, sessions(ctx, svc, bob))

	// The same refusal covers an address the APPLICATION supplies. A
	// provider that returns no address at all — github with a private one is
	// the usual case — leaves the app nothing to key on, so SignInWith takes
	// a FallbackEmail. That value may PROVISION a new account and may never
	// LINK to an existing one, under any policy including LinkAlways: the
	// provider vouched for no address whatsoever, so linking on one would
	// attach an external account to somebody else's local account on the
	// strength of a string the caller typed.
	_, err = svc.SignInWith(ctx, auth.SignInRequest{
		Identity:      auth.ExternalIdentity{Provider: "github", Subject: "github|4004", EmailVerified: true},
		FallbackEmail: "bob@example.com",
		IP:            "198.51.100.66",
	})
	expect(errors.Is(err, auth.ErrLinkRequiresVerification), "a caller-supplied address must never link to an existing account")
	fmt.Printf("  a FallbackEmail naming bob's address (no provider assertion at all) -> %v\n", err)

	// LinkNever refuses the same implicit link whatever the provider says,
	// which is what makes step 6's point sharp rather than incidental.
	_, err = strict.SignInWith(ctx, auth.SignInRequest{
		Identity: github.authorize("github|2002"),
		IP:       "198.51.100.66",
	})
	expect(errors.Is(err, auth.ErrLinkRequiresVerification), "LinkNever must refuse every implicit link")
	fmt.Printf("  the LinkNever service refuses it too -> %v\n", err)

	// The policy is not a wall, though: carol arrives from a provider that
	// DID verify her address, onto a local account that is verified too, and
	// LinkVerified links her implicitly. Created is false — the account was
	// already there.
	carolSignup, err := svc.SignUp(ctx, "carol@example.com", carolPassword)
	must(err)
	carol := carolSignup.User.ID
	_, err = svc.VerifyEmail(ctx, carolSignup.VerifyToken)
	must(err)
	carolIn, err := svc.SignInWith(ctx, auth.SignInRequest{
		Identity:  github.authorize("github|3003"), // asserts carol@example.com, EmailVerified=true
		IP:        "203.0.113.44",
		UserAgent: "demo",
	})
	must(err)
	expect(carolIn.User.ID == carol && !carolIn.Created, "both sides verified must link to the existing account")
	fmt.Printf("  carol id=%s  both sides verified -> linked implicitly, created=%v\n",
		short(carol), carolIn.Created)

	// -- 6. The remedy: LinkIdentity after a password login --------------
	//
	// ErrLinkRequiresVerification is a "not like this", not a dead end. The
	// documented remedy is for the application to authenticate the user by
	// some OTHER means and then link deliberately — a different trust basis
	// entirely, because the user has just proved they hold the account.
	//
	// So LinkIdentity is NOT gated by the Linking policy: the call below is
	// made on the LinkNever service, the strictest policy there is and the
	// one that produces this refusal most often. If the policy that produced
	// the refusal also blocked the remedy, LinkNever would mean "no external
	// identities at all", and the error would have no answer.
	step("the remedy: LinkIdentity after a password login")
	_, err = svc.Login(ctx, "bob@example.com", bobPassword, "198.51.100.7", "laptop")
	must(err)
	fmt.Printf("  bob logs in with his password (sessions: %d)\n", sessions(ctx, svc, bob))

	linked, err := strict.LinkIdentity(ctx, bob, github.authorize("github|2002"))
	must(err)
	fmt.Printf("  strict.LinkIdentity -> %s\n", describe(linked))
	fmt.Println("  LinkNever did not gate it, and neither side had to be verified")
	expect(linked.LastUsedAt == nil, "a link made without a sign-in must leave LastUsedAt nil")

	// And now the same assertion that was refused in step 5 resolves on rung
	// 1, because the link exists. Nothing about the provider changed.
	nowIn, err := svc.SignInWith(ctx, auth.SignInRequest{
		Identity:  github.authorize("github|2002"),
		IP:        "198.51.100.7",
		UserAgent: "laptop",
	})
	must(err)
	expect(nowIn.User.ID == bob && !nowIn.Created, "the explicit link must make rung 1 resolve")
	fmt.Printf("  the same github assertion now signs bob in: id=%s created=%v\n",
		short(nowIn.User.ID), nowIn.Created)
	printIdentities(ctx, svc, "bob", bob)

	// Re-linking the same pair to the same user is a no-op that returns the
	// stored row unchanged, so a retried request costs nothing. Pointing that
	// pair at ANOTHER user is ErrIdentityLinked: an existing link is never
	// re-pointed.
	again, err := svc.LinkIdentity(ctx, bob, github.authorize("github|2002"))
	must(err)
	expect(again.ID == linked.ID, "re-linking the same pair must be idempotent")
	_, err = svc.LinkIdentity(ctx, carol, github.authorize("github|2002"))
	expect(errors.Is(err, auth.ErrIdentityLinked), "an existing link must never be re-pointed")
	fmt.Printf("  re-linking the same pair to bob is a no-op; pointing it at carol -> %v\n", err)

	// -- 7. UnlinkIdentity refuses the last credential -------------------
	//
	// Alice has one identity and no password. Removing it would leave an
	// account nothing in this package can authenticate — Login refuses an
	// empty password hash, and SignInWith would have no link to resolve. The
	// lockout would be permanent and silent, so the removal is refused and
	// NOTHING is deleted.
	//
	// The decision and the delete are one atomic step inside the store, not
	// a read-then-write here: two concurrent unlinks of a user's last two
	// identities would otherwise each see the other's row, each conclude the
	// account stays reachable, and each delete.
	step("unlink refuses the last credential")
	err = svc.UnlinkIdentity(ctx, alice, "google")
	expect(errors.Is(err, auth.ErrLastCredential), "unlinking the last way in must be refused")
	fmt.Printf("  alice has one identity and no password -> %v\n", err)
	fmt.Printf("  identity rows for alice: %d (the row survives)\n", len(list(ctx, svc, alice)))

	// Bob holds a password, so his account stays reachable without the
	// identity and the unlink goes through. It also signs him out
	// EVERYWHERE: removing a credential revokes every session family the
	// account holds, the same sweep LogoutAll performs, because a session
	// minted through the identity being removed must not keep rotating.
	fmt.Printf("  sessions for bob before the unlink: %d\n", sessions(ctx, svc, bob))
	must(svc.UnlinkIdentity(ctx, bob, "github"))
	fmt.Printf("  bob holds a password -> unlinked; identity rows for bob: %d; sessions: %d\n",
		len(list(ctx, svc, bob)), sessions(ctx, svc, bob))
	expect(sessions(ctx, svc, bob) == 0, "removing a credential must revoke every session")

	// A provider the user never linked is a different answer, and a
	// connected-accounts screen acts on it differently.
	err = svc.UnlinkIdentity(ctx, bob, "google")
	expect(errors.Is(err, auth.ErrIdentityNotFound), "nothing to unlink is not the same as refusing to")
	fmt.Printf("  unlinking a provider bob never linked -> %v\n", err)

	// -- 8. A provisioned account has no password ------------------------
	//
	// Not a scrubbed one — an empty column. Every Service method clears
	// PasswordHash on the record it hands back, so the raw store read below
	// is the only way to show the difference.
	//
	// ChangePassword cannot help: it requires the CURRENT password, and
	// there is none to present. The reset flow is the only route to a first
	// password, because redeeming a reset token is itself proof of control
	// of the address it was delivered to.
	step("a provisioned account has no password")
	stored, err := authStore.FindUserByID(ctx, alice)
	must(err)
	fmt.Printf("  stored PasswordHash for alice: %q (empty, not merely scrubbed)\n", stored.PasswordHash)

	_, err = svc.Login(ctx, "alice@example.com", "", "203.0.113.9", "demo")
	expect(errors.Is(err, auth.ErrInvalidCredentials), "the empty string is not a password-less account's password")
	fmt.Printf("  Login with the empty string -> %v\n", err)

	claims, err := svc.VerifyAccessToken(moved.AccessToken)
	must(err)
	err = svc.ChangePassword(ctx, alice, claims.SessionID, "", aliceFirstPassword)
	expect(errors.Is(err, auth.ErrInvalidCredentials), "ChangePassword needs a current password there is none of")
	fmt.Printf("  ChangePassword (it needs the current password) -> %v\n", err)

	resetTok, ok, err := svc.RequestPasswordReset(ctx, "alice@example.com", "203.0.113.9")
	must(err)
	expect(ok, "a password-less account must still be able to request a reset")
	must(svc.ResetPassword(ctx, resetTok, aliceFirstPassword))
	_, err = svc.Login(ctx, "alice@example.com", aliceFirstPassword, "203.0.113.9", "demo")
	must(err)
	fmt.Println("  RequestPasswordReset -> ResetPassword -> Login: the only route to a first password")

	// -- 9. A reset disconnects every linked account ---------------------
	//
	// ResetPassword is UNAUTHENTICATED recovery: whoever redeemed the token
	// proved control of an address and nothing else. So it assumes every
	// OTHER credential on the account is hostile — which is why it revokes
	// every session, and why it also removes every external identity. An
	// attacker who had linked one would otherwise keep signing in through it
	// after the victim performed every recovery step the docs prescribe.
	//
	// ChangePassword deliberately does not sweep: its caller was already
	// authenticated and is doing something routine.
	step("a reset disconnects every linked account")
	expect(len(list(ctx, svc, alice)) == 0, "an unauthenticated recovery must sweep every identity")
	fmt.Printf("  identity rows for alice after her reset: %d (her google link is gone)\n",
		len(list(ctx, svc, alice)))

	// The consequence, stated plainly: connected accounts must be linked
	// again. She is authenticated now — she just logged in with the password
	// the reset gave her — so the application links deliberately.
	relinked, err := svc.LinkIdentity(ctx, alice, google.authorize("google|1001"))
	must(err)
	fmt.Printf("  re-linked after the reset: %s\n", describe(relinked))

	backIn, err := svc.SignInWith(ctx, auth.SignInRequest{
		Identity: google.authorize("google|1001"),
		IP:       "203.0.113.9",
	})
	must(err)
	expect(backIn.User.ID == alice && !backIn.Created, "the re-link must make rung 1 resolve to her account again")
	fmt.Printf("  google signs her in again: id=%s created=%v\n", short(backIn.User.ID), backIn.Created)

	// And with a password held, the unlink step 7 refused is allowed.
	must(svc.UnlinkIdentity(ctx, alice, "google"))
	fmt.Printf("  with a password held, the unlink now succeeds (rows: %d, sessions: %d)\n",
		len(list(ctx, svc, alice)), sessions(ctx, svc, alice))

	fmt.Println("\ndone")
}

// list returns a user's identities in a stable order. ListIdentities is a
// scoped pass-through — it returns that user's rows and nobody else's — and
// leaves the order unspecified, so anything that depends on one sorts. An
// unknown user id comes back empty rather than as an error, which is what
// keeps it from answering "does this account exist?".
func list(ctx context.Context, svc *auth.Service, userID string) []auth.Identity {
	out, err := svc.ListIdentities(ctx, userID)
	must(err)
	sort.Slice(out, func(i, j int) bool { return out[i].Provider < out[j].Provider })
	return out
}

func printIdentities(ctx context.Context, svc *auth.Service, who, userID string) {
	rows := list(ctx, svc, userID)
	fmt.Printf("  identities for %s: %d\n", who, len(rows))
	for _, i := range rows {
		fmt.Printf("    %s\n", describe(i))
	}
}

func describe(i auth.Identity) string {
	used := "LastUsedAt=nil (this link has never signed anyone in)"
	if i.LastUsedAt != nil {
		used = "LastUsedAt=" + i.LastUsedAt.Format(time.RFC3339)
	}
	return fmt.Sprintf("%s/%s  email=%q  %s", i.Provider, i.Subject, i.Email, used)
}

// sessions counts the session rows a user currently holds. ListSessions
// returns rotation history rather than a device list; nothing rotates in this
// program, so the count is the number of sign-ins.
func sessions(ctx context.Context, svc *auth.Service, userID string) int {
	rows, err := svc.ListSessions(ctx, userID)
	must(err)
	return len(rows)
}

func step(label string) {
	fmt.Printf("\n== %s ==\n", strings.ToUpper(label))
}

// short truncates an id or token for display. Never do this to a value you
// are comparing — only to one you are printing.
func short(s string) string {
	if len(s) <= 12 {
		return s
	}
	return s[:12]
}

func expect(cond bool, what string) {
	if !cond {
		panic("authlayer/examples/oauth: " + what)
	}
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
