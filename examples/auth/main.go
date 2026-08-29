// Command auth is a runnable, database-free tour of the whole library wired
// together: authentication (auth), organization RBAC (org/scope) and
// invitations (invite), driven end to end by one script.
//
//	go run ./examples/auth
//
// examples/basic covers the RBAC half on its own. This one exists because the
// three packages meet at seams no single package's doc can show — most of all
// the one in step 1, where invite.New needs the *scope.Service that org.Service
// embeds. Everything runs against store/memory, so there is no database and no
// setup.
//
// # What is deliberately NOT here
//
// A transport. authlayer mints tokens and returns them to you; it never sends
// mail and never writes an HTTP response. Every place a real application would
// email a link, this program prints it and hands it straight to the next step.
// That is also why the verification and invite tokens appear in the trace: in
// production those two strings are the secrets, and printing them is the one
// thing this example does that yours must not.
package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/bernardoforcillo/authlayer/access"
	"github.com/bernardoforcillo/authlayer/auth"
	"github.com/bernardoforcillo/authlayer/invite"
	"github.com/bernardoforcillo/authlayer/org"
	"github.com/bernardoforcillo/authlayer/store/memory"
)

const demoPassword = "Correct-Horse-Battery-9!"

func main() {
	ctx := context.Background()

	// -- 1. Wire the three services --------------------------------------
	//
	// auth owns credentials and sessions; org/scope owns membership and
	// permissions; invite admits someone who has no standing yet. They share
	// no store and no types — the only thing connecting them is a user id
	// string, which auth mints and the other two treat as an opaque subject.
	key := []byte("32-bytes-or-more-from-your-vault") // the HS256 floor, RFC 7518 3.2
	authSvc := auth.New(memory.NewAuthStore(),
		auth.WithJWT([][]byte{key}, 15*time.Minute),
		auth.WithRefreshTTL(30*24*time.Hour),
		auth.WithRequireVerifiedEmail(true))

	orgSvc := org.New(
		org.NewAccess(map[string][]access.Action{
			"project": {"create", "read", "update", "delete"},
		}),
		memory.New[org.Organization, org.Member]())

	// THE SEAM. invite.New wants the *scope.Service — the generic engine —
	// not the org.Service wrapper. org.Service embeds
	// *scope.Service[Organization, Member, *Organization, *Member], so
	// orgSvc.Service is that embedded field, reachable by the embedded
	// type's own name. Every auth+invite integration hits this line.
	inviteSvc := invite.New(orgSvc.Service, memory.NewInviteStore())

	// -- 2. Sign up ------------------------------------------------------
	//
	// SignUp returns the same shape whether the address was new or already
	// registered — that is the enumeration property, and a real handler must
	// not branch on Created when shaping its response. Here we are the
	// operator, not the internet, so printing it is fine.
	step("sign up")
	signup, err := authSvc.SignUp(ctx, "  Alice@Example.com ", demoPassword)
	must(err)
	fmt.Printf("  created=%v  id=%s  email=%q (normalized)\n",
		signup.Created, short(signup.User.ID), signup.User.Email)
	fmt.Printf("  verify token (you deliver this by email): %s...\n", short(signup.VerifyToken))

	// -- 3. Verify the address -------------------------------------------
	//
	// WithRequireVerifiedEmail(true) above means Login refuses until this
	// runs. Redeeming the token is the proof of control.
	step("verify email")
	_, err = authSvc.Login(ctx, "alice@example.com", demoPassword, "203.0.113.9", "demo")
	if !errors.Is(err, auth.ErrEmailNotVerified) {
		panic(fmt.Sprintf("want ErrEmailNotVerified before verification, got %v", err))
	}
	fmt.Println("  login before verification -> ErrEmailNotVerified")
	verified, err := authSvc.VerifyEmail(ctx, signup.VerifyToken)
	must(err)
	fmt.Printf("  verified at %s\n", verified.EmailVerifiedAt.Format(time.RFC3339))

	// -- 4. Log in, and verify the access token --------------------------
	//
	// Login returns a LoginResult: the user plus two credentials. The access
	// token is a short-lived JWT nothing stores; the refresh token is an
	// opaque bearer whose sha256 is a row in the sessions table.
	step("log in")
	login, err := authSvc.Login(ctx, "alice@example.com", demoPassword, "203.0.113.9", "demo")
	must(err)
	fmt.Printf("  access token %s...  refresh token %s...\n",
		short(login.AccessToken), short(login.RefreshToken))

	// This is what a request handler does per request: parse and verify the
	// bearer token locally, with no store round trip. The sid it returns is
	// the session id — the value ChangePassword wants, and the value to look
	// up if you want revocation to bite sooner than the access TTL.
	claims, err := authSvc.VerifyAccessToken(login.AccessToken)
	must(err)
	fmt.Printf("  claims: sub=%s  sid=%s  email=%s  exp=%s\n",
		short(claims.Subject), short(claims.SessionID), claims.Email,
		time.Unix(claims.ExpiresAt, 0).UTC().Format(time.RFC3339))
	if claims.Subject != login.User.ID {
		panic("sub must be the user id")
	}

	// A tampered token fails closed rather than returning partial claims.
	if _, err := authSvc.VerifyAccessToken(login.AccessToken + "x"); err == nil {
		panic("a tampered access token must not verify")
	}
	fmt.Println("  tampered access token -> rejected")

	// -- 5. Alice creates an organization --------------------------------
	//
	// org/scope reads the acting subject from the context. auth's user id is
	// what goes in: that string is the only bridge between the two halves.
	step("create an organization")
	alice := org.WithSubject(ctx, login.User.ID)
	acme, err := orgSvc.CreateOrganization(alice, "Acme", "acme")
	must(err)
	aliceInOrg := org.WithOrg(alice, acme.ID)
	fmt.Printf("  org %q (%s), owned by alice\n", acme.Name, short(acme.ID))

	// -- 6. Invite a second user who does not exist yet ------------------
	//
	// This is the ordering that matters: the invitation is minted for an
	// EMAIL, before bob has an account at all. He signs up afterwards and
	// accepts with the id auth mints for him.
	step("invite bob by email")
	inv, inviteToken, err := inviteSvc.InviteByEmail(aliceInOrg, "bob@example.com", org.RoleAdmin)
	must(err)
	fmt.Printf("  invite %s for %s as %q, expires %s\n",
		short(inv.ID), inv.Email, inv.RoleKey, inv.ExpiresAt.Format(time.RFC3339))
	fmt.Printf("  invite token (you deliver this by email): %s...\n", short(inviteToken))

	// Anyone holding the token can see what it is for before spending it.
	preview, err := inviteSvc.PreviewInvite(ctx, inviteToken)
	must(err)
	fmt.Printf("  preview: role=%q valid=%v\n", preview.RoleKey, preview.Valid)

	// -- 7. Bob signs up, verifies, logs in, and accepts -----------------
	step("bob signs up and accepts")
	bobSignup, err := authSvc.SignUp(ctx, "bob@example.com", demoPassword)
	must(err)
	_, err = authSvc.VerifyEmail(ctx, bobSignup.VerifyToken)
	must(err)
	bobLogin, err := authSvc.Login(ctx, "bob@example.com", demoPassword, "198.51.100.7", "demo")
	must(err)
	fmt.Printf("  bob id=%s\n", short(bobLogin.User.ID))

	bob := org.WithSubject(ctx, bobLogin.User.ID)
	joined, err := inviteSvc.AcceptInvite(bob, inviteToken)
	must(err)
	fmt.Printf("  bob joined %q as %s\n", joined.Name, org.RoleAdmin)

	// A one-time token is one-time: the second accept finds nothing.
	if _, err := inviteSvc.AcceptInvite(bob, inviteToken); err == nil {
		panic("an invite token must not be redeemable twice")
	}
	fmt.Println("  second accept with the same token -> rejected")

	// -- 8. Authorize ----------------------------------------------------
	//
	// Permission checks read subject + org from the context, exactly as in
	// examples/basic. The difference is only that the subject came from a
	// verified access token this time.
	step("authorize")
	bobInOrg := org.WithOrg(bob, acme.ID)
	report("bob  member:create (admin)", can(orgSvc, bobInOrg, org.ResourceMember, org.ActionCreate))
	report("bob  organization:delete", can(orgSvc, bobInOrg, org.ResourceOrganization, org.ActionDelete))
	report("bob  project:create", can(orgSvc, bobInOrg, "project", "create"))

	// -- 9. Refresh ------------------------------------------------------
	//
	// Every refresh rotates: the presented token is superseded and a
	// successor is minted in the same family. Presenting the OLD one again
	// is a replay, and revokes the entire family.
	step("refresh")
	refreshed, err := authSvc.Refresh(ctx, login.RefreshToken)
	must(err)
	fmt.Printf("  new access %s...  new refresh %s... (rotated: %v)\n",
		short(refreshed.AccessToken), short(refreshed.RefreshToken),
		refreshed.RefreshToken != login.RefreshToken)

	// -- 10. Log out -----------------------------------------------------
	//
	// Logout of a CURRENT token removes exactly that row. It deliberately
	// leaves the family's rotated-but-unexpired predecessors alone, because
	// those rows ARE reuse detection: a replay of one is what fires family
	// revocation. (Logout of an already-rotated token is the other case, and
	// takes the whole family — see Logout's doc.)
	//
	// So ListSessions after a logout is not a device list. It is rotation
	// history, and the count below is the step-9 predecessor still sitting
	// there as a tripwire. Build a "your devices" screen from the rows whose
	// RotatedAt is nil, and revoke by family.
	step("log out")
	must(authSvc.Logout(ctx, refreshed.RefreshToken))
	if _, err := authSvc.Refresh(ctx, refreshed.RefreshToken); err == nil {
		panic("a logged-out refresh token must not refresh")
	}
	fmt.Println("  refresh after logout -> rejected")
	sessions, err := authSvc.ListSessions(ctx, login.User.ID)
	must(err)
	live := 0
	for _, sess := range sessions {
		if sess.RotatedAt == nil {
			live++
		}
	}
	fmt.Printf("  ListSessions rows for alice: %d (live: %d, rotated tripwires: %d)\n",
		len(sessions), live, len(sessions)-live)

	// An access token minted before the logout still verifies, because it is
	// stateless and nothing looks it up. That is the bound the readme's
	// "What 'revocable' actually means" spends a section on.
	if _, err := authSvc.VerifyAccessToken(refreshed.AccessToken); err != nil {
		panic("an access token stays valid for its own TTL after logout")
	}
	fmt.Println("  access token from before the logout still verifies (stateless JWT, up to its TTL)")

	fmt.Println("\ndone")
}

func can(svc *org.Service, ctx context.Context, resource string, actions ...access.Action) bool {
	ok, err := svc.Can(ctx, resource, actions...)
	must(err)
	return ok
}

func report(label string, allowed bool) {
	fmt.Printf("  %-28s %v\n", label, allowed)
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

func must(err error) {
	if err != nil {
		panic(err)
	}
}
