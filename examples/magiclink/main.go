// Command magiclink is a runnable, database-free tour of passwordless
// sign-in: RequestMagicLink and RedeemMagicLink.
//
//	go run ./examples/magiclink
//
// A magic link is not a step towards a credential the way a reset token is.
// It IS one: its holder exchanges it for a live session with nothing else
// asked of them. Almost everything below follows from that single fact, so
// this program demonstrates each consequence rather than describing it:
//
//   - a request for a KNOWN and an UNKNOWN address return the same
//     (token, ok, nil) shape, and the unknown one is not an error;
//   - a re-issue invalidates the previous link;
//   - redemption issues a session, and the SAME link a second time does
//     not — the token is burned before anything is issued;
//   - redemption stamps EmailVerifiedAt, because receiving the link at an
//     address is proof of control of it;
//   - a pending link does NOT survive a ChangePassword, which is the row of
//     the sweep matrix that matters most here;
//   - provisioning, opt-in, creates the account at request time — and what
//     that exposes.
//
// Everything runs against store/memory, so there is no database and no setup.
//
// # What is deliberately NOT here
//
// A transport, and any handler shape. authlayer mints tokens and returns
// them; it never sends mail. Every place a real application would email a
// link, this program prints it and hands it to the next step — which is the
// one thing yours must not do, twice over: those strings ARE the session,
// and printing whether one exists is exactly the answer RequestMagicLink
// exists not to give. A public handler must return a fixed response
// regardless of ok. Here we are the operator, not the internet.
package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/bernardoforcillo/authlayer/auth"
	"github.com/bernardoforcillo/authlayer/store/memory"
)

const (
	danaPassword = "Correct-Horse-Battery-9!"
	danaNextPass = "Changed-Horse-Battery-2!"
)

func main() {
	ctx := context.Background()

	// -- 1. Wire the service ---------------------------------------------
	//
	// WithMagicLinkTTL is the shortest of the four token lifetimes on
	// purpose. A "signup" or "email_change" token attests something about
	// an address; a "password_reset" token grants the right to SET a
	// credential; a "magic_link" token is the credential. Fifteen minutes
	// is the default for exactly that reason, and this passes it
	// explicitly so the number is visible.
	step("wire")
	key := []byte("32-bytes-or-more-from-your-vault") // the HS256 floor, RFC 7518 3.2
	svc := auth.New(memory.NewAuthStore(),
		auth.WithJWT([][]byte{key}, 15*time.Minute),
		auth.WithMagicLinkTTL(15*time.Minute))
	fmt.Println("  auth.Service over store/memory; magic links live 15 minutes")

	// -- 2. One account, never verified ----------------------------------
	//
	// dana signs up and never clicks the confirmation mail. Step 5 is what
	// that sets up: a redemption certifies the address, so the link is
	// itself the way out of an unconfirmed account.
	step("one account")
	dana, err := svc.SignUp(ctx, "dana@example.com", danaPassword)
	must(err)
	before, err := svc.User(ctx, dana.User.ID)
	must(err)
	fmt.Printf("  dana  id=%s  EmailVerifiedAt=%v\n", short(dana.User.ID), before.EmailVerifiedAt)

	// -- 3. Request a link: known address, unknown address ---------------
	//
	// THE ENUMERATION PROPERTY, and it is the same one RequestPasswordReset
	// carries. Both calls return (string, bool, error). The unknown address
	// is NOT an error — it returns ("", false, nil) — so a handler has
	// nothing to branch on but ok, and ok decides whether to send mail,
	// never what to tell the client.
	//
	// An ANONYMIZED account takes this same branch, with the same return,
	// for the same reason: a distinguishable refusal would be the oracle
	// this shape exists to close.
	step("request a link: known and unknown")
	firstTok, knownOK, err := svc.RequestMagicLink(ctx, "dana@example.com", "203.0.113.9")
	must(err)
	unknownTok, unknownOK, unknownErr := svc.RequestMagicLink(ctx, "nobody@example.com", "203.0.113.9")
	must(unknownErr)
	fmt.Printf("  %-20s token=%-6v ok=%-6v err=%v\n", "dana@example.com", firstTok != "", knownOK, err)
	fmt.Printf("  %-20s token=%-6v ok=%-6v err=%v\n", "nobody@example.com", unknownTok != "", unknownOK, unknownErr)
	expect(knownOK && firstTok != "", "a known address must mint a link")
	expect(!unknownOK && unknownTok == "", "an unknown address must mint nothing")
	fmt.Println("  same (token, ok, nil) shape both times; the unknown address never errors")

	// ip is not optional, for the same reason it is not optional on Login:
	// a blank one collapses every caller that omits it into one shared
	// rate-limit bucket.
	_, _, err = svc.RequestMagicLink(ctx, "dana@example.com", "")
	expect(errors.Is(err, auth.ErrMissingIP), "an empty ip must be ErrMissingIP")
	fmt.Println("  empty ip -> ErrMissingIP (a wiring bug, not caller input)")

	// Each request invalidates the account's previous link, so at most one
	// is live at a time. That is also a nuisance lever: anyone who merely
	// knows an address can kill a victim's unclicked link by looping this
	// call, which is what WithMagicLinkRateLimiter is for.
	linkTok, ok, err := svc.RequestMagicLink(ctx, "dana@example.com", "203.0.113.9")
	must(err)
	expect(ok, "the second request must also mint")
	_, err = svc.RedeemMagicLink(ctx, firstTok, "203.0.113.9", "phone")
	expect(errors.Is(err, auth.ErrVerificationNotFound), "re-issuing must invalidate the previous link")
	fmt.Println("  re-issuing invalidated the first link -> ErrVerificationNotFound")

	// -- 4. Redeem it ----------------------------------------------------
	//
	// RedeemMagicLink burns the token BEFORE it issues anything. That
	// ordering is the whole reason two people clicking the same link do not
	// both get in — and a link forwarded, quoted in a reply, or read out of
	// a shared mailbox is exactly how a second click happens with no
	// attacker doing anything clever.
	step("redeem it")
	session, err := svc.RedeemMagicLink(ctx, linkTok, "203.0.113.9", "phone")
	must(err)
	fmt.Printf("  signed in with no password at all: access=%v refresh=%v\n",
		session.AccessToken != "", session.RefreshToken != "")

	_, err = svc.RedeemMagicLink(ctx, linkTok, "203.0.113.9", "phone")
	expect(errors.Is(err, auth.ErrVerificationNotFound), "a magic link must be one-time")
	fmt.Println("  the same link a second time -> ErrVerificationNotFound (burned)")

	// A "password_reset" token is NOT redeemable here, and that check runs
	// before the burn. Without it, a token granting only the right to set a
	// password would be exchangeable directly for a session.
	resetTok, ok, err := svc.RequestPasswordReset(ctx, "dana@example.com", "203.0.113.9")
	must(err)
	expect(ok, "dana's address is registered")
	_, err = svc.RedeemMagicLink(ctx, resetTok, "203.0.113.9", "phone")
	expect(errors.Is(err, auth.ErrVerificationPurpose), "a reset token must not redeem as a magic link")
	fmt.Println("  a password_reset token here -> ErrVerificationPurpose (and it is NOT burned)")

	// -- 5. A redemption certifies the address ---------------------------
	//
	// A magic link is only ever DELIVERABLE to the address it was minted
	// for, so redeeming one is proof of control of that address — the same
	// argument that makes a completed reset stamp EmailVerifiedAt.
	step("a redemption certifies the address")
	after, err := svc.User(ctx, dana.User.ID)
	must(err)
	expect(after.EmailVerifiedAt != nil, "a redemption must stamp EmailVerifiedAt")
	fmt.Printf("  dana EmailVerifiedAt: %v -> %s\n",
		before.EmailVerifiedAt, after.EmailVerifiedAt.Format(time.RFC3339))
	fmt.Println("  the link was the way into an account that never clicked its signup mail")

	// -- 6. A pending link does not survive a ChangePassword -------------
	//
	// The side door, and it is the most direct of the three the sweep
	// matrix covers. An attacker parks a link for a victim's address and
	// waits. The victim notices something and changes their password — the
	// one thing a user does on suspecting compromise. If that left the
	// parked link armed, it would hand the account straight back for the
	// rest of its TTL, with no password needed.
	//
	// ChangePassword, ResetPassword and LogoutAll each sweep password_reset,
	// email_change AND magic_link. Logout and RevokeSession deliberately do
	// not: they are routine, per-device actions, and sweeping there would
	// break "request a link on your laptop, sign that laptop out, click it
	// on your phone".
	step("a pending link does not survive a ChangePassword")
	parked, ok, err := svc.RequestMagicLink(ctx, "dana@example.com", "198.51.100.66")
	must(err)
	expect(ok, "the attacker's request succeeds; that is the point")
	fmt.Println("  an attacker parks a magic link for dana's address")

	claims, err := svc.VerifyAccessToken(session.AccessToken)
	must(err)
	must(svc.ChangePassword(ctx, dana.User.ID, claims.SessionID, danaPassword, danaNextPass))
	fmt.Println("  dana changes her password (the sid from her own access token spares her family)")

	_, err = svc.RedeemMagicLink(ctx, parked, "198.51.100.66", "attacker")
	expect(errors.Is(err, auth.ErrVerificationNotFound), "the parked link must be swept")
	fmt.Println("  the parked link -> ErrVerificationNotFound (swept by the change)")

	// Logout is the other side of that rule, and it is a rule rather than
	// an omission: a link requested before signing a device out still works
	// afterwards.
	survivor, ok, err := svc.RequestMagicLink(ctx, "dana@example.com", "203.0.113.9")
	must(err)
	expect(ok, "dana requests a link on her laptop")
	must(svc.Logout(ctx, session.RefreshToken))
	phone, err := svc.RedeemMagicLink(ctx, survivor, "203.0.113.9", "phone")
	must(err)
	expect(phone.AccessToken != "", "the link must still redeem after a Logout")
	fmt.Println("  requested on a laptop, laptop signed out, clicked on a phone -> still works")

	// -- 7. Provisioning, and what it exposes ----------------------------
	//
	// WithMagicLinkProvisioning(true) makes an unrecognised address create
	// the account rather than fall through. Say plainly what that means:
	// anyone who can receive mail can create an account for any address
	// they control, which is the exposure an open SignUp endpoint already
	// has. The rate limiter is the control, not the option's absence.
	//
	// Note the reversal it causes in the enumeration property: with
	// provisioning ON the UNKNOWN branch becomes the slower one, because it
	// performs an extra CreateUser. The sign of the timing difference
	// flips; it does not disappear.
	step("provisioning")
	open := auth.New(memory.NewAuthStore(),
		auth.WithJWT([][]byte{key}, 15*time.Minute),
		auth.WithMagicLinkProvisioning(true))
	newcomerTok, ok, err := open.RequestMagicLink(ctx, "newcomer@example.com", "203.0.113.9")
	must(err)
	expect(ok && newcomerTok != "", "provisioning must mint for an address nobody registered")
	fmt.Println("  an address nobody registered -> ok=true, and the account now exists")

	minted, err := open.RedeemMagicLink(ctx, newcomerTok, "203.0.113.9", "phone")
	must(err)
	fmt.Printf("  redeemed: id=%s  verified=%v\n",
		short(minted.User.ID), minted.User.EmailVerifiedAt != nil)
	fmt.Println("  the account has NO password credential at all; ResetPassword is how it gets one")

	// Asking for a link proves nothing about an address — only redeeming
	// one does. An account provisioned by a REQUEST therefore holds no
	// password and carries no verification stamp, and a request nobody
	// clicks leaves exactly that row sitting there.
	_, ok, err = open.RequestMagicLink(ctx, "never-clicks@example.com", "203.0.113.9")
	must(err)
	expect(ok, "provisioning mints for this one too")
	_, err = open.Login(ctx, "never-clicks@example.com", danaPassword, "203.0.113.9", "laptop")
	expect(errors.Is(err, auth.ErrInvalidCredentials), "a provisioned account holds no password")
	fmt.Println("  a request nobody clicks still leaves an account: Login on it is ErrInvalidCredentials")
	fmt.Println("  that is the exposure to weigh — the rate limiter is the control, not the option's absence")

	fmt.Println("\ndone")
}

func step(label string) {
	fmt.Printf("\n== %s ==\n", strings.ToUpper(label))
}

// short truncates an id for display. Never do this to a value you are
// comparing — only to one you are printing.
func short(s string) string {
	if len(s) <= 12 {
		return s
	}
	return s[:12]
}

func expect(cond bool, what string) {
	if !cond {
		panic("authlayer/examples/magiclink: " + what)
	}
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
