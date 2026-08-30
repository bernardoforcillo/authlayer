// Command reset is a runnable, database-free tour of the three auth methods
// examples/auth never reaches: RequestPasswordReset, ResetPassword and
// RequestEmailChange.
//
//	go run ./examples/reset
//
// "Forgot my password" is the commonest reason to reach for a library like
// this one, and it carries the subtlest semantics in the package — so this
// program demonstrates each of them rather than describing them:
//
//   - a reset request for a KNOWN and an UNKNOWN address return the same
//     (token, ok, nil) shape, and the unknown one is not an error;
//   - a second request invalidates the first request's token;
//   - redeeming a reset burns the token, revokes every session, and stamps
//     EmailVerifiedAt when the account had none;
//   - RequestEmailChange requires the account's CURRENT PASSWORD, and
//     VerifyEmail then redeems the result with no authentication at all;
//   - a reset token parked by an attacker does not survive the victim's
//     ChangePassword.
//
// Everything runs against store/memory, so there is no database and no setup.
//
// # What is deliberately NOT here
//
// A transport, and any handler shape. authlayer mints tokens and returns
// them; it never sends mail. Every place a real application would email a
// link, this program prints it and hands it to the next step — which is the
// one thing yours must not do, twice over: those strings are the secrets,
// AND printing whether one exists is exactly the answer RequestPasswordReset
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
	alicePassword   = "Correct-Horse-Battery-9!"
	aliceResetPass  = "Reset-Horse-Battery-1!"
	aliceFinalPass  = "Changed-Horse-Battery-2!"
	bobPassword     = "Correct-Horse-Battery-8!"
	aliceNewAddress = "alice@newmail.example"
)

func main() {
	ctx := context.Background()

	// -- 1. Wire the service ---------------------------------------------
	//
	// WithRequireVerifiedEmail(true) is what makes step 5 mean something:
	// with it on, an account that never confirmed its address cannot log in
	// at all, and this package ships no "resend the verification email"
	// path. A completed password reset is the way out, because redeeming a
	// reset token IS proof of control of the address it was delivered to.
	step("wire")
	key := []byte("32-bytes-or-more-from-your-vault") // the HS256 floor, RFC 7518 3.2
	svc := auth.New(memory.NewAuthStore(),
		auth.WithJWT([][]byte{key}, 15*time.Minute),
		auth.WithVerificationTTL(24*time.Hour), // signup + email_change tokens
		auth.WithPasswordResetTTL(1*time.Hour), // password_reset tokens
		auth.WithRequireVerifiedEmail(true))
	fmt.Println("  auth.Service over store/memory; verified email required to log in")

	// -- 2. Two accounts -------------------------------------------------
	//
	// alice confirms her address and signs in on two devices — two session
	// FAMILIES, which is what step 4 revokes. bob never confirms his, so he
	// cannot log in yet; step 5 is how he gets in.
	step("two accounts")
	alice, err := svc.SignUp(ctx, "alice@example.com", alicePassword)
	must(err)
	_, err = svc.VerifyEmail(ctx, alice.VerifyToken)
	must(err)
	laptop, err := svc.Login(ctx, "alice@example.com", alicePassword, "203.0.113.9", "laptop")
	must(err)
	_, err = svc.Login(ctx, "alice@example.com", alicePassword, "203.0.113.9", "phone")
	must(err)
	fmt.Printf("  alice  id=%s  verified, %d live session families\n",
		short(alice.User.ID), families(ctx, svc, alice.User.ID))

	bob, err := svc.SignUp(ctx, "bob@example.com", bobPassword)
	must(err)
	_, err = svc.Login(ctx, "bob@example.com", bobPassword, "198.51.100.7", "laptop")
	expect(errors.Is(err, auth.ErrEmailNotVerified), "bob must not log in unverified")
	fmt.Printf("  bob    id=%s  never verified -> Login is ErrEmailNotVerified\n",
		short(bob.User.ID))

	// -- 3. Request a reset: known address, unknown address --------------
	//
	// THE ENUMERATION PROPERTY. Both calls return (string, bool, error).
	// The unknown address is NOT an error — it returns ("", false, nil) —
	// so a handler has nothing to branch on but ok, and ok decides whether
	// to send mail, never what to tell the client. Everything observable to
	// an anonymous caller must be identical for the two rows printed below.
	// (Latency is not: the known branch performs two extra writes, and that
	// residual channel is measured rather than assumed — see the readme's
	// "Enumeration safety is bounded, not absolute".)
	step("request a reset: known and unknown")
	knownTok, knownOK, err := svc.RequestPasswordReset(ctx, "alice@example.com", "203.0.113.9")
	must(err)
	unknownTok, unknownOK, unknownErr := svc.RequestPasswordReset(ctx, "nobody@example.com", "203.0.113.9")
	must(unknownErr)
	fmt.Printf("  %-20s token=%-6v ok=%-6v err=%v\n", "alice@example.com", knownTok != "", knownOK, err)
	fmt.Printf("  %-20s token=%-6v ok=%-6v err=%v\n", "nobody@example.com", unknownTok != "", unknownOK, unknownErr)
	expect(knownOK && knownTok != "", "a known address must mint a token")
	expect(!unknownOK && unknownTok == "", "an unknown address must mint nothing")
	fmt.Println("  same (token, ok, nil) shape both times; the unknown address never errors")

	// ip is not optional: a blank one would put every caller that omits it
	// into one shared rate-limit bucket, so it is refused rather than
	// tolerated as "unknown".
	_, _, err = svc.RequestPasswordReset(ctx, "alice@example.com", "")
	expect(errors.Is(err, auth.ErrMissingIP), "an empty ip must be ErrMissingIP")
	fmt.Println("  empty ip -> ErrMissingIP (a wiring bug, not caller input)")

	// Each request invalidates the account's previous reset token. That is
	// also a nuisance lever: anyone who merely knows an address can kill a
	// victim's genuine pending link by looping this call, which is what
	// WithPasswordResetRateLimiter is for.
	resetTok, ok, err := svc.RequestPasswordReset(ctx, "alice@example.com", "203.0.113.9")
	must(err)
	expect(ok, "the second request must also mint")
	expect(errors.Is(svc.ResetPassword(ctx, knownTok, aliceResetPass), auth.ErrVerificationNotFound),
		"re-issuing must invalidate the previous reset token")
	fmt.Println("  re-issuing invalidated the first token -> ErrVerificationNotFound")

	// -- 4. Redeem it ----------------------------------------------------
	//
	// ResetPassword claims the verification FIRST and applies second, so a
	// failure after the claim burns the token rather than leaving it
	// redeemable twice. It then revokes every session the account has — on
	// every device, with no "spare the caller's own" exception, because
	// presenting a reset token is no evidence the caller is using any of
	// the account's existing sessions.
	step("redeem it")
	must(svc.ResetPassword(ctx, resetTok, aliceResetPass))
	fmt.Println("  password reset")

	err = svc.ResetPassword(ctx, resetTok, aliceFinalPass)
	expect(errors.Is(err, auth.ErrVerificationNotFound), "a reset token must be one-time")
	fmt.Println("  the same token a second time -> ErrVerificationNotFound (burned)")

	fmt.Printf("  live session families for alice: %d (was 2)\n", families(ctx, svc, alice.User.ID))
	_, err = svc.Refresh(ctx, laptop.RefreshToken)
	expect(err != nil, "a pre-reset refresh token must be dead")
	fmt.Println("  the laptop's refresh token no longer refreshes")

	_, err = svc.Login(ctx, "alice@example.com", alicePassword, "203.0.113.9", "laptop")
	expect(errors.Is(err, auth.ErrInvalidCredentials), "the old password must be dead")
	aliceLogin, err := svc.Login(ctx, "alice@example.com", aliceResetPass, "203.0.113.9", "laptop")
	must(err)
	fmt.Println("  old password -> ErrInvalidCredentials; new password -> logged in")

	// -- 5. A completed reset certifies the address ----------------------
	//
	// bob signed up with an address he never confirmed, and cannot log in.
	// A reset link is only ever DELIVERABLE to the address it was minted
	// for, so redeeming one is the same proof of control a signup token
	// carries, arriving through a different door — and ResetPassword stamps
	// EmailVerifiedAt when it is not already set. Without that, an
	// unconfirmed account had no way in at all.
	step("a completed reset certifies the address")
	before, err := svc.User(ctx, bob.User.ID)
	must(err)
	fmt.Printf("  bob EmailVerifiedAt before: %v\n", before.EmailVerifiedAt)

	bobTok, ok, err := svc.RequestPasswordReset(ctx, "bob@example.com", "198.51.100.7")
	must(err)
	expect(ok, "bob's address is registered")
	must(svc.ResetPassword(ctx, bobTok, bobPassword))

	after, err := svc.User(ctx, bob.User.ID)
	must(err)
	expect(after.EmailVerifiedAt != nil, "a completed reset must stamp EmailVerifiedAt")
	fmt.Printf("  bob EmailVerifiedAt after:  %s\n", after.EmailVerifiedAt.Format(time.RFC3339))
	_, err = svc.Login(ctx, "bob@example.com", bobPassword, "198.51.100.7", "laptop")
	must(err)
	fmt.Println("  bob can now log in under WithRequireVerifiedEmail(true)")

	// An already-verified address keeps its ORIGINAL timestamp: the field
	// records when control was first proven, and an unrelated reset must
	// not move it forward.
	stamp := after.EmailVerifiedAt
	again, ok, err := svc.RequestPasswordReset(ctx, "bob@example.com", "198.51.100.7")
	must(err)
	expect(ok, "bob's address is still registered")
	must(svc.ResetPassword(ctx, again, bobPassword))
	restamped, err := svc.User(ctx, bob.User.ID)
	must(err)
	expect(restamped.EmailVerifiedAt.Equal(*stamp), "a second reset must not re-stamp")
	fmt.Println("  a second reset leaves the original stamp alone")

	// -- 6. Change the address -------------------------------------------
	//
	// RequestEmailChange ARMS a rotation of the account's login identifier
	// and VerifyEmail then redeems it with NO authentication at all, so
	// arming it is held to ChangePassword's standard: the current password,
	// checked with the same timing discipline. Without that check a
	// briefly-held session, or a leaked 15-minute access token, bought a
	// 24-hour account takeover.
	step("change the address")
	_, err = svc.RequestEmailChange(ctx, alice.User.ID, "not-her-password", aliceNewAddress)
	expect(errors.Is(err, auth.ErrInvalidCredentials), "a wrong password must not arm a rotation")
	fmt.Println("  wrong current password -> ErrInvalidCredentials (nothing minted)")

	changeTok, err := svc.RequestEmailChange(ctx, alice.User.ID, aliceResetPass, aliceNewAddress)
	must(err)
	fmt.Printf("  email_change token (you deliver this to the NEW address): %s...\n", short(changeTok))

	// The new address is not checked for uniqueness until redemption: a
	// pre-check here would be an unrate-limited "is this registered?"
	// oracle for any authenticated caller.
	moved, err := svc.VerifyEmail(ctx, changeTok)
	must(err)
	fmt.Printf("  VerifyEmail (unauthenticated) moved the account to %s\n", moved.Email)
	_, err = svc.Login(ctx, "alice@example.com", aliceResetPass, "203.0.113.9", "laptop")
	expect(errors.Is(err, auth.ErrInvalidCredentials), "the old address must no longer resolve")
	_, err = svc.Login(ctx, aliceNewAddress, aliceResetPass, "203.0.113.9", "laptop")
	must(err)
	fmt.Println("  old address -> ErrInvalidCredentials; new address -> logged in")

	// -- 7. An outstanding reset does not survive a ChangePassword -------
	//
	// The side door: an attacker requests a reset link for a victim's
	// address and waits. The victim notices something and changes their
	// password — the one thing a user does on suspecting compromise. If
	// that left the parked token armed, it would keep working for its whole
	// hour. ChangePassword, ResetPassword and LogoutAll each sweep every
	// outstanding password_reset AND email_change token for the account.
	step("an outstanding reset does not survive a ChangePassword")
	parked, ok, err := svc.RequestPasswordReset(ctx, aliceNewAddress, "198.51.100.66")
	must(err)
	expect(ok, "the attacker's request succeeds; that is the point")
	fmt.Println("  an attacker parks a reset token for alice's address")

	claims, err := svc.VerifyAccessToken(aliceLogin.AccessToken)
	must(err)
	must(svc.ChangePassword(ctx, alice.User.ID, claims.SessionID, aliceResetPass, aliceFinalPass))
	fmt.Println("  alice changes her password (the sid from her own access token spares her family)")

	err = svc.ResetPassword(ctx, parked, "Attacker-Owns-This-3!")
	expect(errors.Is(err, auth.ErrVerificationNotFound), "the parked token must be swept")
	fmt.Println("  the parked token -> ErrVerificationNotFound (swept by the change)")

	_, err = svc.Login(ctx, aliceNewAddress, aliceFinalPass, "203.0.113.9", "laptop")
	must(err)
	fmt.Println("  alice logs in with the password she chose")

	fmt.Println("\ndone")
}

// families counts the distinct session families a user currently has.
// ListSessions returns rotation HISTORY, not a device list, so anything
// device-shaped has to group by FamilyID — see the readme's "Rotation, reuse
// detection, and family revocation".
func families(ctx context.Context, svc *auth.Service, userID string) int {
	sessions, err := svc.ListSessions(ctx, userID)
	must(err)
	seen := map[string]bool{}
	for _, s := range sessions {
		seen[s.FamilyID] = true
	}
	return len(seen)
}

func step(label string) {
	fmt.Printf("\n== %s ==\n", strings.ToUpper(label))
}

// short truncates a token for display. Never do this to a value you are
// comparing — only to one you are printing.
func short(s string) string {
	if len(s) <= 12 {
		return s
	}
	return s[:12]
}

func expect(cond bool, what string) {
	if !cond {
		panic("authlayer/examples/reset: " + what)
	}
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
