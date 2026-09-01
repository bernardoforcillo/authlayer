// Command deletion is a runnable, database-free tour of the two account
// removal postures: DeleteAccount (hard) and AnonymizeAccount (soft), and
// the cascade hook that is the boundary between what authlayer owns and
// what your application owns.
//
//	go run ./examples/deletion
//
// Deletion is the one flow where getting the ORDER wrong is worse than not
// shipping it, so this program demonstrates each ordering rule rather than
// describing it:
//
//   - the hook fires FIRST, before any authlayer row is removed, and it
//     reports what it would clean up;
//   - a hook error ABORTS the deletion, with the account fully intact —
//     fail closed, because a half-deleted account is worse than an
//     undeleted one;
//   - a wrong current password refuses and removes nothing;
//   - hard deletion removes every session, every verification, every
//     linked external identity, and the user row — in that order, so a
//     failure part-way leaves an account that cannot be USED rather than
//     one whose data is gone and whose sessions live;
//   - anonymization leaves a stamped row that Login refuses, while the
//     original address becomes free for a new sign-up.
//
// Everything runs against store/memory, so there is no database and no setup.
//
// # What is deliberately NOT here
//
// A transport, and any confirmation UI. Both methods act on the caller's
// authority: the application must already have authenticated the user whose
// id it passes. Here we are the operator, not the internet.
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
	erinPassword  = "Correct-Horse-Battery-9!"
	frankPassword = "Correct-Horse-Battery-8!"
	erinAddress   = "erin@example.com"
	frankAddress  = "frank@example.com"
)

// errHookRefused is what the application's own cleanup returns when it could not
// finish. Returning it is what makes the whole deletion abort.
var errHookRefused = errors.New("the billing service could not be reached")

func main() {
	ctx := context.Background()

	// -- 1. Wire the service, with a hook --------------------------------
	//
	// WithAccountDeletionHook is the boundary. authlayer removes what it
	// owns — users, sessions, verifications, and (with an IdentityStore
	// wired) identities. Everything else is yours, and the hook is where it
	// goes: your own tables, and critically the `scope` memberships
	// authlayer cannot reach from here.
	//
	// It fires BEFORE any authlayer row is removed, and an error from it
	// aborts. Both properties are load-bearing: a hook that ran afterwards
	// could not refuse, and a hook whose error was swallowed would leave an
	// account deleted here and alive in your billing system.
	step("wire")
	var hookLog []string
	failHook := false
	ids := memory.NewIdentityStore()
	svc := auth.New(memory.NewAuthStore(),
		auth.WithJWT([][]byte{[]byte("32-bytes-or-more-from-your-vault")}, 15*time.Minute),
		auth.WithIdentityStore(ids),
		auth.WithAccountDeletionHook(func(_ context.Context, userID string) error {
			if failHook {
				hookLog = append(hookLog, "hook REFUSED for "+short(userID))
				return errHookRefused
			}
			hookLog = append(hookLog, "hook cleaned up rows for "+short(userID))
			return nil
		}))
	fmt.Println("  auth.Service over store/memory, with an identity store and a deletion hook")

	// -- 2. Two accounts, fully furnished --------------------------------
	//
	// Each gets two session families and two outstanding verifications, so
	// the sweeps below have something to sweep and a sweep that covered
	// only the newest row would be visible.
	step("two accounts")
	erin := furnish(ctx, svc, erinAddress, erinPassword)
	frank := furnish(ctx, svc, frankAddress, frankPassword)
	fmt.Printf("  erin   id=%s  %d session families, reset+change pending, %d linked identity\n",
		short(erin.id), families(ctx, svc, erin.id), linked(ctx, svc, erin.id))
	fmt.Printf("  frank  id=%s  %d session families, reset+change pending, %d linked identity\n",
		short(frank.id), families(ctx, svc, frank.id), linked(ctx, svc, frank.id))

	// -- 3. A wrong password refuses -------------------------------------
	//
	// Re-authentication is required when the account HAS a password. An
	// account with none — OAuth-only, magic-link-only — cannot supply one
	// and proceeds on the caller's authority, because there is nothing to
	// check. Say that plainly rather than implying every deletion is
	// re-authenticated.
	//
	// The hook does not fire on a failed re-authentication: the check comes
	// first, so a wrong password does not send your application off
	// deleting rows.
	step("a wrong password refuses")
	before := len(hookLog)
	err := svc.DeleteAccount(ctx, erin.id, "not-her-password")
	expect(errors.Is(err, auth.ErrInvalidCredentials), "a wrong password must refuse")
	expect(len(hookLog) == before, "the hook must not fire on a failed re-authentication")
	fmt.Println("  wrong current password -> ErrInvalidCredentials, and the hook never ran")
	assertIntact(ctx, svc, &erin, 2, "a refused deletion must change nothing")
	fmt.Println("  erin's sessions, tokens and password all still work")

	// -- 4. A hook error aborts, with the account intact -----------------
	//
	// FAIL CLOSED. The application said it could not finish its own
	// cleanup, so authlayer does not proceed to remove its half. The
	// account is exactly as it was, and the caller gets the hook's own
	// error back to act on.
	step("a hook error aborts")
	failHook = true
	err = svc.DeleteAccount(ctx, erin.id, erinPassword)
	expect(errors.Is(err, errHookRefused), "the hook's own error must reach the caller")
	fmt.Printf("  DeleteAccount -> %v\n", err)
	assertIntact(ctx, svc, &erin, 2, "an aborted deletion must leave the account whole")
	fmt.Println("  erin's sessions, tokens and password all still work")
	failHook = false

	// -- 5. Hard deletion ------------------------------------------------
	//
	// The order is fail-safe and is not negotiable: hook, then SESSIONS (so
	// access stops immediately), then verifications, then identities, then
	// the user row LAST. A failure part-way leaves an account that cannot
	// be logged into and cannot be refreshed into, and that is still there
	// to retry the whole call against.
	//
	// It is not atomic, and cannot be: Store exposes no transaction, the
	// identities live behind a different port that may be a different
	// backend, and the hook reaches tables authlayer has no connection to
	// at all. What the ORDER buys is that every partial state falls on the
	// safe side.
	step("hard deletion")
	must(svc.DeleteAccount(ctx, erin.id, erinPassword))
	fmt.Printf("  %s\n", hookLog[len(hookLog)-1])

	_, err = svc.Login(ctx, erinAddress, erinPassword, "203.0.113.9", "laptop")
	expect(errors.Is(err, auth.ErrInvalidCredentials), "the row is gone; the address resolves to nothing")
	_, err = svc.Refresh(ctx, erin.refresh)
	expect(err != nil, "a pre-deletion refresh token must be dead")
	err = svc.ResetPassword(ctx, erin.resetToken, "Anything-At-All-1!")
	expect(errors.Is(err, auth.ErrVerificationNotFound), "a pending reset token must not outlive the account")
	expect(linked(ctx, svc, erin.id) == 0, "a linked identity must not outlive the account")
	fmt.Println("  Login -> ErrInvalidCredentials; the refresh token is dead; the reset token is gone")
	fmt.Println("  the google identity went too: a row outliving its user is a credential")
	fmt.Println("  pointing at an id that no longer resolves, which a later account could inherit")

	// The address is free immediately. That is the whole point of the hard
	// posture, and the reason to think about whether anything OUTSIDE
	// authlayer still holds the old user id.
	fresh, err := svc.SignUp(ctx, erinAddress, "Somebody-Else-Entirely-1!")
	must(err)
	expect(fresh.User.ID != erin.id, "a new sign-up gets a new id")
	fmt.Printf("  %s signed up again -> a NEW id (%s), not the old one\n", erinAddress, short(fresh.User.ID))

	// -- 6. Anonymization ------------------------------------------------
	//
	// The SOFT posture. Same re-authentication rule, same hook, same
	// fail-safe order — it differs in one step and one consequence. The
	// step: the row is KEPT and scrubbed rather than removed. The
	// consequence: a stamped row is one every authentication entry point
	// has to refuse, which is the part of this feature that must not be got
	// wrong.
	//
	// Choose it over DeleteAccount on one question: does anything outside
	// authlayer still hold the user id? An audit trail, an order history, a
	// foreign key. If so, removing the row leaves those pointing at
	// nothing.
	step("anonymization")
	must(svc.AnonymizeAccount(ctx, frank.id, frankPassword))
	fmt.Printf("  %s\n", hookLog[len(hookLog)-1])

	stamped, err := svc.User(ctx, frank.id)
	must(err)
	expect(stamped.DeletedAt != nil, "the row must be stamped")
	expect(stamped.Email != frankAddress, "the address must be scrubbed")
	expect(stamped.EmailVerifiedAt == nil, "the verification stamp must be cleared")
	fmt.Printf("  the row is still readable by id: email=%q  DeletedAt=%s\n",
		stamped.Email, stamped.DeletedAt.Format(time.RFC3339))
	fmt.Println("  the scrubbed address is derived from the user's own id, so two of them never collide")

	// Every entry point refuses it. This is a sample, not the whole list —
	// Login, Refresh, ChangePassword, RequestEmailChange, ResetPassword,
	// VerifyEmail, RequestPasswordReset, RequestMagicLink, RedeemMagicLink,
	// SignInWith and LinkIdentity all refuse a stamped account.
	_, err = svc.Login(ctx, frankAddress, frankPassword, "203.0.113.9", "laptop")
	expect(errors.Is(err, auth.ErrInvalidCredentials), "Login must refuse")
	_, err = svc.Refresh(ctx, frank.refresh)
	expect(err != nil, "Refresh must refuse")
	err = svc.ChangePassword(ctx, frank.id, "", frankPassword, "New-Password-Entirely-1!")
	expect(errors.Is(err, auth.ErrUserNotFound), "ChangePassword must refuse")
	fmt.Println("  Login, Refresh and ChangePassword all refuse the stamped row")

	// The identity sweep matters MORE on the soft path, not less. The scrub
	// clears the password, so an identity left standing would be the ONLY
	// credential the account still had — a stamped row reachable through an
	// external provider and through nothing else, which is the opposite of
	// what anonymizing means. LinkIdentity refuses a stamped row too, so it
	// cannot acquire a replacement afterwards.
	expect(linked(ctx, svc, frank.id) == 0, "anonymization must sweep identities")
	fmt.Println("  the google identity is gone — the credential the scrub itself does not touch")

	// The two enumeration-safe methods keep their indistinguishable
	// ("", false, nil). Ask against the SCRUBBED address, because that is
	// the one that still reaches the stamped row — the original resolves to
	// nothing at all now, and would answer the same way for the ordinary
	// unknown-address reason. A new error on either would tell an anonymous
	// caller that a particular address had been anonymized, which is the
	// oracle their whole shape exists to close.
	tok, ok, err := svc.RequestPasswordReset(ctx, stamped.Email, "203.0.113.9")
	must(err)
	expect(!ok && tok == "", "RequestPasswordReset must stay indistinguishable")
	tok, ok, err = svc.RequestMagicLink(ctx, stamped.Email, "203.0.113.9")
	must(err)
	expect(!ok && tok == "", "RequestMagicLink must stay indistinguishable")
	fmt.Println("  against the scrubbed address, both stay (\"\", false, nil) — never a new error")

	// The original address is free, exactly as after a hard deletion.
	reborn, err := svc.SignUp(ctx, frankAddress, "Somebody-Else-Entirely-2!")
	must(err)
	expect(reborn.User.ID != frank.id, "a new sign-up gets a new id")
	fmt.Printf("  %s signed up again -> a NEW id (%s); the old row is still there, scrubbed\n",
		frankAddress, short(reborn.User.ID))

	// -- 7. What neither posture revokes ---------------------------------
	//
	// An access token ALREADY ISSUED. It is a stateless, signed JWT: this
	// package never looks a presented one up in the Store, only verifies
	// its signature and expiry. A device holding one keeps working for the
	// remainder of its own TTL — fifteen minutes by default — after either
	// method returns. Closing that gap needs a per-request lookup of the
	// SessionID ("sid") claim against the Store, which an application can
	// do and this package does not do for it.
	step("what neither posture revokes")
	claims, err := svc.VerifyAccessToken(frank.access)
	must(err)
	fmt.Printf("  frank's pre-anonymization access token still parses: sub=%s sid=%s\n",
		short(claims.Subject), short(claims.SessionID))
	fmt.Println("  it is bounded by WithJWT's TTL; check the sid claim per request to close it sooner")

	fmt.Println("\ndone")
}

// account is one furnished account and the credentials this program then
// tries to use after it has been removed.
type account struct {
	id         string
	access     string
	refresh    string
	resetToken string
}

// furnish registers an account and gives it everything authlayer can hold
// for one: two session families and two outstanding verifications.
func furnish(ctx context.Context, svc *auth.Service, email, plain string) account {
	res, err := svc.SignUp(ctx, email, plain)
	must(err)
	_, err = svc.VerifyEmail(ctx, res.VerifyToken)
	must(err)

	first, err := svc.Login(ctx, email, plain, "203.0.113.9", "laptop")
	must(err)
	_, err = svc.Login(ctx, email, plain, "203.0.113.9", "phone")
	must(err)

	resetToken, ok, err := svc.RequestPasswordReset(ctx, email, "203.0.113.9")
	must(err)
	expect(ok, "a registered address must mint a reset token")
	_, err = svc.RequestEmailChange(ctx, res.User.ID, plain, "moved-"+email)
	must(err)

	// A linked social account is a way IN that needs no password at all, so
	// it is one of the things both postures have to remove.
	_, err = svc.LinkIdentity(ctx, res.User.ID, auth.ExternalIdentity{
		Provider:      "google",
		Subject:       "google-subject-for-" + email,
		Email:         email,
		EmailVerified: true,
	})
	must(err)

	return account{
		id:         res.User.ID,
		access:     first.AccessToken,
		refresh:    first.RefreshToken,
		resetToken: resetToken,
	}
}

// assertIntact is the "nothing was removed" check the two refusal steps
// share. It is deliberately READ-ONLY: redeeming the pending reset token
// here to prove it survived would consume the very thing the next step
// needs, so the token's survival is proved once, at the end, by the fact
// that the hard deletion is what finally destroys it.
func assertIntact(ctx context.Context, svc *auth.Service, a *account, wantFamilies int, why string) {
	if _, err := svc.User(ctx, a.id); err != nil {
		panic("authlayer/examples/deletion: " + why + " (the user row is gone)")
	}
	if n := families(ctx, svc, a.id); n != wantFamilies {
		panic("authlayer/examples/deletion: " + why + " (session families were revoked)")
	}
	// Refresh ROTATES, so the new token has to replace the old one here:
	// presenting a superseded token again is what this package reads as a
	// stolen refresh token, and it revokes the whole family.
	rotated, err := svc.Refresh(ctx, a.refresh)
	if err != nil {
		panic("authlayer/examples/deletion: " + why + " (the refresh token no longer rotates)")
	}
	a.refresh, a.access = rotated.RefreshToken, rotated.AccessToken
}

// linked counts the external identities attached to a user.
func linked(ctx context.Context, svc *auth.Service, userID string) int {
	rows, err := svc.ListIdentities(ctx, userID)
	must(err)
	return len(rows)
}

// families counts the distinct session families a user currently has.
// ListSessions returns rotation HISTORY, not a device list, so anything
// device-shaped has to group by FamilyID.
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
		panic("authlayer/examples/deletion: " + what)
	}
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
