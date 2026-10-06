// Command privacy is a runnable, database-free tour of the data-protection
// features: what a person can ask of the data you hold, and the call that
// answers it.
//
//	go run ./examples/privacy
//
// It walks one person through the lifecycle the GDPR describes:
//
//   - consent (Art. 7): she accepts the terms, then a newer version;
//   - minimization (Art. 5(1)(c)): the audit log keeps a truncated IP and a
//     pseudonym instead of her id;
//   - access and portability (Arts. 15 and 20): one JSON bundle of everything
//     held about her, with no credential in it and nobody else's identity;
//   - erasure (Art. 17): deleting the account also erases her from the audit
//     log (by destroying her pseudonym key) and removes her consent records,
//     while the log itself stays sealed and verifiable.
//
// Everything runs against store/memory.
//
// # What is deliberately NOT here
//
// Your own tables, your backups, your vendors, and the legal side — the lawful
// basis, the notice, the processor agreements, the breach procedure. See
// docs/privacy/data-protection for the full split.
package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/bernardoforcillo/authlayer"
	"github.com/bernardoforcillo/authlayer/audit"
	"github.com/bernardoforcillo/authlayer/audit/audithook"
	"github.com/bernardoforcillo/authlayer/auth"
	"github.com/bernardoforcillo/authlayer/consent"
	"github.com/bernardoforcillo/authlayer/core"
	"github.com/bernardoforcillo/authlayer/org"
	"github.com/bernardoforcillo/authlayer/privacy"
	"github.com/bernardoforcillo/authlayer/store/memory"
)

const pw = "Correct-Horse-Battery-9!"

func main() {
	ctx := context.Background()
	now := time.Date(2026, 3, 1, 9, 0, 0, 0, time.UTC)
	sh := authlayer.Shared{Runtime: core.Runtime{Clock: func() time.Time { return now }}}

	// -- 1. Wiring ----------------------------------------------------------
	//
	// The audit log pseudonymizes people (WithSubjectKeys), truncates IPs
	// (WithIPMode) and clears IP and user agent after a week
	// (ClientDataRetention) while keeping the event for a year.
	keys := memory.NewAuditKeyStore()
	topics := audithook.Topics()
	for i := range topics {
		topics[i].ClientDataRetention = 7 * 24 * time.Hour
	}
	auditSvc := audit.New(memory.NewAuditStore(), sh.Audit(),
		audit.WithSubjectKeys(keys), audit.WithIPMode(audit.IPTruncate), audit.WithTopics(topics...))
	consentSvc := consent.New(memory.NewConsentStore(), consent.WithRuntime(sh.Runtime))
	orgs := org.New(org.NewAccess(nil), memory.New[org.Organization, org.Member](), sh.Scope(),
		org.WithHooks(audithook.Scope(auditSvc)))
	authSvc := auth.New(memory.NewAuthStore(), sh.Auth(),
		auth.WithJWT([][]byte{[]byte("32-bytes-or-more-from-your-vault")}, 15*time.Minute),
		auth.WithMFAStore(memory.NewMFAStore()),
		auth.WithHooks(audithook.Auth(auditSvc)),
		auth.WithSweeper(authlayer.RemoveUserSweeper(orgs)),
		// Deleting the account also erases the audit identity and consent.
		auth.WithSweeper(privacy.ErasureSweeper(privacy.AuditForget(auditSvc), privacy.ConsentErase(consentSvc))))

	// -- 2. A person signs up, consents, uses the product -------------------
	step("sign up and consent")
	su, err := authSvc.SignUp(ctx, "alice@example.com", pw)
	must(err)
	_, err = authSvc.VerifyEmail(ctx, su.VerifyToken)
	must(err)
	uid := su.User.ID
	_, err = consentSvc.Grant(ctx, uid, "terms", "2026-01", "signup_form")
	must(err)
	_, err = authSvc.Login(ctx, "alice@example.com", pw, "203.0.113.77", "Mozilla/5.0")
	must(err)
	now = now.Add(time.Hour)
	_, err = consentSvc.Grant(ctx, uid, "terms", "2026-03", "banner") // a newer version supersedes
	must(err)
	_, err = consentSvc.Grant(ctx, uid, "marketing_email", "2026-01", "settings")
	must(err)
	must(consentSvc.Withdraw(ctx, uid, "marketing_email")) // as easy to withdraw as to give
	ok, _ := consentSvc.Accepted(ctx, uid, "terms", "2026-03")
	fmt.Printf("  accepted terms 2026-03: %v\n", ok)
	actx := org.WithSubject(ctx, uid)
	acme, err := orgs.CreateOrganization(actx, "Acme", "acme")
	must(err)
	_, err = orgs.AddMember(org.WithOrg(actx, acme.ID), "bob", org.RoleMember)
	must(err)

	// -- 3. What the log really holds ---------------------------------------
	step("what is stored in the audit log")
	stored, _, err := auditSvc.List(ctx, audit.Filter{ActorID: uid, ActionPrefix: "auth.logged_in"}, audit.Page{Limit: 1})
	must(err)
	e := stored[0]
	fmt.Printf("  actor=%.8s… (a pseudonym, not %q) ip=%q display=%q\n", e.Actor.ID, uid[:8], e.IP, e.Actor.Display)

	// -- 4. Access and portability ------------------------------------------
	step("access request: one JSON bundle")
	ex := privacy.Exporter{Runtime: sh.Runtime, Sources: []privacy.Source{
		privacy.Account(authSvc), privacy.Memberships(orgs), privacy.Consents(consentSvc), privacy.AuditTrail(auditSvc, 1000),
	}}
	bundle, err := ex.Export(ctx, uid)
	must(err)
	fmt.Printf("  sections: %v\n", bundle.SectionNames())
	fmt.Println("  --- bundle (excerpt written to stdout below) ---")
	must(bundle.WriteJSON(os.Stdout))

	// -- 5. Retention of client data ----------------------------------------
	step("a week later: IP and user agent are cleared, the event stays")
	now = now.AddDate(0, 0, 8)
	cleared, err := auditSvc.ScrubClientData(ctx)
	must(err)
	fmt.Printf("  cleared client data on events: %v\n", cleared)

	// -- 6. Erasure -----------------------------------------------------------
	step("erasure request: delete the account")
	_, err = auditSvc.Seal(ctx, now) // the days so far are sealed
	must(err)
	// She owns Acme; the default policy refuses to orphan it, so she hands it
	// to Bob first.
	must(orgs.TransferOwnership(org.WithOrg(actx, acme.ID), "bob"))
	must(authSvc.DeleteAccount(ctx, uid, "", pw))
	trail, _, _ := auditSvc.List(ctx, audit.Filter{Member: uid}, audit.Page{})
	hist, _ := consentSvc.History(ctx, uid)
	fmt.Printf("  trail reachable by her id: %d events; consent records left: %d\n", len(trail), len(hist))
	total, _ := auditSvc.Count(ctx, audit.Filter{})
	statuses, err := auditSvc.Verify(ctx, []string{audithook.TopicAuth}, time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC), time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC))
	must(err)
	fmt.Printf("  events kept in the log: %d; verify %s %s: %s\n", total, statuses[0].Topic, statuses[0].Day.Format(time.DateOnly), statuses[0].State)
}

func step(s string) { fmt.Printf("\n== %s\n", s) }

func must(err error) {
	if err != nil {
		panic(err)
	}
}
