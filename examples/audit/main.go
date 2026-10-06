// Command audit is a runnable, database-free tour of the audit package: a
// tamper-evident record of what people and machines do.
//
//	go run ./examples/audit
//
// It runs against store/memory and walks the whole lifecycle:
//
//   - the lifecycle hooks of auth and org feed the log through audithook,
//     with no change to either package's own code;
//   - your own actions are recorded in two phases, Begin before the action
//     and Complete after it, with code inside the action adding what it
//     learned (the resource, a before/after diff) through Annotate;
//   - a process that dies mid-action leaves an open event, which Reconcile
//     closes as "unknown" so the day can be sealed;
//   - Seal chains each UTC day into a hash, Verify recomputes it and says
//     "ok", then retention purges old events while the seals stay and
//     Verify says "purged" rather than raising a false alarm.
//
// # What is deliberately NOT here
//
// A transport, and tampering with the store: the memory store is a Go map,
// so there is nothing to guard. The PostgreSQL store (store/drops) refuses
// rewrites with SQLSTATE AU001-AU004, and docs/audit/integrity shows what
// Verify reports when a row is changed behind the library's back.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/bernardoforcillo/authlayer"
	"github.com/bernardoforcillo/authlayer/audit"
	"github.com/bernardoforcillo/authlayer/audit/audithook"
	"github.com/bernardoforcillo/authlayer/auth"
	"github.com/bernardoforcillo/authlayer/core"
	"github.com/bernardoforcillo/authlayer/org"
	"github.com/bernardoforcillo/authlayer/store/memory"
)

func main() {
	ctx := context.Background()

	// A movable clock, so the example can run through weeks in an instant.
	now := time.Date(2026, 3, 1, 9, 0, 0, 0, time.UTC)
	sh := authlayer.Shared{Runtime: core.Runtime{Clock: func() time.Time { return now }}}

	// -- 1. The audit Service -----------------------------------------------
	//
	// Topics are declared up front: a typo cannot open a topic nobody seals
	// or purges. "menus" is this application's own; the others are the
	// defaults audithook records under. "auth" keeps events 30 days, the
	// rest the default year.
	topics := append(audithook.Topics(), audit.Topic{Key: "menus"})
	for i := range topics {
		if topics[i].Key == audithook.TopicAuth {
			topics[i].Retention = 30 * 24 * time.Hour
		}
	}
	svc := audit.New(memory.NewAuditStore(), sh.Audit(), audit.WithTopics(topics...))

	// -- 2. Hooks feed it ---------------------------------------------------
	step("authlayer hooks become events")
	authSvc := auth.New(memory.NewAuthStore(), sh.Auth(),
		auth.WithJWT([][]byte{[]byte("32-bytes-or-more-from-your-vault")}, 15*time.Minute),
		auth.WithHooks(audithook.Auth(svc)))
	orgs := org.New(org.NewAccess(nil), memory.New[org.Organization, org.Member](), sh.Scope(),
		org.WithHooks(audithook.Scope(svc)))

	su, err := authSvc.SignUp(ctx, "alice@example.com", "Correct-Horse-Battery-9")
	must(err)
	_, err = authSvc.VerifyEmail(ctx, su.VerifyToken)
	must(err)
	_, _ = authSvc.Login(ctx, "alice@example.com", "not-her-password", "203.0.113.9", "demo")
	_, err = authSvc.Login(ctx, "alice@example.com", "Correct-Horse-Battery-9", "203.0.113.9", "demo")
	must(err)
	actx := org.WithSubject(ctx, su.User.ID)
	acme, err := orgs.CreateOrganization(actx, "Acme", "acme")
	must(err)
	_, err = orgs.AddMember(org.WithOrg(actx, acme.ID), "bob", org.RoleMember)
	must(err)
	dump(ctx, svc, map[string]string{su.User.ID: "alice", acme.ID: "acme"})

	// -- 3. Your own actions, in two phases ---------------------------------
	step("a two-phase action: Begin, Annotate, Complete")
	open, err := svc.Begin(ctx, audit.Event{
		Topic: "menus", Action: "menu.update", Origin: "backend",
		Actor:   audit.Actor{Type: audit.ActorUser, ID: su.User.ID},
		Request: json.RawMessage(`{"name":"Lunch","api_key":"sk-live-1234"}`), // redacted on the way in
	})
	must(err)
	fmt.Printf("  begun: %s (open: %v)\n", open.Action, open.CompletedAt == nil)

	// Inside the action, code that has no idea about auditing adds what it
	// knows. Without a Pending on the context this is a no-op.
	pending := audit.NewPending(open.ID)
	actionCtx := audit.WithPending(ctx, pending)
	audit.Annotate(actionCtx,
		audit.WithResource("menu", "m1"),
		audit.WithContainer(acme.ID),
		audit.WithChanges(json.RawMessage(`{"name":"Lunch","price":9}`), json.RawMessage(`{"name":"Lunch","price":12}`)))
	must(svc.Complete(ctx, open.ID, pending.Completion(audit.OutcomeOK, "", 12)))
	done, err := svc.Get(ctx, open.ID)
	must(err)
	fmt.Printf("  completed: outcome=%s resource=%s/%s\n  request: %s\n  changes: %s\n",
		done.Outcome, done.Resource.Type, done.Resource.ID, done.Request, done.Changes)

	// -- 4. A crash leaves an open event; Reconcile closes it ----------------
	step("a process dies mid-action")
	crashed, err := svc.Begin(ctx, audit.Event{
		Topic: "menus", Action: "menu.delete", Origin: "backend",
		Actor: audit.Actor{Type: audit.ActorUser, ID: su.User.ID},
	})
	must(err)
	now = now.Add(26 * time.Hour) // the next day; the process never came back
	others, err := svc.Seal(ctx, now)
	fmt.Printf("  Seal refused for the topic with an open event: %v (the other topics sealed %d days regardless)\n",
		errors.Is(err, audit.ErrOpenEvents), len(others))
	n, err := svc.Reconcile(ctx, time.Hour)
	must(err)
	closed, _ := svc.Get(ctx, crashed.ID)
	fmt.Printf("  Reconcile closed %d: outcome=%s reason=%s\n", n, closed.Outcome, closed.Reason)

	// -- 5. Seal, Verify ----------------------------------------------------
	step("seal the finished days and verify the chain")
	seals, err := svc.Seal(ctx, now)
	must(err)
	fmt.Printf("  sealed %d more (topic, day) pairs\n", len(seals))
	verify(ctx, svc, "menus", now.AddDate(0, 0, -2), now)

	// -- 6. Retention -------------------------------------------------------
	step("retention: auth keeps 30 days")
	now = now.AddDate(0, 0, 45)
	_, err = svc.Seal(ctx, now)
	must(err)
	deleted, err := svc.ApplyRetention(ctx)
	must(err)
	fmt.Printf("  deleted: auth=%d menus=%d scope=%d\n", deleted["auth"], deleted["menus"], deleted["scope"])
	verify(ctx, svc, "auth", time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC), time.Date(2026, 3, 2, 0, 0, 0, 0, time.UTC))
}

func dump(ctx context.Context, svc *audit.Service, names map[string]string) {
	name := func(id string) string {
		if n, ok := names[id]; ok {
			return n
		}
		return id
	}
	events, _, err := svc.List(ctx, audit.Filter{}, audit.Page{})
	must(err)
	for i := len(events) - 1; i >= 0; i-- { // oldest first
		e := events[i]
		fmt.Printf("  %-6s %-18s %-7s actor=%-6s resource=%s/%s reason=%s\n",
			e.Topic, e.Action, e.Outcome, name(e.Actor.ID), e.Resource.Type, name(e.Resource.ID), e.Reason)
	}
}

func verify(ctx context.Context, svc *audit.Service, topic string, from, to time.Time) {
	statuses, err := svc.Verify(ctx, []string{topic}, from, to)
	must(err)
	for _, s := range statuses {
		fmt.Printf("  verify %s %s: %s %s\n", s.Topic, s.Day.Format(time.DateOnly), s.State, s.Detail)
	}
}

func step(s string) { fmt.Printf("\n== %s\n", s) }

func must(err error) {
	if err != nil {
		panic(err)
	}
}
