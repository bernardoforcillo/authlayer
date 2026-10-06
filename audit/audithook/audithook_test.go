package audithook_test

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/bernardoforcillo/authlayer/apikey"
	"github.com/bernardoforcillo/authlayer/audit"
	"github.com/bernardoforcillo/authlayer/audit/audithook"
	"github.com/bernardoforcillo/authlayer/auth"
	"github.com/bernardoforcillo/authlayer/oauth"
	"github.com/bernardoforcillo/authlayer/org"
	"github.com/bernardoforcillo/authlayer/scope"
	"github.com/bernardoforcillo/authlayer/store/memory"
)

const pw = "Correct-Horse-Battery-9!"

func newAudit(t *testing.T) *audit.Service {
	t.Helper()
	return audit.New(memory.NewAuditStore(), audit.WithTopics(audithook.Topics()...))
}

func all(t *testing.T, svc *audit.Service) []audit.Event {
	t.Helper()
	evs, _, err := svc.List(context.Background(), audit.Filter{}, audit.Page{})
	if err != nil {
		t.Fatal(err)
	}
	return evs
}

func TestTopicsAreTheSpecDefaults(t *testing.T) {
	var keys []string
	for _, tp := range audithook.Topics() {
		keys = append(keys, tp.Key)
	}
	if got := strings.Join(keys, ","); got != "access,auth,apikey,oauth" {
		t.Errorf("Topics = %s, want access,auth,apikey,oauth", got)
	}
}

func TestAuthHookRecordsRealLoginFlow(t *testing.T) {
	ctx := context.Background()
	svc := newAudit(t)
	a := auth.New(memory.NewAuthStore(),
		auth.WithJWT([][]byte{[]byte("0123456789abcdef0123456789abcdef")}, 15*time.Minute),
		auth.WithHooks(audithook.Auth(svc)))
	su, err := a.SignUp(ctx, "alice@example.com", pw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.VerifyEmail(ctx, su.VerifyToken); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Login(ctx, "alice@example.com", "wrong", "203.0.113.9", "ua"); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("Login = %v", err)
	}
	if _, err := a.Login(ctx, "nobody@example.com", pw, "203.0.113.9", "ua"); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("Login = %v", err)
	}
	if _, err := a.Login(ctx, "alice@example.com", pw, "203.0.113.9", "ua"); err != nil {
		t.Fatal(err)
	}
	evs := all(t, svc) // newest first
	got := map[string]int{}
	for _, e := range evs {
		got[e.Action+":"+string(e.Outcome)]++
		if e.Topic != audithook.TopicAuth || e.Origin != audithook.DefaultOrigin || e.CompletedAt == nil {
			t.Errorf("event %+v: wrong topic/origin/completion", e)
		}
	}
	for _, want := range []string{"auth.signed_up:ok", "auth.email_verified:ok", "auth.login_failed:denied", "auth.logged_in:ok"} {
		if got[want] == 0 {
			t.Errorf("no %s event in %v", want, got)
		}
	}
	if got["auth.login_failed:denied"] != 2 {
		t.Errorf("denied logins = %d, want 2", got["auth.login_failed:denied"])
	}
	var unknown, wrong, ok *audit.Event
	for i := range evs {
		e := &evs[i]
		switch {
		case e.Action == "auth.login_failed" && e.Reason == auth.DetailUnknownUser:
			unknown = e
		case e.Action == "auth.login_failed" && e.Reason == auth.DetailWrongPassword:
			wrong = e
		case e.Action == "auth.logged_in":
			ok = e
		}
	}
	if unknown == nil || unknown.Actor != (audit.Actor{Type: audit.ActorAnonymous}) || unknown.Resource != (audit.Resource{}) || unknown.IP != "203.0.113.9" {
		t.Errorf("unknown-user login = %+v", unknown)
	}
	// The caller of a failed sign-in is not the account it targeted: the
	// account is the resource, the actor is anonymous.
	if wrong == nil || wrong.Actor != (audit.Actor{Type: audit.ActorAnonymous}) ||
		wrong.Resource != (audit.Resource{Type: audit.ResourceUser, ID: su.User.ID}) {
		t.Errorf("wrong-password login = %+v", wrong)
	}
	if ok == nil || ok.Actor.Type != audit.ActorUser || ok.Actor.ID != su.User.ID || ok.SessionID == "" ||
		ok.Resource != (audit.Resource{Type: "session", ID: ok.SessionID}) || ok.Reason != auth.DetailPassword {
		t.Errorf("login = %+v", ok)
	}
	if mine, _, _ := svc.List(ctx, audit.Filter{Member: su.User.ID}, audit.Page{}); len(mine) != 4 {
		t.Errorf("alice's trail has %d events, want 4 (sign-up, verification, the failed and the good login)", len(mine))
	}
}

func TestAuthRefusalsAndChallengesAreAnonymous(t *testing.T) {
	ctx := context.Background()
	svc := newAudit(t)
	h := audithook.Auth(svc)
	for _, ev := range []auth.Event{
		{Kind: auth.TokenReuseDetected, UserID: "u1", SessionID: "s1", Detail: auth.DetailReuse},
		{Kind: auth.MFAChallenged, UserID: "u1"},
	} {
		if err := h.On(ctx, ev); err != nil {
			t.Fatal(err)
		}
	}
	for _, e := range all(t, svc) {
		if e.Actor != (audit.Actor{Type: audit.ActorAnonymous}) || e.Resource != (audit.Resource{Type: audit.ResourceUser, ID: "u1"}) {
			t.Errorf("%s = actor %+v resource %+v, want anonymous about user u1", e.Action, e.Actor, e.Resource)
		}
		if e.Action == "auth.token_reuse_detected" && e.Outcome != audit.OutcomeDenied {
			t.Errorf("token reuse outcome = %s, want denied", e.Outcome)
		}
	}
}

func TestScopeHookThroughOrg(t *testing.T) {
	ctx := org.WithSubject(context.Background(), "alice")
	svc := newAudit(t)
	o := org.New(org.NewAccess(nil), memory.New[org.Organization, org.Member](), org.WithHooks(audithook.Scope(svc)))
	acme, err := o.CreateOrganization(ctx, "Acme", "acme")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := o.AddMember(org.WithOrg(ctx, acme.ID), "bob", org.RoleMember); err != nil {
		t.Fatal(err)
	}
	evs := all(t, svc)
	if len(evs) < 2 {
		t.Fatalf("events = %+v", evs)
	}
	add, create := evs[0], evs[len(evs)-1]
	if add.Action != "scope.member_added" || add.Resource != (audit.Resource{Type: audit.ResourceUser, ID: "bob"}) ||
		add.ContainerID != acme.ID || add.Actor.ID != "alice" || add.Topic != audithook.TopicAccess ||
		!audit.EqualJSON(add.Changes, json.RawMessage(`{"role_key":{"before":null,"after":"member"}}`)) {
		t.Errorf("member added = %+v (changes %s)", add, add.Changes)
	}
	if create.Action != "scope.container_created" || create.Resource.Type != "container" {
		t.Errorf("container created = %+v", create)
	}
	if bob, _, _ := svc.List(context.Background(), audit.Filter{Member: "bob"}, audit.Page{}); len(bob) != 1 {
		t.Errorf("bob's trail = %d events, want 1", len(bob))
	}
}

// With an event pending on the context, the adapter adds to it instead of
// recording a second, standalone event.
func TestHooksAnnotateTheEventInFlightInsteadOfRecording(t *testing.T) {
	ctx := org.WithSubject(context.Background(), "alice")
	svc := newAudit(t)
	o := org.New(org.NewAccess(nil), memory.New[org.Organization, org.Member](), org.WithHooks(audithook.Scope(svc)))
	acme, err := o.CreateOrganization(ctx, "Acme", "acme")
	if err != nil {
		t.Fatal(err)
	}
	before := len(all(t, svc))

	open, err := svc.Begin(ctx, audit.Event{Topic: audithook.TopicAccess, Action: "members.add", Origin: "backend",
		Actor: audit.Actor{Type: audit.ActorUser, ID: "alice"}})
	if err != nil {
		t.Fatal(err)
	}
	pending := audit.NewPending(open.ID)
	if _, err := o.AddMember(org.WithOrg(audit.WithPending(ctx, pending), acme.ID), "bob", org.RoleMember); err != nil {
		t.Fatal(err)
	}
	if err := svc.Complete(ctx, open.ID, pending.Completion(audit.OutcomeOK, "", 3)); err != nil {
		t.Fatal(err)
	}
	if n := len(all(t, svc)); n != before+1 {
		t.Fatalf("events = %d, want %d: the hook recorded a standalone event besides the pending one", n, before+1)
	}
	got, err := svc.Get(ctx, open.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Resource != (audit.Resource{Type: audit.ResourceUser, ID: "bob"}) || got.ContainerID != acme.ID ||
		!audit.EqualJSON(got.Changes, json.RawMessage(`{"role_key":{"before":null,"after":"member"}}`)) {
		t.Errorf("annotated event = %+v (changes %s)", got, got.Changes)
	}
}

// An operation that fires several hooks under one pending event keeps every
// one of them: the first membership event of the call annotates the pending
// event, every further one is recorded on its own, and the succession that
// RemoveUser performs as a side effect never claims the pending event, so
// its resource stays the removed user.
func TestEveryHookOfAMultiEventCallIsKept(t *testing.T) {
	for _, anonymize := range []bool{false, true} {
		svc := newAudit(t)
		o := org.New(org.NewAccess(nil), memory.New[org.Organization, org.Member](),
			org.WithHooks(audithook.Scope(svc)), scope.WithOrphanPolicy(scope.SuccessorFirstMember))
		alice := org.WithSubject(context.Background(), "alice")
		carol := org.WithSubject(context.Background(), "carol")
		a1, err := o.CreateOrganization(alice, "A1", "a1")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := o.AddMember(org.WithOrg(alice, a1.ID), "bob", org.RoleMember); err != nil {
			t.Fatal(err)
		}
		var others []string
		for _, slug := range []string{"c1", "d1"} {
			c, err := o.CreateOrganization(carol, strings.ToUpper(slug), slug)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := o.AddMember(org.WithOrg(carol, c.ID), "alice", org.RoleMember); err != nil {
				t.Fatal(err)
			}
			others = append(others, c.ID)
		}
		before := len(all(t, svc))

		ctx := context.Background()
		open, err := svc.Begin(ctx, audit.Event{Topic: audithook.TopicAccess, Action: "users.delete", Origin: "backend",
			Actor: audit.Actor{Type: audit.ActorUser, ID: "admin"}})
		if err != nil {
			t.Fatal(err)
		}
		p := audit.NewPending(open.ID)
		remove := o.RemoveUser
		if anonymize {
			remove = o.RemoveUserAnonymized
		}
		if err := remove(audit.WithPending(ctx, p), "alice"); err != nil {
			t.Fatal(err)
		}
		if err := svc.Complete(ctx, open.ID, p.Completion(audit.OutcomeOK, "", 1)); err != nil {
			t.Fatal(err)
		}

		evs := all(t, svc)
		fresh := evs[:len(evs)-before] // newest first
		if len(fresh) != 4 {
			t.Fatalf("anonymize=%v: %d new events, want 4 (the pending one, the transfer, two removals): %+v", anonymize, len(fresh), fresh)
		}
		got, err := svc.Get(ctx, open.ID)
		if err != nil {
			t.Fatal(err)
		}
		// RemoveUser walks alice's containers in no fixed order: the first
		// removal annotates the pending event, the other two are standalone.
		if got.Resource != (audit.Resource{Type: audit.ResourceUser, ID: "alice"}) ||
			!slices.Contains(append([]string{a1.ID}, others...), got.ContainerID) {
			t.Errorf("anonymize=%v: pending event = resource %+v container %s, want user/alice in one of her containers",
				anonymize, got.Resource, got.ContainerID)
		}
		removed := map[string]bool{got.ContainerID: true}
		transferred := false
		for _, e := range fresh {
			if e.ID == open.ID {
				continue
			}
			if e.Origin != audithook.DefaultOrigin || e.Topic != audithook.TopicAccess || e.Outcome != audit.OutcomeOK {
				t.Errorf("standalone %s = %+v", e.Action, e)
			}
			switch e.Action {
			case "scope.ownership_transferred":
				transferred = e.ContainerID == a1.ID && e.Resource == (audit.Resource{Type: audit.ResourceUser, ID: "bob"})
			case "scope.member_removed":
				if e.Resource != (audit.Resource{Type: audit.ResourceUser, ID: "alice"}) || removed[e.ContainerID] {
					t.Errorf("anonymize=%v: removal = %+v", anonymize, e)
				}
				removed[e.ContainerID] = true
				if anonymize && !audit.EqualJSON(e.Request, json.RawMessage(`{"anonymized":true}`)) {
					t.Errorf("removal from %s request = %s, want the anonymized flag", e.ContainerID, e.Request)
				}
			default:
				t.Errorf("unexpected event %s", e.Action)
			}
		}
		if !transferred {
			t.Errorf("anonymize=%v: no standalone transfer of A1 to bob in %+v", anonymize, fresh)
		}
		for _, c := range append([]string{a1.ID}, others...) {
			if !removed[c] {
				t.Errorf("anonymize=%v: alice's removal from %s is not in the log", anonymize, c)
			}
		}
		trail, _, err := svc.List(ctx, audit.Filter{Member: "alice"}, audit.Page{})
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for _, e := range trail {
			if e.ID == open.ID || e.Action == "scope.member_removed" {
				n++
			}
		}
		if n != 3 {
			t.Errorf("anonymize=%v: alice's trail holds %d of the deletion and her two other removals, want 3", anonymize, n)
		}
	}
}

// A failed audit write aborts the authlayer operation it observes; for
// CreateOrganization, whose hooks run inside its transaction, that is a
// rollback.
func TestHookErrorAbortsCreateOrganization(t *testing.T) {
	ctx := org.WithSubject(context.Background(), "alice")
	noAccess := audit.New(memory.NewAuditStore(), audit.WithTopics(audit.Topic{Key: audithook.TopicAuth}))
	store := memory.New[org.Organization, org.Member]()
	o := org.New(org.NewAccess(nil), store, org.WithHooks(audithook.Scope(noAccess)))
	if _, err := o.CreateOrganization(ctx, "Acme", "acme"); !errors.Is(err, audit.ErrUnknownTopic) {
		t.Fatalf("CreateOrganization err = %v, want the audit write's ErrUnknownTopic", err)
	}
	// The slug is free again: the organization was rolled back.
	if _, err := org.New(org.NewAccess(nil), store).CreateOrganization(ctx, "Acme", "acme"); err != nil {
		t.Errorf("recreating the rolled-back organization: %v", err)
	}
}

func TestAPIKeyAndOAuthMapping(t *testing.T) {
	ctx := context.Background()
	svc := newAudit(t)
	ak, oa := audithook.APIKey(svc), audithook.OAuth(svc)
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(ak.On(ctx, apikey.Event{Kind: apikey.KeyAuthenticated, ContainerID: "c1", ActorID: "sa1", ServiceAccountID: "sa1", KeyID: "k1"}))
	must(ak.On(ctx, apikey.Event{Kind: apikey.KeyAuthenticationFailed, Detail: apikey.DetailKeyRevoked, KeyID: "k1"}))
	must(ak.On(ctx, apikey.Event{Kind: apikey.ServiceAccountRoleChanged, ActorID: "alice", ServiceAccountID: "sa1", RoleKey: "admin"}))
	must(oa.On(ctx, oauth.Event{Kind: oauth.TokenIssued, ActorID: "u1", ClientID: "cl1", GrantID: "g1", Detail: "authorization_code"}))
	must(oa.On(ctx, oauth.Event{Kind: oauth.AuthenticationFailed, Detail: oauth.DetailTokenInvalid}))
	must(oa.On(ctx, oauth.Event{Kind: oauth.TokenReuseDetected, ClientID: "cl1", GrantID: "g1", Detail: oauth.DetailRefreshReplayed}))
	must(oa.On(ctx, oauth.Event{Kind: oauth.ClientCreated, ActorID: "alice", ClientID: "cl2"}))
	must(oa.On(ctx, oauth.Event{Kind: oauth.ClientRegistered, ClientID: "cl3"}))

	byKey := map[string]audit.Event{}
	for _, e := range all(t, svc) {
		byKey[e.Topic+"/"+e.Action+":"+string(e.Outcome)+":"+e.Reason] = e
	}
	check := func(key string, f func(e audit.Event) bool) {
		t.Helper()
		e, ok := byKey[key]
		if !ok {
			t.Fatalf("no event %q in %v", key, byKey)
		}
		if !f(e) {
			t.Errorf("%s = %+v", key, e)
		}
	}
	check("apikey/apikey.key_authenticated:ok:", func(e audit.Event) bool {
		return e.Actor == audit.Actor{Type: audit.ActorServiceAccount, ID: "sa1"} && e.Resource == audit.Resource{Type: "key", ID: "k1"} && e.ContainerID == "c1"
	})
	check("apikey/apikey.key_authentication_failed:denied:"+apikey.DetailKeyRevoked, func(e audit.Event) bool {
		return e.Actor.Type == audit.ActorAnonymous
	})
	check("apikey/apikey.service_account_role_changed:ok:", func(e audit.Event) bool {
		return e.Actor == audit.Actor{Type: audit.ActorSubject, ID: "alice"} &&
			audit.EqualJSON(e.Changes, json.RawMessage(`{"role_key":{"before":null,"after":"admin"}}`))
	})
	check("oauth/oauth.token_issued:ok:authorization_code", func(e audit.Event) bool {
		return e.Resource == audit.Resource{Type: "grant", ID: "g1"} && e.Actor.ID == "u1"
	})
	check("oauth/oauth.authentication_failed:denied:"+oauth.DetailTokenInvalid, func(e audit.Event) bool {
		return e.Actor.Type == audit.ActorAnonymous
	})
	check("oauth/oauth.token_reuse_detected:denied:"+oauth.DetailRefreshReplayed, func(e audit.Event) bool {
		return e.Actor.Type == audit.ActorAnonymous
	})
	check("oauth/oauth.client_created:ok:", func(e audit.Event) bool {
		return e.Resource == audit.Resource{Type: "client", ID: "cl2"}
	})
	// A dynamically registered client did not exist before: it is the
	// resource of its registration, not its own actor.
	check("oauth/oauth.client_registered:ok:", func(e audit.Event) bool {
		return e.Actor == audit.Actor{Type: audit.ActorAnonymous} && e.Resource == audit.Resource{Type: "client", ID: "cl3"}
	})
}

func TestOptions(t *testing.T) {
	ctx := context.Background()
	svc := audit.New(memory.NewAuditStore(), audit.WithTopics(append(audithook.Topics(),
		audit.Topic{Key: "members"}, audit.Topic{Key: "roles"})...))
	route := func(action string) string {
		if strings.HasPrefix(action, "scope.member_") {
			return "members"
		}
		return "" // the adapter's default
	}
	h := audithook.Scope(svc, audithook.WithTopic(route), audithook.WithOrigin("backend"),
		audithook.WithSkipActions("scope.role_deleted", "scope.member_added:ok"))
	for _, k := range []scope.EventKind{scope.RoleDeleted, scope.MemberAdded, scope.MemberRemoved, scope.RoleCreated} {
		if err := h.On(ctx, scope.Event{Kind: k, ContainerID: "c", TargetID: "u", RoleKey: "r"}); err != nil {
			t.Fatal(err)
		}
	}
	evs := all(t, svc)
	if len(evs) != 2 {
		t.Fatalf("events = %+v, want 2", evs)
	}
	created, removed := evs[0], evs[1]
	if removed.Action != "scope.member_removed" || removed.Topic != "members" || removed.Origin != "backend" {
		t.Errorf("removed = %+v, want topic members, origin backend", removed)
	}
	if created.Action != "scope.role_created" || created.Topic != audithook.TopicAccess {
		t.Errorf("role created = %+v, want the default topic", created)
	}
}

type failing struct{}

func (failing) Begin(context.Context, audit.Event) (audit.Event, error) {
	return audit.Event{}, errBoom
}
func (failing) Complete(context.Context, string, audit.Completion) error { return errBoom }
func (failing) Record(context.Context, audit.Event) (audit.Event, error) {
	return audit.Event{}, errBoom
}

var errBoom = errors.New("boom")

func TestFailurePolicy(t *testing.T) {
	ctx := context.Background()
	ev := scope.Event{Kind: scope.MemberAdded}
	if err := audithook.Scope(failing{}).On(ctx, ev); !errors.Is(err, errBoom) {
		t.Errorf("default policy err = %v, want the audit error", err)
	}
	var seen error
	h := audithook.Scope(failing{}, audithook.WithBestEffort(func(_ context.Context, err error) { seen = err }))
	if err := h.On(ctx, ev); err != nil || !errors.Is(seen, errBoom) {
		t.Errorf("best effort = %v, callback saw %v", err, seen)
	}
}
