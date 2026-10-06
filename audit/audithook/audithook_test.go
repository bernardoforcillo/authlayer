package audithook_test

import (
	"context"
	"errors"
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
	for _, want := range []string{"user.signup:ok", "email.verify:ok", "session.login:denied", "session.login:ok"} {
		if got[want] == 0 {
			t.Errorf("no %s event in %v", want, got)
		}
	}
	if got["session.login:denied"] != 2 {
		t.Errorf("denied logins = %d, want 2", got["session.login:denied"])
	}
	var unknown, ok *audit.Event
	for i := range evs {
		e := &evs[i]
		if e.Action == "session.login" && e.Outcome == audit.OutcomeDenied && e.Reason == auth.DetailUnknownUser {
			unknown = e
		}
		if e.Action == "session.login" && e.Outcome == audit.OutcomeOK {
			ok = e
		}
	}
	if unknown == nil || unknown.Actor.Type != audit.ActorAnonymous || unknown.Actor.ID != "" || unknown.IP != "203.0.113.9" {
		t.Errorf("unknown-user login = %+v", unknown)
	}
	if ok == nil || ok.Actor.Type != audit.ActorUser || ok.Actor.ID != su.User.ID || ok.SessionID == "" ||
		ok.Resource != (audit.Resource{Type: "session", ID: ok.SessionID}) || ok.Reason != auth.DetailPassword {
		t.Errorf("login = %+v", ok)
	}
	if mine, _, _ := svc.List(ctx, audit.Filter{Member: su.User.ID}, audit.Page{}); len(mine) < 3 {
		t.Errorf("alice's trail has %d events, want at least 3", len(mine))
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
	if add.Action != "member.add" || add.Resource != (audit.Resource{Type: audit.ResourceUser, ID: "bob"}) ||
		add.ContainerID != acme.ID || add.Actor.ID != "alice" || add.Topic != audithook.TopicScope {
		t.Errorf("member.add = %+v", add)
	}
	if create.Action != "container.create" || create.Resource.Type != "container" {
		t.Errorf("container.create = %+v", create)
	}
	if bob, _, _ := svc.List(context.Background(), audit.Filter{Member: "bob"}, audit.Page{}); len(bob) != 1 {
		t.Errorf("bob's trail = %d events, want 1", len(bob))
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
	check("apikey/key.authenticate:ok:", func(e audit.Event) bool {
		return e.Actor == audit.Actor{Type: audit.ActorServiceAccount, ID: "sa1"} && e.Resource == audit.Resource{Type: "key", ID: "k1"} && e.ContainerID == "c1"
	})
	check("apikey/key.authenticate:denied:"+apikey.DetailKeyRevoked, func(e audit.Event) bool {
		return e.Actor.Type == audit.ActorAnonymous
	})
	check("apikey/service_account.role_change:ok:", func(e audit.Event) bool {
		return e.Actor == audit.Actor{Type: audit.ActorSubject, ID: "alice"} && string(e.Request) == `{"role":"admin"}`
	})
	check("oauth/token.issue:ok:authorization_code", func(e audit.Event) bool {
		return e.Resource == audit.Resource{Type: "grant", ID: "g1"} && e.Actor.ID == "u1"
	})
	check("oauth/token.authenticate:denied:"+oauth.DetailTokenInvalid, func(e audit.Event) bool {
		return e.Actor.Type == audit.ActorAnonymous
	})
	check("oauth/token.reuse:denied:"+oauth.DetailRefreshReplayed, func(e audit.Event) bool {
		return e.Actor.Type == audit.ActorAnonymous
	})
	check("oauth/client.create:ok:", func(e audit.Event) bool {
		return e.Resource == audit.Resource{Type: "client", ID: "cl2"}
	})
}

func TestOptions(t *testing.T) {
	ctx := context.Background()
	svc := newAudit(t)
	h := audithook.Scope(svc, audithook.WithTopic("auth"), audithook.WithOrigin("backend"),
		audithook.WithSkipActions("role.delete", "member.add:ok"))
	for _, k := range []scope.EventKind{scope.RoleDeleted, scope.MemberAdded, scope.MemberRemoved} {
		if err := h.On(ctx, scope.Event{Kind: k, ContainerID: "c", TargetID: "u", RoleKey: "r"}); err != nil {
			t.Fatal(err)
		}
	}
	evs := all(t, svc)
	if len(evs) != 1 || evs[0].Action != "member.remove" || evs[0].Topic != "auth" || evs[0].Origin != "backend" {
		t.Fatalf("events = %+v", evs)
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
