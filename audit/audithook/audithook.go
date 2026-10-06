// Package audithook turns the lifecycle hooks of the other authlayer packages
// into audit events. Each constructor returns the hook type of its package,
// ready for that package's WithHooks:
//
//	rec := audit.New(store, audit.WithTopics(audithook.Topics()...))
//	authSvc := auth.New(authStore, signer, auth.WithHooks(audithook.Auth(rec)))
//	orgSvc := org.New(access, orgStore, org.WithHooks(audithook.Scope(rec)))
//
// # What gets recorded
//
// Hooks fire after the mutation they describe, so every event is stored with
// [audit.Recorder.Record], already over: a refusal ([auth.LoginFailed], a
// rejected key or token, a detected token replay) is [audit.OutcomeDenied]
// and everything else [audit.OutcomeOK]. The closed [Detail] vocabulary of
// the source event becomes [audit.Event.Reason]; nothing else is copied — no
// email address, no token, no secret — because the source events carry none.
//
// Actions are "<noun>.<verb>" and stable: "session.login", "member.add",
// "key.authenticate", "token.issue". A user's own events (their sign-in,
// their removal from a container) name that user as the resource so the whole
// trail is reachable with [audit.Filter.Member].
//
// # Failure policy
//
// A hook error aborts the call it observes, with the change already in
// place. By default a failed audit write is returned, so an unrecorded action
// is loud. [WithBestEffort] swallows it into a callback instead, the right
// choice for a high-volume event whose loss is acceptable. [WithSkipActions]
// drops events you do not want at all, such as "key.authenticate".
package audithook

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"

	"github.com/bernardoforcillo/authlayer/apikey"
	"github.com/bernardoforcillo/authlayer/audit"
	"github.com/bernardoforcillo/authlayer/auth"
	"github.com/bernardoforcillo/authlayer/oauth"
	"github.com/bernardoforcillo/authlayer/scope"
)

// The default topic of each adapter. Declare them on the audit.Service with
// [Topics] (or your own audit.WithTopics) before using an adapter.
const (
	TopicAuth   = "auth"
	TopicScope  = "scope"
	TopicAPIKey = "apikey"
	TopicOAuth  = "oauth"
)

// DefaultOrigin is the audit.Event.Origin the adapters stamp unless
// [WithOrigin] says otherwise.
const DefaultOrigin = "authlayer"

// Resource and actor types the adapters use beyond the audit package's own.
const (
	ResourceContainer      = "container"
	ResourceRole           = "role"
	ResourceSession        = "session"
	ResourceServiceAccount = "service_account"
	ResourceKey            = "key"
	ResourceClient         = "client"
	ResourceGrant          = "grant"
	ActorOAuthClient       = "oauth_client"
)

// Topics returns the four default topics with the Service's default
// retention, for audit.WithTopics.
func Topics() []audit.Topic {
	return []audit.Topic{{Key: TopicAuth}, {Key: TopicScope}, {Key: TopicAPIKey}, {Key: TopicOAuth}}
}

type config struct {
	topic  string
	origin string
	skip   []string
	onErr  func(context.Context, error)
	hasErr bool
}

// Option customizes an adapter.
type Option func(*config)

// WithTopic records the adapter's events under topic instead of its default.
func WithTopic(topic string) Option {
	return func(c *config) {
		if topic != "" {
			c.topic = topic
		}
	}
}

// WithOrigin names the reporting service, [DefaultOrigin] otherwise.
func WithOrigin(origin string) Option {
	return func(c *config) {
		if origin != "" {
			c.origin = origin
		}
	}
}

// WithSkipActions drops events whose action, or "action:outcome", is listed:
// "key.authenticate" drops every API-key authentication, while
// "key.authenticate:ok" drops only the successful ones.
func WithSkipActions(actions ...string) Option {
	return func(c *config) { c.skip = append(c.skip, actions...) }
}

// WithBestEffort makes a failed audit write non-fatal: onErr receives it and
// the hook returns nil. A nil onErr discards the error.
func WithBestEffort(onErr func(ctx context.Context, err error)) Option {
	return func(c *config) {
		c.hasErr = true
		c.onErr = onErr
	}
}

func newConfig(topic string, opts []Option) config {
	c := config{topic: topic, origin: DefaultOrigin}
	for _, o := range opts {
		if o != nil {
			o(&c)
		}
	}
	return c
}

// record stores one finished event, applying the skip list and the failure
// policy.
func (c config) record(ctx context.Context, rec audit.Recorder, e audit.Event) error {
	if slices.Contains(c.skip, e.Action) || slices.Contains(c.skip, e.Action+":"+string(e.Outcome)) {
		return nil
	}
	e.Topic, e.Origin = c.topic, c.origin
	if _, err := rec.Record(ctx, e); err != nil {
		if c.hasErr {
			if c.onErr != nil {
				c.onErr(ctx, err)
			}
			return nil
		}
		return fmt.Errorf("audithook: record %s: %w", e.Action, err)
	}
	return nil
}

func outcome(denied bool) audit.Outcome {
	if denied {
		return audit.OutcomeDenied
	}
	return audit.OutcomeOK
}

func request(kv map[string]any) json.RawMessage {
	if len(kv) == 0 {
		return nil
	}
	b, err := json.Marshal(kv)
	if err != nil {
		return nil
	}
	return b
}

// subjectActor is the actor behind an id the reporting package cannot type;
// an empty id is the application itself.
func subjectActor(id string) audit.Actor {
	if id == "" {
		return audit.Actor{Type: audit.ActorSystem}
	}
	return audit.Actor{Type: audit.ActorSubject, ID: id}
}

// ── scope / org / team ──────────────────────────────────────────────────────

type action struct {
	name     string
	denied   bool
	resource string // resource type; the id comes from the adapter
}

var scopeActions = map[scope.EventKind]action{
	scope.ContainerCreated:     {name: "container.create", resource: ResourceContainer},
	scope.MemberAdded:          {name: "member.add", resource: audit.ResourceUser},
	scope.MemberRoleChanged:    {name: "member.role_change", resource: audit.ResourceUser},
	scope.MemberRemoved:        {name: "member.remove", resource: audit.ResourceUser},
	scope.RoleCreated:          {name: "role.create", resource: ResourceRole},
	scope.RoleUpdated:          {name: "role.update", resource: ResourceRole},
	scope.RoleDeleted:          {name: "role.delete", resource: ResourceRole},
	scope.OwnershipTransferred: {name: "ownership.transfer", resource: audit.ResourceUser},
}

// Scope adapts the hooks of scope, and so of org and team, which alias them.
// Member and ownership events name the affected subject as a user resource;
// role events name the role key; container creation names the container.
func Scope(rec audit.Recorder, opts ...Option) scope.Hook {
	c := newConfig(TopicScope, opts)
	return scope.HookFunc(func(ctx context.Context, ev scope.Event) error {
		a, ok := scopeActions[ev.Kind]
		if !ok {
			a = action{name: fmt.Sprintf("event.kind_%d", ev.Kind)}
		}
		e := audit.Event{
			Action: a.name, Outcome: audit.OutcomeOK, Actor: subjectActor(ev.ActorID), ContainerID: ev.ContainerID,
		}
		switch a.resource {
		case ResourceContainer:
			e.Resource = audit.Resource{Type: ResourceContainer, ID: ev.ContainerID}
		case ResourceRole:
			e.Resource = audit.Resource{Type: ResourceRole, ID: ev.RoleKey}
		case audit.ResourceUser:
			e.Resource = audit.Resource{Type: audit.ResourceUser, ID: ev.TargetID}
		}
		kv := map[string]any{}
		if ev.RoleKey != "" && a.resource != ResourceRole {
			kv["role"] = ev.RoleKey
		}
		if ev.Anonymized {
			kv["anonymized"] = true
		}
		e.Request = request(kv)
		return c.record(ctx, rec, e)
	})
}

// ── auth ────────────────────────────────────────────────────────────────────

var authActions = map[auth.EventKind]action{
	auth.SignedUp:             {name: "user.signup", resource: audit.ResourceUser},
	auth.EmailVerified:        {name: "email.verify", resource: audit.ResourceUser},
	auth.LoggedIn:             {name: "session.login", resource: ResourceSession},
	auth.LoginFailed:          {name: "session.login", denied: true, resource: ResourceSession},
	auth.MFAChallenged:        {name: "mfa.challenge", resource: ResourceSession},
	auth.SessionRefreshed:     {name: "session.refresh", resource: ResourceSession},
	auth.TokenReuseDetected:   {name: "session.reuse", denied: true, resource: ResourceSession},
	auth.LoggedOut:            {name: "session.logout", resource: ResourceSession},
	auth.LoggedOutAll:         {name: "session.logout_all", resource: audit.ResourceUser},
	auth.SessionRevoked:       {name: "session.revoke", resource: ResourceSession},
	auth.PasswordChanged:      {name: "password.change", resource: audit.ResourceUser},
	auth.PasswordReset:        {name: "password.reset", resource: audit.ResourceUser},
	auth.EmailChanged:         {name: "email.change", resource: audit.ResourceUser},
	auth.MagicLinkRedeemed:    {name: "magiclink.redeem", resource: ResourceSession},
	auth.IdentityLinked:       {name: "identity.link", resource: audit.ResourceUser},
	auth.IdentityUnlinked:     {name: "identity.unlink", resource: audit.ResourceUser},
	auth.MFAEnrolled:          {name: "mfa.enroll", resource: audit.ResourceUser},
	auth.MFADisabled:          {name: "mfa.disable", resource: audit.ResourceUser},
	auth.PasskeyRegistered:    {name: "passkey.register", resource: audit.ResourceUser},
	auth.PasskeyDeleted:       {name: "passkey.delete", resource: audit.ResourceUser},
	auth.DeviceTrusted:        {name: "device.trust", resource: audit.ResourceUser},
	auth.TrustedDeviceRevoked: {name: "device.revoke", resource: audit.ResourceUser},
	auth.AccountDeleted:       {name: "account.delete", resource: audit.ResourceUser},
	auth.AccountAnonymized:    {name: "account.anonymize", resource: audit.ResourceUser},
}

// Auth adapts auth's hooks. The account is the actor, as a user, and the
// session (when there is one) goes on audit.Event.SessionID; a login with no
// account to name, such as an unknown address, is an anonymous actor. The
// source's Detail becomes the Reason.
func Auth(rec audit.Recorder, opts ...Option) auth.Hook {
	c := newConfig(TopicAuth, opts)
	return auth.HookFunc(func(ctx context.Context, ev auth.Event) error {
		a, ok := authActions[ev.Kind]
		if !ok {
			a = action{name: fmt.Sprintf("event.kind_%d", ev.Kind)}
		}
		actor := audit.Actor{Type: audit.ActorAnonymous}
		if ev.UserID != "" {
			actor = audit.Actor{Type: audit.ActorUser, ID: ev.UserID}
		}
		e := audit.Event{
			Action: a.name, Outcome: outcome(a.denied), Actor: actor, SessionID: ev.SessionID,
			Reason: ev.Detail, IP: ev.IP, UserAgent: ev.UserAgent,
		}
		switch {
		case a.resource == ResourceSession && ev.SessionID != "":
			e.Resource = audit.Resource{Type: ResourceSession, ID: ev.SessionID}
		case ev.UserID != "":
			e.Resource = audit.Resource{Type: audit.ResourceUser, ID: ev.UserID}
		}
		return c.record(ctx, rec, e)
	})
}

// ── apikey ──────────────────────────────────────────────────────────────────

var apikeyActions = map[apikey.EventKind]action{
	apikey.ServiceAccountCreated:     {name: "service_account.create", resource: ResourceServiceAccount},
	apikey.ServiceAccountDisabled:    {name: "service_account.disable", resource: ResourceServiceAccount},
	apikey.ServiceAccountEnabled:     {name: "service_account.enable", resource: ResourceServiceAccount},
	apikey.ServiceAccountRoleChanged: {name: "service_account.role_change", resource: ResourceServiceAccount},
	apikey.ServiceAccountDeleted:     {name: "service_account.delete", resource: ResourceServiceAccount},
	apikey.KeyCreated:                {name: "key.create", resource: ResourceKey},
	apikey.KeyRevoked:                {name: "key.revoke", resource: ResourceKey},
	apikey.KeyAuthenticated:          {name: "key.authenticate", resource: ResourceKey},
	apikey.KeyAuthenticationFailed:   {name: "key.authenticate", denied: true, resource: ResourceKey},
}

// APIKey adapts apikey's hooks. A key authenticating is the service account
// acting as itself; a refused authentication has no actor; management calls
// are acted by the subject on the context.
func APIKey(rec audit.Recorder, opts ...Option) apikey.Hook {
	c := newConfig(TopicAPIKey, opts)
	return apikey.HookFunc(func(ctx context.Context, ev apikey.Event) error {
		a, ok := apikeyActions[ev.Kind]
		if !ok {
			a = action{name: fmt.Sprintf("event.kind_%d", ev.Kind)}
		}
		var actor audit.Actor
		switch {
		case ev.Kind == apikey.KeyAuthenticated && ev.ActorID != "":
			actor = audit.Actor{Type: audit.ActorServiceAccount, ID: ev.ActorID}
		case a.denied:
			actor = audit.Actor{Type: audit.ActorAnonymous}
		default:
			actor = subjectActor(ev.ActorID)
		}
		e := audit.Event{
			Action: a.name, Outcome: outcome(a.denied), Actor: actor, ContainerID: ev.ContainerID, Reason: ev.Detail,
		}
		switch {
		case a.resource == ResourceKey && ev.KeyID != "":
			e.Resource = audit.Resource{Type: ResourceKey, ID: ev.KeyID}
		case ev.ServiceAccountID != "":
			e.Resource = audit.Resource{Type: ResourceServiceAccount, ID: ev.ServiceAccountID}
		}
		if ev.RoleKey != "" {
			e.Request = request(map[string]any{"role": ev.RoleKey})
		}
		return c.record(ctx, rec, e)
	})
}

// ── oauth ───────────────────────────────────────────────────────────────────

var oauthActions = map[oauth.EventKind]action{
	oauth.ClientCreated:        {name: "client.create", resource: ResourceClient},
	oauth.ClientRegistered:     {name: "client.register", resource: ResourceClient},
	oauth.ClientDisabled:       {name: "client.disable", resource: ResourceClient},
	oauth.ClientEnabled:        {name: "client.enable", resource: ResourceClient},
	oauth.ClientDeleted:        {name: "client.delete", resource: ResourceClient},
	oauth.GrantCreated:         {name: "grant.create", resource: ResourceGrant},
	oauth.GrantRevoked:         {name: "grant.revoke", resource: ResourceGrant},
	oauth.TokenIssued:          {name: "token.issue", resource: ResourceGrant},
	oauth.TokenRefreshed:       {name: "token.refresh", resource: ResourceGrant},
	oauth.TokenReuseDetected:   {name: "token.reuse", denied: true, resource: ResourceGrant},
	oauth.DeviceApproved:       {name: "device.approve", resource: ResourceGrant},
	oauth.DeviceDenied:         {name: "device.deny", resource: ResourceGrant},
	oauth.TokenAuthenticated:   {name: "token.authenticate", resource: ResourceGrant},
	oauth.AuthenticationFailed: {name: "token.authenticate", denied: true, resource: ResourceGrant},
}

// OAuth adapts oauth's hooks. Grant-bound events name the grant (the client
// when there is none); with no subject, an event is attributed to the client
// when one is known and is anonymous otherwise. Detail — the grant type, the
// refusal reason, the revocation path — becomes the Reason.
func OAuth(rec audit.Recorder, opts ...Option) oauth.Hook {
	c := newConfig(TopicOAuth, opts)
	return oauth.HookFunc(func(ctx context.Context, ev oauth.Event) error {
		a, ok := oauthActions[ev.Kind]
		if !ok {
			a = action{name: fmt.Sprintf("event.kind_%d", ev.Kind)}
		}
		var actor audit.Actor
		switch {
		case ev.ActorID != "":
			actor = audit.Actor{Type: audit.ActorSubject, ID: ev.ActorID}
		case ev.ClientID != "" && !a.denied:
			actor = audit.Actor{Type: ActorOAuthClient, ID: ev.ClientID}
		default:
			actor = audit.Actor{Type: audit.ActorAnonymous}
		}
		e := audit.Event{
			Action: a.name, Outcome: outcome(a.denied), Actor: actor, ContainerID: ev.ContainerID, Reason: ev.Detail,
		}
		switch {
		case a.resource == ResourceGrant && ev.GrantID != "":
			e.Resource = audit.Resource{Type: ResourceGrant, ID: ev.GrantID}
		case ev.ClientID != "":
			e.Resource = audit.Resource{Type: ResourceClient, ID: ev.ClientID}
		}
		if ev.ClientID != "" && e.Resource.Type == ResourceGrant {
			e.Request = request(map[string]any{"client_id": ev.ClientID})
		}
		return c.record(ctx, rec, e)
	})
}
