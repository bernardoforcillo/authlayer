// Package audithook turns the lifecycle hooks of the other authlayer packages
// into audit events. Each constructor returns the hook type of its package,
// ready for that package's WithHooks:
//
//	rec := audit.New(store, audit.WithTopics(audithook.Topics()...))
//	authSvc := auth.New(authStore, auth.WithJWT(keys, ttl), auth.WithHooks(audithook.Auth(rec)))
//	orgSvc := org.New(access, orgStore, org.WithHooks(audithook.Scope(rec)))
//
// # Annotating or recording
//
// When an event is pending on the context — an interceptor called
// [audit.Recorder.Begin] and put an [audit.Pending] there with
// [audit.WithPending] — the adapter adds what the hook knows to that event
// with [audit.Annotate]: the resource (the target user, the role, the key…),
// the container, the Detail as the reason, and a role key as Changes
// ({"role_key": …}). It records nothing of its own, and the interceptor
// completes the event with the call's real outcome.
//
// Otherwise it records a standalone event with [audit.Recorder.Record],
// already over: hooks fire after the mutation they describe. A refusal
// ([auth.LoginFailed], a rejected key or token, a detected token replay) is
// [audit.OutcomeDenied] and everything else [audit.OutcomeOK].
//
// Actions are "<package>.<kind in snake case>" and stable:
// "auth.logged_in", "auth.login_failed", "scope.member_role_changed",
// "apikey.key_authenticated", "oauth.token_issued". The default topics are
// [TopicAccess] for scope, org and team, and [TopicAuth], [TopicAPIKey] and
// [TopicOAuth]; [WithTopic] routes per action.
//
// # Who and what
//
// A session event (a sign-in, a refresh, a sign-out) names the session as
// its resource and the user as its actor; an account event (a password
// change, a deletion) names the user as both. A failed sign-in, a second
// factor challenge and a replayed refresh token are anonymous — whoever made
// the attempt is not authenticated as the account — and name the account as
// their resource, so [audit.Filter.Member] still finds them. Membership
// events name the member as a resource of type [audit.ResourceUser] even
// when the member is a service account, so one Member filter covers both. A
// dynamically registered OAuth client is the resource of its registration,
// with an anonymous actor.
//
// What is copied: ids, the closed Detail vocabulary as the Reason, the role
// key, and from auth the caller's IP address, user agent and session id. No
// email address, no token, no secret — the source events carry none.
//
// # Failure policy
//
// A hook error aborts the call it observes. By default a failed audit write
// is returned, so an unrecorded action is loud. [WithBestEffort] swallows it
// into a callback instead, the right choice for a high-volume event whose
// loss is acceptable. [WithSkipActions] drops events you do not want at all,
// such as "apikey.key_authenticated".
//
// The change the hook observed is already in place when the hook runs, with
// one exception: scope's CreateContainer (and so org.CreateOrganization)
// runs its hooks inside its transaction and rolls back when a hook fails.
// That is why a standalone "scope.container_created" can outlive its
// organization: it is written by the audit Service outside that transaction,
// so if a hook registered after this one fails, or the commit itself does,
// the creation is rolled back and the event stays. Register the audit hook
// last, and record inside a pending event when you need the outcome to be the
// call's own: an annotation ends with whatever the interceptor observed.
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
	TopicAccess = "access" // scope, org and team
	TopicAuth   = "auth"
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
	return []audit.Topic{{Key: TopicAccess}, {Key: TopicAuth}, {Key: TopicAPIKey}, {Key: TopicOAuth}}
}

type config struct {
	topic  string
	route  func(action string) string
	origin string
	skip   []string
	onErr  func(context.Context, error)
	hasErr bool
}

// Option customizes an adapter.
type Option func(*config)

// WithTopic routes each standalone event to the topic route returns for its
// action ("scope.member_role_changed"); an empty result keeps the adapter's
// default topic. Every topic it can return must be declared on the Service.
func WithTopic(route func(action string) string) Option {
	return func(c *config) { c.route = route }
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
// "apikey.key_authenticated" drops every successful API-key authentication,
// "auth.logged_in:ok" every successful sign-in. A skipped event neither
// annotates nor records.
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

// emit annotates the pending event on ctx with e's resource, container and
// reason and roleKey as Changes, or, with none pending, records e. It
// applies the skip list first and the failure policy last.
func (c config) emit(ctx context.Context, rec audit.Recorder, e audit.Event, roleKey string) error {
	if slices.Contains(c.skip, e.Action) || slices.Contains(c.skip, e.Action+":"+string(e.Outcome)) {
		return nil
	}
	var after json.RawMessage
	if roleKey != "" {
		after, _ = json.Marshal(map[string]string{"role_key": roleKey})
	}
	if _, ok := audit.PendingFrom(ctx); ok {
		var anns []audit.Annotation
		if e.Resource != (audit.Resource{}) {
			anns = append(anns, audit.WithResource(e.Resource.Type, e.Resource.ID))
		}
		if e.ContainerID != "" {
			anns = append(anns, audit.WithContainer(e.ContainerID))
		}
		if e.Reason != "" {
			anns = append(anns, audit.WithReason(e.Reason))
		}
		if after != nil {
			anns = append(anns, audit.WithChanges(nil, after))
		}
		audit.Annotate(ctx, anns...)
		return nil
	}
	if after != nil {
		e.Changes = audit.Diff(nil, after)
	}
	e.Topic, e.Origin = c.topic, c.origin
	if c.route != nil {
		if t := c.route(e.Action); t != "" {
			e.Topic = t
		}
	}
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

// action is one kind of a package's events: its name in snake case, whether
// it is a refusal, and the type of resource it names.
type action struct {
	kind     string
	denied   bool
	resource string
}

func (a action) name(pkg string) string { return pkg + "." + a.kind }

// lookup finds kind's row; an unknown kind (one added upstream after this
// table) is "kind_<n>", so it is still recorded.
func lookup[K ~int](table map[K]action, kind K) action {
	if a, ok := table[kind]; ok {
		return a
	}
	return action{kind: fmt.Sprintf("kind_%d", kind)}
}

// ── scope / org / team ──────────────────────────────────────────────────────

var scopeActions = map[scope.EventKind]action{
	scope.ContainerCreated:     {kind: "container_created", resource: ResourceContainer},
	scope.MemberAdded:          {kind: "member_added", resource: audit.ResourceUser},
	scope.MemberRoleChanged:    {kind: "member_role_changed", resource: audit.ResourceUser},
	scope.MemberRemoved:        {kind: "member_removed", resource: audit.ResourceUser},
	scope.RoleCreated:          {kind: "role_created", resource: ResourceRole},
	scope.RoleUpdated:          {kind: "role_updated", resource: ResourceRole},
	scope.RoleDeleted:          {kind: "role_deleted", resource: ResourceRole},
	scope.OwnershipTransferred: {kind: "ownership_transferred", resource: audit.ResourceUser},
}

// Scope adapts the hooks of scope, and so of org and team, which alias them.
// Member and ownership events name the affected subject — a user or a
// service account — as a resource of type audit.ResourceUser, with the role
// key as Changes; role events name the role key; container creation names
// the container.
func Scope(rec audit.Recorder, opts ...Option) scope.Hook {
	c := newConfig(TopicAccess, opts)
	return scope.HookFunc(func(ctx context.Context, ev scope.Event) error {
		a := lookup(scopeActions, ev.Kind)
		e := audit.Event{
			Action: a.name("scope"), Outcome: audit.OutcomeOK, Actor: subjectActor(ev.ActorID), ContainerID: ev.ContainerID,
		}
		roleKey := ev.RoleKey
		switch a.resource {
		case ResourceContainer:
			e.Resource = audit.Resource{Type: ResourceContainer, ID: ev.ContainerID}
		case ResourceRole:
			e.Resource, roleKey = audit.Resource{Type: ResourceRole, ID: ev.RoleKey}, ""
		case audit.ResourceUser:
			e.Resource = audit.Resource{Type: audit.ResourceUser, ID: ev.TargetID}
		}
		if ev.Anonymized {
			e.Request = request(map[string]any{"anonymized": true})
		}
		return c.emit(ctx, rec, e, roleKey)
	})
}

// ── auth ────────────────────────────────────────────────────────────────────

var authActions = map[auth.EventKind]action{
	auth.SignedUp:             {kind: "signed_up", resource: audit.ResourceUser},
	auth.EmailVerified:        {kind: "email_verified", resource: audit.ResourceUser},
	auth.LoggedIn:             {kind: "logged_in", resource: ResourceSession},
	auth.LoginFailed:          {kind: "login_failed", denied: true, resource: audit.ResourceUser},
	auth.MFAChallenged:        {kind: "mfa_challenged", resource: audit.ResourceUser},
	auth.SessionRefreshed:     {kind: "session_refreshed", resource: ResourceSession},
	auth.TokenReuseDetected:   {kind: "token_reuse_detected", denied: true, resource: audit.ResourceUser},
	auth.LoggedOut:            {kind: "logged_out", resource: ResourceSession},
	auth.LoggedOutAll:         {kind: "logged_out_all", resource: audit.ResourceUser},
	auth.SessionRevoked:       {kind: "session_revoked", resource: ResourceSession},
	auth.PasswordChanged:      {kind: "password_changed", resource: audit.ResourceUser},
	auth.PasswordReset:        {kind: "password_reset", resource: audit.ResourceUser},
	auth.EmailChanged:         {kind: "email_changed", resource: audit.ResourceUser},
	auth.MagicLinkRedeemed:    {kind: "magic_link_redeemed", resource: audit.ResourceUser},
	auth.IdentityLinked:       {kind: "identity_linked", resource: audit.ResourceUser},
	auth.IdentityUnlinked:     {kind: "identity_unlinked", resource: audit.ResourceUser},
	auth.MFAEnrolled:          {kind: "mfa_enrolled", resource: audit.ResourceUser},
	auth.MFADisabled:          {kind: "mfa_disabled", resource: audit.ResourceUser},
	auth.PasskeyRegistered:    {kind: "passkey_registered", resource: audit.ResourceUser},
	auth.PasskeyDeleted:       {kind: "passkey_deleted", resource: audit.ResourceUser},
	auth.DeviceTrusted:        {kind: "device_trusted", resource: audit.ResourceUser},
	auth.TrustedDeviceRevoked: {kind: "trusted_device_revoked", resource: audit.ResourceUser},
	auth.AccountDeleted:       {kind: "account_deleted", resource: audit.ResourceUser},
	auth.AccountAnonymized:    {kind: "account_anonymized", resource: audit.ResourceUser},
}

// anonymousAuth are the kinds whose caller is not authenticated as the
// account they concern: a refused sign-in, a sign-in stopped at its second
// factor, a replayed refresh token.
var anonymousAuth = []auth.EventKind{auth.LoginFailed, auth.MFAChallenged, auth.TokenReuseDetected}

// Auth adapts auth's hooks. The account is the actor, as a user, and the
// session (when there is one) goes on audit.Event.SessionID; a failed
// sign-in, a challenged one and a token replay are anonymous with the account
// as their resource. The source's Detail becomes the Reason, and IP and user
// agent are copied.
func Auth(rec audit.Recorder, opts ...Option) auth.Hook {
	c := newConfig(TopicAuth, opts)
	return auth.HookFunc(func(ctx context.Context, ev auth.Event) error {
		a := lookup(authActions, ev.Kind)
		actor := audit.Actor{Type: audit.ActorAnonymous}
		if ev.UserID != "" && !slices.Contains(anonymousAuth, ev.Kind) {
			actor = audit.Actor{Type: audit.ActorUser, ID: ev.UserID}
		}
		e := audit.Event{
			Action: a.name("auth"), Outcome: outcome(a.denied), Actor: actor, SessionID: ev.SessionID,
			Reason: ev.Detail, IP: ev.IP, UserAgent: ev.UserAgent,
		}
		switch {
		case a.resource == ResourceSession && ev.SessionID != "":
			e.Resource = audit.Resource{Type: ResourceSession, ID: ev.SessionID}
		case ev.UserID != "":
			e.Resource = audit.Resource{Type: audit.ResourceUser, ID: ev.UserID}
		}
		return c.emit(ctx, rec, e, "")
	})
}

// ── apikey ──────────────────────────────────────────────────────────────────

var apikeyActions = map[apikey.EventKind]action{
	apikey.ServiceAccountCreated:     {kind: "service_account_created", resource: ResourceServiceAccount},
	apikey.ServiceAccountDisabled:    {kind: "service_account_disabled", resource: ResourceServiceAccount},
	apikey.ServiceAccountEnabled:     {kind: "service_account_enabled", resource: ResourceServiceAccount},
	apikey.ServiceAccountRoleChanged: {kind: "service_account_role_changed", resource: ResourceServiceAccount},
	apikey.ServiceAccountDeleted:     {kind: "service_account_deleted", resource: ResourceServiceAccount},
	apikey.KeyCreated:                {kind: "key_created", resource: ResourceKey},
	apikey.KeyRevoked:                {kind: "key_revoked", resource: ResourceKey},
	apikey.KeyAuthenticated:          {kind: "key_authenticated", resource: ResourceKey},
	apikey.KeyAuthenticationFailed:   {kind: "key_authentication_failed", denied: true, resource: ResourceKey},
}

// APIKey adapts apikey's hooks. A key authenticating is the service account
// acting as itself; a refused authentication has no actor; management calls
// are acted by the subject on the context. A role key goes to Changes.
func APIKey(rec audit.Recorder, opts ...Option) apikey.Hook {
	c := newConfig(TopicAPIKey, opts)
	return apikey.HookFunc(func(ctx context.Context, ev apikey.Event) error {
		a := lookup(apikeyActions, ev.Kind)
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
			Action: a.name("apikey"), Outcome: outcome(a.denied), Actor: actor, ContainerID: ev.ContainerID, Reason: ev.Detail,
		}
		switch {
		case a.resource == ResourceKey && ev.KeyID != "":
			e.Resource = audit.Resource{Type: ResourceKey, ID: ev.KeyID}
		case ev.ServiceAccountID != "":
			e.Resource = audit.Resource{Type: ResourceServiceAccount, ID: ev.ServiceAccountID}
		}
		return c.emit(ctx, rec, e, ev.RoleKey)
	})
}

// ── oauth ───────────────────────────────────────────────────────────────────

var oauthActions = map[oauth.EventKind]action{
	oauth.ClientCreated:        {kind: "client_created", resource: ResourceClient},
	oauth.ClientRegistered:     {kind: "client_registered", resource: ResourceClient},
	oauth.ClientDisabled:       {kind: "client_disabled", resource: ResourceClient},
	oauth.ClientEnabled:        {kind: "client_enabled", resource: ResourceClient},
	oauth.ClientDeleted:        {kind: "client_deleted", resource: ResourceClient},
	oauth.GrantCreated:         {kind: "grant_created", resource: ResourceGrant},
	oauth.GrantRevoked:         {kind: "grant_revoked", resource: ResourceGrant},
	oauth.TokenIssued:          {kind: "token_issued", resource: ResourceGrant},
	oauth.TokenRefreshed:       {kind: "token_refreshed", resource: ResourceGrant},
	oauth.TokenReuseDetected:   {kind: "token_reuse_detected", denied: true, resource: ResourceGrant},
	oauth.DeviceApproved:       {kind: "device_approved", resource: ResourceGrant},
	oauth.DeviceDenied:         {kind: "device_denied", resource: ResourceGrant},
	oauth.TokenAuthenticated:   {kind: "token_authenticated", resource: ResourceGrant},
	oauth.AuthenticationFailed: {kind: "authentication_failed", denied: true, resource: ResourceGrant},
}

// OAuth adapts oauth's hooks. Grant-bound events name the grant (the client
// when there is none); with no subject, an event is attributed to the client
// when one is known and is anonymous otherwise, except a dynamic
// registration, whose new client is its resource and never its own actor.
// Detail — the grant type, the refusal reason, the revocation path — becomes
// the Reason.
func OAuth(rec audit.Recorder, opts ...Option) oauth.Hook {
	c := newConfig(TopicOAuth, opts)
	return oauth.HookFunc(func(ctx context.Context, ev oauth.Event) error {
		a := lookup(oauthActions, ev.Kind)
		var actor audit.Actor
		switch {
		case ev.ActorID != "":
			actor = audit.Actor{Type: audit.ActorSubject, ID: ev.ActorID}
		case ev.ClientID != "" && !a.denied && ev.Kind != oauth.ClientRegistered:
			actor = audit.Actor{Type: ActorOAuthClient, ID: ev.ClientID}
		default:
			actor = audit.Actor{Type: audit.ActorAnonymous}
		}
		e := audit.Event{
			Action: a.name("oauth"), Outcome: outcome(a.denied), Actor: actor, ContainerID: ev.ContainerID, Reason: ev.Detail,
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
		return c.emit(ctx, rec, e, "")
	})
}
