package oauth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/bernardoforcillo/authlayer/access"
	"github.com/bernardoforcillo/authlayer/apikey"
	"github.com/bernardoforcillo/authlayer/internal/uid"
	"github.com/bernardoforcillo/authlayer/scope"
	"github.com/bernardoforcillo/authlayer/token"
)

// Authority is the slice of the RBAC engine this package needs: a user's
// standing in a container, and the statements to encode and decode
// permission caps against. *scope.Service satisfies it, so an
// org.Service's embedded Service is what you pass — the Service here is
// deliberately not generic, since nothing it does depends on the container
// or member types.
//
// Standing is read for three subjects: the acting administrator (capped by
// the context's permission cap, which this package applies by
// scope.Service.CapStanding's rule), the service account a client is bound
// to, and the user approving a delegation. It is the cap-free,
// explicit-user form by contract, which is exactly why the cap is applied
// here and never trusted from the token.
type Authority interface {
	Standing(ctx context.Context, containerID, userID string) (access.Permission, bool, error)
	Access() *access.Access
}

// Default lifetimes and the polling interval, per the option that changes
// each.
const (
	DefaultAccessTTL      = 10 * time.Minute
	DefaultRefreshTTL     = 30 * 24 * time.Hour
	DefaultCodeTTL        = 60 * time.Second
	DefaultDeviceTTL      = 10 * time.Minute
	DefaultDeviceInterval = 5 * time.Second
)

// config is the resolved Service configuration, built from the defaults and
// mutated via Option — the same shape scope's, invite's and apikey's follow.
type config struct {
	clock               func() time.Time
	idgen               func() string
	hooks               []Hook
	issuer              string
	audience            []string
	accessTTL           time.Duration
	refreshTTL          time.Duration
	codeTTL             time.Duration
	deviceTTL           time.Duration
	deviceInterval      time.Duration
	grantTTL            time.Duration
	dynamicRegistration bool
	serviceAccounts     apikey.Store
	scopeMap            map[string]map[string][]access.Action
	offline             bool
}

func defaultConfig() config {
	return config{
		clock:          func() time.Time { return time.Now().UTC() },
		idgen:          uid.NewV7,
		accessTTL:      DefaultAccessTTL,
		refreshTTL:     DefaultRefreshTTL,
		codeTTL:        DefaultCodeTTL,
		deviceTTL:      DefaultDeviceTTL,
		deviceInterval: DefaultDeviceInterval,
	}
}

// Option customizes a Service. Options are applied in order at construction
// and never afterwards, so a Service's configuration is immutable once built.
type Option func(*config)

// WithClock sets the clock used for every timestamp and every expiry test.
// The default is time.Now().UTC(). A nil clock is ignored. The signer keeps
// its own clock for iat/exp, which this option does not reach.
func WithClock(now func() time.Time) Option {
	return func(c *config) {
		if now != nil {
			c.clock = now
		}
	}
}

// WithIDGenerator sets the id generator for clients, grants, codes, device
// authorizations, refresh tokens and the jti of every access token. The
// default is UUIDv7, and the same caveat scope.WithIDGenerator carries
// applies: against store/drops a non-UUID generator needs
// dropsstore.WithOAuthTextLibraryIDs, or the first create fails with
// SQLSTATE 22P02. A nil generator is ignored.
func WithIDGenerator(gen func() string) Option {
	return func(c *config) {
		if gen != nil {
			c.idgen = gen
		}
	}
}

// WithHooks appends lifecycle hooks. It appends rather than replaces, so
// several calls accumulate and hooks run in registration order. See [Hook]
// for what a hook error does to the call that emitted it.
func WithHooks(hooks ...Hook) Option {
	return func(c *config) { c.hooks = append(c.hooks, hooks...) }
}

// WithIssuer sets the iss claim of every token this Service mints and the
// value [Service.Authenticate] requires a presented token to carry. It is
// REQUIRED for minting: with it unset every token endpoint fails closed
// with [ErrIssuerRequired], because a delegated token that names no issuer
// cannot be scoped to one server, and a verifier that accepted one would
// accept a token minted by any deployment sharing the signing key. Use the
// issuer URL RFC 8414 publishes — the same string you pass to
// [Service.ServerMetadata].
func WithIssuer(issuer string) Option {
	return func(c *config) { c.issuer = strings.TrimSpace(issuer) }
}

// WithAudience sets the aud claim of every minted token and the set
// [Service.Authenticate] accepts: a presented token must carry at least one
// of them. The default is no audience minted and none checked — right for a
// single-resource deployment, wrong the moment two resource servers share
// an issuer, since a token for one would then verify at the other.
func WithAudience(aud ...string) Option {
	return func(c *config) { c.audience = slices.Clone(aud) }
}

// WithAccessTTL sets the access-token lifetime. The default is ten
// minutes: short, because a JWT cannot be recalled — see
// [Service.Revoke]. d <= 0 is ignored.
func WithAccessTTL(d time.Duration) Option {
	return func(c *config) {
		if d > 0 {
			c.accessTTL = d
		}
	}
}

// WithRefreshTTL sets the refresh-token lifetime — thirty days by default.
// Rotation issues a fresh token with a fresh lifetime, so an active client
// never expires; an idle one does. d <= 0 is ignored.
func WithRefreshTTL(d time.Duration) Option {
	return func(c *config) {
		if d > 0 {
			c.refreshTTL = d
		}
	}
}

// WithCodeTTL sets how long an authorization code is redeemable — sixty
// seconds by default, the ceiling RFC 6749 §4.1.2 recommends. d <= 0 is
// ignored.
func WithCodeTTL(d time.Duration) Option {
	return func(c *config) {
		if d > 0 {
			c.codeTTL = d
		}
	}
}

// WithDeviceTTL sets how long a device authorization waits for the user —
// ten minutes by default. d <= 0 is ignored.
func WithDeviceTTL(d time.Duration) Option {
	return func(c *config) {
		if d > 0 {
			c.deviceTTL = d
		}
	}
}

// WithDeviceInterval sets the minimum polling interval a device
// authorization advertises and [Service.PollDevice] enforces — five seconds
// by default (RFC 8628 §3.2). Sub-second values are rounded down to whole
// seconds, since the wire format is an integer; d < 1s is ignored.
func WithDeviceInterval(d time.Duration) Option {
	return func(c *config) {
		if d >= time.Second {
			c.deviceInterval = d.Truncate(time.Second)
		}
	}
}

// WithGrantTTL sets how long a delegation grant lives from approval. The
// default, zero, is until revoked: a "connected app" stays connected until
// the user disconnects it. d < 0 is ignored.
func WithGrantTTL(d time.Duration) Option {
	return func(c *config) {
		if d >= 0 {
			c.grantTTL = d
		}
	}
}

// WithDynamicRegistration enables [Service.RegisterClient], the RFC 7591
// endpoint an MCP client uses to register itself. Off by default: an open
// registration endpoint lets anyone create clients, which is harmless in
// itself (a client has no power until a user approves it) but is a surface
// you should choose to expose.
func WithDynamicRegistration(on bool) Option {
	return func(c *config) { c.dynamicRegistration = on }
}

// WithServiceAccounts wires the apikey.Store service accounts live in, so
// [Service.CreateClient] and [Service.ClientCredentials] can refuse a
// client bound to a service account that is missing or disabled. Without
// it the account's MEMBERSHIP is still checked — a client-credentials mint
// always resolves the account's standing — but DisableServiceAccount is
// invisible to this package.
func WithServiceAccounts(st apikey.Store) Option {
	return func(c *config) { c.serviceAccounts = st }
}

// WithScopeMap translates OAuth scope strings into RBAC permissions: each
// key is a scope a client may request, each value the grants it stands
// for, compiled against the Authority's own statements. An approved scope
// set becomes a permission cap — the union of its entries — so an agent's
// requested scopes bound what it may do without the application writing
// permission maths, and [Service.ServerMetadata] publishes the keys as
// scopes_supported. When a map is set, every requested scope must be a key
// of it (else [ErrInvalidScope]); when none is, scopes are opaque strings
// carried on the token and the cap comes from [Approval.Permissions] alone.
//
// The map is compiled at [New], which panics on an undeclared (resource,
// action) pair: a scope map that names a permission the scope does not
// declare is a startup programming error, exactly as a mis-declared role
// is to access.NewRole, and failing every mint at runtime instead would be
// the quiet version of the same bug.
func WithScopeMap(m map[string]map[string][]access.Action) Option {
	return func(c *config) { c.scopeMap = m }
}

// WithOfflineVerification makes [Service.Authenticate] verify a delegated
// token from its signature and claims alone, skipping the grant liveness
// lookup, and a client-credentials token likewise skip the client lookup.
// It buys a store-free hot path at a stated cost: a revoked grant, a
// disabled client or a replayed-and-revoked refresh token is not seen by
// Authenticate until the access token expires — up to [WithAccessTTL],
// ten minutes by default. Refresh still checks everything, so no client
// outlives its grant by more than one access-token lifetime. Use it when
// the resource server is not the authorization server and holds only the
// JWKS; keep it off when it is.
func WithOfflineVerification() Option {
	return func(c *config) { c.offline = true }
}

// Service is the authorization server: client management, the three
// grants, refresh, verification, introspection, revocation, the
// connected-apps view and discovery. It is safe for concurrent use if its
// Store, Authority and Signer are, and caches nothing but the compiled
// scope map.
type Service struct {
	st     Store
	auth   Authority
	signer token.Signer
	cfg    config
	// scopes is the sorted key set of the scope map, and scopePerms each
	// key compiled against the Authority's statements — both built once at
	// New.
	scopes     []string
	scopePerms map[string]access.Permission
}

// New wires a Store, an Authority and a Signer into a Service.
//
// authority supplies every permission decision — *scope.Service (an
// org.Service's embedded Service) is the one implementation. signer mints
// and verifies access tokens; pass auth.Service.Signer() so the tokens this
// Service issues verify at the same place a session's do, and prefer an
// EdDSA signer whenever anything that is not this process must verify —
// see token.EdDSA. store is the port described in the package doc:
// store/memory for tests and development, store/drops for production.
//
//	orgSvc := org.New(org.NewAccess(nil), memory.New[org.Organization, org.Member]())
//	as := oauth.New(memory.NewOAuthStore(), orgSvc.Service, signer, oauth.WithIssuer("https://auth.example"))
//
// It panics on a nil store, authority or signer, and on a [WithScopeMap]
// entry the authority's statements do not declare — all startup
// programming errors.
func New(store Store, authority Authority, signer token.Signer, opts ...Option) *Service {
	if store == nil || authority == nil || signer == nil {
		panic("authlayer/oauth: New requires a non-nil Store, Authority and Signer")
	}
	cfg := defaultConfig()
	for _, o := range opts {
		o(&cfg)
	}
	s := &Service{st: store, auth: authority, signer: signer, cfg: cfg}
	if cfg.scopeMap != nil {
		s.scopePerms = make(map[string]access.Permission, len(cfg.scopeMap))
		for name, grants := range cfg.scopeMap {
			p, err := authority.Access().Permission(grants)
			if err != nil {
				panic(fmt.Sprintf("authlayer/oauth: WithScopeMap entry %q: %v", name, err))
			}
			s.scopePerms[name] = p
			s.scopes = append(s.scopes, name)
		}
		slices.Sort(s.scopes)
	}
	return s
}

// ctxActor extracts the acting subject and active container from ctx,
// mirroring scope's own unexported helper from the two calls it exports.
func ctxActor(ctx context.Context) (subject, containerID string, err error) {
	subject, ok := scope.SubjectFrom(ctx)
	if !ok {
		return "", "", scope.ErrSubjectMissing
	}
	containerID, ok = scope.ScopeFrom(ctx)
	if !ok {
		return "", "", scope.ErrScopeMissing
	}
	return subject, containerID, nil
}

func (s *Service) emit(ctx context.Context, e Event) error {
	if e.At.IsZero() {
		e.At = s.cfg.clock()
	}
	for _, h := range s.cfg.hooks {
		if err := h.On(ctx, e); err != nil {
			return err
		}
	}
	return nil
}

// refuse emits e and returns sentinel, with a hook's error joined on rather
// than replacing it: a refusal is the answer, and a hook cannot make it any
// more refused.
func (s *Service) refuse(ctx context.Context, e Event, sentinel error) error {
	if herr := s.emit(ctx, e); herr != nil {
		return errors.Join(sentinel, herr)
	}
	return sentinel
}

// capStanding applies the permission cap on ctx, if any, to a standing —
// scope.Service.CapStanding's rule, restated here because [Authority]
// carries Standing alone: effective = perms ∩ cap, and elevation survives
// only if the cap is Full in this scope's statement space. A nil cap on
// the context leaves the standing as it is.
func (s *Service) capStanding(ctx context.Context, perms access.Permission, elevated bool) (access.Permission, bool) {
	ceiling, ok := scope.PermissionCapFrom(ctx)
	if !ok {
		return perms, elevated
	}
	fullHere := s.auth.Access().Full().Intersect(ceiling).IsFull()
	return perms.Intersect(ceiling), elevated && fullHere
}

// actorStanding resolves the ctx subject's standing in containerID WITH
// the permission cap on ctx applied. Every guard in this package compares
// against this, which is what keeps a restricted API key, or a delegated
// agent, from minting above its own ceiling.
func (s *Service) actorStanding(ctx context.Context, containerID, actor string) (access.Permission, bool, error) {
	perms, elevated, err := s.auth.Standing(ctx, containerID, actor)
	if err != nil {
		return access.Permission{}, false, err
	}
	perms, elevated = s.capStanding(ctx, perms, elevated)
	return perms, elevated, nil
}

// authorize is scope.Service.Authorize for the one control resource this
// package checks, scope.ResourceServiceAccount, computed from the actor's
// capped standing: elevated passes, a standing that Allows the action
// passes, anything else is scope.ErrForbidden. A non-member is
// scope.ErrNotMember from Standing.
func (s *Service) authorize(ctx context.Context, containerID, actor string, action access.Action) error {
	perms, elevated, err := s.actorStanding(ctx, containerID, actor)
	if err != nil {
		return err
	}
	if elevated || perms.Allows(scope.ResourceServiceAccount, action) {
		return nil
	}
	return scope.ErrForbidden
}

// newSecret draws a client secret: 32 bytes of crypto/rand as 43 url-safe
// base64 characters, and its hash. A crypto/rand failure is returned
// rather than degraded, matching token.GenerateOpaque.
func newSecret() (plain, hash string, err error) {
	var b [32]byte
	if _, rerr := rand.Read(b[:]); rerr != nil {
		return "", "", fmt.Errorf("authlayer/oauth: generate secret: %w", rerr)
	}
	plain = base64.RawURLEncoding.EncodeToString(b[:])
	return plain, token.HashOpaque(plain), nil
}

// splitScope parses a space-separated scope string into its distinct
// scopes, in order, ignoring repeats and surrounding whitespace.
func splitScope(scopeStr string) []string {
	var out []string
	for _, sc := range strings.Fields(scopeStr) {
		if !slices.Contains(out, sc) {
			out = append(out, sc)
		}
	}
	return out
}

// allowedScope checks a requested scope string against what c may request
// and what the server knows, and returns it normalised (distinct scopes,
// single-spaced). A scope outside c.Scopes when that list is set, or
// outside the scope map when one is set, is [ErrInvalidScope].
func (s *Service) allowedScope(c Client, requested string) (string, error) {
	scopes := splitScope(requested)
	for _, sc := range scopes {
		if len(c.Scopes) > 0 && !slices.Contains(c.Scopes, sc) {
			return "", fmt.Errorf("%w: %q is not one the client may request", ErrInvalidScope, sc)
		}
		if s.scopePerms != nil {
			if _, ok := s.scopePerms[sc]; !ok {
				return "", fmt.Errorf("%w: %q is not a scope this server knows", ErrInvalidScope, sc)
			}
		}
	}
	return strings.Join(scopes, " "), nil
}

// decodeCap turns stored permission bytes back into a cap against the
// Authority's statements, or nil for empty bytes (no cap).
func (s *Service) decodeCap(b []byte) (*access.Permission, error) {
	if len(b) == 0 {
		return nil, nil
	}
	p, err := s.auth.Access().Decode(b)
	if err != nil {
		return nil, err
	}
	return &p, nil
}
