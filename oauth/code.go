package oauth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"slices"

	"github.com/bernardoforcillo/authlayer/access"
	"github.com/bernardoforcillo/authlayer/scope"
	"github.com/bernardoforcillo/authlayer/token"
)

// AuthorizationRequest is the RFC 6749 §4.1.1 authorization request as the
// application decoded it from the query string: what
// [Service.BeginAuthorization] validates and [Service.Approve] consumes.
// response_type is not a field, since "code" is the only value this
// package supports and [AuthorizationServerMetadata] says so.
type AuthorizationRequest struct {
	// ClientID is the client asking.
	ClientID string
	// RedirectURI must exactly match one of the client's registered URIs.
	// It may be empty when the client has exactly one registered, in which
	// case BeginAuthorization fills it in (RFC 6749 §3.1.2.3).
	RedirectURI string
	// Scope is the space-separated scope string requested.
	Scope string
	// State is the client's opaque value, carried through untouched for
	// the application to echo on the redirect. This package reads it
	// nowhere.
	State string
	// CodeChallenge is the RFC 7636 challenge: 43–128 characters of the
	// unreserved set.
	CodeChallenge string
	// CodeChallengeMethod must be "S256". "plain", and absent, are
	// [ErrPKCERequired] — OAuth 2.1 §4.1.1 makes PKCE mandatory and this
	// package accepts only the method that does not put the verifier on
	// the front channel.
	CodeChallengeMethod string
}

// Approval is what the consent screen decided, handed to [Service.Approve]
// and [Service.ApproveDevice] by the approving user's request.
type Approval struct {
	// Permissions is an explicit delegation cap, compiled against the
	// Authority's statements: the agent's standing becomes the user's
	// current standing ∩ this. nil means the cap the scope map implies for
	// the requested scopes ([WithScopeMap]), or — with no map — no cap: the
	// user's whole standing, as it stands at each check. It must sit
	// within the user's own capped standing (scope.ErrPrivilegeEscalation)
	// and must not compile to nothing ([ErrEmptyPermissions]).
	Permissions map[string][]access.Action
}

// CodeExchange is the RFC 6749 §4.1.3 token request for the
// authorization-code grant, as the application decoded it from the form
// body (and, for client_secret_basic, the Authorization header).
type CodeExchange struct {
	// ClientID and ClientSecret authenticate the client; ClientSecret is
	// empty for a public client.
	ClientID     string
	ClientSecret string
	// Code is the plaintext [Service.Approve] returned.
	Code string
	// RedirectURI, when non-empty, must equal the one the authorization
	// request used. OAuth 2.1 §4.1.3 drops the parameter — PKCE is what
	// binds the code to the client that asked — so an empty value is
	// accepted; a present, different one is [ErrInvalidGrant].
	RedirectURI string
	// CodeVerifier is the RFC 7636 verifier whose S256 hash must equal the
	// challenge the code was issued against.
	CodeVerifier string
}

// pkceRE is RFC 7636 §4.1's grammar for a verifier and §4.2's for a
// challenge: 43 to 128 characters of the unreserved set.
var pkceRE = regexp.MustCompile(`^[A-Za-z0-9._~-]{43,128}$`)

// s256 is RFC 7636 §4.2's transform: base64url, unpadded, of the SHA-256 of
// the ASCII verifier.
func s256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// BeginAuthorization validates an authorization request for the consent
// screen and returns it normalised — RedirectURI filled in when the client
// has exactly one registered, Scope with its distinct scopes single-spaced
// — together with the client, so the screen can show its name. It is
// stateless: nothing is written, and no subject is needed, since the user
// may not have signed in yet.
//
// Refusals, in order: [ErrClientNotFound]; [ErrClientDisabled];
// [ErrUnauthorizedClient] when the client does not hold
// GrantAuthorizationCode; [ErrInvalidRedirectURI] when RedirectURI is not
// registered, byte for byte, or is empty with more than one registered;
// [ErrPKCERequired] when the challenge is absent, not S256, or not 43–128
// characters of the unreserved set; [ErrInvalidScope] for a scope outside
// the client's list or the scope map. The first two and the redirect
// failure must NOT redirect the browser to the client (RFC 6749 §4.1.2.1
// — an unregistered redirect URI is exactly the thing not to send a
// response to); the rest may, with the error code [ErrorCode] gives.
func (s *Service) BeginAuthorization(ctx context.Context, req AuthorizationRequest) (AuthorizationRequest, Client, error) {
	c, err := s.st.FindClient(ctx, req.ClientID)
	if err != nil {
		return AuthorizationRequest{}, Client{}, err
	}
	if c.DisabledAt != nil {
		return AuthorizationRequest{}, Client{}, ErrClientDisabled
	}
	if err := requireGrantType(c, GrantAuthorizationCode); err != nil {
		return AuthorizationRequest{}, Client{}, err
	}
	switch {
	case req.RedirectURI == "" && len(c.RedirectURIs) == 1:
		req.RedirectURI = c.RedirectURIs[0]
	case !slices.Contains(c.RedirectURIs, req.RedirectURI):
		return AuthorizationRequest{}, Client{}, fmt.Errorf("%w: %q", ErrInvalidRedirectURI, req.RedirectURI)
	}
	if req.CodeChallengeMethod != "S256" {
		return AuthorizationRequest{}, Client{}, fmt.Errorf("%w: code_challenge_method %q", ErrPKCERequired, req.CodeChallengeMethod)
	}
	if !pkceRE.MatchString(req.CodeChallenge) {
		return AuthorizationRequest{}, Client{}, fmt.Errorf("%w: code_challenge is not 43-128 unreserved characters", ErrPKCERequired)
	}
	req.Scope, err = s.allowedScope(c, req.Scope)
	if err != nil {
		return AuthorizationRequest{}, Client{}, err
	}
	return req, c, nil
}

// capFromScope turns an approved scope string into the cap the scope map
// implies — the union of each scope's permissions — or nil when no map is
// configured. With a map configured, an empty scope set is
// [ErrInvalidScope]: it would compile to a cap granting nothing, and a
// token that may do nothing is a request to refuse, not to mint.
func (s *Service) capFromScope(scopeStr string) (*access.Permission, error) {
	if s.scopePerms == nil {
		return nil, nil
	}
	scopes := splitScope(scopeStr)
	if len(scopes) == 0 {
		return nil, fmt.Errorf("%w: no scope requested", ErrInvalidScope)
	}
	ps := make([]access.Permission, 0, len(scopes))
	for _, sc := range scopes {
		p, ok := s.scopePerms[sc]
		if !ok {
			return nil, fmt.Errorf("%w: %q is not a scope this server knows", ErrInvalidScope, sc)
		}
		ps = append(ps, p)
	}
	union, err := s.auth.Access().Union(ps...)
	if err != nil {
		return nil, err
	}
	return &union, nil
}

// encodeCap returns a cap's stored form, or nil for no cap.
func encodeCap(p *access.Permission) []byte {
	if p == nil {
		return nil
	}
	return p.Encode()
}

// delegate creates the Grant behind an approval: user delegating to c in
// containerID, for scopeStr, capped as a and the scope map decide. It is
// the escalation guard every delegation shares — Approve and ApproveDevice
// both end here.
//
// The cap is a.Permissions when set, else the scope map's union for the
// scopes, else nil. It must sit within the user's CAPPED standing unless
// they are elevated (scope.ErrPrivilegeEscalation), and must not grant
// nothing ([ErrEmptyPermissions]). A user with no standing in the container
// cannot delegate any (scope.ErrNotMember). And one more rule, for the
// approver who is themselves acting under a cap — a delegated agent, or a
// restricted API key, approving a further delegation: when no cap is asked
// for, the grant is capped to the approver's capped standing as it stands
// now, because "the user's whole standing" is more than that approver
// holds, and a delegation never exceeds its grantor.
func (s *Service) delegate(ctx context.Context, user, containerID string, c Client, scopeStr string, a Approval) (Grant, error) {
	perms, elevated, err := s.actorStanding(ctx, containerID, user)
	if err != nil {
		return Grant{}, err
	}
	var ceiling *access.Permission
	if a.Permissions != nil {
		p, err := s.auth.Access().Permission(a.Permissions)
		if err != nil {
			return Grant{}, err
		}
		ceiling = &p
	} else if ceiling, err = s.capFromScope(scopeStr); err != nil {
		return Grant{}, err
	}
	if ceiling == nil {
		if _, capped := scope.PermissionCapFrom(ctx); capped {
			snapshot := perms
			ceiling = &snapshot
		}
	}
	if ceiling != nil {
		if ceiling.IsZero() {
			return Grant{}, ErrEmptyPermissions
		}
		if !elevated && !ceiling.SubsetOf(perms) {
			return Grant{}, scope.ErrPrivilegeEscalation
		}
	}
	now := s.cfg.clock()
	g := Grant{
		ID:          s.cfg.idgen(),
		ClientID:    c.ID,
		UserID:      user,
		ContainerID: containerID,
		Scope:       scopeStr,
		Permissions: encodeCap(ceiling),
		CreatedAt:   now,
	}
	if s.cfg.grantTTL > 0 {
		exp := now.Add(s.cfg.grantTTL)
		g.ExpiresAt = &exp
	}
	return s.st.CreateGrant(ctx, g)
}

// Approve records the user's consent: it re-validates req exactly as
// [Service.BeginAuthorization] does (the request may have been tampered
// with between the two calls, or the client disabled), creates the
// [Grant] from the ctx subject to the client in the ctx container, mints
// an authorization code bound to that grant, the redirect URI and the
// PKCE challenge, and returns the code's plaintext — exactly ONCE; only
// its hash is stored. Redirect the browser to req.RedirectURI with the
// code and req.State.
//
// The ctx carries the user and the container (scope.WithSubject,
// scope.WithScope); the user must be a member of the container
// (scope.ErrNotMember) and the cap must sit within their capped standing
// (scope.ErrPrivilegeEscalation) — see [Approval] and the package doc.
// Every approval is a new grant, revocable on its own.
func (s *Service) Approve(ctx context.Context, req AuthorizationRequest, a Approval) (string, error) {
	user, containerID, err := ctxActor(ctx)
	if err != nil {
		return "", err
	}
	req, c, err := s.BeginAuthorization(ctx, req)
	if err != nil {
		return "", err
	}
	g, err := s.delegate(ctx, user, containerID, c, req.Scope, a)
	if err != nil {
		return "", err
	}
	plain, hash, err := token.GenerateOpaque()
	if err != nil {
		return "", err
	}
	now := s.cfg.clock()
	if _, err := s.st.CreateCode(ctx, AuthorizationCode{
		ID:            s.cfg.idgen(),
		CodeHash:      hash,
		ClientID:      c.ID,
		GrantID:       g.ID,
		RedirectURI:   req.RedirectURI,
		CodeChallenge: req.CodeChallenge,
		ExpiresAt:     now.Add(s.cfg.codeTTL),
		CreatedAt:     now,
	}); err != nil {
		return "", err
	}
	if err := s.emit(ctx, Event{Kind: GrantCreated, ContainerID: containerID, ActorID: user, ClientID: c.ID, GrantID: g.ID}); err != nil {
		return "", err
	}
	return plain, nil
}

// revokeAfterMisuse revokes a grant on one of the two replay paths and
// emits the two events for it; the caller returns sentinel, joined with
// any error the revocation itself hit, so the alarm is never lost to the
// failure of the response to it.
func (s *Service) revokeAfterMisuse(ctx context.Context, c Client, grantID, detail string, sentinel error) error {
	now := s.cfg.clock()
	rerr := s.st.RevokeGrant(ctx, grantID, now)
	if errors.Is(rerr, ErrGrantNotFound) {
		rerr = nil
	}
	events := []Event{{Kind: GrantRevoked, ContainerID: c.ContainerID, ClientID: c.ID, GrantID: grantID, Detail: detail, At: now}}
	if detail != DetailWrongClient {
		events = append([]Event{{Kind: TokenReuseDetected, ContainerID: c.ContainerID, ClientID: c.ID, GrantID: grantID, Detail: detail, At: now}}, events...)
	}
	for _, e := range events {
		if herr := s.emit(ctx, e); herr != nil {
			rerr = errors.Join(rerr, herr)
		}
	}
	if rerr != nil {
		return errors.Join(sentinel, rerr)
	}
	return sentinel
}

// ExchangeCode is the RFC 6749 §4.1.3 token request: the client
// authenticates, presents the code and its PKCE verifier, and receives an
// access token — delegated, sub the user and act the client — plus a
// refresh token when the client holds GrantRefreshToken.
//
// The code is redeemed through [Store.RedeemCode]'s compare-and-set, so
// exactly one exchange of a code ever mints. A second presentation is
// [ErrCodeReused], AND the grant the code minted is revoked (OAuth 2.1
// §4.1.2), so the tokens the first exchange produced stop refreshing at
// once and verifying within an access-token lifetime — a replayed code
// means the code leaked, and the party that got there first may have been
// the thief. A code presented by a client other than the one it was issued
// to is [ErrInvalidGrant] with the same revocation. Then, all
// [ErrInvalidGrant]: an unknown code (wrapping ErrCodeNotFound), an
// expired one (checked after the redemption, so an expired code is
// consumed too), a RedirectURI that differs from the request's. A verifier
// that is not 43–128 unreserved characters or whose S256 is not the
// challenge is [ErrPKCEMismatch], compared in constant time. The grant
// must still be live ([ErrGrantRevoked], [ErrGrantExpired]). Client
// authentication failures come first: [ErrInvalidClient],
// [ErrClientDisabled], [ErrUnauthorizedClient].
func (s *Service) ExchangeCode(ctx context.Context, x CodeExchange) (TokenResponse, error) {
	c, err := s.authenticateClient(ctx, x.ClientID, x.ClientSecret)
	if err != nil {
		return TokenResponse{}, err
	}
	if err := requireGrantType(c, GrantAuthorizationCode); err != nil {
		return TokenResponse{}, err
	}
	now := s.cfg.clock()
	code, won, err := s.st.RedeemCode(ctx, token.HashOpaque(x.Code), now)
	if err != nil {
		if errors.Is(err, ErrCodeNotFound) {
			return TokenResponse{}, fmt.Errorf("%w: %w", ErrInvalidGrant, err)
		}
		return TokenResponse{}, err
	}
	if !won {
		return TokenResponse{}, s.revokeAfterMisuse(ctx, c, code.GrantID, DetailCodeReplayed, ErrCodeReused)
	}
	if code.ClientID != c.ID {
		return TokenResponse{}, s.revokeAfterMisuse(ctx, c, code.GrantID, DetailWrongClient,
			fmt.Errorf("%w: code was issued to another client", ErrInvalidGrant))
	}
	if !now.Before(code.ExpiresAt) {
		return TokenResponse{}, fmt.Errorf("%w: code expired", ErrInvalidGrant)
	}
	if x.RedirectURI != "" && x.RedirectURI != code.RedirectURI {
		return TokenResponse{}, fmt.Errorf("%w: redirect_uri does not match the authorization request", ErrInvalidGrant)
	}
	if !pkceRE.MatchString(x.CodeVerifier) ||
		subtle.ConstantTimeCompare([]byte(s256(x.CodeVerifier)), []byte(code.CodeChallenge)) != 1 {
		return TokenResponse{}, ErrPKCEMismatch
	}
	g, err := s.liveGrant(ctx, code.GrantID, now)
	if err != nil {
		if errors.Is(err, ErrGrantNotFound) {
			return TokenResponse{}, fmt.Errorf("%w: %w", ErrInvalidGrant, err)
		}
		return TokenResponse{}, err
	}
	resp, err := s.issueDelegated(ctx, c, g, "", now)
	if err != nil {
		return TokenResponse{}, err
	}
	if err := s.emit(ctx, Event{
		Kind: TokenIssued, ContainerID: g.ContainerID, ActorID: g.UserID,
		ClientID: c.ID, GrantID: g.ID, Detail: GrantAuthorizationCode, At: now,
	}); err != nil {
		return TokenResponse{}, err
	}
	return resp, nil
}
