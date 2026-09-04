package oauth

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/bernardoforcillo/authlayer/access"
	"github.com/bernardoforcillo/authlayer/apikey"
	"github.com/bernardoforcillo/authlayer/scope"
	"github.com/bernardoforcillo/authlayer/token"
)

// TokenResponse is the RFC 6749 §5.1 success response of every token
// endpoint call, with that section's JSON names. RefreshToken is empty for
// a client-credentials grant (RFC 6749 §4.4.3 says a refresh token SHOULD
// NOT be issued there) and for a client that does not hold
// GrantRefreshToken.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// The claim names this package writes into [token.Claims.Extra], and the
// value of ExtraKind on a client-credentials token. They are exported so a
// verifier that is not this package can read them off a parsed token.
const (
	// ExtraContainerID is the scope the token acts in.
	ExtraContainerID = "container_id"
	// ExtraGrantID is the delegation grant a delegated token is bound to.
	ExtraGrantID = "grant_id"
	// ExtraKind is present, with the value KindServiceAccount, on a
	// client-credentials token.
	ExtraKind = "kind"
	// ExtraPermissions is the permission cap, base64url of
	// [access.Permission.Encode], present when the token is capped.
	ExtraPermissions = "permissions"
	// KindServiceAccount is ExtraKind's value on a client-credentials
	// token — the same string as apikey.KindServiceAccount.
	KindServiceAccount = string(apikey.KindServiceAccount)
)

// mint describes one access token to issue.
type mint struct {
	subject     string
	clientID    string
	scope       string
	containerID string
	grantID     string // delegated when set
	capBytes    []byte // nil for no cap
}

// mintAccess signs an access token for m and returns it with its lifetime
// in seconds. An empty issuer is [ErrIssuerRequired] — checked here so no
// path can mint an unscoped token.
func (s *Service) mintAccess(m mint) (string, int64, error) {
	if s.cfg.issuer == "" {
		return "", 0, ErrIssuerRequired
	}
	extra := map[string]any{ExtraContainerID: m.containerID}
	c := token.Claims{
		Subject:  m.subject,
		Issuer:   s.cfg.issuer,
		Audience: token.Audience(slices.Clone(s.cfg.audience)),
		ID:       s.cfg.idgen(),
		ClientID: m.clientID,
		Scope:    m.scope,
		Extra:    extra,
	}
	if m.grantID != "" {
		c.Actor = &token.Actor{Subject: m.clientID}
		extra[ExtraGrantID] = m.grantID
	} else {
		extra[ExtraKind] = KindServiceAccount
	}
	if len(m.capBytes) > 0 {
		extra[ExtraPermissions] = base64.RawURLEncoding.EncodeToString(m.capBytes)
	}
	raw, err := s.signer.Issue(c, s.cfg.accessTTL)
	if err != nil {
		return "", 0, err
	}
	return raw, int64(s.cfg.accessTTL / time.Second), nil
}

// liveGrant loads a grant and refuses one that is revoked or expired.
func (s *Service) liveGrant(ctx context.Context, id string, now time.Time) (Grant, error) {
	g, err := s.st.FindGrant(ctx, id)
	if err != nil {
		return Grant{}, err
	}
	if g.RevokedAt != nil {
		return Grant{}, ErrGrantRevoked
	}
	if g.ExpiresAt != nil && !now.Before(*g.ExpiresAt) {
		return Grant{}, ErrGrantExpired
	}
	return g, nil
}

// ClientCredentials is the RFC 6749 §4.4 grant: the client authenticates
// with its secret and receives an access token whose subject is the service
// account it is bound to — no refresh token, as §4.4.3 says. Refusals, in
// order: [ErrInvalidClient] / [ErrClientDisabled] from client
// authentication; [ErrUnauthorizedClient] when the client does not hold the
// grant; [ErrInvalidScope] for a scope outside the client's list or the
// scope map; and, wrapped in ErrInvalidClient so the client is told
// invalid_client and the operator's log the cause, a service account that
// is no longer a member (scope.ErrNotMember) or — with
// [WithServiceAccounts] wired — missing or disabled.
//
// # The mint re-checks the cap
//
// The client's Permissions were within the account's role when the client
// was created; the role may have been lowered since. The mint resolves the
// account's standing NOW and refuses with scope.ErrPrivilegeEscalation a
// cap that no longer sits within it, rather than issue a token that claims
// more than the account holds — the same rule every mint in this package
// applies. The token carries the cap; the engine intersects it with the
// account's then-current role at every check.
func (s *Service) ClientCredentials(ctx context.Context, clientID, clientSecret, scopeStr string) (TokenResponse, error) {
	c, err := s.authenticateClient(ctx, clientID, clientSecret)
	if err != nil {
		return TokenResponse{}, err
	}
	if err := requireGrantType(c, GrantClientCredentials); err != nil {
		return TokenResponse{}, err
	}
	scopeStr, err = s.allowedScope(c, scopeStr)
	if err != nil {
		return TokenResponse{}, err
	}
	perms, elevated, err := s.serviceAccountStanding(ctx, c.ContainerID, c.ServiceAccountID)
	if err != nil {
		if errors.Is(err, scope.ErrNotMember) || errors.Is(err, apikey.ErrServiceAccountNotFound) || errors.Is(err, apikey.ErrServiceAccountDisabled) {
			return TokenResponse{}, fmt.Errorf("%w: %w", ErrInvalidClient, err)
		}
		return TokenResponse{}, err
	}
	if len(c.Permissions) > 0 && !elevated {
		ceiling, err := s.auth.Access().Decode(c.Permissions)
		if err != nil {
			return TokenResponse{}, err
		}
		if !ceiling.SubsetOf(perms) {
			return TokenResponse{}, scope.ErrPrivilegeEscalation
		}
	}
	raw, expiresIn, err := s.mintAccess(mint{
		subject: c.ServiceAccountID, clientID: c.ID, scope: scopeStr,
		containerID: c.ContainerID, capBytes: c.Permissions,
	})
	if err != nil {
		return TokenResponse{}, err
	}
	if err := s.emit(ctx, Event{
		Kind: TokenIssued, ContainerID: c.ContainerID, ActorID: c.ServiceAccountID,
		ClientID: c.ID, Detail: GrantClientCredentials,
	}); err != nil {
		return TokenResponse{}, err
	}
	return TokenResponse{AccessToken: raw, TokenType: "Bearer", ExpiresIn: expiresIn, Scope: scopeStr}, nil
}

// extraString reads a string claim out of Claims.Extra, "" when absent or
// not a string.
func extraString(c token.Claims, key string) string {
	v, _ := c.Extra[key].(string)
	return v
}

// verified is what [Service.verify] establishes about a presented access
// token: the principal it acts as and the claims it carried.
type verified struct {
	principal apikey.Principal
	claims    token.Claims
	detail    string // DetailTouchFailed when the grant touch failed
}

// verify is the shared body of Authenticate and Introspect: parse, check
// issuer and audience, recognise the token as one of this package's, then
// — unless [WithOfflineVerification] — check the grant or client it names
// is live. Every refusal is [ErrInvalidToken] wrapping the cause, with the
// matching Detail in the returned string.
func (s *Service) verify(ctx context.Context, raw string, now time.Time) (verified, string, error) {
	claims, err := s.signer.Parse(raw)
	if err != nil {
		return verified{}, DetailTokenInvalid, fmt.Errorf("%w: %w", ErrInvalidToken, err)
	}
	if claims.Issuer == "" || claims.Issuer != s.cfg.issuer {
		return verified{}, DetailIssuerMismatch, fmt.Errorf("%w: issuer %q", ErrInvalidToken, claims.Issuer)
	}
	if len(s.cfg.audience) > 0 {
		ok := false
		for _, aud := range s.cfg.audience {
			if claims.Audience.Contains(aud) {
				ok = true
				break
			}
		}
		if !ok {
			return verified{}, DetailAudienceMismatch, fmt.Errorf("%w: audience %v", ErrInvalidToken, claims.Audience)
		}
	}
	containerID := extraString(claims, ExtraContainerID)
	if claims.ClientID == "" || claims.SessionID != "" || containerID == "" {
		return verified{}, DetailNotAnAccessToken, fmt.Errorf("%w: not an access token this package minted", ErrInvalidToken)
	}
	var ceiling *access.Permission
	if enc := extraString(claims, ExtraPermissions); enc != "" {
		b, err := base64.RawURLEncoding.DecodeString(enc)
		if err != nil {
			return verified{}, DetailNotAnAccessToken, fmt.Errorf("%w: permissions claim: %w", ErrInvalidToken, err)
		}
		if ceiling, err = s.decodeCap(b); err != nil {
			return verified{}, DetailNotAnAccessToken, fmt.Errorf("%w: permissions claim: %w", ErrInvalidToken, err)
		}
	}
	p := apikey.Principal{
		ID: claims.Subject, ContainerID: containerID, ClientID: claims.ClientID,
		Permissions: ceiling, AuthenticatedAt: now,
	}
	v := verified{claims: claims}

	if claims.Actor != nil {
		grantID := extraString(claims, ExtraGrantID)
		if grantID == "" || claims.Actor.Subject != claims.ClientID {
			return verified{}, DetailNotAnAccessToken, fmt.Errorf("%w: delegated token names no grant", ErrInvalidToken)
		}
		p.Kind = apikey.KindDelegated
		p.GrantID = grantID
		if !s.cfg.offline {
			g, err := s.liveGrant(ctx, grantID, now)
			switch {
			case errors.Is(err, ErrGrantNotFound):
				return verified{}, DetailGrantNotFound, fmt.Errorf("%w: %w", ErrInvalidToken, err)
			case errors.Is(err, ErrGrantRevoked):
				return verified{}, DetailGrantRevoked, fmt.Errorf("%w: %w", ErrInvalidToken, err)
			case errors.Is(err, ErrGrantExpired):
				return verified{}, DetailGrantExpired, fmt.Errorf("%w: %w", ErrInvalidToken, err)
			case err != nil:
				return verified{}, "", err
			}
			if g.UserID != claims.Subject || g.ClientID != claims.ClientID || g.ContainerID != containerID {
				return verified{}, DetailSubjectMismatch, fmt.Errorf("%w: token does not match its grant", ErrInvalidToken)
			}
			if err := s.st.TouchGrant(ctx, grantID, now); err != nil {
				v.detail = DetailTouchFailed
			}
		}
		v.principal = p
		return v, "", nil
	}

	if extraString(claims, ExtraKind) != KindServiceAccount {
		return verified{}, DetailNotAnAccessToken, fmt.Errorf("%w: neither delegated nor a service-account token", ErrInvalidToken)
	}
	p.Kind = apikey.KindServiceAccount
	if !s.cfg.offline {
		c, err := s.st.FindClient(ctx, claims.ClientID)
		switch {
		case errors.Is(err, ErrClientNotFound):
			return verified{}, DetailClientNotFound, fmt.Errorf("%w: %w", ErrInvalidToken, err)
		case err != nil:
			return verified{}, "", err
		case c.DisabledAt != nil:
			return verified{}, DetailClientDisabled, fmt.Errorf("%w: %w", ErrInvalidToken, ErrClientDisabled)
		case c.ServiceAccountID != claims.Subject || c.ContainerID != containerID:
			return verified{}, DetailSubjectMismatch, fmt.Errorf("%w: token does not match its client", ErrInvalidToken)
		}
	}
	v.principal = p
	return v, "", nil
}

// Authenticate resolves a presented access token to the [apikey.Principal]
// it acts as, so [apikey.WithPrincipal] can annotate a context the RBAC
// engine accepts — exactly as an API key's principal does.
//
// The token is parsed by the signer (a signature, key, expiry or shape
// failure is [ErrInvalidToken] wrapping the signer's sentinel), its iss must
// equal [WithIssuer] and its aud contain one of [WithAudience] when any is
// set, and it must be one this package minted: a client_id, no sid, a
// container. A session access token from auth.Service, signed by the same
// signer, is refused here on that last rule — it is a different credential
// for a different door.
//
// A delegated token (act present) authenticates as [apikey.KindDelegated]:
// ID is the user who approved, ContainerID the scope, ClientID the client
// acting, GrantID the grant, and Permissions the delegation cap the token
// carries — so that, once on the context, scope.Service.Can intersects it
// with the user's CURRENT standing, and revoking the user's role revokes
// the agent with it. Unless [WithOfflineVerification] is on, the grant is
// loaded and refused when gone, revoked or expired (ErrInvalidToken
// wrapping ErrGrantNotFound / ErrGrantRevoked / ErrGrantExpired), or when
// its user, client or container disagree with the token's, and LastUsedAt
// is stamped best-effort. A client-credentials token authenticates as
// [apikey.KindServiceAccount] with ID the service account, ClientID the
// client and Permissions the client's cap; unless offline, the client is
// loaded and refused when gone or disabled. Every refusal emits
// [AuthenticationFailed] with the reason in Detail; success emits
// [TokenAuthenticated], with DetailTouchFailed when the grant touch failed
// — that failure is NOT an authentication failure.
//
// Why the reason is disclosed: the caller already holds a token that
// verified, or one that did not; telling them which gives an attacker
// nothing and an operator the diagnosis. Map every ErrInvalidToken to one
// 401 with a WWW-Authenticate: Bearer error="invalid_token" challenge on
// the wire (RFC 6750 §3.1) if you prefer.
func (s *Service) Authenticate(ctx context.Context, rawAccessToken string) (apikey.Principal, error) {
	now := s.cfg.clock()
	v, detail, err := s.verify(ctx, rawAccessToken, now)
	if err != nil {
		if detail == "" {
			return apikey.Principal{}, err // a store failure, not a refusal
		}
		return apikey.Principal{}, s.refuse(ctx, Event{
			Kind: AuthenticationFailed, ContainerID: extraString(v.claims, ExtraContainerID),
			ClientID: v.claims.ClientID, Detail: detail, At: now,
		}, err)
	}
	p := v.principal
	if err := s.emit(ctx, Event{
		Kind: TokenAuthenticated, ContainerID: p.ContainerID, ActorID: p.ID,
		ClientID: p.ClientID, GrantID: p.GrantID, Detail: v.detail, At: now,
	}); err != nil {
		return apikey.Principal{}, err
	}
	return p, nil
}

// Introspection is the RFC 7662 §2.2 response, with that section's JSON
// names. For an inactive token only Active is set, as the RFC says a
// server SHOULD do; for an active one every field the token carries.
type Introspection struct {
	Active    bool           `json:"active"`
	Scope     string         `json:"scope,omitempty"`
	ClientID  string         `json:"client_id,omitempty"`
	Subject   string         `json:"sub,omitempty"`
	TokenType string         `json:"token_type,omitempty"`
	Exp       int64          `json:"exp,omitempty"`
	Iat       int64          `json:"iat,omitempty"`
	Iss       string         `json:"iss,omitempty"`
	Aud       token.Audience `json:"aud,omitempty"`
	Jti       string         `json:"jti,omitempty"`
	Act       *token.Actor   `json:"act,omitempty"`
}

// Introspect is RFC 7662: it answers whether raw is a live token of this
// server, and what it is, and NEVER errors for an invalid one — an
// unparseable, forged, expired, revoked or unknown token is
// Introspection{Active: false}, because the RFC says so, and because a
// resource server asking about a token it was handed must not be told
// anything an attacker who forged it could not already learn. A non-nil
// error is a store failure.
//
// It accepts both token kinds. An access token is verified exactly as
// [Service.Authenticate] verifies it, liveness lookup included (offline
// verification is honoured here too). Anything the signer does not parse
// is tried as a refresh token — hashed and looked up — and is active when
// the row is current, unexpired and its grant live; the response then
// carries the grant's subject, client and scope, the token's own expiry,
// and token_type "refresh_token" so the caller can tell the two apart.
//
// RFC 7662 §2.1 requires the CALLER to be authenticated: introspection is
// for resource servers, and an open introspection endpoint is a token
// validity oracle. That authentication is the application's — this method
// takes no client credentials.
func (s *Service) Introspect(ctx context.Context, rawToken string) (Introspection, error) {
	now := s.cfg.clock()
	v, detail, err := s.verify(ctx, rawToken, now)
	switch {
	case err == nil:
		c := v.claims
		return Introspection{
			Active: true, Scope: c.Scope, ClientID: c.ClientID, Subject: c.Subject,
			TokenType: "Bearer", Exp: c.ExpiresAt, Iat: c.IssuedAt, Iss: c.Issuer,
			Aud: c.Audience, Jti: c.ID, Act: c.Actor,
		}, nil
	case detail == "":
		return Introspection{}, err // a store failure
	case detail != DetailTokenInvalid:
		return Introspection{}, nil // parsed, but refused
	}

	rt, err := s.st.FindRefreshTokenByHash(ctx, token.HashOpaque(rawToken))
	if err != nil {
		if errors.Is(err, ErrRefreshNotFound) {
			return Introspection{}, nil
		}
		return Introspection{}, err
	}
	if rt.RotatedAt != nil || !now.Before(rt.ExpiresAt) {
		return Introspection{}, nil
	}
	g, err := s.liveGrant(ctx, rt.GrantID, now)
	if err != nil {
		if errors.Is(err, ErrGrantNotFound) || errors.Is(err, ErrGrantRevoked) || errors.Is(err, ErrGrantExpired) {
			return Introspection{}, nil
		}
		return Introspection{}, err
	}
	return Introspection{
		Active: true, Scope: g.Scope, ClientID: rt.ClientID, Subject: g.UserID,
		TokenType: "refresh_token", Exp: rt.ExpiresAt.Unix(), Iat: rt.CreatedAt.Unix(),
		Iss: s.cfg.issuer, Aud: token.Audience(slices.Clone(s.cfg.audience)),
	}, nil
}
