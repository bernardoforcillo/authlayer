package oauth

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"

	"github.com/bernardoforcillo/authlayer/access"
	"github.com/bernardoforcillo/authlayer/apikey"
	"github.com/bernardoforcillo/authlayer/scope"
	"github.com/bernardoforcillo/authlayer/token"
)

// ClientSpec is what [Service.CreateClient] takes: the client as an
// administrator describes it. Every field maps onto [Client] and is
// validated on the terms that type's field docs state.
type ClientSpec struct {
	// Name is what a consent screen shows.
	Name string
	// Public marks a client with no secret. It may not hold
	// GrantClientCredentials.
	Public bool
	// RedirectURIs is the exact-match allowlist; required, non-empty, for
	// GrantAuthorizationCode. Each must be an absolute URI without a
	// fragment, and an http one must point at a loopback address.
	RedirectURIs []string
	// GrantTypes is the subset of the Grant* constants the client may use;
	// at least one, all known.
	GrantTypes []string
	// Scopes is the list the client may request; empty for any the server
	// knows. Each must be known to [WithScopeMap] when one is set.
	Scopes []string
	// ServiceAccountID is required exactly when GrantTypes contains
	// GrantClientCredentials, and must be a member of the ctx container.
	ServiceAccountID string
	// Permissions is an optional cap on client-credentials tokens, compiled
	// against the Authority's statements: the token's standing becomes the
	// account's role ∩ this. Only meaningful with GrantClientCredentials.
	// It must sit within the account's role and within the actor's own
	// capped standing (scope.ErrPrivilegeEscalation), and must not compile
	// to nothing ([ErrEmptyPermissions]).
	Permissions map[string][]access.Action
}

// validateRedirectURIs checks each URI is absolute, carries no fragment,
// and — when its scheme is http — points at a loopback host, which is the
// one case OAuth 2.1 §8.4.2 allows a non-TLS redirect for. Anything else is
// [ErrInvalidRedirectURI].
func validateRedirectURIs(uris []string) error {
	for _, raw := range uris {
		u, err := url.Parse(raw)
		if err != nil || u.Scheme == "" || raw == "" {
			return fmt.Errorf("%w: %q is not an absolute URI", ErrInvalidRedirectURI, raw)
		}
		if u.Fragment != "" || strings.Contains(raw, "#") {
			return fmt.Errorf("%w: %q carries a fragment", ErrInvalidRedirectURI, raw)
		}
		if u.Scheme == "http" {
			host := u.Hostname()
			if host != "localhost" && host != "127.0.0.1" && host != "::1" {
				return fmt.Errorf("%w: %q is http on a non-loopback host", ErrInvalidRedirectURI, raw)
			}
		}
	}
	return nil
}

// validateGrantTypes checks the list is non-empty and every entry known.
func validateGrantTypes(types []string) error {
	if len(types) == 0 {
		return fmt.Errorf("%w: at least one grant type is required", ErrInvalidClientMetadata)
	}
	for _, gt := range types {
		if !slices.Contains(KnownGrantTypes, gt) {
			return fmt.Errorf("%w: unknown grant type %q", ErrInvalidClientMetadata, gt)
		}
	}
	return nil
}

// validateScopes checks every scope the client lists is one the scope map
// knows, when a map is set.
func (s *Service) validateScopes(scopes []string) error {
	if s.scopePerms == nil {
		return nil
	}
	for _, sc := range scopes {
		if _, ok := s.scopePerms[sc]; !ok {
			return fmt.Errorf("%w: %q is not a scope this server knows", ErrInvalidScope, sc)
		}
	}
	return nil
}

// validateSpec applies every structural rule a client must satisfy.
func (s *Service) validateSpec(spec ClientSpec) error {
	if strings.TrimSpace(spec.Name) == "" {
		return fmt.Errorf("%w: a name is required", ErrInvalidClientMetadata)
	}
	if err := validateGrantTypes(spec.GrantTypes); err != nil {
		return err
	}
	if err := validateRedirectURIs(spec.RedirectURIs); err != nil {
		return err
	}
	if err := s.validateScopes(spec.Scopes); err != nil {
		return err
	}
	cc := slices.Contains(spec.GrantTypes, GrantClientCredentials)
	switch {
	case cc && spec.Public:
		return fmt.Errorf("%w: a public client may not hold client_credentials", ErrInvalidClientMetadata)
	case cc && spec.ServiceAccountID == "":
		return fmt.Errorf("%w: client_credentials requires a service account", ErrInvalidClientMetadata)
	case !cc && spec.ServiceAccountID != "":
		return fmt.Errorf("%w: a service account is only bound through client_credentials", ErrInvalidClientMetadata)
	case !cc && spec.Permissions != nil:
		return fmt.Errorf("%w: a permission cap applies to client_credentials tokens only", ErrInvalidClientMetadata)
	case slices.Contains(spec.GrantTypes, GrantAuthorizationCode) && len(spec.RedirectURIs) == 0:
		return fmt.Errorf("%w: authorization_code requires at least one redirect URI", ErrInvalidClientMetadata)
	}
	return nil
}

// client loads id and refuses it unless it belongs to containerID,
// reporting ErrClientNotFound for a client that exists elsewhere — an
// application-level one included — exactly as for one that does not
// exist: [Store] is keyed by id and scoped by nothing, so this is where a
// service_account:* grant in one container stops reaching another's
// clients. The same rule apikey applies to its accounts.
func (s *Service) client(ctx context.Context, containerID, id string) (Client, error) {
	c, err := s.st.FindClient(ctx, id)
	if err != nil {
		return Client{}, err
	}
	if c.ContainerID != containerID {
		return Client{}, ErrClientNotFound
	}
	return c, nil
}

// serviceAccountStanding resolves the standing of the service account a
// client-credentials client is bound to, refusing an account that is not a
// member of containerID (scope.ErrNotMember, from the Authority) and —
// when [WithServiceAccounts] is wired — one that is missing, in another
// container, or disabled.
func (s *Service) serviceAccountStanding(ctx context.Context, containerID, saID string) (access.Permission, bool, error) {
	if s.cfg.serviceAccounts != nil {
		sa, err := s.cfg.serviceAccounts.FindServiceAccount(ctx, saID)
		if err != nil {
			return access.Permission{}, false, err
		}
		if sa.ContainerID != containerID {
			return access.Permission{}, false, apikey.ErrServiceAccountNotFound
		}
		if sa.DisabledAt != nil {
			return access.Permission{}, false, apikey.ErrServiceAccountDisabled
		}
	}
	return s.auth.Standing(ctx, containerID, saID)
}

// CreateClient creates a client owned by the ctx container and returns the
// stored record together with its secret — returned exactly ONCE and never
// again, since only its hash is stored; "" for a public client. Deliver it
// now.
//
// The ctx subject needs service_account:update: a client is a credential
// of the organization, or of one of its service accounts, and is managed
// under the same grant as the accounts' keys. The spec is validated on
// [ClientSpec]'s terms — [ErrInvalidClientMetadata], [ErrInvalidRedirectURI]
// or [ErrInvalidScope].
//
// # A client-credentials client is a grant of the account's standing
//
// Whoever holds the secret acts as the service account, so minting one is
// guarded exactly as apikey.Service.CreateKey guards a key: the account
// must be a member of the container (scope.ErrNotMember otherwise, and
// apikey.ErrServiceAccountNotFound or apikey.ErrServiceAccountDisabled
// when [WithServiceAccounts] can see it); spec.Permissions, if set, must
// sit within the account's role, else it would intersect to less than it
// claims and mislead whoever reads it back; and what the client will be
// able to do — the cap, or the whole role — must sit within the actor's
// own CAPPED standing, unless the actor is elevated. Both refusals are
// scope.ErrPrivilegeEscalation, and a cap compiling to nothing is
// [ErrEmptyPermissions]. A client for the other grants is not guarded
// here: it gets power only from a user's approval, which is guarded there.
func (s *Service) CreateClient(ctx context.Context, spec ClientSpec) (Client, string, error) {
	actor, containerID, err := ctxActor(ctx)
	if err != nil {
		return Client{}, "", err
	}
	if err := s.authorize(ctx, containerID, actor, scope.ActionUpdate); err != nil {
		return Client{}, "", err
	}
	if err := s.validateSpec(spec); err != nil {
		return Client{}, "", err
	}

	var encoded []byte
	if slices.Contains(spec.GrantTypes, GrantClientCredentials) {
		clientPerms, clientElevated, err := s.serviceAccountStanding(ctx, containerID, spec.ServiceAccountID)
		if err != nil {
			return Client{}, "", err
		}
		if spec.Permissions != nil {
			ceiling, err := s.auth.Access().Permission(spec.Permissions)
			if err != nil {
				return Client{}, "", err
			}
			if ceiling.IsZero() {
				return Client{}, "", ErrEmptyPermissions
			}
			if !clientElevated && !ceiling.SubsetOf(clientPerms) {
				return Client{}, "", scope.ErrPrivilegeEscalation
			}
			clientPerms = ceiling
			clientElevated = clientElevated && s.auth.Access().Full().Intersect(ceiling).IsFull()
			encoded = ceiling.Encode()
		}
		actorPerms, actorElevated, err := s.actorStanding(ctx, containerID, actor)
		if err != nil {
			return Client{}, "", err
		}
		if !actorElevated && (clientElevated || !clientPerms.SubsetOf(actorPerms)) {
			return Client{}, "", scope.ErrPrivilegeEscalation
		}
	}

	var secret, hash string
	if !spec.Public {
		if secret, hash, err = newSecret(); err != nil {
			return Client{}, "", err
		}
	}
	now := s.cfg.clock()
	c, err := s.st.CreateClient(ctx, Client{
		ID:               s.cfg.idgen(),
		ContainerID:      containerID,
		Name:             strings.TrimSpace(spec.Name),
		SecretHash:       hash,
		Public:           spec.Public,
		RedirectURIs:     slices.Clone(spec.RedirectURIs),
		GrantTypes:       slices.Clone(spec.GrantTypes),
		Scopes:           slices.Clone(spec.Scopes),
		ServiceAccountID: spec.ServiceAccountID,
		Permissions:      encoded,
		CreatedBy:        actor,
		CreatedAt:        now,
		UpdatedAt:        now,
	})
	if err != nil {
		return Client{}, "", err
	}
	if err := s.emit(ctx, Event{Kind: ClientCreated, ContainerID: containerID, ActorID: actor, ClientID: c.ID}); err != nil {
		return Client{}, "", err
	}
	return c, secret, nil
}

// RotateClientSecret replaces the client's secret and returns the new one —
// once, as CreateClient does. The old secret stops authenticating the
// instant the row is written; tokens already issued are untouched. The ctx
// subject needs service_account:update; a client in another container is
// [ErrClientNotFound]; a public client has no secret to rotate and is
// [ErrInvalidClientMetadata].
func (s *Service) RotateClientSecret(ctx context.Context, clientID string) (string, error) {
	actor, containerID, err := ctxActor(ctx)
	if err != nil {
		return "", err
	}
	if err := s.authorize(ctx, containerID, actor, scope.ActionUpdate); err != nil {
		return "", err
	}
	c, err := s.client(ctx, containerID, clientID)
	if err != nil {
		return "", err
	}
	if c.Public {
		return "", fmt.Errorf("%w: a public client holds no secret", ErrInvalidClientMetadata)
	}
	secret, hash, err := newSecret()
	if err != nil {
		return "", err
	}
	c.SecretHash = hash
	c.UpdatedAt = s.cfg.clock()
	if err := s.st.UpdateClient(ctx, c); err != nil {
		return "", err
	}
	return secret, nil
}

// DisableClient stamps the client's DisabledAt: every token endpoint
// refuses it with [ErrClientDisabled] from now on, no consent can begin,
// and [Service.Authenticate] refuses its client-credentials tokens; its
// delegated access tokens live out their TTL, since a JWT cannot be
// recalled, and their refresh is refused. Grants are untouched, so
// [Service.EnableClient] restores the client exactly. The ctx subject needs
// service_account:update; a client in another container is
// [ErrClientNotFound]. Disabling a disabled client is not an error.
func (s *Service) DisableClient(ctx context.Context, clientID string) error {
	return s.setDisabled(ctx, clientID, true)
}

// EnableClient clears the client's DisabledAt. The ctx subject needs
// service_account:update; a client in another container is
// [ErrClientNotFound]. Enabling an enabled client is not an error.
func (s *Service) EnableClient(ctx context.Context, clientID string) error {
	return s.setDisabled(ctx, clientID, false)
}

func (s *Service) setDisabled(ctx context.Context, clientID string, disabled bool) error {
	actor, containerID, err := ctxActor(ctx)
	if err != nil {
		return err
	}
	if err := s.authorize(ctx, containerID, actor, scope.ActionUpdate); err != nil {
		return err
	}
	c, err := s.client(ctx, containerID, clientID)
	if err != nil {
		return err
	}
	now := s.cfg.clock()
	kind := ClientEnabled
	c.DisabledAt = nil
	if disabled {
		c.DisabledAt = &now
		kind = ClientDisabled
	}
	c.UpdatedAt = now
	if err := s.st.UpdateClient(ctx, c); err != nil {
		return err
	}
	return s.emit(ctx, Event{Kind: kind, ContainerID: containerID, ActorID: actor, ClientID: clientID})
}

// UpdateClientRedirectURIs replaces the client's exact-match allowlist. The
// ctx subject needs service_account:update; a client in another container
// is [ErrClientNotFound]; each URI is validated on [ClientSpec]'s terms,
// and an authorization-code client may not be left with none
// ([ErrInvalidClientMetadata]). Codes already issued against a URI that is
// removed still name it and will still redeem within their sixty seconds.
func (s *Service) UpdateClientRedirectURIs(ctx context.Context, clientID string, uris []string) error {
	actor, containerID, err := ctxActor(ctx)
	if err != nil {
		return err
	}
	if err := s.authorize(ctx, containerID, actor, scope.ActionUpdate); err != nil {
		return err
	}
	c, err := s.client(ctx, containerID, clientID)
	if err != nil {
		return err
	}
	if err := validateRedirectURIs(uris); err != nil {
		return err
	}
	if slices.Contains(c.GrantTypes, GrantAuthorizationCode) && len(uris) == 0 {
		return fmt.Errorf("%w: authorization_code requires at least one redirect URI", ErrInvalidClientMetadata)
	}
	c.RedirectURIs = slices.Clone(uris)
	c.UpdatedAt = s.cfg.clock()
	return s.st.UpdateClient(ctx, c)
}

// ListClients returns every client owned by the ctx container, disabled
// ones included — read DisabledAt. The ctx subject needs
// service_account:read. Application-level clients are never listed here:
// they belong to no container.
func (s *Service) ListClients(ctx context.Context) ([]Client, error) {
	actor, containerID, err := ctxActor(ctx)
	if err != nil {
		return nil, err
	}
	if err := s.authorize(ctx, containerID, actor, scope.ActionRead); err != nil {
		return nil, err
	}
	return s.st.ListClients(ctx, containerID)
}

// DeleteClient removes the client and, atomically with it, every grant,
// code, device authorization and refresh token that names it
// ([Store.DeleteClient]'s cascade MUST). Delegated access tokens already
// issued live out their TTL and then have no grant to refresh under;
// [Service.Authenticate] refuses them at once unless
// [WithOfflineVerification] is on. The ctx subject needs
// service_account:delete; a client in another container is
// [ErrClientNotFound].
func (s *Service) DeleteClient(ctx context.Context, clientID string) error {
	actor, containerID, err := ctxActor(ctx)
	if err != nil {
		return err
	}
	if err := s.authorize(ctx, containerID, actor, scope.ActionDelete); err != nil {
		return err
	}
	if _, err := s.client(ctx, containerID, clientID); err != nil {
		return err
	}
	if err := s.st.DeleteClient(ctx, clientID); err != nil {
		return err
	}
	return s.emit(ctx, Event{Kind: ClientDeleted, ContainerID: containerID, ActorID: actor, ClientID: clientID})
}

// authenticateClient is the token-endpoint client authentication every
// grant, Refresh and Revoke run first. An unknown id, a wrong secret, a
// missing secret on a confidential client or a secret presented for a
// public one are all [ErrInvalidClient] (wrapping ErrClientNotFound for the
// first, so the operator's log can tell); the secret is compared in
// constant time against its sha256 — see [Client.SecretHash] for why not
// bcrypt. A disabled client is [ErrClientDisabled], reported only after the
// secret verified, so a wrong secret learns nothing about the client's
// state. The grant-type check is the caller's: this only says who the
// client is.
func (s *Service) authenticateClient(ctx context.Context, clientID, clientSecret string) (Client, error) {
	c, err := s.st.FindClient(ctx, clientID)
	if err != nil {
		if errors.Is(err, ErrClientNotFound) {
			return Client{}, fmt.Errorf("%w: %w", ErrInvalidClient, err)
		}
		return Client{}, err
	}
	if c.Public {
		if clientSecret != "" {
			return Client{}, fmt.Errorf("%w: a public client presented a secret", ErrInvalidClient)
		}
	} else {
		if clientSecret == "" {
			return Client{}, fmt.Errorf("%w: no secret presented", ErrInvalidClient)
		}
		// subtle.ConstantTimeCompare over the two hex hashes: equal length
		// by construction, and the comparison time is independent of where
		// they differ.
		if subtle.ConstantTimeCompare([]byte(token.HashOpaque(clientSecret)), []byte(c.SecretHash)) != 1 {
			return Client{}, fmt.Errorf("%w: wrong secret", ErrInvalidClient)
		}
	}
	if c.DisabledAt != nil {
		return Client{}, ErrClientDisabled
	}
	return c, nil
}

// requireGrantType refuses a client that does not hold gt with
// [ErrUnauthorizedClient].
func requireGrantType(c Client, gt string) error {
	if !slices.Contains(c.GrantTypes, gt) {
		return fmt.Errorf("%w: %s", ErrUnauthorizedClient, gt)
	}
	return nil
}
