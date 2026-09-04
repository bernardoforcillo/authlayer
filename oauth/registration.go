package oauth

import (
	"context"
	"fmt"
	"slices"
	"strings"
)

// ClientRegistration is the RFC 7591 §2 client metadata subset
// [Service.RegisterClient] accepts, with that RFC's JSON names so a
// registration request body decodes straight into it. Anything the RFC
// defines and this struct omits — client_uri, logo_uri, contacts, jwks —
// is ignored on the way in, not refused.
type ClientRegistration struct {
	// ClientName is what a consent screen shows; required.
	ClientName string `json:"client_name"`
	// RedirectURIs is the exact-match allowlist; required for the
	// authorization-code grant, validated on [ClientSpec]'s terms.
	RedirectURIs []string `json:"redirect_uris,omitempty"`
	// GrantTypes defaults to authorization_code and refresh_token when
	// empty (RFC 7591 §2). client_credentials is refused: a dynamically
	// registered client has no service account to act as.
	GrantTypes []string `json:"grant_types,omitempty"`
	// TokenEndpointAuthMethod is "none" for a public client — the shape an
	// MCP client in a browser or a CLI takes — or one of the two secret
	// methods (or empty, which RFC 7591 defaults to client_secret_basic)
	// for a confidential one, which is issued a secret.
	TokenEndpointAuthMethod string `json:"token_endpoint_auth_method,omitempty"`
	// Scope is the space-separated list of scopes the client will request;
	// each must be known to [WithScopeMap] when one is set. Empty means
	// any the server knows.
	Scope string `json:"scope,omitempty"`
}

// RegisterClient is RFC 7591 dynamic client registration: it creates an
// APPLICATION-LEVEL client (ContainerID "", CreatedBy "") from reg and
// returns it with its secret — once, and "" for a public client. It reads
// no subject and performs no authorization: the endpoint is open by
// design, since a client has no power until a user approves it, and is
// refused outright with [ErrRegistrationDisabled] unless the Service was
// built with WithDynamicRegistration(true). The RFC's response
// (client_id, client_secret, client_id_issued_at, and the metadata echoed
// back) is the application's to write from the returned Client.
//
// The grant types are limited to authorization_code, refresh_token and
// device_code — never client_credentials, which needs a service account no
// anonymous registrant can name — and every other rule is [ClientSpec]'s:
// [ErrInvalidClientMetadata], [ErrInvalidRedirectURI], [ErrInvalidScope].
// A public client (token_endpoint_auth_method "none") gets no secret and
// PKCE, which every client gets here anyway.
func (s *Service) RegisterClient(ctx context.Context, reg ClientRegistration) (Client, string, error) {
	if !s.cfg.dynamicRegistration {
		return Client{}, "", ErrRegistrationDisabled
	}
	grantTypes := slices.Clone(reg.GrantTypes)
	if len(grantTypes) == 0 {
		grantTypes = []string{GrantAuthorizationCode, GrantRefreshToken}
	}
	if slices.Contains(grantTypes, GrantClientCredentials) {
		return Client{}, "", fmt.Errorf("%w: client_credentials cannot be registered dynamically", ErrInvalidClientMetadata)
	}
	var public bool
	switch reg.TokenEndpointAuthMethod {
	case AuthMethodNone:
		public = true
	case "", AuthMethodClientSecretBasic, AuthMethodClientSecretPost:
	default:
		return Client{}, "", fmt.Errorf("%w: unsupported token_endpoint_auth_method %q", ErrInvalidClientMetadata, reg.TokenEndpointAuthMethod)
	}
	spec := ClientSpec{
		Name:         reg.ClientName,
		Public:       public,
		RedirectURIs: reg.RedirectURIs,
		GrantTypes:   grantTypes,
		Scopes:       splitScope(reg.Scope),
	}
	if err := s.validateSpec(spec); err != nil {
		return Client{}, "", err
	}

	var secret, hash string
	var err error
	if !public {
		if secret, hash, err = newSecret(); err != nil {
			return Client{}, "", err
		}
	}
	now := s.cfg.clock()
	c, err := s.st.CreateClient(ctx, Client{
		ID:           s.cfg.idgen(),
		Name:         strings.TrimSpace(spec.Name),
		SecretHash:   hash,
		Public:       public,
		RedirectURIs: slices.Clone(spec.RedirectURIs),
		GrantTypes:   spec.GrantTypes,
		Scopes:       spec.Scopes,
		CreatedAt:    now,
		UpdatedAt:    now,
	})
	if err != nil {
		return Client{}, "", err
	}
	if err := s.emit(ctx, Event{Kind: ClientRegistered, ClientID: c.ID}); err != nil {
		return Client{}, "", err
	}
	return c, secret, nil
}
