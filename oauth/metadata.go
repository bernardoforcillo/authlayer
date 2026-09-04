package oauth

import "slices"

// Endpoints names the URLs an application serves this package's flows at.
// Every field is optional except Authorization and Token; an empty field is
// omitted from the metadata so a client does not discover an endpoint that
// does not exist.
type Endpoints struct {
	// Authorization is where BeginAuthorization and Approve are reached
	// (RFC 8414 authorization_endpoint).
	Authorization string
	// Token is where ClientCredentials, ExchangeCode, Refresh and
	// PollDevice are reached (token_endpoint).
	Token string
	// JWKS is where the signer's PublicKeySet is served (jwks_uri).
	JWKS string
	// Revocation is where Revoke is reached (RFC 7009,
	// revocation_endpoint).
	Revocation string
	// Introspection is where Introspect is reached (RFC 7662,
	// introspection_endpoint).
	Introspection string
	// DeviceAuthorization is where BeginDeviceAuthorization is reached
	// (RFC 8628 §4, device_authorization_endpoint).
	DeviceAuthorization string
	// Registration is where RegisterClient is reached (RFC 7591,
	// registration_endpoint). Publish it only with WithDynamicRegistration
	// on.
	Registration string
}

// AuthorizationServerMetadata is the RFC 8414 discovery document, served at
// /.well-known/oauth-authorization-server. It is a struct with JSON tags
// and nothing else — serialise it yourself, at the path RFC 8414 §3
// derives from the issuer.
type AuthorizationServerMetadata struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	JWKSURI                           string   `json:"jwks_uri,omitempty"`
	RegistrationEndpoint              string   `json:"registration_endpoint,omitempty"`
	RevocationEndpoint                string   `json:"revocation_endpoint,omitempty"`
	IntrospectionEndpoint             string   `json:"introspection_endpoint,omitempty"`
	DeviceAuthorizationEndpoint       string   `json:"device_authorization_endpoint,omitempty"`
	ScopesSupported                   []string `json:"scopes_supported,omitempty"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
}

// The token endpoint authentication methods this package accepts (RFC 8414
// token_endpoint_auth_methods_supported, RFC 7591 token_endpoint_auth_method).
// The two secret methods are the same secret carried two ways; which one a
// request used is the application's transport concern, since both reach
// [Service.ClientCredentials] and its siblings as a plain clientSecret.
const (
	AuthMethodClientSecretBasic = "client_secret_basic"
	AuthMethodClientSecretPost  = "client_secret_post"
	AuthMethodNone              = "none"
)

// ServerMetadata builds the RFC 8414 document for issuer with the endpoints
// in e: response_types_supported ["code"], grant_types_supported the four
// this package implements, code_challenge_methods_supported ["S256"] and
// nothing else (PKCE is mandatory and plain is refused),
// token_endpoint_auth_methods_supported the three above, scopes_supported
// the keys of [WithScopeMap] when one is set, and each optional endpoint
// when e names it. An empty issuer falls back to the one [WithIssuer]
// configured; the two must agree, since RFC 8414 §2 requires the issuer
// here to equal the iss in tokens.
func (s *Service) ServerMetadata(issuer string, e Endpoints) AuthorizationServerMetadata {
	if issuer == "" {
		issuer = s.cfg.issuer
	}
	return AuthorizationServerMetadata{
		Issuer:                            issuer,
		AuthorizationEndpoint:             e.Authorization,
		TokenEndpoint:                     e.Token,
		JWKSURI:                           e.JWKS,
		RegistrationEndpoint:              e.Registration,
		RevocationEndpoint:                e.Revocation,
		IntrospectionEndpoint:             e.Introspection,
		DeviceAuthorizationEndpoint:       e.DeviceAuthorization,
		ScopesSupported:                   slices.Clone(s.scopes),
		ResponseTypesSupported:            []string{"code"},
		GrantTypesSupported:               slices.Clone(KnownGrantTypes),
		CodeChallengeMethodsSupported:     []string{"S256"},
		TokenEndpointAuthMethodsSupported: []string{AuthMethodClientSecretBasic, AuthMethodClientSecretPost, AuthMethodNone},
	}
}

// ProtectedResourceMetadata is the RFC 9728 document a resource server
// serves at /.well-known/oauth-protected-resource, so an MCP client that
// hits the resource first learns which authorization server to go to. A
// struct with JSON tags, serialised by the application.
type ProtectedResourceMetadata struct {
	Resource               string   `json:"resource"`
	AuthorizationServers   []string `json:"authorization_servers"`
	ScopesSupported        []string `json:"scopes_supported,omitempty"`
	BearerMethodsSupported []string `json:"bearer_methods_supported,omitempty"`
}

// ProtectedResourceMetadata builds the RFC 9728 document for resource,
// naming authorizationServers (their issuer URLs) and scopes — or, when
// scopes is nil, the keys of [WithScopeMap]. bearer_methods_supported is
// ["header"]: this package's tokens are meant for the Authorization
// header, never a query string.
func (s *Service) ProtectedResourceMetadata(resource string, authorizationServers, scopes []string) ProtectedResourceMetadata {
	if scopes == nil {
		scopes = slices.Clone(s.scopes)
	}
	return ProtectedResourceMetadata{
		Resource:               resource,
		AuthorizationServers:   slices.Clone(authorizationServers),
		ScopesSupported:        scopes,
		BearerMethodsSupported: []string{"header"},
	}
}
