// Package oauth makes an authlayer application an OAuth 2.1 authorization
// server as a library: clients, three grants, delegated tokens that never
// carry more power than the human or service account behind them, refresh
// with rotation and reuse detection, introspection, revocation, discovery
// metadata and dynamic client registration — with no HTTP, no handlers and
// no cookies. The application owns every endpoint and serialises the structs
// this package returns; every method takes a context and returns values.
//
// It exists so agents — CLIs, MCP clients, automation — and machine clients
// authenticate against every product the same way, and so a token an agent
// holds is checked by the same [scope] engine, through the same
// [apikey.Principal] and [apikey.WithPrincipal], as a session or an API key.
//
// # The three grants, and the one delegation model
//
//	Client credentials (RFC 6749 §4.4)     a machine client bound to an apikey.ServiceAccount; sub = the account
//	Device authorization (RFC 8628)        an agent with no browser; a user approves a code; sub = the user, act.sub = the client
//	Authorization code + PKCE (OAuth 2.1)  a third-party or MCP client with a redirect URI; sub = the user, act.sub = the client
//
// A client-credentials token acts AS the service account: its subject is the
// account's id, which is a member of the container, so [scope.Service.Can]
// resolves the account's role exactly as it does for an API key. The other
// two grants produce DELEGATED tokens (RFC 8693 §4.1 "act"): the subject is
// the user who approved, the actor is the client, and the token is bound to a
// [Grant] — one user's delegation to one client in one container. A
// delegated token authenticates as [apikey.KindDelegated] with the grant's
// permission cap, and [apikey.WithPrincipal] installs that cap on the
// context, so the agent's effective standing is the user's CURRENT standing
// ∩ the cap. Revoking the human's role revokes the agent with it; nothing is
// copied onto the token that the engine would later have to trust.
//
// # Every mint is an escalation guard
//
// A cap is only ever a ceiling, and every place one is minted checks it
// against the standing it is carved from: a delegation cap must be within
// the grantor's standing ([Service.Approve], [Service.ApproveDevice]); a
// client-credentials cap must be within the service account's role
// ([Service.CreateClient], re-checked at [Service.ClientCredentials]); and
// where an administrator mints, the client's whole power must be within that
// administrator's own capped standing — so a restricted API key cannot
// register a client that exceeds the key. The refusal is
// scope.ErrPrivilegeEscalation in every case, and a cap compiling to nothing
// is [ErrEmptyPermissions] rather than stored as "no cap".
//
// # What a token carries
//
// Access tokens are JWTs through a [token.Signer] — the same signer
// [github.com/bernardoforcillo/authlayer/auth.Service.Signer] exposes, so one
// verifier accepts both — with sub, iss, aud, jti, client_id, scope, exp and
// iat; delegated tokens add act and the grant and container ids; client
// credentials tokens add the container id. The permission cap travels in
// the token as well (Extra["permissions"]), signed, so [Service.Authenticate]
// can build a principal without a store read when
// [WithOfflineVerification] is on; with it off, every delegated token is
// checked against its grant's liveness first. Refresh tokens are opaque
// ([token.GenerateOpaque]), stored only as their sha256, rotated on every
// use, and a replay of a rotated one revokes the whole family AND the grant.
//
// # What is NOT here
//
// Endpoints, a consent screen, a token store for clients, and any HTTP at
// all. [ErrorCode] maps every sentinel to the RFC 6749 §5.2 error code and a
// status; the application writes the JSON. Discovery documents
// ([AuthorizationServerMetadata], [ProtectedResourceMetadata]) are structs
// with JSON tags. The JWKS is the signer's own ([token.PublicKeySetter]).
//
// # Storage
//
// [Store] is the persistence port: five record kinds, with the obligations
// that matter stated as MUSTs on the port and exercised by
// [github.com/bernardoforcillo/authlayer/oauth/oauthtest] — the contract as
// an executable suite both shipped backends run. store/memory holds the
// reference implementation and store/drops the production one.
package oauth

import (
	"context"
	"errors"
	"time"

	"github.com/bernardoforcillo/authlayer/apikey"
)

// The grant types this package implements, as the strings RFC 6749 §4.1.3,
// §6 and §4.4 and RFC 8628 §3.4 put in a token request's grant_type and RFC
// 7591 puts in a client's grant_types. [Client.GrantTypes] holds a subset.
const (
	// GrantAuthorizationCode is the browser flow with PKCE (OAuth 2.1 §4.1).
	GrantAuthorizationCode = "authorization_code"
	// GrantRefreshToken lets a client renew an access token (RFC 6749 §6).
	// A client without it gets no refresh token from any grant.
	GrantRefreshToken = "refresh_token"
	// GrantClientCredentials is the machine-to-machine grant (RFC 6749 §4.4).
	// Only a confidential client bound to a service account may hold it.
	GrantClientCredentials = "client_credentials"
	// GrantDeviceCode is the device authorization grant (RFC 8628 §3.4).
	GrantDeviceCode = "urn:ietf:params:oauth:grant-type:device_code"
)

// KnownGrantTypes lists every grant type this package implements, in the
// order metadata publishes them. Anything else in a [ClientSpec] is
// [ErrInvalidClientMetadata].
var KnownGrantTypes = []string{GrantAuthorizationCode, GrantRefreshToken, GrantClientCredentials, GrantDeviceCode}

// Client is an OAuth client — an application-level one (registered by an
// operator or dynamically) or one owned by a container, where it is a
// credential of that organization managed under the same
// scope.ResourceServiceAccount grants as its service accounts.
type Client struct {
	// ID is the client_id: minted by the Service id generator, never chosen
	// by the client.
	ID string `drop:"id"`
	// ContainerID is the scope that owns the client, or "" for an
	// application-level client — one registered through
	// [Service.RegisterClient] or written by the operator. The management
	// calls reach only the ctx container's clients; application-level ones
	// are reachable through the token endpoints alone.
	ContainerID string `drop:"container_id"`
	// Name is what a consent screen shows.
	Name string `drop:"name"`
	// SecretHash is [token.HashOpaque] of the client secret, and the only
	// form the secret ever reaches a Store in; "" for a public client. The
	// secret is 32 bytes of crypto/rand, so a sha256 is the right hash for
	// it: bcrypt exists to slow a guess at a LOW-entropy password, and a
	// 256-bit random string cannot be guessed at any speed — while every
	// token request would pay bcrypt's cost. The comparison is constant-time.
	SecretHash string `drop:"secret_hash"`
	// Public marks a client that holds no secret — a CLI, a native app, a
	// browser-based MCP client. A public client gets PKCE mandatory (every
	// client does here), is never issued a secret, and may not hold
	// GrantClientCredentials: with nothing to authenticate, a machine grant
	// would let anyone mint as the service account.
	Public bool `drop:"public"`
	// RedirectURIs is the exact-match allowlist for the authorization-code
	// grant (OAuth 2.1 §4.1.2.1): a request's redirect_uri must equal one of
	// them byte for byte. No prefix or pattern matching — an open redirector
	// turns every code into a leak. store/drops keeps it as jsonb.
	RedirectURIs []string `drop:"redirect_uris"`
	// GrantTypes is the subset of the Grant* constants the client may use.
	// A token request for any other grant is [ErrUnauthorizedClient].
	GrantTypes []string `drop:"grant_types"`
	// Scopes is the list of scope strings the client may request; empty
	// means any scope the server knows — the keys of [WithScopeMap] when one
	// is set, anything at all when none is.
	Scopes []string `drop:"scopes"`
	// ServiceAccountID is the [apikey.ServiceAccount] a client-credentials
	// token acts as, and is required exactly when GrantTypes contains
	// GrantClientCredentials; "" otherwise. The account must be a member of
	// ContainerID.
	ServiceAccountID string `drop:"service_account_id"`
	// Permissions is an optional cap on client-credentials tokens, as
	// [access.Permission.Encode] bytes: the token's effective standing is
	// the account's role ∩ this. nil or empty means no cap. It follows the
	// apikey.Key.Permissions convention exactly — empty bytes are "no cap",
	// so a cap granting nothing cannot be stored and [Service.CreateClient]
	// refuses one with [ErrEmptyPermissions].
	Permissions []byte `drop:"permissions"`
	// CreatedBy is the user id of the actor who created the client; "" for
	// a dynamically registered one, which no user vouched for.
	CreatedBy string `drop:"created_by"`
	// CreatedAt is stamped by the Service clock.
	CreatedAt time.Time `drop:"created_at"`
	// UpdatedAt is stamped by the Service clock on every change.
	UpdatedAt time.Time `drop:"updated_at"`
	// DisabledAt is when the client was disabled; nil means active. While
	// set, every token endpoint refuses the client with [ErrClientDisabled]
	// and no consent can begin; access tokens already issued live out their
	// TTL, refresh tokens are refused, so the client is fully out within
	// one access-token lifetime. Grants are untouched, so enabling restores
	// the client exactly.
	DisabledAt *time.Time `drop:"disabled_at"`
}

// Grant is one user's delegation to one client in one container: the row a
// "connected apps" screen lists, the thing [Service.RevokeGrant] revokes,
// and what every delegated token is bound to. Every approval creates a new
// Grant — two devices approving the same client are two consents, revocable
// separately.
type Grant struct {
	// ID is minted by the Service and carried in every delegated token.
	ID string `drop:"id"`
	// ClientID is the client acting.
	ClientID string `drop:"client_id"`
	// UserID is the user who approved and whose standing the client acts
	// within — the token's sub.
	UserID string `drop:"user_id"`
	// ContainerID is the scope the user approved in.
	ContainerID string `drop:"container_id"`
	// Scope is the space-separated scope string as approved.
	Scope string `drop:"scope"`
	// Permissions is the delegation cap as [access.Permission.Encode] bytes:
	// the token's standing is the user's current standing ∩ this. nil or
	// empty means no cap — the user's whole standing, which is still never
	// more than the user holds at the moment of each check.
	Permissions []byte `drop:"permissions"`
	// CreatedAt is stamped by the Service clock.
	CreatedAt time.Time `drop:"created_at"`
	// ExpiresAt is when the grant stops minting and authenticating; nil
	// means until revoked. Set from [WithGrantTTL].
	ExpiresAt *time.Time `drop:"expires_at"`
	// LastUsedAt is stamped by [Store.TouchGrant] on each token minted or
	// verified under it, best-effort.
	LastUsedAt *time.Time `drop:"last_used_at"`
	// RevokedAt is when the grant was revoked; nil means live. A revoked
	// grant is never un-revoked: the user approves again.
	RevokedAt *time.Time `drop:"revoked_at"`
}

// AuthorizationCode is one authorization code: minted by [Service.Approve],
// redeemed exactly once by [Service.ExchangeCode]. The plaintext is never
// stored.
type AuthorizationCode struct {
	// ID is minted by the Service.
	ID string `drop:"id"`
	// CodeHash is [token.HashOpaque] of the code. An implementation MUST
	// enforce that it is unique across every row — a UNIQUE constraint in a
	// SQL backend: [Store.RedeemCode] is a compare-and-set keyed by this
	// hash, and two rows sharing one would let two concurrent redemptions
	// each atomically win a different row, which is exactly the double
	// redemption the compare-and-set exists to prevent, reached with no
	// atomicity defect at all.
	CodeHash string `drop:"code_hash,unique"`
	// ClientID is the client the code was issued to; the exchange must come
	// from the same one.
	ClientID string `drop:"client_id"`
	// GrantID is the grant the code redeems into tokens for.
	GrantID string `drop:"grant_id"`
	// RedirectURI is the one the authorization request named; the exchange
	// must repeat it (RFC 6749 §4.1.3).
	RedirectURI string `drop:"redirect_uri"`
	// CodeChallenge is the S256 challenge (RFC 7636 §4.2) the exchange's
	// verifier must hash to. Only S256 is accepted, so no method column.
	CodeChallenge string `drop:"code_challenge"`
	// ExpiresAt is CreatedAt plus [WithCodeTTL]; a code is valid strictly
	// before it. Expiry is NOT part of RedeemCode's predicate — the Service
	// checks it after winning.
	ExpiresAt time.Time `drop:"expires_at"`
	// CreatedAt is stamped by the Service clock.
	CreatedAt time.Time `drop:"created_at"`
	// RedeemedAt is set by the one winning RedeemCode; nil means unredeemed.
	RedeemedAt *time.Time `drop:"redeemed_at"`
}

// DeviceStatus is the state of a [DeviceAuthorization].
type DeviceStatus string

// The device statuses, and the two compare-and-set transitions between
// them: pending → approved or denied (by the user), approved → redeemed (by
// the polling client).
const (
	DeviceStatusPending  DeviceStatus = "pending"
	DeviceStatusApproved DeviceStatus = "approved"
	DeviceStatusDenied   DeviceStatus = "denied"
	DeviceStatusRedeemed DeviceStatus = "redeemed"
)

// DeviceAuthorization is one RFC 8628 device authorization: begun by the
// client, approved or denied by a user through its user code, polled by the
// client through its device code.
type DeviceAuthorization struct {
	// ID is minted by the Service.
	ID string `drop:"id"`
	// DeviceCodeHash is [token.HashOpaque] of the device code the client
	// polls with. An implementation MUST enforce that it is unique across
	// every row, for the reason [AuthorizationCode.CodeHash] gives:
	// [Store.SetDeviceStatus] is keyed by the row the hash resolves to.
	DeviceCodeHash string `drop:"device_code_hash,unique"`
	// UserCode is the eight-character code a person types, from the
	// alphabet BCDFGHJKLMNPQRSTVWXZ (RFC 8628 §6.1 — no vowels, so no words;
	// no 0/O/1/I confusions), stored without the display dash and in upper
	// case. An implementation MUST enforce that it is unique across every
	// row: a person types it into a consent screen, and two pending
	// authorizations sharing one would have that person approve whichever
	// the backend returned first.
	UserCode string `drop:"user_code,unique"`
	// ClientID is the client that began the authorization.
	ClientID string `drop:"client_id"`
	// Scope is the space-separated scope string requested.
	Scope string `drop:"scope"`
	// Status is the state; see [DeviceStatus].
	Status DeviceStatus `drop:"status"`
	// GrantID is the grant created on approval; "" until then. store/drops
	// keeps it nullable.
	GrantID string `drop:"grant_id"`
	// Interval is the minimum seconds between polls (RFC 8628 §3.2); a
	// poll sooner than that after LastPolledAt is [ErrSlowDown].
	Interval int `drop:"interval"`
	// LastPolledAt is stamped by [Store.TouchDevicePoll] on every poll.
	LastPolledAt *time.Time `drop:"last_polled_at"`
	// ExpiresAt is CreatedAt plus [WithDeviceTTL]; a poll after it is
	// [ErrExpiredToken].
	ExpiresAt time.Time `drop:"expires_at"`
	// CreatedAt is stamped by the Service clock.
	CreatedAt time.Time `drop:"created_at"`
}

// RefreshToken is one refresh token's row, in exactly the shape of an
// auth.Session: minted at exchange or at a prior rotation, current until
// [Store.MarkRefreshRotated] supersedes it, and grouped into a family that a
// detected replay revokes whole. The plaintext is never stored.
type RefreshToken struct {
	// ID is minted by the Service.
	ID string `drop:"id"`
	// TokenHash is [token.HashOpaque] of the plaintext. An implementation
	// MUST enforce that it is unique across every row, for exactly the
	// reason auth.Session.TokenHash states: MarkRefreshRotated's
	// single-winner contract breaks without it with no atomicity defect at
	// all.
	TokenHash string `drop:"token_hash,unique"`
	// GrantID is the grant the token renews access under.
	GrantID string `drop:"grant_id"`
	// ClientID is the client the token was issued to; a refresh must come
	// from the same one.
	ClientID string `drop:"client_id"`
	// FamilyID is shared by every token in one rotation chain, and is what
	// [Store.DeleteRefreshFamily] deletes by. The first token of a chain
	// has FamilyID equal to its own ID.
	FamilyID string `drop:"family_id"`
	// ExpiresAt is when the token stops refreshing; a rotated token is kept
	// until then so a replay of it is still detected.
	ExpiresAt time.Time `drop:"expires_at"`
	// CreatedAt is stamped by the Service clock.
	CreatedAt time.Time `drop:"created_at"`
	// RotatedAt is nil while the token is current and set when it was
	// superseded; presenting a rotated token is a replay.
	RotatedAt *time.Time `drop:"rotated_at"`
}

// Sentinel errors returned by a Store implementation and by the Service.
// Compare with [errors.Is], never by string — the messages are not part of
// the API. [ErrorCode] maps each to the RFC 6749 §5.2 (or RFC 8628 §3.5, RFC
// 6750 §3.1, RFC 7591 §3.2.2) error code and a suggested HTTP status; the
// table on it is the one the readme reproduces.
//
// They fall into four groups:
//
//   - Not found — ErrClientNotFound, ErrGrantNotFound, ErrCodeNotFound,
//     ErrDeviceNotFound, ErrRefreshNotFound. A Store returns these itself on
//     any lookup, update or delete that matches no row; the management calls
//     also return ErrClientNotFound, deliberately, for a client in ANOTHER
//     container than the one on the context. At a token endpoint the Service
//     wraps the last three in ErrInvalidGrant, since RFC 6749 does not tell a
//     client whether its code was unknown or spent.
//   - Refused at a token endpoint — ErrInvalidClient, ErrClientDisabled,
//     ErrUnauthorizedClient, ErrInvalidGrant, ErrInvalidScope,
//     ErrCodeReused, ErrTokenReuse, ErrPKCEMismatch, ErrGrantRevoked,
//     ErrGrantExpired, and the four RFC 8628 polling answers
//     ErrAuthorizationPending, ErrSlowDown, ErrAccessDenied, ErrExpiredToken.
//   - Refused at the authorization or consent step — ErrInvalidRedirectURI,
//     ErrPKCERequired, ErrDeviceNotPending, ErrInvalidClientMetadata,
//     ErrRegistrationDisabled, ErrEmptyPermissions.
//   - A bad token, or a wiring bug — ErrInvalidToken (wrapping the cause),
//     ErrIssuerRequired, ErrIDTaken.
//
// Denials come from scope and are not re-declared: a management call the
// actor may not make is scope.ErrForbidden (or scope.ErrNotMember), minting
// above one's standing is scope.ErrPrivilegeEscalation, and revoking
// someone else's grant is scope.ErrForbidden.
var (
	// ErrClientNotFound: no client with that id — or, from the management
	// calls, one that belongs to another container than the ctx one.
	ErrClientNotFound = errors.New("authlayer/oauth: client not found")
	// ErrClientDisabled: the client's DisabledAt is set.
	ErrClientDisabled = errors.New("authlayer/oauth: client is disabled")
	// ErrInvalidClient: client authentication failed at a token endpoint —
	// an unknown client id, a wrong secret, a secret where none is held, or
	// (wrapped) a service account the client is bound to that is missing,
	// disabled or no longer a member. RFC 6749 §5.2 invalid_client.
	ErrInvalidClient = errors.New("authlayer/oauth: client authentication failed")
	// ErrInvalidClientMetadata: a [ClientSpec] or [ClientRegistration] is
	// not one this package can honour — an unknown grant type, a public
	// client asking for client_credentials, client_credentials without a
	// service account (or the reverse), an authorization-code client with
	// no redirect URI, a rotation of a public client's secret. RFC 7591
	// §3.2.2 invalid_client_metadata.
	ErrInvalidClientMetadata = errors.New("authlayer/oauth: client metadata is invalid")
	// ErrInvalidGrant: the code, refresh token or device code is unknown,
	// spent, expired, issued to another client, or presented with the wrong
	// redirect URI. RFC 6749 §5.2 invalid_grant. Wraps the specific cause
	// where one is safe to log.
	ErrInvalidGrant = errors.New("authlayer/oauth: invalid grant")
	// ErrCodeReused: an authorization code was presented a second time. The
	// grant it minted is revoked (OAuth 2.1 §4.1.2), so the tokens the first
	// redemption produced stop working too.
	ErrCodeReused = errors.New("authlayer/oauth: authorization code already redeemed; grant revoked")
	// ErrTokenReuse: a rotated-away refresh token was presented again. The
	// whole family and the grant are revoked. Returned alone the revocation
	// succeeded; joined with another error it did not, and the family may
	// still be live — check with errors.Is before anything else, as with
	// auth.ErrTokenReuse.
	ErrTokenReuse = errors.New("authlayer/oauth: refresh token reuse detected; family and grant revoked")
	// ErrInvalidScope: a requested scope is not one the client may request,
	// or not one the server knows. RFC 6749 §5.2 invalid_scope.
	ErrInvalidScope = errors.New("authlayer/oauth: invalid scope")
	// ErrUnauthorizedClient: the client's GrantTypes does not include the
	// grant it asked for. RFC 6749 §5.2 unauthorized_client.
	ErrUnauthorizedClient = errors.New("authlayer/oauth: client is not authorized for this grant type")
	// ErrInvalidRedirectURI: the redirect URI is not one of the client's
	// registered ones (exact match), or is not an absolute URI without a
	// fragment at registration. RFC 7591 §3.2.2 invalid_redirect_uri.
	ErrInvalidRedirectURI = errors.New("authlayer/oauth: redirect URI is not registered")
	// ErrPKCERequired: the authorization request carries no S256 code
	// challenge, or a "plain" one. PKCE is mandatory for every client here
	// (OAuth 2.1 §4.1.1), not only public ones.
	ErrPKCERequired = errors.New("authlayer/oauth: a S256 code_challenge is required")
	// ErrPKCEMismatch: S256(code_verifier) is not the challenge the code was
	// issued against, or the verifier is not 43–128 characters. RFC 7636
	// §4.6 says invalid_grant.
	ErrPKCEMismatch = errors.New("authlayer/oauth: code_verifier does not match the code_challenge")
	// ErrAuthorizationPending: the device authorization is still waiting
	// for the user. RFC 8628 §3.5 authorization_pending — keep polling.
	ErrAuthorizationPending = errors.New("authlayer/oauth: authorization pending")
	// ErrSlowDown: the client polled sooner than Interval seconds after its
	// last poll. RFC 8628 §3.5 slow_down — add five seconds and keep polling.
	ErrSlowDown = errors.New("authlayer/oauth: polling too fast")
	// ErrAccessDenied: the user denied the device authorization. RFC 8628
	// §3.5 access_denied.
	ErrAccessDenied = errors.New("authlayer/oauth: access denied")
	// ErrExpiredToken: the device code expired before the user decided. RFC
	// 8628 §3.5 expired_token.
	ErrExpiredToken = errors.New("authlayer/oauth: device code expired")
	// ErrDeviceNotFound: no device authorization with that device code
	// hash or user code.
	ErrDeviceNotFound = errors.New("authlayer/oauth: device authorization not found")
	// ErrDeviceNotPending: the device authorization is no longer pending —
	// already approved, denied or redeemed, or the compare-and-set that
	// would have moved it lost to a concurrent decision.
	ErrDeviceNotPending = errors.New("authlayer/oauth: device authorization is not pending")
	// ErrGrantNotFound: no grant with that id.
	ErrGrantNotFound = errors.New("authlayer/oauth: grant not found")
	// ErrGrantRevoked: the grant's RevokedAt is set.
	ErrGrantRevoked = errors.New("authlayer/oauth: grant has been revoked")
	// ErrGrantExpired: the grant's ExpiresAt is not in the future.
	ErrGrantExpired = errors.New("authlayer/oauth: grant has expired")
	// ErrInvalidToken: [Service.Authenticate] refused the access token.
	// Every cause — a signature, expiry or key failure from the signer, a
	// wrong issuer or audience, a token that is not one of this package's,
	// a revoked or expired grant, a disabled client — is wrapped, so
	// errors.Is on the cause still holds. RFC 6750 §3.1 invalid_token.
	ErrInvalidToken = errors.New("authlayer/oauth: invalid access token")
	// ErrIssuerRequired: the Service was built without [WithIssuer]. A
	// delegated token without an issuer cannot be scoped to one server, so
	// every mint fails closed rather than sign an unscoped token.
	ErrIssuerRequired = errors.New("authlayer/oauth: WithIssuer is required to mint tokens")
	// ErrRegistrationDisabled: [Service.RegisterClient] was called on a
	// Service built without WithDynamicRegistration(true).
	ErrRegistrationDisabled = errors.New("authlayer/oauth: dynamic client registration is disabled")
	// ErrRefreshNotFound: no refresh token with that hash.
	ErrRefreshNotFound = errors.New("authlayer/oauth: refresh token not found")
	// ErrCodeNotFound: no authorization code with that hash.
	ErrCodeNotFound = errors.New("authlayer/oauth: authorization code not found")
	// ErrIDTaken: a Create* was given an id that already identifies a row of
	// that kind. The default UUIDv7 generator never produces one; a custom
	// [WithIDGenerator] might.
	ErrIDTaken = errors.New("authlayer/oauth: id already exists")
	// ErrEmptyPermissions IS apikey.ErrEmptyPermissions — the same value,
	// aliased rather than re-declared, because it means the same thing: a
	// cap compiled to a set granting nothing, which the stored encoding
	// cannot tell from "no cap", so it is refused rather than stored as an
	// unrestricted grant. errors.Is matches either name.
	ErrEmptyPermissions = apikey.ErrEmptyPermissions
)

// Store is the persistence port for clients, grants, authorization codes,
// device authorizations and refresh tokens. It is not generic — the five
// records are fixed shapes, so every backend shares one table set — and
// composes them in one interface, as apikey.Store does.
//
// A Store performs no authorization, no hashing, no signing and no token
// minting of its own: the Service decides, and hands the Store fully-formed
// values to write or hashes to read by. It interprets no permission bytes.
//
// # The obligations that are MUSTs
//
// Fourteen, and [github.com/bernardoforcillo/authlayer/oauth/oauthtest]
// exercises every one alongside every other method's contract; run the
// suite against a backend rather than reading these comments and hoping.
//
// Four are uniqueness constraints stated on the record types, because they
// constrain the shape of a table rather than the behaviour of one call:
// [AuthorizationCode.CodeHash], [DeviceAuthorization.DeviceCodeHash],
// [DeviceAuthorization.UserCode] and [RefreshToken.TokenHash]. Each defeats
// a single-winner property below WITH NO ATOMICITY DEFECT AT ALL — two rows
// sharing a hash let two concurrent callers each atomically win a different
// row.
//
// Three are compare-and-sets — [Store.RedeemCode], [Store.SetDeviceStatus],
// [Store.MarkRefreshRotated] — and each must decide its predicate and apply
// its write as ONE atomic step. Split into a read and a later write, a code
// redeems twice, a device authorization is approved by one user and denied
// by another with both told they won, and a stolen refresh token becomes an
// undetectable parallel session — the exact failure auth.Store.MarkRotated's
// doc describes.
//
// Two are atomic cascades: [Store.DeleteClient] removes everything of the
// client with the client, and [Store.RevokeGrant] deletes the grant's refresh
// tokens with the revocation. A refresh token outliving its revoked grant
// would be a credential that still rotates for a delegation the user was
// told is gone.
//
// Five are referential refusals: [Store.CreateGrant] and
// [Store.CreateDeviceAuthorization] must refuse a ClientID naming no client,
// and [Store.CreateCode] and [Store.CreateRefreshToken] must refuse a
// GrantID naming no grant — plus the atomic id check every Create* carries.
// A credential row for a principal or a delegation that does not exist is
// what every cascade above exists to prevent, and a create that could write
// one after the cascade ran would reopen it.
type Store interface {
	// CreateClient persists an already-stamped client and returns what was
	// stored, stamping nothing of its own. An id another client holds is
	// ErrIDTaken, and the check and the write MUST be one atomic step (a
	// PRIMARY KEY, or one critical section).
	CreateClient(ctx context.Context, c Client) (Client, error)
	// FindClient loads a client by id, returning ErrClientNotFound when
	// there is none. Disabled clients are returned — the caller reads
	// DisabledAt.
	FindClient(ctx context.Context, id string) (Client, error)
	// ListClients returns every client owned by containerID, disabled or
	// not; "" lists the application-level clients and nothing else. A
	// container with none is not an error; the result may be an empty
	// slice or nil. Order is unspecified.
	ListClients(ctx context.Context, containerID string) ([]Client, error)
	// UpdateClient replaces the mutable fields of the client c.ID names —
	// Name, SecretHash, RedirectURIs, GrantTypes, Scopes, ServiceAccountID,
	// Permissions, UpdatedAt, DisabledAt — with c's, whole-row, returning
	// ErrClientNotFound when no row matched. ID, ContainerID, Public,
	// CreatedBy and CreatedAt are never changed.
	UpdateClient(ctx context.Context, c Client) error
	// DeleteClient removes the client AND every grant, authorization code,
	// device authorization and refresh token that names it, returning
	// ErrClientNotFound when no client matched — a rows-affected answer,
	// so a second delete of the same id is told so.
	//
	// The cascade MUST be atomic with the delete: one transaction, ON
	// DELETE CASCADE, or one critical section spanning all five. A refresh
	// token or a grant that outlived its client would be a credential for a
	// client_id nothing knows — the Service refuses it, since every token
	// path loads the client and fails closed, but a third-party reader of
	// the tables would take it for a live delegation, and a partial delete
	// leaves it there for good.
	DeleteClient(ctx context.Context, id string) error

	// CreateGrant persists an already-stamped grant and returns what was
	// stored. An id another grant holds is ErrIDTaken; a ClientID naming no
	// client MUST be refused with ErrClientNotFound.
	CreateGrant(ctx context.Context, g Grant) (Grant, error)
	// FindGrant loads a grant by id, returning ErrGrantNotFound when there
	// is none. Revoked and expired grants are returned — the caller reads
	// the timestamps, so it can report WHY.
	FindGrant(ctx context.Context, id string) (Grant, error)
	// ListGrantsByUser returns every grant of userID across every container
	// and every client, revoked or expired or not — the caller filters. A
	// user with none is not an error; the result may be an empty slice or
	// nil. Order is unspecified.
	ListGrantsByUser(ctx context.Context, userID string) ([]Grant, error)
	// RevokeGrant stamps RevokedAt with now AND deletes every refresh token
	// whose GrantID is id, returning ErrGrantNotFound when no grant matched.
	// Revoking a revoked grant overwrites the timestamp rather than
	// erroring — revocation is idempotent, as apikey.Store.RevokeKey's is.
	//
	// The deletion MUST be atomic with the stamp: one transaction, or one
	// critical section spanning both. Authorization codes and device
	// authorizations of the grant are left alone — the Service checks the
	// grant's liveness after redeeming either, so they are inert — and are
	// removed by PurgeExpired.
	RevokeGrant(ctx context.Context, id string, now time.Time) error
	// TouchGrant stamps LastUsedAt with now, returning ErrGrantNotFound when
	// no row matched. The Service calls it best-effort on every mint and
	// verification and treats a failure as a logging event, so a backend
	// may make it cheap as long as a nil return means the row exists.
	TouchGrant(ctx context.Context, id string, now time.Time) error

	// CreateCode persists an already-stamped authorization code and returns
	// what was stored. An id another code holds is ErrIDTaken; a GrantID
	// naming no grant MUST be refused with ErrGrantNotFound; and a CodeHash
	// another code already holds MUST be refused — the uniqueness
	// obligation [AuthorizationCode] states — deciding that refusal and
	// performing the write as one atomic step. What a hash collision
	// RETURNS is deliberately unclassified, exactly as apikey.Store leaves
	// it: store/drops lets PostgreSQL's unique violation through,
	// store/memory answers with its own package-local error, and a caller
	// treats any non-nil error as "this code was not created".
	CreateCode(ctx context.Context, c AuthorizationCode) (AuthorizationCode, error)
	// RedeemCode sets RedeemedAt = now on the code whose CodeHash matches IF
	// AND ONLY IF RedeemedAt is nil, and reports (row, true) to the one
	// caller that made the transition and (row, false, nil) to every other
	// — the row as it stood, so the loser can learn WHICH grant to revoke.
	// codeHash matching no row is ErrCodeNotFound.
	//
	// The check and the write MUST be one atomic step: an UPDATE whose
	// WHERE carries redeemed_at IS NULL, or one critical section. A
	// read-then-write lets two concurrent exchanges both see the code
	// unredeemed and both mint, after which the replay that OAuth 2.1
	// §4.1.2 says must revoke the grant is never observed. Expiry is NOT
	// part of the predicate: the Service checks ExpiresAt after winning, so
	// an expired code is still consumed and a replay of it still detected.
	RedeemCode(ctx context.Context, codeHash string, now time.Time) (AuthorizationCode, bool, error)

	// CreateDeviceAuthorization persists an already-stamped authorization
	// and returns what was stored. An id another row holds is ErrIDTaken; a
	// ClientID naming no client MUST be refused with ErrClientNotFound; and
	// both DeviceCodeHash and UserCode MUST be refused when another row
	// holds them, atomically with the write, on CreateCode's terms.
	CreateDeviceAuthorization(ctx context.Context, d DeviceAuthorization) (DeviceAuthorization, error)
	// FindDeviceByCodeHash loads the authorization whose DeviceCodeHash
	// matches, returning ErrDeviceNotFound when none does. Every status is
	// returned — the caller classifies.
	FindDeviceByCodeHash(ctx context.Context, deviceCodeHash string) (DeviceAuthorization, error)
	// FindDeviceByUserCode loads the authorization whose UserCode matches
	// exactly — the Service normalises (strips the dash, upper-cases)
	// before calling — returning ErrDeviceNotFound when none does.
	FindDeviceByUserCode(ctx context.Context, userCode string) (DeviceAuthorization, error)
	// SetDeviceStatus moves the authorization id from Status == from to to,
	// writing GrantID = grantID when to is DeviceStatusApproved (and
	// leaving it alone otherwise), and reports whether THIS call made the
	// transition. (false, nil) means the row exists but its Status was not
	// from — another caller moved it first, or it was never there to move.
	// id matching no row is ErrDeviceNotFound.
	//
	// The compare and the write MUST be one atomic step: an UPDATE whose
	// WHERE carries status = $from, or one critical section. Without it a
	// user approving and a user denying, or two clients polling one
	// approved code, can both be told they won.
	SetDeviceStatus(ctx context.Context, id string, from, to DeviceStatus, grantID string, now time.Time) (bool, error)
	// TouchDevicePoll stamps LastPolledAt with now, returning
	// ErrDeviceNotFound when no row matched. It is what [ErrSlowDown] is
	// measured from.
	TouchDevicePoll(ctx context.Context, id string, now time.Time) error

	// CreateRefreshToken persists an already-stamped token and returns what
	// was stored. An id another token holds is ErrIDTaken; a GrantID naming
	// no grant MUST be refused with ErrGrantNotFound; and a TokenHash
	// another token holds MUST be refused, atomically with the write, on
	// CreateCode's terms.
	CreateRefreshToken(ctx context.Context, r RefreshToken) (RefreshToken, error)
	// FindRefreshTokenByHash loads the token whose TokenHash matches,
	// returning ErrRefreshNotFound when none does. Rotated and expired
	// tokens are returned — the caller classifies; [Service.Introspect]
	// reads the row to answer for a refresh token.
	FindRefreshTokenByHash(ctx context.Context, tokenHash string) (RefreshToken, error)
	// MarkRefreshRotated sets RotatedAt = now on the token whose TokenHash
	// matches IF AND ONLY IF RotatedAt is nil, and reports (row, true) to
	// the one caller that made the transition and (row, false, nil) to
	// every other — exactly auth.Store.MarkRotated's contract, including
	// that tokenHash matching no row at all is ErrRefreshNotFound rather
	// than (row, false). The check and the write MUST be one atomic step,
	// for that method's reason: a read-then-write lets two callers both see
	// the token current, both mint a successor, and the replay is never
	// detected. Expiry is NOT part of the predicate; the Service checks it
	// after winning.
	MarkRefreshRotated(ctx context.Context, tokenHash string, now time.Time) (RefreshToken, bool, error)
	// DeleteRefreshFamily removes every token whose FamilyID matches. A
	// family with no rows is the ordinary case, not a miss: nil.
	DeleteRefreshFamily(ctx context.Context, familyID string) error

	// PurgeExpired deletes every authorization code, device authorization
	// and refresh token whose ExpiresAt is strictly before `before`, and
	// every grant whose ExpiresAt OR whose RevokedAt is strictly before it
	// — together with the codes and refresh tokens of each such grant, so
	// no row is left naming a grant that is gone — and returns how many
	// rows went, across all four kinds. Live rows and clients are never
	// purged. Housekeeping, not a security boundary: every expired or
	// revoked row is already refused by the Service before it is purged, so
	// the cutoff is deliberately strict — a row exactly at its ExpiresAt is
	// refused now and purged on a later pass.
	PurgeExpired(ctx context.Context, before time.Time) (int, error)
}
