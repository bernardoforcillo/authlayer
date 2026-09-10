// Package apikey gives a scope non-human members: service accounts, each an
// ordinary membership whose id this package mints rather than your users
// table, and the API keys that authenticate as them.
//
// # The model
//
// A [ServiceAccount] is a member. [Service.CreateServiceAccount] writes the
// record and then admits its id to the container through
// [scope.Service.GrantMembership] at the role you name, so from that moment
// the RBAC engine treats it exactly like a person: [scope.Service.Can]
// resolves its role, the privilege-escalation guard bounds what it may grant,
// a [scope.Service.PermissionGuard] filters its rows. Nothing in scope knows
// the difference, and nothing needs to.
//
// A [Key] is a bearer credential for one service account. Its plaintext —
// "sk_" followed by the url-safe base64 of 32 random bytes — is returned by
// [Service.CreateKey] exactly once and never persisted: only its sha256
// ([token.HashOpaque]) is stored, so a database leak cannot be replayed into
// a working key. [Service.Authenticate] hashes a presented plaintext, looks it
// up by hash, refuses a revoked, expired or disabled one, and returns a
// [Principal]; [WithPrincipal] then annotates a context the way
// scope.WithSubject and scope.WithScope would for a logged-in user, so the
// same Can/Authorize calls a request handler already makes work unchanged for
// a key.
//
// # Restricted permissions, and the cap
//
// A key may carry a permission set narrower than its account's role
// ([WithPermissions]). It is a CAP, not a grant: the key's effective standing
// is role ∩ cap, enforced by [scope.WithPermissionCap], which the engine
// applies after every other rung of its resolution and which can therefore
// only ever remove. Minting is guarded twice — the cap must be within the
// account's role AND within the actor's own (capped) standing, so a key
// cannot be a way to reach permissions the minter does not hold — and a key
// minted through another restricted key inherits that key's ceiling.
//
// # Authorization of the management calls
//
// Every management method reads the acting subject and active container from
// the context ([scope.WithSubject], [scope.WithScope]) and checks the
// service_account control resource [scope.ResourceServiceAccount] through
// [scope.Service.Authorize]: create, read, update, delete. Those four sit on
// the merged surface every scope.NewAccess builds, so the built-in admin role
// holds them all. Two calls delegate to scope for the membership half and so
// need scope's own grants as well: [Service.ChangeServiceAccountRole] runs
// [scope.Service.ChangeMemberRole] (member:update, escalation guard) and
// [Service.DeleteServiceAccount] runs [scope.Service.RemoveMember]
// (member:delete, target-rank guard). Only [Service.Authenticate] and
// [Service.PurgeExpired] read no subject.
//
// # What is NOT atomic
//
// A service account spans two stores that may not share a database — its
// record in this package's [Store], its membership in scope's — so there is
// no cross-store transaction, exactly as the invite package documents for
// acceptance. Each two-store method orders its steps so that a failure
// between them leaves the inert half behind, never the live one; the method
// docs say which half and what to do about it.
//
// # Storage
//
// [Store] is the persistence port. store/memory holds the reference
// implementation and store/drops the production one, and
// [github.com/bernardoforcillo/authlayer/apikey/apikeytest] is the port's
// contract as an executable suite — apikeytest.RunStoreContract(t, newStore)
// — that both run and a third-party backend should too.
package apikey

import (
	"context"
	"errors"
	"time"
)

// ServiceAccount is a non-human member of a container.
//
// Its ID is minted by the [Service] id generator and is the scope SUBJECT the
// account acts as: it is what [scope.Service.GrantMembership] admits, what
// [Principal.ID] carries, and what scope.WithSubject receives through
// [WithPrincipal]. Its role lives on the membership, not here — read it with
// scope's own member calls, change it with [Service.ChangeServiceAccountRole].
type ServiceAccount struct {
	// ID is the record's key and the account's subject id.
	ID string `drop:"id"`
	// ContainerID is the scope the account belongs to.
	ContainerID string `drop:"container_id"`
	// Name is a human-facing label — "CI deployer", "billing sync".
	Name string `drop:"name"`
	// Description is free text for the management screen.
	Description string `drop:"description"`
	// CreatedBy is the user id of the actor who created the account.
	CreatedBy string `drop:"created_by"`
	// CreatedAt is stamped by the Service clock.
	CreatedAt time.Time `drop:"created_at"`
	// UpdatedAt is stamped by the Service clock on create and on every
	// enable/disable.
	UpdatedAt time.Time `drop:"updated_at"`
	// DisabledAt is when the account was disabled; nil means active. While
	// set, [Service.Authenticate] refuses every key of the account with
	// [ErrServiceAccountDisabled] and [Service.CreateKey] mints none. The
	// membership is untouched, so re-enabling restores the account exactly.
	DisabledAt *time.Time `drop:"disabled_at"`
}

// Key is one API key of a service account. The plaintext is never stored —
// see TokenHash — so a Key read back from the store cannot be used, only
// recognised, revoked and audited.
type Key struct {
	// ID is the record's key, and what [Service.RevokeKey] takes.
	ID string `drop:"id"`
	// ServiceAccountID is the account this key authenticates as.
	ServiceAccountID string `drop:"service_account_id"`
	// ContainerID is the account's container, denormalised onto the key so
	// [Service.Authenticate] can build a [Principal] from the key row alone
	// and so listing and revocation can be scoped without a join.
	ContainerID string `drop:"container_id"`
	// Name is a human-facing label — "github actions", "laptop".
	Name string `drop:"name"`
	// Prefix is the first characters of the plaintext — the key prefix plus
	// eight — kept in clear so a management screen can show "sk_ab12cd34…"
	// and a holder can tell which key they have. Eight base64 characters
	// disclose 48 of the 256 random bits, leaving 208; that is the whole
	// point of storing this rather than a longer slice.
	Prefix string `drop:"prefix"`
	// TokenHash is [token.HashOpaque] of the plaintext — the hex sha256 — and
	// the only form the plaintext ever reaches a Store in. Authentication
	// hashes the presented plaintext and looks it up here.
	//
	// An implementation MUST enforce that TokenHash is unique across every
	// Key row — a UNIQUE constraint in a SQL backend, which the tag option
	// declares for store/drops. [Store.FindKeyByHash] assumes at most one row
	// can match, and every authentication runs through it: two rows sharing
	// a hash would make a bearer credential resolve to whichever row the
	// backend returned first, so WHICH ACCOUNT, at WHICH CAP, a presented key
	// acts as would be decided by row order. It is the same MUST
	// [invite.EmailInvite] and auth.Session carry on their TokenHash.
	TokenHash string `drop:"token_hash,unique"`
	// Permissions is the key's restricted permission set as
	// [access.Permission.Encode] bytes, or nil/empty for a key with no
	// restriction (the account's full role). Opaque to a Store; the Service
	// decodes it against the scope's own statements when the key
	// authenticates and hands it to [scope.WithPermissionCap]. Because the
	// encoding stores grant NAMES, a key survives the application adding or
	// removing resources: a capability that no longer exists is dropped,
	// everything else keeps its meaning.
	//
	// Empty bytes mean "no cap", so a cap granting nothing cannot be
	// represented — [Service.CreateKey] refuses one with
	// [ErrEmptyPermissions] rather than store it as unrestricted.
	Permissions []byte `drop:"permissions"`
	// ExpiresAt is when the key stops authenticating; nil means never. The
	// instant itself is already expired — a key is valid strictly before it.
	ExpiresAt *time.Time `drop:"expires_at"`
	// LastUsedAt is stamped by [Store.TouchKey] on each successful
	// authentication, best-effort: a failed touch is logged through the
	// hook and does not fail the authentication.
	LastUsedAt *time.Time `drop:"last_used_at"`
	// CreatedBy is the user id of the actor who minted the key.
	CreatedBy string `drop:"created_by"`
	// CreatedAt is stamped by the Service clock.
	CreatedAt time.Time `drop:"created_at"`
	// RevokedAt is when the key was revoked; nil means live. A revoked key
	// is refused with [ErrKeyRevoked] and never un-revoked — mint a new one.
	RevokedAt *time.Time `drop:"revoked_at"`
}

// Sentinel errors returned by an apikey.Store implementation and by the
// Service. Compare with [errors.Is], never by string — the messages are not
// part of the API.
//
// They fall into three groups:
//
//   - Not found — ErrServiceAccountNotFound, ErrKeyNotFound. A Store returns
//     these itself on any lookup, update or delete that matches no row; the
//     Service also returns them, deliberately, for a record that exists in
//     ANOTHER container than the one on the context, so a cross-tenant id is
//     indistinguishable from a missing one.
//   - Why an authentication was refused — ErrKeyRevoked, ErrKeyExpired,
//     ErrServiceAccountDisabled. Only [Service.Authenticate] raises them; a
//     Store returns the row and the Service reads the timestamps.
//   - Refused before any store is touched — ErrEmptyPermissions,
//     ErrInvalidExpiry, argument errors from [Service.CreateKey]; and
//     ErrIDTaken, which a Store raises when a create is given an id that
//     already identifies a row of that kind.
//
// Denials come from scope and are not re-declared here: a management call
// the actor may not make is scope.ErrForbidden (or scope.ErrNotMember), and
// minting above one's standing is scope.ErrPrivilegeEscalation.
var (
	// ErrServiceAccountNotFound: no service account with that id — or one
	// that belongs to another container than the one on the context.
	ErrServiceAccountNotFound = errors.New("authlayer/apikey: service account not found")
	// ErrKeyNotFound: no key with that id or token hash — or, from the
	// management calls, one that belongs to another container.
	ErrKeyNotFound = errors.New("authlayer/apikey: key not found")
	// ErrKeyRevoked: the key's RevokedAt is set.
	ErrKeyRevoked = errors.New("authlayer/apikey: key has been revoked")
	// ErrKeyExpired: the key's ExpiresAt is not in the future.
	ErrKeyExpired = errors.New("authlayer/apikey: key has expired")
	// ErrServiceAccountDisabled: the key is live but its account's
	// DisabledAt is set. Also refused by CreateKey.
	ErrServiceAccountDisabled = errors.New("authlayer/apikey: service account is disabled")
	// ErrIDTaken: a Create* was given an id that already identifies a row of
	// that kind. The default UUIDv7 generator never produces one; a custom
	// [WithIDGenerator] might.
	ErrIDTaken = errors.New("authlayer/apikey: id already exists")
	// ErrEmptyPermissions: [WithPermissions] compiled to a set granting
	// nothing. The stored encoding cannot tell an empty cap from no cap, so
	// such a key would authenticate as the FULL role — the opposite of what
	// was asked. Refused instead; mint no key if the key is to do nothing.
	ErrEmptyPermissions = errors.New("authlayer/apikey: restricted permissions grant nothing")
	// ErrInvalidExpiry: [WithExpiry] named an instant not after the Service
	// clock's now — a key already expired at mint, which is a dead credential
	// produced silently.
	ErrInvalidExpiry = errors.New("authlayer/apikey: expiry must be in the future")
)

// Store is the persistence port for service accounts and their keys. Like
// invite.Store it is not generic — [ServiceAccount] and [Key] are fixed
// shapes, so every backend shares one table pair — and it composes both
// record kinds in one interface, since nothing here needs to override just
// one of them.
//
// A Store performs no authorization of its own, the discipline every port in
// this library follows: the Service decides who may create, list, revoke or
// delete, and hands the Store fully-formed values to write, or keys to read
// by. It interprets no permission bytes.
//
// Three obligations are normative MUSTs, and
// [github.com/bernardoforcillo/authlayer/apikey/apikeytest] exercises every
// one of them alongside every other method's contract: [Key.TokenHash]'s
// uniqueness (stated on the record type), DeleteServiceAccount's atomic
// cascade, and CreateKey's refusal of a key naming no account. Run the suite
// against a backend rather than reading these comments and hoping.
type Store interface {
	// CreateServiceAccount persists an already-stamped account and returns
	// what was stored, stamping nothing of its own. An id another account
	// already holds is ErrIDTaken, and the check and the write MUST be one
	// atomic step (a PRIMARY KEY, or one critical section), so two
	// concurrent creates cannot both take an id.
	CreateServiceAccount(ctx context.Context, sa ServiceAccount) (ServiceAccount, error)
	// FindServiceAccount loads an account by id, returning
	// ErrServiceAccountNotFound when there is none. Disabled accounts are
	// returned — the caller reads DisabledAt.
	FindServiceAccount(ctx context.Context, id string) (ServiceAccount, error)
	// ListServiceAccounts returns every account in containerID, disabled or
	// not — the caller filters. A container with none is not an error; the
	// result may be an empty slice or nil, which len and range treat alike.
	// Order is unspecified.
	ListServiceAccounts(ctx context.Context, containerID string) ([]ServiceAccount, error)
	// SetServiceAccountDisabled writes DisabledAt = at (nil re-enables) and
	// UpdatedAt = now, returning ErrServiceAccountNotFound when no row
	// matched. It is idempotent: disabling a disabled account overwrites
	// the timestamp, enabling an enabled one writes nil again.
	SetServiceAccountDisabled(ctx context.Context, id string, at *time.Time, now time.Time) error
	// DeleteServiceAccount removes an account AND every key that names it,
	// returning ErrServiceAccountNotFound when no account matched — a
	// rows-affected answer, so a second delete of the same id is told so.
	//
	// The cascade MUST be atomic with the delete: one transaction, one
	// ON DELETE CASCADE, or one critical section spanning both. A key that
	// outlived its account would still resolve through FindKeyByHash to an
	// account id nothing else knows; [Service.Authenticate] refuses such a
	// key (it loads the account and fails closed), so the window is not an
	// authentication hole, but it IS a row a third-party reader of the keys
	// table would take for a live credential, and a partial delete that
	// removed the account and errored on the keys leaves it there for good.
	// Keys are the only thing deleted along with the account; the membership
	// belongs to scope's Store and the Service removes it separately (see
	// [Service.DeleteServiceAccount]).
	DeleteServiceAccount(ctx context.Context, id string) error

	// CreateKey persists an already-stamped key and returns what was stored,
	// stamping nothing of its own. An id another key holds is ErrIDTaken; a
	// ServiceAccountID naming no account MUST be refused with
	// ErrServiceAccountNotFound, since the row would be a credential for a
	// principal that does not exist. And it MUST refuse a TokenHash another
	// key already holds — the uniqueness obligation [Key] states — deciding
	// that refusal and performing the write as one atomic step, so two
	// concurrent callers cannot both take one hash. What a hash collision
	// RETURNS is deliberately unclassified, for the reason invite.Store gives
	// on the same case: store/drops lets PostgreSQL's own unique violation
	// through, store/memory answers with its own package-local error, and a
	// caller treats any non-nil error as "this key was not created".
	CreateKey(ctx context.Context, k Key) (Key, error)
	// FindKeyByHash loads the key whose TokenHash matches, returning
	// ErrKeyNotFound when none does. This is the authentication path: the
	// caller hashes the presented plaintext and looks it up by hash, since
	// the plaintext itself is never stored. Revoked and expired keys are
	// returned — the caller classifies, so it can report WHY.
	FindKeyByHash(ctx context.Context, tokenHash string) (Key, error)
	// FindKey loads a key by id, returning ErrKeyNotFound when there is
	// none. It is what lets the Service scope RevokeKey to the ctx
	// container before acting.
	FindKey(ctx context.Context, id string) (Key, error)
	// ListKeys returns every key of serviceAccountID, revoked or expired or
	// not — the caller filters. An account with none is not an error; the
	// result may be an empty slice or nil. Order is unspecified.
	ListKeys(ctx context.Context, serviceAccountID string) ([]Key, error)
	// RevokeKey stamps RevokedAt with now, returning ErrKeyNotFound when no
	// row matched. Revoking a revoked key overwrites the timestamp rather
	// than erroring — revocation is idempotent, as invite.Store.RevokeLink's
	// is.
	RevokeKey(ctx context.Context, id string, now time.Time) error
	// TouchKey stamps LastUsedAt with now, returning ErrKeyNotFound when no
	// row matched. The Service calls it on every successful authentication
	// and treats a failure as a logging event, not an authentication
	// failure, so a backend may make this cheap (no fsync, a deferred write)
	// as long as a nil return means the row exists.
	TouchKey(ctx context.Context, id string, now time.Time) error
	// DeleteKey removes a key by id, returning ErrKeyNotFound when no row
	// matched. Housekeeping; the Service revokes rather than deletes.
	DeleteKey(ctx context.Context, id string) error
	// PurgeExpired deletes every key whose ExpiresAt OR whose RevokedAt is
	// strictly before `before`, and returns how many rows went. A live key
	// with no expiry is never purged; nor is any account. Housekeeping, not
	// a security boundary — an expired or revoked key is already refused
	// through FindKeyByHash's classification before it is ever purged — so
	// the cutoff is deliberately looser than Authenticate's (strictly before
	// versus not-in-the-future): a key exactly at its ExpiresAt is refused
	// now and purged on a later pass.
	PurgeExpired(ctx context.Context, before time.Time) (int, error)
}
