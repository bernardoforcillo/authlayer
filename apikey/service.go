package apikey

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/bernardoforcillo/authlayer/access"
	"github.com/bernardoforcillo/authlayer/internal/uid"
	"github.com/bernardoforcillo/authlayer/scope"
	"github.com/bernardoforcillo/authlayer/token"
)

// DefaultKeyPrefix is the prefix a plaintext key starts with unless
// [WithKeyPrefix] says otherwise. It makes the string recognisable to secret
// scanners and to a person reading a log, and [Key.Prefix] keeps it plus the
// next eight characters for display.
const DefaultKeyPrefix = "sk_"

// keyRandomBytes is how much of crypto/rand a plaintext carries: 32 bytes,
// the same as [token.GenerateOpaque], rendered as 43 url-safe base64
// characters rather than 64 hex ones.
const keyRandomBytes = 32

// displayChars is how many characters after the prefix [Key.Prefix] keeps.
const displayChars = 8

// config is the resolved Service configuration, built from the defaults and
// mutated via Option — the same shape scope's and invite's follow.
type config struct {
	clock     func() time.Time
	idgen     func() string
	hooks     []Hook
	keyPrefix string
}

func defaultConfig() config {
	return config{
		clock:     func() time.Time { return time.Now().UTC() },
		idgen:     uid.NewV7,
		keyPrefix: DefaultKeyPrefix,
	}
}

// Option customizes a Service. Options are applied in order at construction
// and never afterwards, so a Service's configuration is immutable once built.
type Option func(*config)

// WithClock sets the clock used for created/updated, expiry, revocation,
// last-used and event timestamps, and for [Service.Authenticate]'s expiry
// test. The default is time.Now().UTC(). A nil clock is ignored.
func WithClock(now func() time.Time) Option {
	return func(c *config) {
		if now != nil {
			c.clock = now
		}
	}
}

// WithIDGenerator sets the id generator for service accounts and keys. The
// default is UUIDv7, and the same caveat scope.WithIDGenerator carries
// applies: against store/drops a non-UUID generator needs
// dropsstore.WithAPIKeyTextLibraryIDs, or the first create fails with
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

// WithKeyPrefix replaces the plaintext prefix, "sk_" by default. Pick
// something a secret scanner can be taught and a human can recognise; an
// empty prefix is ignored, leaving the default in place. The prefix is not
// checked on authentication — the hash is — so changing it later does not
// invalidate keys minted under the old one.
func WithKeyPrefix(prefix string) Option {
	return func(c *config) {
		if prefix != "" {
			c.keyPrefix = prefix
		}
	}
}

// keyOptions is what [KeyOption]s build.
type keyOptions struct {
	expiresAt *time.Time
	grants    map[string][]access.Action
}

// KeyOption customizes one key at [Service.CreateKey].
type KeyOption func(*keyOptions)

// WithExpiry gives the key an expiry: it authenticates strictly before at
// and is [ErrKeyExpired] from that instant on. The default is no expiry.
// An instant not after the Service clock's now is [ErrInvalidExpiry].
func WithExpiry(at time.Time) KeyOption {
	return func(o *keyOptions) {
		t := at
		o.expiresAt = &t
	}
}

// WithPermissions restricts the key to grants, a permission set compiled
// against the scope's own statements: the key's effective standing becomes
// role ∩ grants, through [scope.WithPermissionCap]. It is a cap and never a
// grant — CreateKey refuses a set that is not within the account's role, and
// one that is not within the actor's own capped standing, with
// scope.ErrPrivilegeEscalation, and one that compiles to nothing with
// [ErrEmptyPermissions]. An undeclared (resource, action) pair is an error
// from [access.Access.Permission], so a typo fails closed. The default is no
// restriction: the key acts with the account's whole role.
func WithPermissions(grants map[string][]access.Action) KeyOption {
	return func(o *keyOptions) { o.grants = grants }
}

// Service creates service accounts and keys for one scope instance,
// authenticates keys, and is the audit point for both. C, M, PC, PM mirror
// [scope.Service]'s type parameters exactly, as invite.Service's do: a
// service account's membership is one the wrapped scope.Service itself
// creates.
//
// A Service performs its own authorization through
// [scope.Service.Authorize] against [scope.ResourceServiceAccount] — see the
// package doc for which action each call needs — using the subject and
// container on the context. It is safe for concurrent use if its
// scope.Service and Store are, and caches nothing.
type Service[C scope.Container, M scope.Member,
	PC interface {
		*C
		scope.MutableContainer
	},
	PM interface {
		*M
		scope.MutableMember
	}] struct {
	sc  *scope.Service[C, M, PC, PM]
	st  Store
	cfg config
}

// New wires a scope.Service, a Store and options into a Service.
//
// sc supplies every permission decision without reimplementing scope's
// engine: [scope.Service.Authorize] for the control checks,
// [scope.Service.Standing] plus [scope.Service.CapStanding] for the actor's
// own capped standing, [scope.Service.RolePermissions] for a role's
// permissions, [scope.Service.Access] for compiling and decoding a key's
// restricted permissions in the same statement space the engine decides in,
// and [scope.Service.GrantMembership], ChangeMemberRole and RemoveMember for
// the membership half of an account's life. st is the Store described in the
// package doc: store/memory for tests and development, store/drops for
// production.
//
//	orgSvc := org.New(org.NewAccess(nil), memory.New[org.Organization, org.Member]())
//	keys := apikey.New(orgSvc.Service, memory.NewAPIKeyStore()) // .Service: the embedded *scope.Service
func New[C scope.Container, M scope.Member,
	PC interface {
		*C
		scope.MutableContainer
	},
	PM interface {
		*M
		scope.MutableMember
	}](sc *scope.Service[C, M, PC, PM], st Store, opts ...Option) *Service[C, M, PC, PM] {
	cfg := defaultConfig()
	for _, o := range opts {
		o(&cfg)
	}
	return &Service[C, M, PC, PM]{sc: sc, st: st, cfg: cfg}
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

func (s *Service[C, M, PC, PM]) emit(ctx context.Context, e Event) error {
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

// actorStanding resolves the ctx subject's standing in containerID WITH the
// permission cap on ctx applied — [scope.Service.Standing] reads no cap by
// contract, so the cap is applied here through [scope.Service.CapStanding],
// exactly as scope's own ctx-subject paths do. Every guard in this package
// compares against this, which is what keeps a restricted key from minting
// an account or a key above the key's own ceiling.
func (s *Service[C, M, PC, PM]) actorStanding(ctx context.Context, containerID, actor string) (access.Permission, bool, error) {
	perms, elevated, err := s.sc.Standing(ctx, containerID, actor)
	if err != nil {
		return access.Permission{}, false, err
	}
	perms, elevated = s.sc.CapStanding(ctx, perms, elevated)
	return perms, elevated, nil
}

// guardEscalation enforces, on account creation, the rule scope applies to
// AddMember: unless elevated, the actor may not grant a role whose
// permissions exceed their own capped standing. Like invite's guard it
// recomputes scope's answer from exported calls — Standing, CapStanding and
// RolePermissions — and, like invite's, it always enforces strict escalation
// whatever the wrapped Service's Policy.Escalation says, since Policy is
// unexported; the safe direction to diverge in. An unresolvable roleKey is
// scope.ErrRoleNotFound, not ErrPrivilegeEscalation.
func (s *Service[C, M, PC, PM]) guardEscalation(ctx context.Context, containerID, actor, roleKey string) error {
	perms, elevated, err := s.actorStanding(ctx, containerID, actor)
	if err != nil {
		return err
	}
	grant, err := s.sc.RolePermissions(ctx, containerID, roleKey)
	if err != nil {
		return err
	}
	if elevated {
		return nil
	}
	if !grant.SubsetOf(perms) {
		return scope.ErrPrivilegeEscalation
	}
	return nil
}

// account loads id and refuses it unless it belongs to containerID,
// reporting ErrServiceAccountNotFound for a record that exists elsewhere
// exactly as for one that does not exist — [Store] is keyed by id and scoped
// by nothing, so this is where a service_account:* grant in one container
// stops reaching another's accounts. The same rule invite applies in
// RevokeInvite.
func (s *Service[C, M, PC, PM]) account(ctx context.Context, containerID, id string) (ServiceAccount, error) {
	sa, err := s.st.FindServiceAccount(ctx, id)
	if err != nil {
		return ServiceAccount{}, err
	}
	if sa.ContainerID != containerID {
		return ServiceAccount{}, ErrServiceAccountNotFound
	}
	return sa, nil
}

// CreateServiceAccount creates a service account named name in the ctx
// container and admits it as a member holding roleKey. The returned record
// is what was stored; the account's id is its subject.
//
// The ctx subject needs service_account:create and — unless elevated — may
// not give the account a role more powerful than their own capped standing
// (scope.ErrPrivilegeEscalation; see [guardEscalation]). An unknown roleKey
// is scope.ErrRoleNotFound.
//
// # Ordering, and why
//
// The account spans two stores that may not share a database — its record
// in this package's [Store], its membership in scope's — so there is no
// cross-store transaction. This method writes the record FIRST and grants
// the membership SECOND, the reverse of the order a reader might expect,
// because of what each half is on its own. A record with no membership is
// inert: it has no standing, [Service.CreateKey] refuses to mint for it
// (resolving its role is scope.ErrNotMember), and nothing can authenticate
// as it. A membership with no record would be a member row for a subject
// nothing knows — a phantom with a role — that no key could ever reach but
// that every roster and every ListUserStandings would report. Writing the
// inert half first means a failure between the two leaves the harmless
// shape behind.
//
// If [scope.Service.GrantMembership] fails, the record is deleted again,
// best-effort, and GrantMembership's error is returned; if that compensating
// delete fails too, both errors are returned joined (errors.Join), so
// errors.Is on either still holds, and an inert record remains that
// [Service.DeleteServiceAccount] removes on request. The failure that
// actually happens there is not a store outage: on a NESTED scope under the
// default Policy.MembersFromParent, GrantMembership refuses a subject with
// no standing in the parent — which a freshly minted id never has. A nested
// scope therefore cannot hold service accounts unless MembersFromParent is
// cleared for it, and this method makes no attempt to admit the account to
// the parent on your behalf.
//
// scope emits MemberAdded for the membership with ActorID equal to the
// account id (see [scope.Service.GrantMembership]); the
// [ServiceAccountCreated] event this method emits afterwards carries the
// real actor, so attribute the creation from that one.
func (s *Service[C, M, PC, PM]) CreateServiceAccount(ctx context.Context, name, description, roleKey string) (ServiceAccount, error) {
	actor, containerID, err := ctxActor(ctx)
	if err != nil {
		return ServiceAccount{}, err
	}
	if err := s.sc.Authorize(ctx, scope.ResourceServiceAccount, scope.ActionCreate); err != nil {
		return ServiceAccount{}, err
	}
	if err := s.guardEscalation(ctx, containerID, actor, roleKey); err != nil {
		return ServiceAccount{}, err
	}

	now := s.cfg.clock()
	sa, err := s.st.CreateServiceAccount(ctx, ServiceAccount{
		ID:          s.cfg.idgen(),
		ContainerID: containerID,
		Name:        name,
		Description: description,
		CreatedBy:   actor,
		CreatedAt:   now,
		UpdatedAt:   now,
	})
	if err != nil {
		return ServiceAccount{}, err
	}
	if _, err := s.sc.GrantMembership(ctx, containerID, sa.ID, roleKey); err != nil {
		if derr := s.st.DeleteServiceAccount(ctx, sa.ID); derr != nil {
			return ServiceAccount{}, errors.Join(err, derr)
		}
		return ServiceAccount{}, err
	}
	if err := s.emit(ctx, Event{
		Kind: ServiceAccountCreated, ContainerID: containerID, ActorID: actor,
		ServiceAccountID: sa.ID, RoleKey: roleKey,
	}); err != nil {
		return ServiceAccount{}, err
	}
	return sa, nil
}

// ListServiceAccounts returns every service account in the ctx container,
// disabled ones included — read DisabledAt. The ctx subject needs
// service_account:read. Order is whatever the Store returns.
func (s *Service[C, M, PC, PM]) ListServiceAccounts(ctx context.Context) ([]ServiceAccount, error) {
	_, containerID, err := ctxActor(ctx)
	if err != nil {
		return nil, err
	}
	if err := s.sc.Authorize(ctx, scope.ResourceServiceAccount, scope.ActionRead); err != nil {
		return nil, err
	}
	return s.st.ListServiceAccounts(ctx, containerID)
}

// DisableServiceAccount stamps the account's DisabledAt: from now every one
// of its keys is refused with [ErrServiceAccountDisabled] and none can be
// minted, while the membership and the keys themselves are untouched, so
// [Service.EnableServiceAccount] restores the account exactly. This is the
// call for "we think a key leaked but do not yet know which"; revoke the
// key once you do. The ctx subject needs service_account:update; an id in
// another container is [ErrServiceAccountNotFound]. Disabling a disabled
// account is not an error.
func (s *Service[C, M, PC, PM]) DisableServiceAccount(ctx context.Context, id string) error {
	return s.setDisabled(ctx, id, true)
}

// EnableServiceAccount clears the account's DisabledAt. The ctx subject
// needs service_account:update; an id in another container is
// [ErrServiceAccountNotFound]. Enabling an enabled account is not an error.
func (s *Service[C, M, PC, PM]) EnableServiceAccount(ctx context.Context, id string) error {
	return s.setDisabled(ctx, id, false)
}

func (s *Service[C, M, PC, PM]) setDisabled(ctx context.Context, id string, disabled bool) error {
	actor, containerID, err := ctxActor(ctx)
	if err != nil {
		return err
	}
	if err := s.sc.Authorize(ctx, scope.ResourceServiceAccount, scope.ActionUpdate); err != nil {
		return err
	}
	if _, err := s.account(ctx, containerID, id); err != nil {
		return err
	}
	now := s.cfg.clock()
	var at *time.Time
	kind := ServiceAccountEnabled
	if disabled {
		at = &now
		kind = ServiceAccountDisabled
	}
	if err := s.st.SetServiceAccountDisabled(ctx, id, at, now); err != nil {
		return err
	}
	return s.emit(ctx, Event{Kind: kind, ContainerID: containerID, ActorID: actor, ServiceAccountID: id})
}

// ChangeServiceAccountRole reassigns the account's membership to roleKey,
// through [scope.Service.ChangeMemberRole] and with exactly its semantics:
// the actor needs member:update as well as service_account:update, and —
// unless elevated — may not grant a role exceeding their own capped
// standing (scope.ErrPrivilegeEscalation). An unknown roleKey is
// scope.ErrRoleNotFound; an id in another container is
// [ErrServiceAccountNotFound].
//
// Existing keys are not touched, and do not need to be: a key's
// Permissions is a cap intersected with the role at each check, so lowering
// the role lowers every key with it, and raising it never lifts a
// restricted key above its own cap. scope emits MemberRoleChanged; this
// emits [ServiceAccountRoleChanged] with the real actor.
func (s *Service[C, M, PC, PM]) ChangeServiceAccountRole(ctx context.Context, id, roleKey string) error {
	actor, containerID, err := ctxActor(ctx)
	if err != nil {
		return err
	}
	if err := s.sc.Authorize(ctx, scope.ResourceServiceAccount, scope.ActionUpdate); err != nil {
		return err
	}
	if _, err := s.account(ctx, containerID, id); err != nil {
		return err
	}
	if err := s.sc.ChangeMemberRole(ctx, id, roleKey); err != nil {
		return err
	}
	return s.emit(ctx, Event{
		Kind: ServiceAccountRoleChanged, ContainerID: containerID, ActorID: actor,
		ServiceAccountID: id, RoleKey: roleKey,
	})
}

// DeleteServiceAccount removes the account: its membership, then its record
// and every one of its keys. The ctx subject needs service_account:delete,
// and — because the membership half runs through
// [scope.Service.RemoveMember] — member:delete too, subject to that call's
// target-rank guard: unless elevated, the actor may not remove an account
// whose role exceeds their own capped standing (scope.ErrPrivilegeEscalation).
// An id in another container is [ErrServiceAccountNotFound].
//
// # Ordering, and why
//
// Two stores, no cross-store transaction, so the order is chosen for what a
// failure between the halves leaves behind. The membership goes FIRST: the
// instant it is gone the account has no standing anywhere, so a key that
// still authenticates resolves to a principal every Can and Authorize
// refuses — inert. The record and keys go SECOND, atomically together
// ([Store.DeleteServiceAccount]'s cascade MUST). The reverse order would
// leave, on a failure, a membership for a subject with no record: a phantom
// member with a role that rosters report and nothing can clean up through
// this package, since every method here starts by loading the record.
//
// A record with no membership (a create whose GrantMembership failed and
// whose compensation failed too) is deleted all the same: RemoveMember's
// scope.ErrNotMember is folded, since there is nothing to remove.
func (s *Service[C, M, PC, PM]) DeleteServiceAccount(ctx context.Context, id string) error {
	actor, containerID, err := ctxActor(ctx)
	if err != nil {
		return err
	}
	if err := s.sc.Authorize(ctx, scope.ResourceServiceAccount, scope.ActionDelete); err != nil {
		return err
	}
	if _, err := s.account(ctx, containerID, id); err != nil {
		return err
	}
	if err := s.sc.RemoveMember(ctx, id); err != nil && !errors.Is(err, scope.ErrNotMember) {
		return err
	}
	if err := s.st.DeleteServiceAccount(ctx, id); err != nil {
		return err
	}
	return s.emit(ctx, Event{Kind: ServiceAccountDeleted, ContainerID: containerID, ActorID: actor, ServiceAccountID: id})
}

// CreateKey mints a key for serviceAccountID and returns the stored record
// together with the plaintext — returned exactly ONCE and never again, since
// only its hash is stored ([Key.TokenHash]). Deliver it now.
//
// The ctx subject needs service_account:update. An id in another container
// is [ErrServiceAccountNotFound]; a disabled account is
// [ErrServiceAccountDisabled] — re-enable it first. [WithExpiry] and
// [WithPermissions] shape the key; see each for its refusals.
//
// # A key is a grant of the account's standing
//
// Whoever holds the key acts as the account, so minting one is, in effect,
// granting the account's standing to the minter — and it is guarded like
// [scope.Service.AddMember] is: unless the actor is elevated, what the key
// will be able to do must be within the actor's own capped standing, else
// scope.ErrPrivilegeEscalation. Without WithPermissions that is the account's
// whole role; with it, the restricted set, which must ALSO be within the
// account's role — a cap outside the role would intersect to less than it
// claims and mislead whoever reads it back. Both comparisons use the actor's
// CAPPED standing, so a key minted through a restricted key cannot exceed
// that key's ceiling. An account whose membership is missing (see
// [Service.CreateServiceAccount]) resolves to scope.ErrNotMember and gets no
// key.
//
// The plaintext is the key prefix ("sk_" by default) followed by the url-safe
// base64 of 32 bytes from crypto/rand — 43 characters, no padding. Its hash
// is [token.HashOpaque] of the whole string, prefix included.
func (s *Service[C, M, PC, PM]) CreateKey(ctx context.Context, serviceAccountID, name string, opts ...KeyOption) (Key, string, error) {
	actor, containerID, err := ctxActor(ctx)
	if err != nil {
		return Key{}, "", err
	}
	if err := s.sc.Authorize(ctx, scope.ResourceServiceAccount, scope.ActionUpdate); err != nil {
		return Key{}, "", err
	}
	sa, err := s.account(ctx, containerID, serviceAccountID)
	if err != nil {
		return Key{}, "", err
	}
	if sa.DisabledAt != nil {
		return Key{}, "", ErrServiceAccountDisabled
	}

	var o keyOptions
	for _, opt := range opts {
		opt(&o)
	}
	now := s.cfg.clock()
	if o.expiresAt != nil && !o.expiresAt.After(now) {
		return Key{}, "", ErrInvalidExpiry
	}

	// What the key will be able to do: the account's role, narrowed by the
	// cap if one was asked for.
	keyPerms, keyElevated, err := s.sc.Standing(ctx, containerID, sa.ID)
	if err != nil {
		return Key{}, "", err
	}
	var encoded []byte
	if o.grants != nil {
		ceiling, err := s.sc.Access().Permission(o.grants)
		if err != nil {
			return Key{}, "", err
		}
		if ceiling.IsZero() {
			return Key{}, "", ErrEmptyPermissions
		}
		if !keyElevated && !ceiling.SubsetOf(keyPerms) {
			return Key{}, "", scope.ErrPrivilegeEscalation
		}
		// The cap is within the role (or the role is Full), so the key's
		// effective set is the cap itself, and it is elevated only if the
		// cap grants every pair this scope declares.
		keyPerms = ceiling
		keyElevated = keyElevated && s.sc.Access().Full().Intersect(ceiling).IsFull()
		encoded = ceiling.Encode()
	}

	// ... which must be within what the actor holds, capped.
	actorPerms, actorElevated, err := s.actorStanding(ctx, containerID, actor)
	if err != nil {
		return Key{}, "", err
	}
	if !actorElevated && (keyElevated || !keyPerms.SubsetOf(actorPerms)) {
		return Key{}, "", scope.ErrPrivilegeEscalation
	}

	plain, err := s.newPlaintext()
	if err != nil {
		return Key{}, "", err
	}
	k, err := s.st.CreateKey(ctx, Key{
		ID:               s.cfg.idgen(),
		ServiceAccountID: sa.ID,
		ContainerID:      containerID,
		Name:             name,
		Prefix:           plain[:len(s.cfg.keyPrefix)+displayChars],
		TokenHash:        token.HashOpaque(plain),
		Permissions:      encoded,
		ExpiresAt:        o.expiresAt,
		CreatedBy:        actor,
		CreatedAt:        now,
	})
	if err != nil {
		return Key{}, "", err
	}
	if err := s.emit(ctx, Event{
		Kind: KeyCreated, ContainerID: containerID, ActorID: actor,
		ServiceAccountID: sa.ID, KeyID: k.ID,
	}); err != nil {
		return Key{}, "", err
	}
	return k, plain, nil
}

// newPlaintext draws the key's random half. A crypto/rand failure is
// returned rather than degraded, matching [token.GenerateOpaque].
func (s *Service[C, M, PC, PM]) newPlaintext() (string, error) {
	var b [keyRandomBytes]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("authlayer/apikey: generate key: %w", err)
	}
	return s.cfg.keyPrefix + base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// ListKeys returns every key of serviceAccountID, revoked and expired ones
// included — read RevokedAt and ExpiresAt. No plaintext is in a Key, so
// nothing here needs redacting. The ctx subject needs service_account:read;
// an account in another container is [ErrServiceAccountNotFound].
func (s *Service[C, M, PC, PM]) ListKeys(ctx context.Context, serviceAccountID string) ([]Key, error) {
	_, containerID, err := ctxActor(ctx)
	if err != nil {
		return nil, err
	}
	if err := s.sc.Authorize(ctx, scope.ResourceServiceAccount, scope.ActionRead); err != nil {
		return nil, err
	}
	if _, err := s.account(ctx, containerID, serviceAccountID); err != nil {
		return nil, err
	}
	return s.st.ListKeys(ctx, serviceAccountID)
}

// RevokeKey stamps the key's RevokedAt: it is refused with [ErrKeyRevoked]
// from now on, and the row stays for audit until [Service.PurgeExpired]
// removes it. The ctx subject needs service_account:update; a key in another
// container is [ErrKeyNotFound]. Revoking a revoked key is not an error.
func (s *Service[C, M, PC, PM]) RevokeKey(ctx context.Context, keyID string) error {
	actor, containerID, err := ctxActor(ctx)
	if err != nil {
		return err
	}
	if err := s.sc.Authorize(ctx, scope.ResourceServiceAccount, scope.ActionUpdate); err != nil {
		return err
	}
	k, err := s.st.FindKey(ctx, keyID)
	if err != nil {
		return err
	}
	if k.ContainerID != containerID {
		return ErrKeyNotFound
	}
	if err := s.st.RevokeKey(ctx, keyID, s.cfg.clock()); err != nil {
		return err
	}
	return s.emit(ctx, Event{
		Kind: KeyRevoked, ContainerID: containerID, ActorID: actor,
		ServiceAccountID: k.ServiceAccountID, KeyID: keyID,
	})
}

// Authenticate resolves a presented plaintext to the [Principal] it acts as.
//
// Unlike every management call, ctx needs no subject and no container: the
// key IS the credential, and the container comes from the key. The
// plaintext is hashed ([token.HashOpaque]) and looked up by hash — the
// plaintext is never stored — then refused, in this order, when no key
// matches ([ErrKeyNotFound]), the key is revoked ([ErrKeyRevoked]), the key
// is expired ([ErrKeyExpired] — valid strictly before ExpiresAt), the key's
// account no longer exists (ErrServiceAccountNotFound, a row the Store's
// cascade MUST prevent), or the account is disabled
// ([ErrServiceAccountDisabled]). A refusal emits [KeyAuthenticationFailed]
// with the reason in Detail; a hook error there is joined onto the sentinel,
// never substituted for it.
//
// On success the key's Permissions, if any, are decoded against the scope's
// statements into [Principal.Permissions], and [Store.TouchKey] stamps
// LastUsedAt — best-effort: a touch failure is NOT an authentication
// failure. It is reported on the [KeyAuthenticated] event as
// DetailTouchFailed and the principal is returned all the same, because a
// store hiccup on a bookkeeping column must not lock every automated client
// out. A hook error on KeyAuthenticated, by contrast, IS returned instead of
// the principal (see [Hook]).
//
// Why the reason is disclosed: the caller already holds the key. A 256-bit
// random plaintext cannot be enumerated, so telling its holder that it is
// revoked rather than unknown gives an attacker nothing and gives an
// operator the diagnosis. Hand the specific sentinel to your own logs and a
// uniform 401 to the wire if you prefer.
//
// Pass the result to [WithPrincipal] to act on it.
func (s *Service[C, M, PC, PM]) Authenticate(ctx context.Context, plaintext string) (Principal, error) {
	now := s.cfg.clock()
	k, err := s.st.FindKeyByHash(ctx, token.HashOpaque(plaintext))
	if err != nil {
		if errors.Is(err, ErrKeyNotFound) {
			return Principal{}, s.refuse(ctx, Event{Kind: KeyAuthenticationFailed, Detail: DetailKeyNotFound, At: now}, err)
		}
		return Principal{}, err
	}
	failed := Event{
		Kind: KeyAuthenticationFailed, ContainerID: k.ContainerID,
		ServiceAccountID: k.ServiceAccountID, KeyID: k.ID, At: now,
	}
	if k.RevokedAt != nil {
		failed.Detail = DetailKeyRevoked
		return Principal{}, s.refuse(ctx, failed, ErrKeyRevoked)
	}
	if k.ExpiresAt != nil && !now.Before(*k.ExpiresAt) {
		failed.Detail = DetailKeyExpired
		return Principal{}, s.refuse(ctx, failed, ErrKeyExpired)
	}
	sa, err := s.st.FindServiceAccount(ctx, k.ServiceAccountID)
	if err != nil {
		if errors.Is(err, ErrServiceAccountNotFound) {
			failed.Detail = DetailAccountNotFound
			return Principal{}, s.refuse(ctx, failed, err)
		}
		return Principal{}, err
	}
	if sa.DisabledAt != nil {
		failed.Detail = DetailAccountDisabled
		return Principal{}, s.refuse(ctx, failed, ErrServiceAccountDisabled)
	}

	p := Principal{
		Kind:            KindServiceAccount,
		ID:              sa.ID,
		ContainerID:     k.ContainerID,
		KeyID:           k.ID,
		AuthenticatedAt: now,
	}
	if len(k.Permissions) > 0 {
		ceiling, err := s.sc.Access().Decode(k.Permissions)
		if err != nil {
			return Principal{}, err
		}
		p.Permissions = &ceiling
	}

	ok := Event{
		Kind: KeyAuthenticated, ContainerID: k.ContainerID, ActorID: sa.ID,
		ServiceAccountID: sa.ID, KeyID: k.ID, At: now,
	}
	if err := s.st.TouchKey(ctx, k.ID, now); err != nil {
		ok.Detail = DetailTouchFailed
	}
	if err := s.emit(ctx, ok); err != nil {
		return Principal{}, err
	}
	return p, nil
}

// refuse emits a KeyAuthenticationFailed event and returns sentinel, with a
// hook's error joined on rather than replacing it: a refusal is the answer,
// and a hook cannot make it any more refused.
func (s *Service[C, M, PC, PM]) refuse(ctx context.Context, e Event, sentinel error) error {
	if herr := s.emit(ctx, e); herr != nil {
		return errors.Join(sentinel, herr)
	}
	return sentinel
}

// PurgeExpired deletes every key expired or revoked strictly before `before`,
// across every container the Store holds, and returns how many went. It
// performs NO authorization check and reads neither a subject nor a
// container from the context — there is no ctx container to check against,
// since one call spans every container — so call it from a cron job or a
// trusted maintenance path, never from a per-request handler wired to caller
// input: an unauthenticated caller who could trigger it at will gets a
// cross-tenant denial-of-service knob even though it cannot itself grant
// access. Accounts are never purged.
func (s *Service[C, M, PC, PM]) PurgeExpired(ctx context.Context, before time.Time) (int, error) {
	return s.st.PurgeExpired(ctx, before)
}
