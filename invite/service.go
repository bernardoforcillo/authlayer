package invite

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/bernardoforcillo/authlayer/access"
	"github.com/bernardoforcillo/authlayer/internal/uid"
	"github.com/bernardoforcillo/authlayer/scope"
)

// Preview is the unauthenticated view of a pending [EmailInvite] or [Link],
// returned by [Service.PreviewInvite] and [Service.PreviewLink]. It exists so
// a "you've been invited" landing page can tell an unauthenticated visitor
// who is inviting them to what, and whether accepting would even succeed,
// without exposing the container record itself — which may carry fields of
// the application's own devising that are not meant for an anonymous reader.
type Preview struct {
	// ContainerID is the scope being invited into.
	ContainerID string
	// RoleKey is the role that will be granted on acceptance.
	RoleKey string
	// Email is the invited address. Empty for a link preview, which admits
	// whoever presents the code rather than one named recipient.
	Email string
	// Valid reports whether accepting right now would succeed: the token or
	// code resolves to a record that is not expired, revoked, or exhausted.
	// Checking it consumes nothing.
	Valid bool
}

// Notifier delivers a freshly minted email invitation to its recipient.
// authlayer knows no base URL and owns no transport — [Service.InviteByEmail]
// hands you the stored [EmailInvite] and the plain token in one call, and
// turning those into an actual email (which URL, which template, which
// provider) is entirely your own business. [WithNotifier] is optional sugar
// over calling this yourself right after InviteByEmail returns; the zero
// value (nil, the default) means InviteByEmail sends nothing at all.
type Notifier interface {
	// Notify is called once, synchronously, by InviteByEmail immediately
	// after inv is persisted, together with the plain token that will never
	// be available again afterwards — only its hash is stored (see
	// [EmailInvite]). A non-nil error is returned to InviteByEmail's own
	// caller: the invite row still exists at that point, but its token
	// cannot be recovered, only re-minted by inviting the same address
	// again (see [Store.DeleteEmailInvitesFor]).
	Notify(ctx context.Context, inv EmailInvite, plainToken string) error
}

// config is the resolved Service configuration, built from the defaults and
// mutated via Option — the same shape scope's own config follows.
type config struct {
	inviteExpiry           time.Duration
	notifier               Notifier
	tokens                 func() string
	recheckInviterOnAccept bool
}

func defaultConfig() config {
	return config{
		inviteExpiry:           7 * 24 * time.Hour,
		tokens:                 randomToken,
		recheckInviterOnAccept: true,
	}
}

// randomToken returns 32 bytes of crypto/rand, hex-encoded, as the default
// plain value for an email token or a link code. A crypto/rand failure
// panics rather than degrading to a predictable value — matching
// internal/uid's own stance: a token generator that silently weakens is
// worse than one that stops the process.
func randomToken() string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("authlayer/invite: crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(b[:])
}

// hashToken computes the hex-encoded sha256 of a plain token, the only form
// an EmailInvite ever persists (see that type's doc for why).
func hashToken(plain string) string {
	sum := sha256.Sum256([]byte(plain))
	return hex.EncodeToString(sum[:])
}

// Option customizes a Service. Options are applied in order at construction
// and never afterwards, so a Service's configuration is immutable once
// built — matching [scope.Option].
type Option func(*config)

// WithInviteExpiry sets how long a freshly minted email invite remains
// acceptable: [Service.InviteByEmail] stamps ExpiresAt as CreatedAt+d. The
// default is seven days. d <= 0 is ignored, leaving the default (or a prior
// option) in place, rather than minting an invite that is already expired.
//
// It has no effect on links: a link's expiry is the caller's own explicit,
// per-link choice passed to [Service.CreateLink], where nil means never —
// unlike an email invite, which always expires (see [EmailInvite]).
func WithInviteExpiry(d time.Duration) Option {
	return func(c *config) {
		if d > 0 {
			c.inviteExpiry = d
		}
	}
}

// WithNotifier wires a [Notifier] that [Service.InviteByEmail] calls once it
// has persisted each invite. The default is nil: InviteByEmail mints, stores
// and returns the plain token, and sends nothing — delivery is left entirely
// to the caller.
func WithNotifier(n Notifier) Option {
	return func(c *config) { c.notifier = n }
}

// WithTokens overrides the generator used to mint plain email tokens and
// link codes. The default reads 32 bytes from crypto/rand and hex-encodes
// them — safe for production, but unpredictable, which makes it useless for
// a test that wants to assert on the exact value returned. A nil gen is
// ignored, leaving the default (or a prior option) in place.
//
// SECURITY WARNING: gen is the entire source of unguessability for both an
// email invite's token and a link's code — either one, on its own, is
// sufficient to be admitted to the container once Task 6's AcceptInvite /
// JoinViaLink land (a token is hashed and compared, a code is looked up in
// clear; see [EmailInvite] and [Link]). No authorization check upstream of
// this option can compensate for a weak one: a short, predictable, or
// deterministic generator makes every invitation this Service mints
// guessable by anyone who can enumerate its output. This option exists ONLY
// so a test can assert on a known plain value — never wire a non-default
// generator in production.
//
//	svc := invite.New(sc, st, invite.WithTokens(func() string { return "fixed-token" }))
func WithTokens(gen func() string) Option {
	return func(c *config) {
		if gen != nil {
			c.tokens = gen
		}
	}
}

// WithRecheckInviterOnAccept controls whether [Service.AcceptInvite] and
// [Service.JoinViaLink] re-run the privilege-escalation guard against the
// inviter's CURRENT standing before admitting anyone. The default is true.
//
// The guard already ran once, at mint time ([Service.InviteByEmail] /
// [Service.CreateLink]), against the inviter's standing as of that moment.
// Nothing about a stored token or link updates afterwards, so without a
// recheck a credential keeps paying out at the power level its inviter held
// when they minted it — even after that inviter is demoted, or leaves the
// container entirely. An admin who invites someone to an admin-level role and
// is then demoted to member would otherwise leave behind a still-live
// invitation that grants more than the admin could grant if asked again right
// now. Enabled, that pending invitation dies the moment its inviter's own
// standing can no longer support it: a demoted inviter fails with
// scope.ErrPrivilegeEscalation, the same guard [Service.guardEscalation]
// applies at mint time, reapplied here against the inviter's standing as of
// right now rather than as of when they minted the credential. An inviter who
// has left the container entirely fails the same way but with a different
// sentinel — scope.ErrNotMember, surfaced from the guard's own
// [scope.Service.Standing] call — since there is no standing left to compare
// against at all. Both are refusals; neither admits anyone.
//
// Disabling it (enabled=false) trades that safety for durability: an
// invitation survives its inviter's departure or demotion and still admits at
// the role it was minted for. That can be the right call for an application
// that treats "who invited me" as provenance rather than as an ongoing
// authorization the inviter must keep backing — know that trade-off before
// turning it off.
func WithRecheckInviterOnAccept(enabled bool) Option {
	return func(c *config) { c.recheckInviterOnAccept = enabled }
}

// Service mints, lists, revokes and previews invitations for one scope
// instance. C, M, PC, PM mirror [scope.Service]'s own type parameters exactly
// — a Service is built over the same container and member types as the
// scope.Service it wraps, since accepting an invitation ends in exactly the
// membership scope.Service itself would create.
//
// A Service performs its own authorization — invite:create, invite:read,
// invite:delete via [scope.Service.Authorize], plus a privilege-escalation
// guard on creation — using the acting subject and active container carried
// on the context, the same convention scope.Service follows
// ([scope.WithSubject], [scope.WithScope]). It is safe for concurrent use if
// its scope.Service and Store are, and caches nothing.
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

// New wires a scope.Service, an invite.Store and options into a Service.
//
// sc supplies every permission decision this package needs without
// reimplementing scope's engine: [scope.Service.Authorize] for the
// invite:create/read/delete checks, [scope.Service.Standing] for the
// actor's own standing, and [scope.Service.RolePermissions] for a role's
// resolved permissions — used both by the escalation guard on creation and
// by the [Service.ListLinks] redaction. RolePermissions is the same
// resolution every permission check in scope performs, so this package and
// [scope.Service.GrantMembership] can never disagree about what a role
// grants. st is the invitation Store described in this package's own doc:
// store/memory for tests and development, store/drops for production.
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

// ctxActor extracts the acting subject and active container from ctx. It
// mirrors scope's own unexported ctxActor (scope/context.go) exactly, built
// from the two calls scope exports for precisely this purpose, since this
// package cannot call the unexported one directly.
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

// guardEscalation enforces, on invite and link creation, the same rule
// scope.Service applies to AddMember: unless the actor is elevated, they may
// not mint a credential for a role more powerful than their own standing
// (scope.ErrPrivilegeEscalation). scope.Service's own guardEscalation is
// unexported and unreachable from this package, so this recomputes the
// identical answer from two exported calls — [scope.Service.Standing] for
// the actor's own permissions and elevation, [scope.Service.RolePermissions]
// for roleKey's resolved permissions.
//
// RolePermissions is a thin wrapper over scope's own unexported resolveRole
// — the same call [scope.Service.AddMember]'s guard and
// [scope.Service.GrantMembership] use — so this asks the engine the
// identical question rather than reconstructing an approximation of it (see
// that method's own doc for why building an equivalent from
// [scope.Service.ListRoles] is NOT safe: ListRoles omits any code-defined
// role beyond the three hardcoded defaults).
//
// A roleKey that resolves to no role at all is scope.ErrRoleNotFound,
// propagated as-is from RolePermissions, not scope.ErrPrivilegeEscalation —
// matching scope.Service's own resolveRole, which is checked BEFORE the
// SubsetOf comparison in scope's guardEscalation (scope/scope.go).
// Conflating the two would tell a caller who mistyped a role key that they
// lack the privilege to grant it, when the real problem is that no such
// role exists to grant.
//
// One deliberate divergence: scope's own guard also stands down when the
// wrapped Service's Policy.Escalation is EscalationOff, but Policy is
// unexported and this package has no way to read it, so this guard always
// enforces strict escalation regardless of how the wrapped scope.Service was
// configured. That is the safe direction to diverge in — it can only refuse
// an invite/link creation that a lenient policy would have allowed via
// AddMember directly, never the reverse — but an application running with
// EscalationOff should know invite/link creation does not inherit that
// leniency.
func (s *Service[C, M, PC, PM]) guardEscalation(ctx context.Context, containerID, actorID, roleKey string) error {
	perms, elevated, err := s.sc.Standing(ctx, containerID, actorID)
	if err != nil {
		return err
	}
	if elevated {
		return nil
	}
	grant, err := s.sc.RolePermissions(ctx, containerID, roleKey)
	if err != nil {
		return err
	}
	if !grant.SubsetOf(perms) {
		return scope.ErrPrivilegeEscalation
	}
	return nil
}

// recheckValid reports whether the escalation guard, reapplied against
// inviterID's CURRENT standing, would currently admit — the same question
// [Service.AcceptInvite] and [Service.JoinViaLink] ask via [guardEscalation]
// when [WithRecheckInviterOnAccept] is enabled, exposed here so
// [Service.PreviewInvite] and [Service.PreviewLink] can report a Valid that
// actually matches what acceptance will do, instead of going stale the
// moment an inviter's standing changes.
//
// The knob being off short-circuits to (true, nil): the recheck plays no
// part in acceptance, so it plays no part in the preview either.
//
// A refusal acceptance itself would treat as a refusal —
// scope.ErrPrivilegeEscalation, scope.ErrRoleNotFound (the role was deleted),
// or scope.ErrNotMember (the inviter left) — is folded into (false, nil):
// those are answers, not failures to answer, matching how [Preview.Valid]
// already folds an expired token or a revoked link. Anything else — a store
// failure, typically — is returned as an error rather than silently read as
// "not valid", the same discipline [scope.Service.Can]'s own doc describes:
// a question that could not be answered must never be narrowed into a denial.
func (s *Service[C, M, PC, PM]) recheckValid(ctx context.Context, containerID, inviterID, roleKey string) (bool, error) {
	if !s.cfg.recheckInviterOnAccept {
		return true, nil
	}
	err := s.guardEscalation(ctx, containerID, inviterID, roleKey)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, scope.ErrPrivilegeEscalation), errors.Is(err, scope.ErrRoleNotFound), errors.Is(err, scope.ErrNotMember):
		return false, nil
	default:
		return false, err
	}
}

// InviteByEmail mints a one-time invitation for email to hold roleKey once
// accepted, and returns the plain token alongside the stored record. The
// plain value is returned exactly once and never again — only its sha256 is
// persisted (see [EmailInvite]) — so the caller must deliver it now, either
// itself using the return value or via [WithNotifier].
//
// The ctx subject needs invite:create in the ctx container, and — unless
// elevated — may not invite to a role more powerful than their own (see
// [Service.guardEscalation]). Re-inviting an address that already has a
// pending invitation replaces it: [Store.DeleteEmailInvitesFor] runs first,
// so the old token stops resolving the instant the new one is minted, not
// merely once it later expires.
//
// The invite always expires — [WithInviteExpiry] sets how long, seven days
// by default. There is no "never" case for an email invite, unlike a link.
//
// If a [Notifier] is configured, it is called once the invite is persisted;
// a Notify error is returned here, after the row is already stored (see
// [Notifier] for what that leaves behind).
func (s *Service[C, M, PC, PM]) InviteByEmail(ctx context.Context, email, roleKey string) (EmailInvite, string, error) {
	actor, containerID, err := ctxActor(ctx)
	if err != nil {
		return EmailInvite{}, "", err
	}
	if err := s.sc.Authorize(ctx, scope.ResourceInvite, scope.ActionCreate); err != nil {
		return EmailInvite{}, "", err
	}
	if err := s.guardEscalation(ctx, containerID, actor, roleKey); err != nil {
		return EmailInvite{}, "", err
	}

	if err := s.st.DeleteEmailInvitesFor(ctx, containerID, email); err != nil {
		return EmailInvite{}, "", err
	}

	plain := s.cfg.tokens()
	now := time.Now().UTC()
	stored, err := s.st.CreateEmailInvite(ctx, EmailInvite{
		ID:          uid.NewV7(),
		ContainerID: containerID,
		Email:       email,
		RoleKey:     roleKey,
		TokenHash:   hashToken(plain),
		InvitedBy:   actor,
		ExpiresAt:   now.Add(s.cfg.inviteExpiry),
		CreatedAt:   now,
	})
	if err != nil {
		return EmailInvite{}, "", err
	}

	if s.cfg.notifier != nil {
		if err := s.cfg.notifier.Notify(ctx, stored, plain); err != nil {
			return EmailInvite{}, "", err
		}
	}
	return stored, plain, nil
}

// CreateLink mints a reusable invitation link admitting up to maxUses
// redemptions (0 meaning unlimited) at roleKey, and returns the plain code
// alongside the stored record. Unlike an email token, Code is stored in
// clear (see [Link]) — a link is meant to be re-displayed on a "manage
// invite links" screen, so the returned code and the stored one are the same
// value, not a one-time reveal.
//
// The ctx subject needs invite:create in the ctx container, and — unless
// elevated — may not create a link for a role more powerful than their own
// (see [Service.guardEscalation]).
//
// expiresAt is the caller's explicit choice: nil means the link never
// expires, matching [Link.ExpiresAt]'s own doc. There is no default the way
// [WithInviteExpiry] provides one for email invites — a link's whole point is
// to stay reusable for as long as its owner intends, which InviteByEmail's
// single-recipient token has no equivalent of.
func (s *Service[C, M, PC, PM]) CreateLink(ctx context.Context, roleKey string, maxUses int, expiresAt *time.Time) (Link, string, error) {
	actor, containerID, err := ctxActor(ctx)
	if err != nil {
		return Link{}, "", err
	}
	if err := s.sc.Authorize(ctx, scope.ResourceInvite, scope.ActionCreate); err != nil {
		return Link{}, "", err
	}
	if err := s.guardEscalation(ctx, containerID, actor, roleKey); err != nil {
		return Link{}, "", err
	}

	code := s.cfg.tokens()
	stored, err := s.st.CreateLink(ctx, Link{
		ID:          uid.NewV7(),
		ContainerID: containerID,
		Code:        code,
		RoleKey:     roleKey,
		CreatedBy:   actor,
		MaxUses:     maxUses,
		ExpiresAt:   expiresAt,
		CreatedAt:   time.Now().UTC(),
	})
	if err != nil {
		return Link{}, "", err
	}
	return stored, code, nil
}

// ListInvites returns every pending email invite in the ctx container. The
// ctx subject needs invite:read. Unlike [Service.ListLinks], nothing here is
// redacted: an [EmailInvite] never stores the plain token, only its sha256
// (see that type's doc), so there is no secret left in the record for
// invite:read to leak in the first place.
func (s *Service[C, M, PC, PM]) ListInvites(ctx context.Context) ([]EmailInvite, error) {
	_, containerID, err := ctxActor(ctx)
	if err != nil {
		return nil, err
	}
	if err := s.sc.Authorize(ctx, scope.ResourceInvite, scope.ActionRead); err != nil {
		return nil, err
	}
	return s.st.ListEmailInvites(ctx, containerID)
}

// ListLinks returns every invitation link in the ctx container, with Code
// blanked on any link the ctx subject could not have minted themselves.
//
// # This is the security core of the invite package
//
// invite:read sits on the merged permission surface (see
// [scope.ControlStatements]), so the built-in admin role acquires it
// automatically — and admin is deliberately not IsFull, so it is normally
// subject to the privilege-escalation guard everywhere else in this
// codebase. Without redaction here that guard is worthless: a non-elevated
// admin lists the links, reads the owner's Code in clear, leaves the
// container, and rejoins at the owner role through JoinViaLink, which admits
// via [scope.Service.GrantMembership] — a call that by design runs no
// escalation check of its own, because the whole point of a link is to admit
// someone who has no standing yet to check. Two calls, full escalation, and
// every fine-grained check elsewhere in the codebase never touched.
//
// So a Code survives in the result only when BOTH halves of the mint test
// hold for the reader, because the invariant being defended is "nothing hands
// a usable credential to a principal who could not have minted it", and
// minting takes two things:
//
//  1. The capability. The reader must hold invite:create in the ctx container
//     — the same permission [Service.CreateLink] requires — resolved once for
//     the whole list via [scope.Service.Can], not per link. A reader granted
//     invite:read WITHOUT invite:create could not have minted ANY link here,
//     so they see no Code at all, whatever the roles involved. That
//     configuration is ordinary and supported: splitting a resource's actions
//     across roles is the entire product, and [scope.Service.CreateRole]
//     accepts an "auditor" granting only invite:read. Without this half such
//     a reader silently gains the power to admit arbitrary third parties —
//     read-implies-admit — which is precisely the capability invite:create
//     exists to gate. Note it does not shrink to a denial when the question
//     cannot be answered: Can folds only ErrForbidden/ErrNotMember to false
//     and surfaces everything else as an error.
//
//  2. The standing. The ctx subject must be elevated, or the link's RoleKey
//     must resolve to a permission set that is a SubsetOf the subject's own
//     current standing — exactly the test [Service.guardEscalation] applies
//     when a link is created, reapplied here on the way out, because a role's
//     grants (or the reader's own standing) can change after the link was
//     minted.
//
// The two are independent and neither implies the other: (1) bounds WHETHER
// this principal mints at all, (2) bounds HOW HIGH. Every other field — ID, ContainerID,
// RoleKey, CreatedBy, MaxUses, UseCount, ExpiresAt, RevokedAt, CreatedAt —
// stays populated, so a management screen can still list and let its owner
// call [Service.RevokeLink] on a link whose Code they cannot read back.
// RoleKey specifically is never redacted: the role's name is not the
// credential, only Code is.
//
// Each link's RoleKey is resolved via [scope.Service.RolePermissions] —
// scope's own registry-then-store lookup, wrapped rather than
// reimplemented — never via [scope.Service.ListRoles], which does not
// enumerate every code-defined role (see RolePermissions' own doc) and
// would silently mis-redact one that only ListRoles doesn't know about. A
// RoleKey that RolePermissions cannot resolve at all (scope.ErrRoleNotFound)
// is redacted, not kept: an unresolvable role is not one the reader can be
// shown to subsume. The lookup is memoized per distinct RoleKey within this
// call — the same per-(container, role) cache
// [scope.Service.ContainersWith] keeps for itself — so listing many links
// naming a handful of roles costs one RolePermissions call per distinct
// role, not one per link.
//
// The ctx subject needs invite:read to call this at all, same as
// [Service.ListInvites]; invite:create is not required to call it, only to
// read any Code back.
func (s *Service[C, M, PC, PM]) ListLinks(ctx context.Context) ([]Link, error) {
	actor, containerID, err := ctxActor(ctx)
	if err != nil {
		return nil, err
	}
	if err := s.sc.Authorize(ctx, scope.ResourceInvite, scope.ActionRead); err != nil {
		return nil, err
	}

	links, err := s.st.ListLinks(ctx, containerID)
	if err != nil {
		return nil, err
	}

	// Half one of the mint test, asked once for the whole list rather than
	// per link: could this reader have minted anything here at all? A
	// reader without invite:create could not have, so every Code is blanked
	// regardless of role — including for an elevated reader, so that the
	// conjunction has no exception to reason about. (In practice an
	// elevated subject holds Full permissions and so always clears this.)
	mayMint, err := s.sc.Can(ctx, scope.ResourceInvite, scope.ActionCreate)
	if err != nil {
		return nil, err
	}
	if !mayMint {
		out := make([]Link, len(links))
		for i, l := range links {
			l.Code = ""
			out[i] = l
		}
		return out, nil
	}

	// Half two: how high could they have minted?
	perms, elevated, err := s.sc.Standing(ctx, containerID, actor)
	if err != nil {
		return nil, err
	}
	if elevated {
		return links, nil
	}

	resolved := make(map[string]access.Permission, len(links))
	out := make([]Link, len(links))
	for i, l := range links {
		grant, ok := resolved[l.RoleKey]
		if !ok {
			g, rErr := s.sc.RolePermissions(ctx, containerID, l.RoleKey)
			switch {
			case errors.Is(rErr, scope.ErrRoleNotFound):
				// Unresolvable: cannot be shown to subsume anything, so
				// redact. Deliberately NOT cached in resolved — caching a
				// "not found" answer as anything storable here would risk
				// the same mistake a zero access.Permission would (see
				// scope.Service.ContainersWith's identical choice not to
				// cache this branch): resolved must only ever hold real,
				// resolved permissions, never a stand-in for "unknown".
				l.Code = ""
				out[i] = l
				continue
			case rErr != nil:
				return nil, rErr
			}
			grant = g
			resolved[l.RoleKey] = grant
		}
		if !grant.SubsetOf(perms) {
			l.Code = ""
		}
		out[i] = l
	}
	return out, nil
}

// RevokeInvite deletes a pending email invite by id. The ctx subject needs
// invite:delete in the ctx container.
//
// [Store]'s own DeleteEmailInvite takes only an id — invite records are
// looked up by surrogate key, not scoped by container the way
// [scope.Store]'s member/role methods are, because Store "performs no
// authorization or scoping of its own" (see that interface's doc). So this
// method loads the record first and refuses to act unless it belongs to the
// ctx container, reporting [ErrInviteNotFound] exactly as if the id did not
// exist at all, rather than revealing that a differently-scoped record does:
// an invite:delete grant in one container must never become a way to revoke
// an invitation that belongs to another.
func (s *Service[C, M, PC, PM]) RevokeInvite(ctx context.Context, id string) error {
	_, containerID, err := ctxActor(ctx)
	if err != nil {
		return err
	}
	if err := s.sc.Authorize(ctx, scope.ResourceInvite, scope.ActionDelete); err != nil {
		return err
	}
	inv, err := s.st.FindEmailInvite(ctx, id)
	if err != nil {
		return err
	}
	if inv.ContainerID != containerID {
		return ErrInviteNotFound
	}
	return s.st.DeleteEmailInvite(ctx, id)
}

// RevokeLink revokes an invitation link by id, stamping RevokedAt rather than
// deleting the row (see [Store.RevokeLink]). The ctx subject needs
// invite:delete in the ctx container, and — for exactly the reason given on
// [Service.RevokeInvite] — this checks the loaded link's ContainerID against
// the ctx container before acting, reporting [ErrLinkNotFound] for a link
// that belongs elsewhere rather than revoking across a tenant boundary.
func (s *Service[C, M, PC, PM]) RevokeLink(ctx context.Context, id string) error {
	_, containerID, err := ctxActor(ctx)
	if err != nil {
		return err
	}
	if err := s.sc.Authorize(ctx, scope.ResourceInvite, scope.ActionDelete); err != nil {
		return err
	}
	l, err := s.st.FindLink(ctx, id)
	if err != nil {
		return err
	}
	if l.ContainerID != containerID {
		return ErrLinkNotFound
	}
	return s.st.RevokeLink(ctx, id, time.Now().UTC())
}

// AcceptInvite redeems plainToken, admitting the ctx subject into the
// invite's container at its invited role, and returns that container.
//
// Unlike every other method on Service, ctx carries only a subject
// ([scope.WithSubject]) — no active container ([scope.WithScope]) — because
// the invitee has no standing anywhere yet to name one. The container comes
// back from the token itself.
//
// # Ordering, and why
//
// Acceptance spans two stores that may not share a database — the invite
// lives in this package's own Store, the membership in [scope.Service]'s —
// so there is no cross-store transaction. This method claims the invite
// FIRST and grants the membership SECOND — the same direction
// [Service.JoinViaLink] uses for a link's use, and for the identical reason.
// The claim is [Store.DeleteEmailInvite], whose contract is rows-affected
// gated: it reports [ErrInviteNotFound] when no row matched, so of any two
// callers racing to delete the same id — including the same token presented
// twice — at most one can ever see a nil error. Only that caller proceeds to
// [scope.Service.GrantMembership]; the other is refused with
// ErrInviteNotFound, indistinguishable from the token never having existed.
// That is the same claim-then-admit shape [Store.ConsumeLink] already gives
// a link, just expressed through a delete's rows-affected count instead of
// an UPDATE's — both stores already implement DeleteEmailInvite this way
// (store/memory holds its mutex across the check-and-delete; store/drops'
// DELETE is a single statement gated on rows affected), so no store change
// was needed to get this property.
//
// The reverse order — admit first, claim second — is what an earlier version
// of this method did, and it is a Critical: while the invite row still
// exists, the token stays redeemable by ANYONE presenting it, not merely by
// the original caller retrying. A one-time credential must never pay out more
// than once; this package's own stated rule for [Service.JoinViaLink] is
// "over-admission past a use limit... is the one direction this package must
// never fail open in" — an email invite's MaxUses is implicitly one, and the
// same rule applies here.
//
// One consequence worth stating plainly: accepting is NOT safe to retry with
// the same token. If GrantMembership fails after the claim already succeeded
// — a store outage, an unresolvable role — the invite is gone and cannot be
// re-presented; the invitee must be re-invited ([Service.InviteByEmail],
// which replaces any prior pending invite for the same address). This is the
// same trade [Service.JoinViaLink] already makes for a link: a failure after
// the claim under-admits (burns the credential, admits no one extra), which
// is the safe direction, at the cost of idempotent retries.
//
// scope.ErrAlreadyMember from GrantMembership is still folded to success:
// the subject already holds the outcome the invitation exists to produce.
// One sharp edge that follows from that fold: a member who already holds a
// LOWER role than the invitation grants gets no error and no promotion — the
// invite is consumed, their membership is left exactly as it was, and
// nothing in this call's return value distinguishes "already had this role"
// from "already had a lesser one". This never over-privileges — folding a
// duplicate can only leave someone at or below what they already had — but
// it can silently under-deliver an intended promotion. An application that
// needs to detect that case should check [scope.Service.Standing] before
// calling AcceptInvite, or route promotions through
// [scope.Service.ChangeMemberRole] rather than a fresh invitation.
//
// # What is checked before claiming
//
// The presented token is hashed and looked up by hash — the plain value is
// never stored (see [EmailInvite]) — an unknown token is [ErrInviteNotFound].
// A token past its ExpiresAt is [ErrInviteExpired] and admits no one; this is
// checked before anything else runs, so an expired token is never claimed
// (or admitted) — [Service.PurgeExpired] remains the intended way to remove
// it. Unless [WithRecheckInviterOnAccept] was set to false, the escalation
// guard then re-runs against the inviter's CURRENT standing — see that
// option's doc for what changed and why — before the invite is claimed, so a
// refused recheck does not spend the credential either.
//
// Accepted asymmetry with [Store.ConsumeLink]: the expiry check above reads
// ExpiresAt once, before the claim, rather than re-evaluating it atomically
// as part of the claim itself the way ConsumeLink folds expiry into its
// single UPDATE. An invitation that expires in the narrow window between that
// read and the claim a few lines later can therefore be claimed and admitted
// microseconds past its nominal deadline. This is deliberately left as-is:
// the claim still admits at most one caller regardless, so it is a boundary
// imprecision, not an over-admission risk, and closing it would mean adding
// an expiry predicate to [Store.DeleteEmailInvite]'s port contract — a
// bigger change, across every Store implementation, than the boundary is
// worth.
func (s *Service[C, M, PC, PM]) AcceptInvite(ctx context.Context, plainToken string) (C, error) {
	var zero C
	subject, ok := scope.SubjectFrom(ctx)
	if !ok {
		return zero, scope.ErrSubjectMissing
	}

	inv, err := s.st.FindEmailInviteByTokenHash(ctx, hashToken(plainToken))
	if err != nil {
		return zero, err
	}
	if !time.Now().UTC().Before(inv.ExpiresAt) {
		return zero, ErrInviteExpired
	}

	if s.cfg.recheckInviterOnAccept {
		if err := s.guardEscalation(ctx, inv.ContainerID, inv.InvitedBy, inv.RoleKey); err != nil {
			return zero, err
		}
	}

	// The claim: DeleteEmailInvite's rows-affected contract means at most one
	// caller ever sees a nil error for this id. Losing the race — including a
	// second presentation of the SAME token — is ErrInviteNotFound, exactly as
	// if the token had never existed. Only the winner proceeds.
	if err := s.st.DeleteEmailInvite(ctx, inv.ID); err != nil {
		return zero, err
	}

	if _, err := s.sc.GrantMembership(ctx, inv.ContainerID, subject, inv.RoleKey); err != nil &&
		!errors.Is(err, scope.ErrAlreadyMember) {
		return zero, err
	}

	return s.sc.Container(ctx, inv.ContainerID)
}

// JoinViaLink redeems code, admitting the ctx subject into the link's
// container at its role, and returns that container. Like [Service.AcceptInvite],
// ctx carries only a subject — no active container — for the same reason.
//
// # Already a member
//
// If the ctx subject already has standing in the link's container —
// membership, inheritance, or ownership; the same question
// [scope.Service.Standing] answers — this returns the container immediately,
// consuming nothing: no use is taken from the link, and no redundant
// membership write is attempted (see spec §6.5). This is checked FIRST,
// before the escalation recheck and before touching the link's use count at
// all, precisely so an existing member re-clicking an invite link never costs
// it anything.
//
// # Ordering, and why
//
// For a subject with no standing yet, the two-store idempotency argument from
// [Service.AcceptInvite] applies here too, but the safe direction is
// reversed: this method consumes the link's use FIRST (atomically, via
// [Store.ConsumeLink]) and grants the membership SECOND. If the membership
// grant then fails, one use is burned for nothing — under-admission, and
// recoverable: the invitee can be re-invited or, MaxUses permitting, try the
// same link again. The reverse order — grant first, consume second — would
// let every concurrent caller of a MaxUses:1 link past GrantMembership before
// any of them touched the use count, since GrantMembership itself enforces no
// such limit: only one of them would then win the atomic consume, but all of
// them would already hold a real membership. That is over-admission past a
// use limit specifically designed to bound it, which is the one direction
// this package must never fail open in.
//
// # What is checked before consuming
//
// An unknown code is [ErrLinkNotFound]. Unless [WithRecheckInviterOnAccept]
// was set to false, the escalation guard re-runs against the link creator's
// CURRENT standing next — see that option's doc — checked before consumption
// so a link whose creator can no longer support its role does not burn a use
// either. [Store.ConsumeLink] then reports ok=false for a revoked, expired,
// or exhausted link without saying which; this method re-reads the link to
// tell them apart and reports [ErrLinkRevoked], [ErrLinkExpired], or
// [ErrLinkExhausted] accordingly.
func (s *Service[C, M, PC, PM]) JoinViaLink(ctx context.Context, code string) (C, error) {
	var zero C
	subject, ok := scope.SubjectFrom(ctx)
	if !ok {
		return zero, scope.ErrSubjectMissing
	}

	l, err := s.st.FindLinkByCode(ctx, code)
	if err != nil {
		return zero, err
	}

	switch _, _, err := s.sc.Standing(ctx, l.ContainerID, subject); {
	case err == nil:
		// Already has standing here: hand back the container, consume nothing.
		return s.sc.Container(ctx, l.ContainerID)
	case !errors.Is(err, scope.ErrNotMember):
		return zero, err
	}

	if s.cfg.recheckInviterOnAccept {
		if err := s.guardEscalation(ctx, l.ContainerID, l.CreatedBy, l.RoleKey); err != nil {
			return zero, err
		}
	}

	now := time.Now().UTC()
	ok2, err := s.st.ConsumeLink(ctx, l.ID, now)
	if err != nil {
		return zero, err
	}
	if !ok2 {
		cur, err := s.st.FindLink(ctx, l.ID)
		if err != nil {
			return zero, err
		}
		switch {
		case cur.RevokedAt != nil:
			return zero, ErrLinkRevoked
		case cur.ExpiresAt != nil && !now.Before(*cur.ExpiresAt):
			return zero, ErrLinkExpired
		default:
			return zero, ErrLinkExhausted
		}
	}

	// Unlike AcceptInvite, an ErrAlreadyMember here is NOT folded to success.
	// That is a deliberate choice but not a safety one either way: ConsumeLink
	// above already ran and already burned the use before this call, so
	// folding would cost zero additional uses if it were added — the
	// candidate ordering couldn't produce it under the normal "already a
	// member" short-circuit earlier in this method, only under the narrow
	// same-subject race where two calls both pass that check before either
	// writes. Left unfolded because that race is rare enough that a surfaced
	// error (prompting a caller to just re-check their own membership) is a
	// reasonable default, not because folding it would be unsafe.
	if _, err := s.sc.GrantMembership(ctx, l.ContainerID, subject, l.RoleKey); err != nil {
		return zero, err
	}

	return s.sc.Container(ctx, l.ContainerID)
}

// PreviewInvite resolves a plain email token to a [Preview], for an
// unauthenticated "you've been invited" page. It reads nothing from the
// context and performs no permission check of its own caller — there is no
// standing to check yet, which is exactly the situation such a page is in —
// and it never exposes the container record itself, only ContainerID,
// RoleKey, Email and whether accepting would currently succeed.
//
// An unknown token is [ErrInviteNotFound]. A known but expired one is not an
// error: Preview.Valid is false and the rest of the fields stay populated,
// so the page can say "this invitation has expired" rather than a generic
// failure. Unless [WithRecheckInviterOnAccept] was set to false, an
// unexpired token whose inviter's CURRENT standing would now fail the
// escalation guard is ALSO reported as Valid=false, via [recheckValid] — the
// same question [Service.AcceptInvite] asks before admitting, asked here too
// so this preview cannot tell an unauthenticated visitor their invitation is
// good when acceptance would immediately refuse it with
// scope.ErrPrivilegeEscalation.
func (s *Service[C, M, PC, PM]) PreviewInvite(ctx context.Context, plainToken string) (Preview, error) {
	inv, err := s.st.FindEmailInviteByTokenHash(ctx, hashToken(plainToken))
	if err != nil {
		return Preview{}, err
	}
	valid := time.Now().UTC().Before(inv.ExpiresAt)
	if valid {
		valid, err = s.recheckValid(ctx, inv.ContainerID, inv.InvitedBy, inv.RoleKey)
		if err != nil {
			return Preview{}, err
		}
	}
	return Preview{
		ContainerID: inv.ContainerID,
		RoleKey:     inv.RoleKey,
		Email:       inv.Email,
		Valid:       valid,
	}, nil
}

// PreviewLink resolves a link code to a [Preview], the link equivalent of
// [Service.PreviewInvite]. Email is always empty — a link has no single
// named recipient — and Valid folds every reason redemption could currently
// fail (revoked, expired, exhausted, and — unless [WithRecheckInviterOnAccept]
// was set to false — the creator's current standing no longer supporting the
// role, via [recheckValid], for the same reason [Service.PreviewInvite]
// checks it) into one boolean, since a preview has no need to distinguish
// which: [Service.JoinViaLink] is what will surface the specific sentinel on
// an actual redemption attempt.
//
// It performs no check that would consume the link — computing Valid costs
// nothing, and previewing a link must never be the thing that exhausts it.
func (s *Service[C, M, PC, PM]) PreviewLink(ctx context.Context, code string) (Preview, error) {
	l, err := s.st.FindLinkByCode(ctx, code)
	if err != nil {
		return Preview{}, err
	}
	valid := l.RevokedAt == nil &&
		(l.ExpiresAt == nil || time.Now().UTC().Before(*l.ExpiresAt)) &&
		(l.MaxUses == 0 || l.UseCount < l.MaxUses)
	if valid {
		valid, err = s.recheckValid(ctx, l.ContainerID, l.CreatedBy, l.RoleKey)
		if err != nil {
			return Preview{}, err
		}
	}
	return Preview{
		ContainerID: l.ContainerID,
		RoleKey:     l.RoleKey,
		Valid:       valid,
	}, nil
}

// PurgeExpired deletes every expired invite and link, across every container
// this Store holds, and returns how many rows were removed — a direct pass
// through to [Store.PurgeExpired]. It is housekeeping over rows that are
// already unusable through the normal lookup and consume paths, not a
// security boundary (see that method's own doc).
//
// This is deliberate, matching the warnings on [scope.Service.HasPermission]
// and [scope.Service.GrantMembership]: PurgeExpired performs NO authorization
// check and reads NEITHER a subject nor a container from the context — there
// is no ctx container to check against in the first place, since a single
// call spans every container the Store holds, and deleting an already-dead
// row confers no standing on anyone. That does not make it safe to expose to
// an end user, though: an unauthenticated or under-privileged caller who
// could trigger it at will gets a cross-tenant denial-of-service knob
// (hammering the Store, or deleting another tenant's rows on demand) even
// though it cannot itself grant access. Call it only from a trusted context
// — a cron job, a superuser console — never from a per-request handler wired
// to caller input.
func (s *Service[C, M, PC, PM]) PurgeExpired(ctx context.Context, before time.Time) (int, error) {
	return s.st.PurgeExpired(ctx, before)
}
