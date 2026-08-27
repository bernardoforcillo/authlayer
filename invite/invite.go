// Package invite defines the persistence shape for admitting a person who has
// no standing in a scope, by a path other than a direct AddMember call: a
// one-time emailed token ([EmailInvite]) or a reusable link ([Link]).
//
// Like scope, this package is split into a pure-persistence port ([Store])
// and the types it moves. It performs no authorization and interprets no
// permission itself — that is left to the service layer built on top, which
// mints tokens and links, checks the invite:create/read/delete control
// statements, and calls [scope.Service.GrantMembership] to perform the actual
// admission. store/memory holds the reference Store implementation used by
// this package's own tests; store/drops is the production one.
package invite

import (
	"context"
	"errors"
	"time"
)

// EmailInvite is a one-time invitation delivered by email.
//
// # The token is a bearer credential
//
// One-time means it pays out at most once, not that it pays out only to the
// invited person. Whoever holds the token can redeem it:
// [Service.AcceptInvite] admits the ctx subject at RoleKey and never compares
// that subject to Email. A forwarded, intercepted or shoulder-surfed
// invitation email admits whoever clicks it, at the invited role.
//
// Email is a delivery hint and an audit record — where the token was sent,
// and what to show on a "pending invitations" screen — not an authorization
// check. It cannot be one here: authlayer stores no users and has no notion
// of a subject's verified address (see the package doc's "no user table"
// stance), so there is nothing for the library to compare the accepting
// subject against. An application that needs the invitation bound to its
// recipient must enforce that itself, before calling AcceptInvite — compare
// Email against the authenticated user's own verified address, using
// [Service.PreviewInvite] to read the invited address out of a token without
// consuming it.
//
// Only TokenHash is stored — never the plain token. The token is emailed once
// and never redisplayed to anyone, including the inviter, so persisting just
// its sha256 hash means a database leak cannot be replayed to gain admission:
// an attacker who steals the row still cannot produce a token that hashes to
// it. Acceptance means hashing the presented token and looking it up by hash
// ([Store.FindEmailInviteByTokenHash]), never looking a plaintext token back
// up.
//
// ExpiresAt is a plain time.Time, not a pointer, because an email invite
// always expires — there is no "never" case to represent, unlike [Link].
type EmailInvite struct {
	// ID is the record's surrogate key, stamped by the service.
	ID string `drop:"id"`
	// ContainerID is the scope the invitee is admitted to on acceptance.
	ContainerID string `drop:"container_id"`
	// Email is the address the token was sent to. Delivery hint and audit
	// record only — acceptance never checks it. See the type doc.
	Email string `drop:"email"`
	// RoleKey is the role the invitee holds once admitted.
	RoleKey string `drop:"role_key"`
	// TokenHash is sha256(token). See the type doc for why the plain token
	// itself is never persisted.
	TokenHash string `drop:"token_hash"`
	// InvitedBy is the user id of whoever minted the invite.
	InvitedBy string `drop:"invited_by"`
	// ExpiresAt is when the invite stops being acceptable. Always set — see
	// the type doc for why this is not a pointer.
	ExpiresAt time.Time `drop:"expires_at"`
	// CreatedAt is stamped by the service clock.
	CreatedAt time.Time `drop:"created_at"`
}

// Link is a reusable invitation: anyone who presents Code is admitted, up to
// MaxUses redemptions (or without limit, if MaxUses is 0).
//
// Unlike [EmailInvite], Code is stored in clear rather than hashed. A link is
// meant to be shown again — a "manage invite links" screen needs to display or
// re-copy the URL for whoever owns it — and a hash makes that impossible. A
// link's security therefore does not come from secrecy of storage the way a
// token's does; it comes from MaxUses, ExpiresAt and revocation, which is
// exactly why those three fields exist and why [Store.ConsumeLink] must weigh
// all three atomically before admitting anyone.
type Link struct {
	// ID is the record's surrogate key, stamped by the service.
	ID string `drop:"id"`
	// ContainerID is the scope the link admits into.
	ContainerID string `drop:"container_id"`
	// Code is the value presented to redeem the link, stored in clear — see
	// the type doc for why.
	Code string `drop:"code"`
	// RoleKey is the role a redeemer is admitted with.
	RoleKey string `drop:"role_key"`
	// CreatedBy is the user id of whoever minted the link.
	CreatedBy string `drop:"created_by"`
	// MaxUses caps how many times the link may be redeemed. 0 means unlimited.
	MaxUses int `drop:"max_uses"` // 0 = unlimited
	// UseCount is how many times the link has been redeemed so far.
	UseCount int `drop:"use_count"`
	// ExpiresAt is when the link stops being redeemable. nil means never —
	// unlike EmailInvite.ExpiresAt, "never expires" is a real, common case for
	// a link, which is why this one is a pointer.
	ExpiresAt *time.Time `drop:"expires_at"` // nil = never
	// RevokedAt is when the link was revoked. nil means it has not been.
	RevokedAt *time.Time `drop:"revoked_at"` // nil = not revoked
	// CreatedAt is stamped by the service clock.
	CreatedAt time.Time `drop:"created_at"`
}

// Sentinel errors returned by an invite.Store implementation and consumed by
// the service layer built on top. Compare with [errors.Is], never by string —
// the messages are not part of the API.
//
// They fall into two groups:
//
//   - Not found — ErrInviteNotFound, ErrLinkNotFound. A Store returns these
//     itself: whenever a lookup or a delete by id, token hash, or code finds
//     no row.
//   - Caller bug — ErrInvalidMaxUses. Raised by the service layer before it
//     touches a Store at all; a Store never returns it.
//   - Why a redemption did not happen — ErrInviteExpired, ErrLinkRevoked,
//     ErrLinkExpired, ErrLinkExhausted. No Store method returns these
//     directly. [Store.ConsumeLink] reports only ok=false for all three link
//     reasons at once, because the check and the increment must be a single
//     atomic step; asking that same step to also report which of three
//     conditions applied would mean a second, separate read, which is exactly
//     the race the atomicity requirement rules out. The service layer, which
//     is allowed to look twice, re-reads the record (FindLink or
//     FindEmailInvite/FindEmailInviteByTokenHash) after a false/not-ok result
//     and compares RevokedAt, ExpiresAt and UseCount/MaxUses itself to decide
//     which of these to surface to its own caller.
var (
	// ErrInviteNotFound: no EmailInvite with that id or token hash exists.
	ErrInviteNotFound = errors.New("authlayer/invite: invite not found")
	// ErrInviteExpired: the invite's ExpiresAt has passed. See the group doc
	// above for who is responsible for raising it.
	ErrInviteExpired = errors.New("authlayer/invite: invite has expired")
	// ErrLinkNotFound: no Link with that id or code exists.
	ErrLinkNotFound = errors.New("authlayer/invite: link not found")
	// ErrLinkRevoked: the link's RevokedAt is set. See the group doc above for
	// who is responsible for raising it.
	ErrLinkRevoked = errors.New("authlayer/invite: link has been revoked")
	// ErrLinkExpired: the link's ExpiresAt has passed. See the group doc above
	// for who is responsible for raising it.
	ErrLinkExpired = errors.New("authlayer/invite: link has expired")
	// ErrLinkExhausted: the link's UseCount has reached its (non-zero)
	// MaxUses. See the group doc above for who is responsible for raising it.
	ErrLinkExhausted = errors.New("authlayer/invite: link has reached its use limit")
	// ErrInvalidMaxUses: [Service.CreateLink] was passed a negative maxUses.
	// 0 means unlimited and any positive value is a cap, so a negative one
	// names no reachable policy — it would mint a link that can never be
	// redeemed at all, since ConsumeLink's own predicate (MaxUses != 0 &&
	// UseCount >= MaxUses) is already true at UseCount 0. That is a dead
	// credential produced silently, so it is refused instead.
	ErrInvalidMaxUses = errors.New("authlayer/invite: maxUses must not be negative")
)

// Store is the persistence port for invitations. Unlike scope.Store it is not
// generic — [EmailInvite] and [Link] are fixed shapes, so every backend shares
// one table pair — and it composes the two record kinds in a single interface
// rather than smaller pieces, since nothing in this package needs to embed or
// override just one of them.
//
// A Store performs no authorization of its own, the same discipline
// scope.Store follows: the service layer decides who may create, list, or
// revoke an invitation and hands the Store fully-formed values to write, or
// keys to read by.
type Store interface {
	// CreateEmailInvite persists an already-stamped invite and returns what
	// was stored.
	CreateEmailInvite(ctx context.Context, inv EmailInvite) (EmailInvite, error)
	// FindEmailInviteByTokenHash loads the invite whose TokenHash matches,
	// returning ErrInviteNotFound when none does. This is the acceptance path:
	// the caller hashes the presented plaintext token and looks it up by
	// hash, since the plaintext itself is never stored (see [EmailInvite]).
	FindEmailInviteByTokenHash(ctx context.Context, tokenHash string) (EmailInvite, error)
	// FindEmailInvite loads an invite by id, returning ErrInviteNotFound when
	// there is none.
	FindEmailInvite(ctx context.Context, id string) (EmailInvite, error)
	// ListEmailInvites returns every invite in containerID, expired or not —
	// the caller filters. A container with none is not an error; the result
	// may be an empty slice or nil, which len and range treat alike, so do
	// not distinguish them. Order is unspecified.
	ListEmailInvites(ctx context.Context, containerID string) ([]EmailInvite, error)
	// DeleteEmailInvite removes an invite by id, returning ErrInviteNotFound
	// when no row matched.
	DeleteEmailInvite(ctx context.Context, id string) error
	// DeleteEmailInvitesFor removes every invite for (containerID, email),
	// however many there are. It is what makes re-inviting an address replace
	// rather than duplicate: the service calls it immediately before minting a
	// fresh invite for the same address. Deleting zero rows is not an error.
	DeleteEmailInvitesFor(ctx context.Context, containerID, email string) error

	// CreateLink persists an already-stamped link and returns what was stored.
	CreateLink(ctx context.Context, l Link) (Link, error)
	// FindLinkByCode loads the link whose Code matches, returning
	// ErrLinkNotFound when none does. Code is stored in clear (see [Link]),
	// so this is a plain lookup, unlike FindEmailInviteByTokenHash.
	FindLinkByCode(ctx context.Context, code string) (Link, error)
	// FindLink loads a link by id, returning ErrLinkNotFound when there is
	// none.
	FindLink(ctx context.Context, id string) (Link, error)
	// ListLinks returns every link in containerID, revoked or not, expired or
	// not — the caller filters. A container with none is not an error; the
	// result may be an empty slice or nil, which len and range treat alike,
	// so do not distinguish them. Order is unspecified.
	ListLinks(ctx context.Context, containerID string) ([]Link, error)
	// RevokeLink stamps RevokedAt with at, returning ErrLinkNotFound when no
	// row matched. Revoking an already-revoked link overwrites the timestamp
	// rather than erroring — revocation is idempotent.
	RevokeLink(ctx context.Context, id string, at time.Time) error
	// ConsumeLink atomically increments UseCount if and only if the link is
	// unrevoked, unexpired at now, and below MaxUses (0 meaning unlimited).
	// ok=false means the link exists but could not be consumed for one of
	// those three reasons; the caller distinguishes why by re-reading it (see
	// the sentinel doc above). A not-found id is reported as
	// (false, ErrLinkNotFound), not as a silent ok=false.
	//
	// An implementation MUST make the check and the increment a single atomic
	// step whose outcome cannot be split by a concurrent caller of the same
	// method — one SQL UPDATE ... WHERE guarding all three conditions, whose
	// rows-affected count IS ok, or a single critical section held across both
	// the check and the write in an in-process store. A read-then-write
	// implementation (read the link, decide in the caller, then write) is NOT
	// atomic: two concurrent callers can both read UseCount below MaxUses,
	// both decide ok, and both increment, so a MaxUses:1 link ends up admitting
	// two people instead of one. That is a fail-open bug, not a cosmetic race,
	// because MaxUses exists specifically to bound who gets in.
	ConsumeLink(ctx context.Context, id string, now time.Time) (ok bool, err error)

	// PurgeExpired deletes every EmailInvite and Link expired strictly before
	// `before` — email invites by ExpiresAt, links by a non-nil ExpiresAt —
	// and returns how many rows were removed in total, across both kinds. A
	// link with a nil ExpiresAt ("never") is never purged by this call. It is
	// housekeeping, not a security boundary: an invite past its ExpiresAt is
	// already unacceptable through the normal lookup and consume paths before
	// it is ever purged. A revoked-but-unexpired link is left alone —
	// revocation and expiry are different reasons and this method only acts on
	// the latter.
	PurgeExpired(ctx context.Context, before time.Time) (int, error)
}
