package invitetest

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/bernardoforcillo/authlayer/invite"
)

// gap is how long the deliberately non-atomic doubles below hold their
// check-then-write window open.
//
// A real split-lock implementation's window is sub-microsecond, and this
// project has measured it directly: store/memory's own ConsumeLink race, at
// 2000 goroutines behind a channel barrier, passed a split-lock ConsumeLink
// 20 times out of 20. That is far too unreliable for a control whose whole
// job is to prove a check bites. Widening the window to milliseconds makes
// each control deterministic: the concurrent callers always land inside it.
// What these controls therefore prove is that the check DETECTS the defect
// when the interleaving occurs, not that it forces the interleaving on a
// subtly broken backend — a limit the contract checks' own doc comments state
// rather than paper over.
const gap = 5 * time.Millisecond

// ── The non-compliant doubles ───────────────────────────────────────────
//
// Each is exactly one defect away from [refStore]: it embeds one and
// overrides a single method (or, where the defect is one policy expressed
// across several methods, that policy's methods) with a deliberately wrong
// shape. That is what makes "this check failed" evidence about the defect and
// nothing else — see TestTheReferenceStorePassesTheContract.

// droppedRoleKey loses [invite.EmailInvite.RoleKey] and [invite.Link.RoleKey]
// on the way in. The port says a create "persists an already-stamped invite
// and returns what was stored", and RoleKey is what a redeemer is admitted
// AT, so a store that drops it admits at the zero role instead.
type droppedRoleKey struct{ *refStore }

func (s droppedRoleKey) CreateEmailInvite(ctx context.Context, inv invite.EmailInvite) (invite.EmailInvite, error) {
	inv.RoleKey = ""
	return s.refStore.CreateEmailInvite(ctx, inv)
}

func (s droppedRoleKey) CreateLink(ctx context.Context, l invite.Link) (invite.Link, error) {
	l.RoleKey = ""
	return s.refStore.CreateLink(ctx, l)
}

// sharedTokenHashes lets two email invites hold one token hash — the
// uniqueness MUST [invite.EmailInvite.TokenHash] states on the record type.
type sharedTokenHashes struct{ *refStore }

func (s sharedTokenHashes) CreateEmailInvite(_ context.Context, inv invite.EmailInvite) (invite.EmailInvite, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pairTaken(inv.ContainerID, inv.Email) {
		return invite.EmailInvite{}, errDuplicatePair
	}
	s.emailInvites[inv.ID] = inv
	return inv, nil
}

// duplicatePendingInvites lets one container hold two pending invites for one
// address — the (ContainerID, Email) uniqueness MUST. It is the shape
// store/memory's InviteStore had before this package existed.
type duplicatePendingInvites struct{ *refStore }

func (s duplicatePendingInvites) CreateEmailInvite(_ context.Context, inv invite.EmailInvite) (invite.EmailInvite, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tokenHashTaken(inv.TokenHash) {
		return invite.EmailInvite{}, errDuplicateTokenHash
	}
	s.emailInvites[inv.ID] = inv
	return inv, nil
}

// globallyUniqueAddress enforces uniqueness on the ADDRESS alone rather than
// on the (ContainerID, Email) pair — the over-broad reading of the same
// constraint, which stops one person being invited to a second container.
type globallyUniqueAddress struct{ *refStore }

func (s globallyUniqueAddress) CreateEmailInvite(_ context.Context, inv invite.EmailInvite) (invite.EmailInvite, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tokenHashTaken(inv.TokenHash) {
		return invite.EmailInvite{}, errDuplicateTokenHash
	}
	for _, existing := range s.emailInvites {
		if existing.Email == inv.Email {
			return invite.EmailInvite{}, errDuplicatePair
		}
	}
	s.emailInvites[inv.ID] = inv
	return inv, nil
}

// silentNotFound answers every miss with a zero record and a nil error
// instead of the sentinel the port names. A caller cannot tell "no such
// token" from "a token for the zero container at the zero role".
type silentNotFound struct{ *refStore }

func (s silentNotFound) FindEmailInvite(ctx context.Context, id string) (invite.EmailInvite, error) {
	inv, err := s.refStore.FindEmailInvite(ctx, id)
	if errors.Is(err, invite.ErrInviteNotFound) {
		return invite.EmailInvite{}, nil
	}
	return inv, err
}

func (s silentNotFound) FindEmailInviteByTokenHash(ctx context.Context, tokenHash string) (invite.EmailInvite, error) {
	inv, err := s.refStore.FindEmailInviteByTokenHash(ctx, tokenHash)
	if errors.Is(err, invite.ErrInviteNotFound) {
		return invite.EmailInvite{}, nil
	}
	return inv, err
}

func (s silentNotFound) FindLink(ctx context.Context, id string) (invite.Link, error) {
	l, err := s.refStore.FindLink(ctx, id)
	if errors.Is(err, invite.ErrLinkNotFound) {
		return invite.Link{}, nil
	}
	return l, err
}

func (s silentNotFound) FindLinkByCode(ctx context.Context, code string) (invite.Link, error) {
	l, err := s.refStore.FindLinkByCode(ctx, code)
	if errors.Is(err, invite.ErrLinkNotFound) {
		return invite.Link{}, nil
	}
	return l, err
}

// listsIgnoreTheContainer returns every row of each kind whatever container
// was asked for — a cross-tenant leak that shows one organization's pending
// invitations and links to another.
type listsIgnoreTheContainer struct{ *refStore }

func (s listsIgnoreTheContainer) ListEmailInvites(_ context.Context, _ string) ([]invite.EmailInvite, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []invite.EmailInvite
	for _, inv := range s.emailInvites {
		out = append(out, inv)
	}
	return out, nil
}

func (s listsIgnoreTheContainer) ListLinks(_ context.Context, _ string) ([]invite.Link, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []invite.Link
	for _, l := range s.links {
		out = append(out, l)
	}
	return out, nil
}

// listsFilterForTheCaller hides expired invites, and revoked or expired
// links, doing the filtering the port explicitly leaves to the caller. The
// rows it hides are exactly the ones a manage-invitations screen needs in
// order to explain, or clear, what happened to an invitation.
type listsFilterForTheCaller struct{ *refStore }

func (s listsFilterForTheCaller) ListEmailInvites(ctx context.Context, containerID string) ([]invite.EmailInvite, error) {
	all, err := s.refStore.ListEmailInvites(ctx, containerID)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	var out []invite.EmailInvite
	for _, inv := range all {
		if now.Before(inv.ExpiresAt) {
			out = append(out, inv)
		}
	}
	return out, nil
}

func (s listsFilterForTheCaller) ListLinks(ctx context.Context, containerID string) ([]invite.Link, error) {
	all, err := s.refStore.ListLinks(ctx, containerID)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	var out []invite.Link
	for _, l := range all {
		if l.RevokedAt != nil {
			continue
		}
		if l.ExpiresAt != nil && !now.Before(*l.ExpiresAt) {
			continue
		}
		out = append(out, l)
	}
	return out, nil
}

// emptyListIsAnError reports a container with no rows as a not-found error
// rather than as an empty result, which the port rules out for both list
// methods.
type emptyListIsAnError struct{ *refStore }

func (s emptyListIsAnError) ListEmailInvites(ctx context.Context, containerID string) ([]invite.EmailInvite, error) {
	out, err := s.refStore.ListEmailInvites(ctx, containerID)
	if err == nil && len(out) == 0 {
		return nil, invite.ErrInviteNotFound
	}
	return out, err
}

func (s emptyListIsAnError) ListLinks(ctx context.Context, containerID string) ([]invite.Link, error) {
	out, err := s.refStore.ListLinks(ctx, containerID)
	if err == nil && len(out) == 0 {
		return nil, invite.ErrLinkNotFound
	}
	return out, err
}

// overbroadDeleteEmailInvite removes every invite in the named invite's
// container rather than the one row named — a claim that spends credentials
// nobody presented.
type overbroadDeleteEmailInvite struct{ *refStore }

func (s overbroadDeleteEmailInvite) DeleteEmailInvite(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	target, ok := s.emailInvites[id]
	if !ok {
		return invite.ErrInviteNotFound
	}
	for other, inv := range s.emailInvites {
		if inv.ContainerID == target.ContainerID {
			delete(s.emailInvites, other)
		}
	}
	return nil
}

// silentDeleteEmailInvite answers nil to a delete that removed nothing. That
// is the claim's rows-affected gate removed: every concurrent presentation of
// one token, and every second presentation of a spent one, is told it won.
type silentDeleteEmailInvite struct{ *refStore }

func (s silentDeleteEmailInvite) DeleteEmailInvite(ctx context.Context, id string) error {
	if err := s.refStore.DeleteEmailInvite(ctx, id); err != nil && !errors.Is(err, invite.ErrInviteNotFound) {
		return err
	}
	return nil
}

// deleteEmailInvitesForIgnoresTheAddress sweeps the whole container instead
// of the (containerID, email) pair, so re-inviting one person cancels
// everybody else's pending invitation.
type deleteEmailInvitesForIgnoresTheAddress struct{ *refStore }

func (s deleteEmailInvitesForIgnoresTheAddress) DeleteEmailInvitesFor(_ context.Context, containerID, _ string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, inv := range s.emailInvites {
		if inv.ContainerID == containerID {
			delete(s.emailInvites, id)
		}
	}
	return nil
}

// deleteEmailInvitesForErrorsOnZeroRows reports a sweep that matched nothing
// as ErrInviteNotFound. The service calls it unconditionally before every
// fresh invite, so this refuses the FIRST invitation ever sent to an address.
type deleteEmailInvitesForErrorsOnZeroRows struct{ *refStore }

func (s deleteEmailInvitesForErrorsOnZeroRows) DeleteEmailInvitesFor(_ context.Context, containerID, email string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for id, inv := range s.emailInvites {
		if inv.ContainerID == containerID && inv.Email == email {
			delete(s.emailInvites, id)
			n++
		}
	}
	if n == 0 {
		return invite.ErrInviteNotFound
	}
	return nil
}

// sharedLinkCodes lets two links hold one code — the uniqueness MUST
// [invite.Link.Code] states on the record type.
type sharedLinkCodes struct{ *refStore }

func (s sharedLinkCodes) CreateLink(_ context.Context, l invite.Link) (invite.Link, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.links[l.ID] = l
	return l, nil
}

// revokeDoesNotStamp reports success without writing RevokedAt. Every
// revocation appears to work and nothing is ever revoked.
type revokeDoesNotStamp struct{ *refStore }

func (s revokeDoesNotStamp) RevokeLink(_ context.Context, id string, _ time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.links[id]; !ok {
		return invite.ErrLinkNotFound
	}
	return nil
}

// revokeRefusesASecondTime treats an already-revoked link as an error rather
// than re-stamping it, which the port rules out: revocation is idempotent.
type revokeRefusesASecondTime struct{ *refStore }

func (s revokeRefusesASecondTime) RevokeLink(_ context.Context, id string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	l, ok := s.links[id]
	if !ok {
		return invite.ErrLinkNotFound
	}
	if l.RevokedAt != nil {
		return invite.ErrLinkRevoked
	}
	l.RevokedAt = &at
	s.links[id] = l
	return nil
}

// silentRevoke answers nil when no row matched, so a caller cannot tell a
// revocation that happened from one that named nothing.
type silentRevoke struct{ *refStore }

func (s silentRevoke) RevokeLink(ctx context.Context, id string, at time.Time) error {
	if err := s.refStore.RevokeLink(ctx, id, at); err != nil && !errors.Is(err, invite.ErrLinkNotFound) {
		return err
	}
	return nil
}

// consumeWithoutIncrementing admits the caller but never raises UseCount, so
// every limit is unreachable and MaxUses bounds nothing.
type consumeWithoutIncrementing struct{ *refStore }

func (s consumeWithoutIncrementing) ConsumeLink(_ context.Context, id string, now time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	l, ok := s.links[id]
	if !ok {
		return false, invite.ErrLinkNotFound
	}
	if l.RevokedAt != nil {
		return false, nil
	}
	if l.ExpiresAt != nil && !now.Before(*l.ExpiresAt) {
		return false, nil
	}
	if l.MaxUses != 0 && l.UseCount >= l.MaxUses {
		return false, nil
	}
	return true, nil
}

// consumeOffByOneMaxUses compares UseCount > MaxUses rather than >=, so a
// MaxUses:N link admits N+1 people.
type consumeOffByOneMaxUses struct{ *refStore }

func (s consumeOffByOneMaxUses) ConsumeLink(_ context.Context, id string, now time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	l, ok := s.links[id]
	if !ok {
		return false, invite.ErrLinkNotFound
	}
	if l.RevokedAt != nil {
		return false, nil
	}
	if l.ExpiresAt != nil && !now.Before(*l.ExpiresAt) {
		return false, nil
	}
	if l.MaxUses != 0 && l.UseCount > l.MaxUses {
		return false, nil
	}
	l.UseCount++
	s.links[id] = l
	return true, nil
}

// consumeTreatsZeroMaxUsesAsExhausted drops the "0 = unlimited" exemption, so
// every link minted without a limit is dead on arrival.
type consumeTreatsZeroMaxUsesAsExhausted struct{ *refStore }

func (s consumeTreatsZeroMaxUsesAsExhausted) ConsumeLink(_ context.Context, id string, now time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	l, ok := s.links[id]
	if !ok {
		return false, invite.ErrLinkNotFound
	}
	if l.RevokedAt != nil {
		return false, nil
	}
	if l.ExpiresAt != nil && !now.Before(*l.ExpiresAt) {
		return false, nil
	}
	if l.UseCount >= l.MaxUses {
		return false, nil
	}
	l.UseCount++
	s.links[id] = l
	return true, nil
}

// consumeIgnoresRevocation drops the revocation guard, so revoking a leaked
// link stops nobody.
type consumeIgnoresRevocation struct{ *refStore }

func (s consumeIgnoresRevocation) ConsumeLink(_ context.Context, id string, now time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	l, ok := s.links[id]
	if !ok {
		return false, invite.ErrLinkNotFound
	}
	if l.ExpiresAt != nil && !now.Before(*l.ExpiresAt) {
		return false, nil
	}
	if l.MaxUses != 0 && l.UseCount >= l.MaxUses {
		return false, nil
	}
	l.UseCount++
	s.links[id] = l
	return true, nil
}

// consumeIgnoresExpiry drops the expiry guard, so a link's deadline bounds
// nothing.
type consumeIgnoresExpiry struct{ *refStore }

func (s consumeIgnoresExpiry) ConsumeLink(_ context.Context, id string, _ time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	l, ok := s.links[id]
	if !ok {
		return false, invite.ErrLinkNotFound
	}
	if l.RevokedAt != nil {
		return false, nil
	}
	if l.MaxUses != 0 && l.UseCount >= l.MaxUses {
		return false, nil
	}
	l.UseCount++
	s.links[id] = l
	return true, nil
}

// consumeInclusiveExpiryBoundary admits a caller at exactly ExpiresAt,
// treating the deadline as the last redeemable instant rather than the first
// unredeemable one — the boundary divergence a caller would otherwise meet
// for the first time on another backend.
type consumeInclusiveExpiryBoundary struct{ *refStore }

func (s consumeInclusiveExpiryBoundary) ConsumeLink(_ context.Context, id string, now time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	l, ok := s.links[id]
	if !ok {
		return false, invite.ErrLinkNotFound
	}
	if l.RevokedAt != nil {
		return false, nil
	}
	if l.ExpiresAt != nil && now.After(*l.ExpiresAt) {
		return false, nil
	}
	if l.MaxUses != 0 && l.UseCount >= l.MaxUses {
		return false, nil
	}
	l.UseCount++
	s.links[id] = l
	return true, nil
}

// consumeNilExpiryIsExpired reads a nil ExpiresAt as a zero time rather than
// as "never", so every link minted without a deadline is already expired.
type consumeNilExpiryIsExpired struct{ *refStore }

func (s consumeNilExpiryIsExpired) ConsumeLink(_ context.Context, id string, now time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	l, ok := s.links[id]
	if !ok {
		return false, invite.ErrLinkNotFound
	}
	if l.RevokedAt != nil {
		return false, nil
	}
	var expires time.Time
	if l.ExpiresAt != nil {
		expires = *l.ExpiresAt
	}
	if !now.Before(expires) {
		return false, nil
	}
	if l.MaxUses != 0 && l.UseCount >= l.MaxUses {
		return false, nil
	}
	l.UseCount++
	s.links[id] = l
	return true, nil
}

// consumeSilentNotFound reports an unknown id as an ordinary refusal, which
// the port rules out by name: the service tells "this code is not a link"
// apart from "this link cannot be used right now" on exactly that error.
type consumeSilentNotFound struct{ *refStore }

func (s consumeSilentNotFound) ConsumeLink(ctx context.Context, id string, now time.Time) (bool, error) {
	ok, err := s.refStore.ConsumeLink(ctx, id, now)
	if errors.Is(err, invite.ErrLinkNotFound) {
		return false, nil
	}
	return ok, err
}

// inclusivePurge treats the cutoff as "expired at or before", not "expired
// strictly before", so a record whose ExpiresAt is exactly the cutoff is
// swept when the port says it survives.
type inclusivePurge struct{ *refStore }

func (s inclusivePurge) PurgeExpired(_ context.Context, before time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for id, inv := range s.emailInvites {
		if !inv.ExpiresAt.After(before) {
			delete(s.emailInvites, id)
			n++
		}
	}
	for id, l := range s.links {
		if l.ExpiresAt != nil && !l.ExpiresAt.After(before) {
			delete(s.links, id)
			n++
		}
	}
	return n, nil
}

// purgeCountsOnlyInvites deletes both kinds but returns only the email-invite
// count, so the total the port promises "across both kinds" understates what
// was removed.
type purgeCountsOnlyInvites struct{ *refStore }

func (s purgeCountsOnlyInvites) PurgeExpired(_ context.Context, before time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for id, inv := range s.emailInvites {
		if inv.ExpiresAt.Before(before) {
			delete(s.emailInvites, id)
			n++
		}
	}
	for id, l := range s.links {
		if l.ExpiresAt != nil && l.ExpiresAt.Before(before) {
			delete(s.links, id)
		}
	}
	return n, nil
}

// purgeSweepsNeverExpiringLinks reads a nil ExpiresAt as a zero time, so the
// first housekeeping pass deletes every link minted without a deadline.
type purgeSweepsNeverExpiringLinks struct{ *refStore }

func (s purgeSweepsNeverExpiringLinks) PurgeExpired(_ context.Context, before time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for id, inv := range s.emailInvites {
		if inv.ExpiresAt.Before(before) {
			delete(s.emailInvites, id)
			n++
		}
	}
	for id, l := range s.links {
		var expires time.Time
		if l.ExpiresAt != nil {
			expires = *l.ExpiresAt
		}
		if expires.Before(before) {
			delete(s.links, id)
			n++
		}
	}
	return n, nil
}

// purgeSweepsRevokedLinks folds revocation into expiry, deleting the audit
// record of a deliberate act on the next housekeeping pass.
type purgeSweepsRevokedLinks struct{ *refStore }

func (s purgeSweepsRevokedLinks) PurgeExpired(ctx context.Context, before time.Time) (int, error) {
	n, err := s.refStore.PurgeExpired(ctx, before)
	if err != nil {
		return n, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, l := range s.links {
		if l.RevokedAt != nil {
			delete(s.links, id)
			n++
		}
	}
	return n, nil
}

// splitConsumeLink reads the link and decides under one lock acquisition and
// increments under a second — the read-then-write shape
// [invite.Store.ConsumeLink]'s MUST forbids by name. Two concurrent callers
// both read UseCount below MaxUses, both decide ok, and both increment.
type splitConsumeLink struct{ *refStore }

func (s splitConsumeLink) ConsumeLink(_ context.Context, id string, now time.Time) (bool, error) {
	s.mu.Lock()
	l, ok := s.links[id]
	s.mu.Unlock()
	if !ok {
		return false, invite.ErrLinkNotFound
	}
	if l.RevokedAt != nil {
		return false, nil
	}
	if l.ExpiresAt != nil && !now.Before(*l.ExpiresAt) {
		return false, nil
	}
	if l.MaxUses != 0 && l.UseCount >= l.MaxUses {
		return false, nil
	}

	time.Sleep(gap)

	s.mu.Lock()
	defer s.mu.Unlock()
	l.UseCount++
	s.links[id] = l
	return true, nil
}

// splitDeleteEmailInvite checks the row exists under one lock acquisition and
// deletes under a second, reporting nil to every caller that saw it. The
// claim's rows-affected gate is gone, so several concurrent presentations of
// one emailed token all win.
type splitDeleteEmailInvite struct{ *refStore }

func (s splitDeleteEmailInvite) DeleteEmailInvite(_ context.Context, id string) error {
	s.mu.Lock()
	_, ok := s.emailInvites[id]
	s.mu.Unlock()
	if !ok {
		return invite.ErrInviteNotFound
	}

	time.Sleep(gap)

	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.emailInvites, id)
	return nil
}

// splitCreateEmailInvite decides both uniqueness conflicts from a read,
// releases its lock, and only then writes — the check-then-write shape that
// lets several concurrent callers all find a hash, or a (container, email)
// pair, free and all take it.
type splitCreateEmailInvite struct{ *refStore }

func (s splitCreateEmailInvite) CreateEmailInvite(_ context.Context, inv invite.EmailInvite) (invite.EmailInvite, error) {
	s.mu.Lock()
	hashTaken := s.tokenHashTaken(inv.TokenHash)
	pairTaken := s.pairTaken(inv.ContainerID, inv.Email)
	s.mu.Unlock()
	if hashTaken {
		return invite.EmailInvite{}, errDuplicateTokenHash
	}
	if pairTaken {
		return invite.EmailInvite{}, errDuplicatePair
	}

	time.Sleep(gap)

	s.mu.Lock()
	defer s.mu.Unlock()
	s.emailInvites[inv.ID] = inv
	return inv, nil
}

// splitCreateLink is splitCreateEmailInvite's counterpart for
// [invite.Link.Code].
type splitCreateLink struct{ *refStore }

func (s splitCreateLink) CreateLink(_ context.Context, l invite.Link) (invite.Link, error) {
	s.mu.Lock()
	taken := s.codeTaken(l.Code)
	s.mu.Unlock()
	if taken {
		return invite.Link{}, errDuplicateCode
	}

	time.Sleep(gap)

	s.mu.Lock()
	defer s.mu.Unlock()
	s.links[l.ID] = l
	return l, nil
}

// ── Driving a check and capturing its verdict ──────────────────────────

// recorder is a [tb] that records failures instead of reporting them to the
// test framework, so a check can be run against a store that is SUPPOSED to
// fail it. Fatalf calls runtime.Goexit, exactly as testing.T.Fatalf does, so
// a check that gives up mid-way stops where it would have stopped for real.
type recorder struct {
	mu       sync.Mutex
	failures []string
}

func (r *recorder) Helper()                           {}
func (r *recorder) Logf(string, ...any)               {}
func (r *recorder) Errorf(format string, args ...any) { r.record(format, args) }

func (r *recorder) Fatalf(format string, args ...any) {
	r.record(format, args)
	runtime.Goexit()
}

func (r *recorder) record(format string, args []any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.failures = append(r.failures, fmt.Sprintf(format, args...))
}

// runCheck runs one check against st and reports what it complained about.
// The check runs in its own goroutine so the recorder's Fatalf can end it
// with runtime.Goexit the way testing.T.Fatalf would.
func runCheck(c check, st invite.Store) []string {
	r := &recorder{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		c.fn(r, st)
	}()
	<-done
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.failures...)
}

// allChecks is every check [RunStoreContract] runs. It stays a named helper
// rather than a direct call so the negative-control loop below reads as
// "run the whole suite against this defective store".
func allChecks() []check {
	return storeContractChecks()
}

func findCheck(t *testing.T, name string) check {
	t.Helper()
	for _, c := range allChecks() {
		if c.name == name {
			return c
		}
	}
	t.Fatalf("no check named %q — the negative-control table names a check that does not exist", name)
	return check{}
}

// TestTheReferenceStorePassesTheContract is the control on the controls
// below. [refStore] is a correct store, so [RunStoreContract] must pass it
// end to end; if it did not, a non-compliant double failing a check would
// prove nothing about the defect injected into it.
func TestTheReferenceStorePassesTheContract(t *testing.T) {
	RunStoreContract(t, func(*testing.T) invite.Store { return newRefStore() })
}

// TestEveryContractCheckHasANegativeControl fails if a check is added to the
// suite without a row in the table below. A check nothing is known to fail is
// a check that might assert nothing at all, and that is invisible from a
// green run.
func TestEveryContractCheckHasANegativeControl(t *testing.T) {
	covered := map[string]bool{}
	for _, tc := range negativeControls() {
		covered[tc.check] = true
	}
	for _, c := range allChecks() {
		if !covered[c.name] {
			t.Errorf("check %q has no negative control — add a store that fails it to negativeControls()", c.name)
		}
	}
}

// negativeControl pairs a deliberately broken store with the one check that
// must catch its defect.
type negativeControl struct {
	defect   string
	check    string
	newStore func() invite.Store
}

func negativeControls() []negativeControl {
	return []negativeControl{
		{
			defect:   "CreateEmailInvite drops the invited RoleKey",
			check:    "CreateEmailInvite/RoundTrip",
			newStore: func() invite.Store { return droppedRoleKey{newRefStore()} },
		},
		{
			defect:   "CreateLink drops the link's RoleKey",
			check:    "CreateLink/RoundTrip",
			newStore: func() invite.Store { return droppedRoleKey{newRefStore()} },
		},
		{
			defect:   "two email invites may share one token hash",
			check:    "CreateEmailInvite/TokenHashIsUnique",
			newStore: func() invite.Store { return sharedTokenHashes{newRefStore()} },
		},
		{
			defect:   "one container may hold two pending invites for one address",
			check:    "CreateEmailInvite/ContainerEmailPairIsUnique",
			newStore: func() invite.Store { return duplicatePendingInvites{newRefStore()} },
		},
		{
			defect:   "the address is unique globally rather than per container",
			check:    "CreateEmailInvite/OtherContainersMayInviteTheSameAddress",
			newStore: func() invite.Store { return globallyUniqueAddress{newRefStore()} },
		},
		{
			defect:   "FindEmailInvite answers a miss with a zero record and no error",
			check:    "FindEmailInvite/UnknownIDReturnsErrInviteNotFound",
			newStore: func() invite.Store { return silentNotFound{newRefStore()} },
		},
		{
			defect:   "FindEmailInviteByTokenHash answers a miss with a zero record and no error",
			check:    "FindEmailInviteByTokenHash/UnknownHashReturnsErrInviteNotFound",
			newStore: func() invite.Store { return silentNotFound{newRefStore()} },
		},
		{
			defect:   "FindLink answers a miss with a zero record and no error",
			check:    "FindLink/UnknownIDReturnsErrLinkNotFound",
			newStore: func() invite.Store { return silentNotFound{newRefStore()} },
		},
		{
			defect:   "FindLinkByCode answers a miss with a zero record and no error",
			check:    "FindLinkByCode/UnknownCodeReturnsErrLinkNotFound",
			newStore: func() invite.Store { return silentNotFound{newRefStore()} },
		},
		{
			defect:   "ListEmailInvites ignores the container it was asked for",
			check:    "ListEmailInvites/ScopesToTheContainer",
			newStore: func() invite.Store { return listsIgnoreTheContainer{newRefStore()} },
		},
		{
			defect:   "ListLinks ignores the container it was asked for",
			check:    "ListLinks/ScopesToTheContainer",
			newStore: func() invite.Store { return listsIgnoreTheContainer{newRefStore()} },
		},
		{
			defect:   "ListEmailInvites hides expired invites",
			check:    "ListEmailInvites/ReturnsExpiredRowsToo",
			newStore: func() invite.Store { return listsFilterForTheCaller{newRefStore()} },
		},
		{
			defect:   "ListLinks hides revoked and expired links",
			check:    "ListLinks/ReturnsRevokedAndExpiredRowsToo",
			newStore: func() invite.Store { return listsFilterForTheCaller{newRefStore()} },
		},
		{
			defect:   "ListEmailInvites reports a container with no rows as an error",
			check:    "ListEmailInvites/EmptyContainerIsNotAnError",
			newStore: func() invite.Store { return emptyListIsAnError{newRefStore()} },
		},
		{
			defect:   "ListLinks reports a container with no rows as an error",
			check:    "ListLinks/EmptyContainerIsNotAnError",
			newStore: func() invite.Store { return emptyListIsAnError{newRefStore()} },
		},
		{
			defect:   "DeleteEmailInvite removes the whole container, not the row named",
			check:    "DeleteEmailInvite/RemovesExactlyOneRow",
			newStore: func() invite.Store { return overbroadDeleteEmailInvite{newRefStore()} },
		},
		{
			defect:   "DeleteEmailInvite answers nil when it removed nothing",
			check:    "DeleteEmailInvite/UnknownIDReturnsErrInviteNotFound",
			newStore: func() invite.Store { return silentDeleteEmailInvite{newRefStore()} },
		},
		{
			defect:   "DeleteEmailInvitesFor sweeps the container, ignoring the address",
			check:    "DeleteEmailInvitesFor/RemovesOnlyThatPair",
			newStore: func() invite.Store { return deleteEmailInvitesForIgnoresTheAddress{newRefStore()} },
		},
		{
			defect:   "DeleteEmailInvitesFor reports a sweep that matched nothing as an error",
			check:    "DeleteEmailInvitesFor/ZeroRowsIsNotAnError",
			newStore: func() invite.Store { return deleteEmailInvitesForErrorsOnZeroRows{newRefStore()} },
		},
		{
			defect:   "two links may share one code",
			check:    "CreateLink/CodeIsUnique",
			newStore: func() invite.Store { return sharedLinkCodes{newRefStore()} },
		},
		{
			defect:   "RevokeLink reports success without writing RevokedAt",
			check:    "RevokeLink/StampsRevokedAt",
			newStore: func() invite.Store { return revokeDoesNotStamp{newRefStore()} },
		},
		{
			defect:   "RevokeLink refuses an already-revoked link",
			check:    "RevokeLink/IsIdempotentAndOverwritesTheTimestamp",
			newStore: func() invite.Store { return revokeRefusesASecondTime{newRefStore()} },
		},
		{
			defect:   "RevokeLink answers nil when no row matched",
			check:    "RevokeLink/UnknownIDReturnsErrLinkNotFound",
			newStore: func() invite.Store { return silentRevoke{newRefStore()} },
		},
		{
			defect:   "ConsumeLink admits the caller without incrementing UseCount",
			check:    "ConsumeLink/IncrementsUseCount",
			newStore: func() invite.Store { return consumeWithoutIncrementing{newRefStore()} },
		},
		{
			defect:   "ConsumeLink compares UseCount > MaxUses rather than >=",
			check:    "ConsumeLink/StopsAtMaxUses",
			newStore: func() invite.Store { return consumeOffByOneMaxUses{newRefStore()} },
		},
		{
			defect:   "ConsumeLink reads MaxUses 0 as exhausted rather than unlimited",
			check:    "ConsumeLink/MaxUsesZeroIsUnlimited",
			newStore: func() invite.Store { return consumeTreatsZeroMaxUsesAsExhausted{newRefStore()} },
		},
		{
			defect:   "ConsumeLink ignores RevokedAt",
			check:    "ConsumeLink/RevokedLinkIsRefusedWithoutAnError",
			newStore: func() invite.Store { return consumeIgnoresRevocation{newRefStore()} },
		},
		{
			defect:   "ConsumeLink ignores ExpiresAt",
			check:    "ConsumeLink/ExpiredLinkIsRefusedWithoutAnError",
			newStore: func() invite.Store { return consumeIgnoresExpiry{newRefStore()} },
		},
		{
			defect:   "ConsumeLink admits at exactly ExpiresAt",
			check:    "ConsumeLink/TheExpiresAtInstantItselfIsExpired",
			newStore: func() invite.Store { return consumeInclusiveExpiryBoundary{newRefStore()} },
		},
		{
			defect:   "ConsumeLink reads a nil ExpiresAt as a zero time",
			check:    "ConsumeLink/NilExpiresAtNeverExpires",
			newStore: func() invite.Store { return consumeNilExpiryIsExpired{newRefStore()} },
		},
		{
			defect:   "ConsumeLink reports an unknown id as an ordinary refusal",
			check:    "ConsumeLink/UnknownIDReturnsErrLinkNotFound",
			newStore: func() invite.Store { return consumeSilentNotFound{newRefStore()} },
		},
		{
			defect:   "PurgeExpired treats the cutoff as inclusive",
			check:    "PurgeExpired/CutoffIsStrictAcrossBothKinds",
			newStore: func() invite.Store { return inclusivePurge{newRefStore()} },
		},
		{
			defect:   "PurgeExpired counts only the email invites it removed",
			check:    "PurgeExpired/CutoffIsStrictAcrossBothKinds",
			newStore: func() invite.Store { return purgeCountsOnlyInvites{newRefStore()} },
		},
		{
			defect:   "PurgeExpired reads a link's nil ExpiresAt as a zero time",
			check:    "PurgeExpired/NeverPurgesALinkWithNoExpiry",
			newStore: func() invite.Store { return purgeSweepsNeverExpiringLinks{newRefStore()} },
		},
		{
			defect:   "PurgeExpired folds revocation into expiry",
			check:    "PurgeExpired/LeavesARevokedButUnexpiredLinkAlone",
			newStore: func() invite.Store { return purgeSweepsRevokedLinks{newRefStore()} },
		},
		{
			defect:   "PurgeExpired removes rows a cutoff nothing has passed should leave alone",
			check:    "PurgeExpired/NothingToPurgeReturnsZero",
			newStore: func() invite.Store { return purgeSweepsNeverExpiringLinks{newRefStore()} },
		},
		{
			defect:   "ConsumeLink decides under one lock and increments under a second",
			check:    "ConsumeLink/ConcurrentCallersAdmitExactlyOneWinner",
			newStore: func() invite.Store { return splitConsumeLink{newRefStore()} },
		},
		{
			defect:   "ConsumeLink decides under one lock and increments under a second (past a MaxUses:4 limit)",
			check:    "ConsumeLink/ConcurrentCallersNeverExceedMaxUses",
			newStore: func() invite.Store { return splitConsumeLink{newRefStore()} },
		},
		{
			defect:   "ConsumeLink decides under one lock and increments under a second (losing increments)",
			check:    "ConsumeLink/ConcurrentCallersOnAnUnlimitedLinkAllSucceed",
			newStore: func() invite.Store { return splitConsumeLink{newRefStore()} },
		},
		{
			defect:   "DeleteEmailInvite checks the row, then deletes under a second lock",
			check:    "DeleteEmailInvite/ConcurrentCallersAdmitExactlyOneWinner",
			newStore: func() invite.Store { return splitDeleteEmailInvite{newRefStore()} },
		},
		{
			defect:   "CreateEmailInvite checks both conflicts, then writes under a second lock",
			check:    "CreateEmailInvite/ConcurrentSameTokenHashAdmitsOneWinner",
			newStore: func() invite.Store { return splitCreateEmailInvite{newRefStore()} },
		},
		{
			defect:   "CreateEmailInvite checks both conflicts, then writes under a second lock (same pair)",
			check:    "CreateEmailInvite/ConcurrentSamePairAdmitsOneWinner",
			newStore: func() invite.Store { return splitCreateEmailInvite{newRefStore()} },
		},
		{
			defect:   "CreateLink checks the code, then writes under a second lock",
			check:    "CreateLink/ConcurrentSameCodeAdmitsOneWinner",
			newStore: func() invite.Store { return splitCreateLink{newRefStore()} },
		},
		{
			defect:   "a re-invite may add a second pending invite for one address",
			check:    "DeleteEmailInvitesFor/RacingCreateEmailInviteLeavesNoDuplicate",
			newStore: func() invite.Store { return duplicatePendingInvites{newRefStore()} },
		},
	}
}

// TestTheContractRejectsNonCompliantStores is what makes this suite worth
// having: a contract suite that passes everything is worthless, and that
// failure mode is invisible without controls. Each row of [negativeControls]
// is a store that is exactly one defect away from [refStore], paired with the
// check that must catch that defect. The whole suite is run against each one,
// the named check is required to have failed, and every check that failed is
// logged so the blast radius of each defect is on the record rather than
// inferred.
func TestTheContractRejectsNonCompliantStores(t *testing.T) {
	for _, tc := range negativeControls() {
		t.Run(tc.defect, func(t *testing.T) {
			want := findCheck(t, tc.check)

			var caught []string
			var firstMessage string
			for _, c := range allChecks() {
				failures := runCheck(c, tc.newStore())
				if len(failures) == 0 {
					continue
				}
				caught = append(caught, c.name)
				if c.name == want.name {
					firstMessage = failures[0]
				}
			}
			sort.Strings(caught)

			if firstMessage == "" {
				t.Fatalf("%s PASSED %s — the check does not catch this defect. Checks that did fail: %v", tc.defect, tc.check, caught)
			}
			t.Logf("%s\n  caught by %s: %s\n  all checks that failed: %v", tc.defect, tc.check, firstMessage, caught)
		})
	}
}
