package invitetest

import (
	"context"
	"errors"
	"time"

	"github.com/bernardoforcillo/authlayer/invite"
)

func emailInviteChecks() []check {
	return []check{
		{"CreateEmailInvite/RoundTrip", checkCreateEmailInviteRoundTrip},
		{"CreateEmailInvite/NormalizesTheAddress", checkCreateEmailInviteNormalizes},
		{"CreateEmailInvite/TokenHashIsUnique", checkEmailInviteTokenHashUnique},
		{"CreateEmailInvite/ContainerEmailPairIsUnique", checkEmailInviteContainerEmailUnique},
		{"CreateEmailInvite/ContainerEmailPairIsUniqueAcrossSpelling", checkEmailInvitePairUniqueAcrossSpelling},
		{"CreateEmailInvite/OtherContainersMayInviteTheSameAddress", checkEmailInviteAddressIsNotGloballyUnique},
		{"FindEmailInvite/UnknownIDReturnsErrInviteNotFound", checkFindEmailInviteNotFound},
		{"FindEmailInviteByTokenHash/UnknownHashReturnsErrInviteNotFound", checkFindEmailInviteByTokenHashNotFound},
		{"ListEmailInvites/ScopesToTheContainer", checkListEmailInvitesScopes},
		{"ListEmailInvites/ReturnsExpiredRowsToo", checkListEmailInvitesIncludesExpired},
		{"ListEmailInvites/EmptyContainerIsNotAnError", checkListEmailInvitesEmpty},
		{"DeleteEmailInvite/RemovesExactlyOneRow", checkDeleteEmailInvite},
		{"DeleteEmailInvite/UnknownIDReturnsErrInviteNotFound", checkDeleteEmailInviteNotFound},
		{"DeleteEmailInvitesFor/RemovesOnlyThatPair", checkDeleteEmailInvitesFor},
		{"DeleteEmailInvitesFor/NormalizesTheAddress", checkDeleteEmailInvitesForNormalizes},
		{"DeleteEmailInvitesFor/ZeroRowsIsNotAnError", checkDeleteEmailInvitesForEmpty},
	}
}

// checkCreateEmailInviteRoundTrip asserts CreateEmailInvite returns what it
// stored and that both read paths — by id and by token hash — return the
// same record: every field of [invite.EmailInvite] survives, timestamps
// included.
//
// The port says CreateEmailInvite "persists an already-stamped invite and
// returns what was stored", so the store stamps nothing of its own and drops
// nothing it was given. RoleKey in particular is what a redeemer is admitted
// AT, so a store that silently loses it admits at the zero role rather than
// the invited one.
//
// The fixture's address is already normalized, so the one field a store IS
// allowed to change comes back identical here; whether it normalizes at all
// is "CreateEmailInvite/NormalizesTheAddress".
func checkCreateEmailInviteRoundTrip(t tb, st invite.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	inv := newInvite(newID(), newEmail(), at)

	created := mustCreateEmailInvite(t, st, inv)
	assertInviteEqual(t, "CreateEmailInvite returned", created, inv)

	byID, err := st.FindEmailInvite(ctx, inv.ID)
	wantNoErr(t, "FindEmailInvite", err)
	assertInviteEqual(t, "FindEmailInvite returned", byID, inv)

	byHash, err := st.FindEmailInviteByTokenHash(ctx, inv.TokenHash)
	wantNoErr(t, "FindEmailInviteByTokenHash", err)
	assertInviteEqual(t, "FindEmailInviteByTokenHash returned", byHash, inv)
}

// assertInviteEqual compares every field of an EmailInvite, with the two
// instants by time.Time.Equal so a backend returning them in another
// location still passes.
func assertInviteEqual(t tb, what string, got, want invite.EmailInvite) {
	t.Helper()
	if got.ID != want.ID {
		t.Fatalf("%s ID %q, want %q", what, got.ID, want.ID)
	}
	if got.ContainerID != want.ContainerID {
		t.Fatalf("%s ContainerID %q, want %q", what, got.ContainerID, want.ContainerID)
	}
	if got.Email != want.Email {
		t.Fatalf("%s Email %q, want %q", what, got.Email, want.Email)
	}
	if got.RoleKey != want.RoleKey {
		t.Fatalf("%s RoleKey %q, want %q — a lost role admits the invitee at the wrong one", what, got.RoleKey, want.RoleKey)
	}
	if got.TokenHash != want.TokenHash {
		t.Fatalf("%s TokenHash %q, want %q", what, got.TokenHash, want.TokenHash)
	}
	if got.InvitedBy != want.InvitedBy {
		t.Fatalf("%s InvitedBy %q, want %q", what, got.InvitedBy, want.InvitedBy)
	}
	wantTimeEqual(t, what+" ExpiresAt", got.ExpiresAt, want.ExpiresAt)
	wantTimeEqual(t, what+" CreatedAt", got.CreatedAt, want.CreatedAt)
}

// checkCreateEmailInviteNormalizes asserts [invite.EmailInvite]'s
// address-normalization MUST on the write path: an invite created from an
// upper-cased, whitespace-padded address is stored — and returned — under
// the normalized form, and every read path hands that form back.
//
// The returned record matters as much as the stored one.
// [invite.Service.InviteByEmail] returns what CreateEmailInvite gave it, and
// [invite.Service.PreviewInvite] and ListInvites return what the read paths
// give them, so a store that normalizes on the way in but echoes the
// caller's spelling back on the way out reintroduces the mismatch an
// application hits when it compares an invited address against a verified
// account address.
func checkCreateEmailInviteNormalizes(t tb, st invite.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	containerID := newID()
	email := newEmail()
	inv := newInvite(containerID, mixedCase(email), at)

	created := mustCreateEmailInvite(t, st, inv)
	if created.Email != email {
		t.Fatalf("CreateEmailInvite(%q) returned Email %q, want the normalized %q — invite.EmailInvite's address-normalization MUST applies before the uniqueness check and the write, and the returned record is what was stored", inv.Email, created.Email, email)
	}

	byID, err := st.FindEmailInvite(ctx, inv.ID)
	wantNoErr(t, "FindEmailInvite", err)
	if byID.Email != email {
		t.Fatalf("FindEmailInvite returned Email %q, want the normalized %q — the stored row still carries the raw spelling", byID.Email, email)
	}

	byHash, err := st.FindEmailInviteByTokenHash(ctx, inv.TokenHash)
	wantNoErr(t, "FindEmailInviteByTokenHash", err)
	if byHash.Email != email {
		t.Fatalf("FindEmailInviteByTokenHash returned Email %q, want the normalized %q", byHash.Email, email)
	}

	list, err := st.ListEmailInvites(ctx, containerID)
	wantNoErr(t, "ListEmailInvites", err)
	if len(list) != 1 {
		t.Fatalf("ListEmailInvites returned %d row(s), want 1", len(list))
	}
	if list[0].Email != email {
		t.Fatalf("ListEmailInvites returned Email %q, want the normalized %q — a pending-invitations screen renders this value", list[0].Email, email)
	}

	// The normalized form is also what the sweep the re-invite performs will
	// be handed, so it has to match the row that was just written.
	wantNoErr(t, "DeleteEmailInvitesFor(the normalized address)", st.DeleteEmailInvitesFor(ctx, containerID, email))
	if _, err := st.FindEmailInvite(ctx, inv.ID); !errors.Is(err, invite.ErrInviteNotFound) {
		t.Fatalf("FindEmailInvite after sweeping the normalized address: error = %v, want ErrInviteNotFound — the row was written under a spelling the sweep cannot reach", err)
	}
}

// checkEmailInvitePairUniqueAcrossSpelling is the (ContainerID, Email)
// uniqueness MUST asked of a PERSON rather than of a byte string: a second
// invite for the same address spelled differently must be refused exactly as
// an identically-spelled one is.
//
// This is the security-relevant half of the normalization obligation, and it
// is reachable with no concurrency at all. Without normalization,
// "erin@example.com" and "Erin@Example.com" are two different pairs: both
// writes succeed, both tokens are live, and the sweep
// [invite.Service.InviteByEmail] performs first matches only the spelling it
// was handed. The container ends up holding two redeemable invitations for
// one human, and revoking the row an admin recognises on a
// pending-invitations screen leaves the other one live at the invited role.
//
// The colliding row is given its own TokenHash, so it fails only on the
// pair. What the refusal RETURNS is not asserted, for the reason the package
// doc gives.
func checkEmailInvitePairUniqueAcrossSpelling(t tb, st invite.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	containerID := newID()
	email := newEmail()
	first := mustCreateEmailInvite(t, st, newInvite(containerID, email, at))

	clash := newInvite(containerID, mixedCase(email), at)
	if _, err := st.CreateEmailInvite(ctx, clash); err == nil {
		t.Fatalf("CreateEmailInvite(%q) returned nil while %q already has a pending invite in this container — addresses are not normalized, so the (ContainerID, Email) constraint is byte-exact. Two casings of one address are two LIVE tokens for one person: revoking the row an admin recognises leaves the other redeemable, at the invited role, with nothing reporting that it is still out there", clash.Email, first.Email)
	}

	list, err := st.ListEmailInvites(ctx, containerID)
	wantNoErr(t, "ListEmailInvites after the rejected duplicate", err)
	wantSameIDs(t, "ListEmailInvites after the rejected duplicate", inviteIDs(list), []string{first.ID})
}

// checkEmailInviteTokenHashUnique asserts [invite.EmailInvite.TokenHash]'s
// uniqueness MUST: a second invite taking a hash another row already holds
// must be refused, and the hash must still resolve to the original row.
//
// The colliding row is deliberately in a DIFFERENT container and for a
// DIFFERENT address, so nothing else about it conflicts — this check fails
// only a backend missing the token_hash constraint itself, not one that
// happens to catch the collision through (ContainerID, Email).
//
// What the refusal RETURNS is not asserted: [invite.Store] classifies no
// conflict-on-create at all (see the package doc), and the two backends
// answer differently on purpose.
func checkEmailInviteTokenHashUnique(t tb, st invite.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	first := mustCreateEmailInvite(t, st, newInvite(newID(), newEmail(), at))

	clash := newInvite(newID(), newEmail(), at)
	clash.TokenHash = first.TokenHash
	if _, err := st.CreateEmailInvite(ctx, clash); err == nil {
		t.Fatalf("CreateEmailInvite with a token hash another invite already holds returned nil — invite.EmailInvite.TokenHash's uniqueness MUST is not enforced. Two rows sharing a hash let two concurrent presentations of one token resolve DIFFERENT rows through FindEmailInviteByTokenHash and each win its own DeleteEmailInvite, so a one-time credential pays out twice")
	}

	got, err := st.FindEmailInviteByTokenHash(ctx, first.TokenHash)
	wantNoErr(t, "FindEmailInviteByTokenHash after the rejected duplicate", err)
	if got.ID != first.ID {
		t.Fatalf("FindEmailInviteByTokenHash returned id %q, want the only row that should hold the hash, %q", got.ID, first.ID)
	}
	if _, err := st.FindEmailInvite(ctx, clash.ID); !errors.Is(err, invite.ErrInviteNotFound) {
		t.Fatalf("FindEmailInvite(the rejected row) error = %v, want ErrInviteNotFound — a refused create must write nothing", err)
	}
}

// checkEmailInviteContainerEmailUnique asserts the (ContainerID, Email)
// uniqueness MUST: one container may hold at most one pending invite per
// address, so a second one is refused and the original survives.
//
// The colliding row is given its own TokenHash, so it fails only on the pair
// — a backend that enforces token_hash and not the pair does not pass this
// by accident. It also asserts a different address in the SAME container is
// unaffected, so a store cannot pass by refusing every second invite in a
// container.
//
// The obligation is what makes [invite.Store.DeleteEmailInvitesFor] +
// CreateEmailInvite — the re-invite sequence the service performs — REPLACE
// rather than duplicate when two such calls race. Two pending invites for one
// address are two live tokens where the pending-invitations screen shows one
// row, so revoking the visible one leaves the other redeemable.
func checkEmailInviteContainerEmailUnique(t tb, st invite.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	containerID := newID()
	email := newEmail()
	first := mustCreateEmailInvite(t, st, newInvite(containerID, email, at))

	clash := newInvite(containerID, email, at)
	if _, err := st.CreateEmailInvite(ctx, clash); err == nil {
		t.Fatalf("CreateEmailInvite for a (container, email) pair that already has a pending invite returned nil — the pair's uniqueness MUST is not enforced, so re-inviting an address duplicates instead of replacing and a revocation can leave a second live token behind")
	}

	list, err := st.ListEmailInvites(ctx, containerID)
	wantNoErr(t, "ListEmailInvites after the rejected duplicate", err)
	wantSameIDs(t, "ListEmailInvites after the rejected duplicate", inviteIDs(list), []string{first.ID})

	// A different address in the same container is a different pair.
	other := mustCreateEmailInvite(t, st, newInvite(containerID, newEmail(), at))
	list, err = st.ListEmailInvites(ctx, containerID)
	wantNoErr(t, "ListEmailInvites", err)
	wantSameIDs(t, "ListEmailInvites", inviteIDs(list), []string{first.ID, other.ID})
}

// checkEmailInviteAddressIsNotGloballyUnique asserts the pair constraint is
// exactly a PAIR: the same address invited to two different containers is
// two legitimate rows, not a conflict. An over-broad constraint on email
// alone would stop a person being invited to a second organization, which is
// the ordinary case, so this check exists to keep the previous one from
// being satisfied by a blunter rule.
func checkEmailInviteAddressIsNotGloballyUnique(t tb, st invite.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	email := newEmail()
	here, there := newID(), newID()

	first := mustCreateEmailInvite(t, st, newInvite(here, email, at))

	second, err := st.CreateEmailInvite(ctx, newInvite(there, email, at))
	if err != nil {
		t.Fatalf("CreateEmailInvite for %q in a second container returned %v, want nil — the uniqueness obligation is on the (ContainerID, Email) PAIR, not on the address alone; one person is routinely invited to more than one container", email, err)
	}

	hereList, err := st.ListEmailInvites(ctx, here)
	wantNoErr(t, "ListEmailInvites(first container)", err)
	wantSameIDs(t, "ListEmailInvites(first container)", inviteIDs(hereList), []string{first.ID})

	thereList, err := st.ListEmailInvites(ctx, there)
	wantNoErr(t, "ListEmailInvites(second container)", err)
	wantSameIDs(t, "ListEmailInvites(second container)", inviteIDs(thereList), []string{second.ID})
}

// checkFindEmailInviteNotFound asserts an id no invite holds is reported as
// ErrInviteNotFound rather than a zero value with a nil error.
func checkFindEmailInviteNotFound(t tb, st invite.Store) {
	t.Helper()
	_, err := st.FindEmailInvite(context.Background(), newID())
	wantErrIs(t, "FindEmailInvite(unknown id)", err, invite.ErrInviteNotFound)
}

// checkFindEmailInviteByTokenHashNotFound asserts a hash no invite holds is
// ErrInviteNotFound. This is the acceptance path's miss, and it must be an
// error rather than a zero record: the service branches on it to refuse an
// unknown token.
func checkFindEmailInviteByTokenHashNotFound(t tb, st invite.Store) {
	t.Helper()
	_, err := st.FindEmailInviteByTokenHash(context.Background(), newHash())
	wantErrIs(t, "FindEmailInviteByTokenHash(unknown hash)", err, invite.ErrInviteNotFound)
}

// checkListEmailInvitesScopes asserts ListEmailInvites returns every invite
// in the named container and nothing from any other. Ids are compared as a
// set, since the port leaves order unspecified.
func checkListEmailInvitesScopes(t tb, st invite.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	here, there := newID(), newID()

	a := mustCreateEmailInvite(t, st, newInvite(here, newEmail(), at))
	b := mustCreateEmailInvite(t, st, newInvite(here, newEmail(), at))
	elsewhere := mustCreateEmailInvite(t, st, newInvite(there, newEmail(), at))

	list, err := st.ListEmailInvites(ctx, here)
	wantNoErr(t, "ListEmailInvites", err)
	wantSameIDs(t, "ListEmailInvites", inviteIDs(list), []string{a.ID, b.ID})

	other, err := st.ListEmailInvites(ctx, there)
	wantNoErr(t, "ListEmailInvites(the other container)", err)
	wantSameIDs(t, "ListEmailInvites(the other container)", inviteIDs(other), []string{elsewhere.ID})
}

// checkListEmailInvitesIncludesExpired asserts the port's "expired or not —
// the caller filters": an invite whose ExpiresAt is long past is still
// listed. A store that filters on the caller's behalf hides exactly the rows
// a pending-invitations screen needs in order to show, and let an admin
// clear, a stale invitation.
func checkListEmailInvitesIncludesExpired(t tb, st invite.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	containerID := newID()

	fresh := mustCreateEmailInvite(t, st, newInvite(containerID, newEmail(), at))
	stale := newInvite(containerID, newEmail(), at)
	stale.ExpiresAt = at.Add(-24 * time.Hour)
	stale = mustCreateEmailInvite(t, st, stale)

	list, err := st.ListEmailInvites(ctx, containerID)
	wantNoErr(t, "ListEmailInvites", err)
	wantSameIDs(t, "ListEmailInvites", inviteIDs(list), []string{fresh.ID, stale.ID})
}

// checkListEmailInvitesEmpty asserts a container with no invites is not an
// error. The result is read through len only: the port says an empty slice
// and nil are alike and must not be distinguished.
func checkListEmailInvitesEmpty(t tb, st invite.Store) {
	t.Helper()
	list, err := st.ListEmailInvites(context.Background(), newID())
	wantNoErr(t, "ListEmailInvites(a container with no invites)", err)
	if len(list) != 0 {
		t.Fatalf("ListEmailInvites(a container with no invites) returned %d row(s), want 0", len(list))
	}
}

// checkDeleteEmailInvite asserts the claim removes exactly the row named and
// leaves a sibling in the same container alone, and that deleting the same
// id twice is ErrInviteNotFound the second time.
//
// That second delete is the sequential form of the property
// Service.AcceptInvite's one-time-credential guarantee rests on: the claim is
// rows-affected gated, so a token presented twice is refused the second time
// exactly as if it had never existed. The concurrent form is
// "DeleteEmailInvite/ConcurrentCallersAdmitExactlyOneWinner".
func checkDeleteEmailInvite(t tb, st invite.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	containerID := newID()
	target := mustCreateEmailInvite(t, st, newInvite(containerID, newEmail(), at))
	sibling := mustCreateEmailInvite(t, st, newInvite(containerID, newEmail(), at))

	wantNoErr(t, "DeleteEmailInvite", st.DeleteEmailInvite(ctx, target.ID))

	if _, err := st.FindEmailInvite(ctx, target.ID); !errors.Is(err, invite.ErrInviteNotFound) {
		t.Fatalf("FindEmailInvite(the claimed invite) error = %v, want ErrInviteNotFound", err)
	}
	if _, err := st.FindEmailInvite(ctx, sibling.ID); err != nil {
		t.Fatalf("FindEmailInvite(a sibling in the same container) error = %v, want nil — DeleteEmailInvite removes one row", err)
	}

	err := st.DeleteEmailInvite(ctx, target.ID)
	wantErrIs(t, "DeleteEmailInvite(the same id twice)", err, invite.ErrInviteNotFound)
}

// checkDeleteEmailInviteNotFound asserts an id no invite holds is
// ErrInviteNotFound rather than a silent nil. A store that answers nil turns
// every losing claim into a successful one, and the whole
// one-token-one-admission property with it.
func checkDeleteEmailInviteNotFound(t tb, st invite.Store) {
	t.Helper()
	err := st.DeleteEmailInvite(context.Background(), newID())
	wantErrIs(t, "DeleteEmailInvite(unknown id)", err, invite.ErrInviteNotFound)
}

// checkDeleteEmailInvitesFor asserts the sweep a re-invite performs first is
// scoped to exactly (containerID, email): the row for that pair goes, and
// rows for another address in the same container, or for the same address in
// another container, survive.
func checkDeleteEmailInvitesFor(t tb, st invite.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	here, there := newID(), newID()
	email := newEmail()

	doomed := mustCreateEmailInvite(t, st, newInvite(here, email, at))
	otherAddress := mustCreateEmailInvite(t, st, newInvite(here, newEmail(), at))
	otherContainer := mustCreateEmailInvite(t, st, newInvite(there, email, at))

	wantNoErr(t, "DeleteEmailInvitesFor", st.DeleteEmailInvitesFor(ctx, here, email))

	if _, err := st.FindEmailInvite(ctx, doomed.ID); !errors.Is(err, invite.ErrInviteNotFound) {
		t.Fatalf("FindEmailInvite(the swept row) error = %v, want ErrInviteNotFound", err)
	}
	for _, survivor := range []invite.EmailInvite{otherAddress, otherContainer} {
		if _, err := st.FindEmailInvite(ctx, survivor.ID); err != nil {
			t.Fatalf("FindEmailInvite(%s, outside the swept pair) error = %v, want nil", survivor.ID, err)
		}
	}
}

// checkDeleteEmailInvitesForNormalizes asserts the read-side half of
// [invite.EmailInvite]'s address-normalization MUST: the sweep matches on
// the normalized address, so a mixed-case, whitespace-padded spelling
// removes the row a normalized one wrote.
//
// This is what keeps the re-invite sequence correct for a caller that
// reaches the Store directly with whatever its own form field produced. A
// sweep that matched byte-exactly would leave the pending row behind and let
// the CreateEmailInvite that follows it add a second one — or, against a
// backend that normalizes on create, would refuse that create as a duplicate
// and fail an invitation that should have replaced.
//
// A sibling in the same container and the same address in another container
// are asserted to survive, so a store cannot pass by sweeping too widely —
// "DeleteEmailInvitesFor/RemovesOnlyThatPair" makes the same demand of the
// exact spelling.
func checkDeleteEmailInvitesForNormalizes(t tb, st invite.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	here, there := newID(), newID()
	email := newEmail()

	doomed := mustCreateEmailInvite(t, st, newInvite(here, email, at))
	otherAddress := mustCreateEmailInvite(t, st, newInvite(here, newEmail(), at))
	otherContainer := mustCreateEmailInvite(t, st, newInvite(there, email, at))

	wantNoErr(t, "DeleteEmailInvitesFor(a case variant)", st.DeleteEmailInvitesFor(ctx, here, mixedCase(email)))

	if _, err := st.FindEmailInvite(ctx, doomed.ID); !errors.Is(err, invite.ErrInviteNotFound) {
		t.Fatalf("FindEmailInvite(%s) after sweeping %q: error = %v, want ErrInviteNotFound — the sweep must normalize its address argument, or a re-invite leaves the pending row behind and the container holds two live tokens for one person", doomed.ID, mixedCase(email), err)
	}
	for _, survivor := range []invite.EmailInvite{otherAddress, otherContainer} {
		if _, err := st.FindEmailInvite(ctx, survivor.ID); err != nil {
			t.Fatalf("FindEmailInvite(%s, outside the swept pair) error = %v, want nil", survivor.ID, err)
		}
	}
}

// checkDeleteEmailInvitesForEmpty asserts sweeping a pair with no rows is
// not an error — the port says so, and the service calls it unconditionally
// before every fresh invite, including the first one for an address.
func checkDeleteEmailInvitesForEmpty(t tb, st invite.Store) {
	t.Helper()
	err := st.DeleteEmailInvitesFor(context.Background(), newID(), newEmail())
	wantNoErr(t, "DeleteEmailInvitesFor(a pair with no rows)", err)
}
