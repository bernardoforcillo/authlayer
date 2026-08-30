package invitetest

import (
	"context"
	"time"

	"github.com/bernardoforcillo/authlayer/invite"
)

func linkChecks() []check {
	return []check{
		{"CreateLink/RoundTrip", checkCreateLinkRoundTrip},
		{"CreateLink/CodeIsUnique", checkLinkCodeUnique},
		{"FindLink/UnknownIDReturnsErrLinkNotFound", checkFindLinkNotFound},
		{"FindLinkByCode/UnknownCodeReturnsErrLinkNotFound", checkFindLinkByCodeNotFound},
		{"ListLinks/ScopesToTheContainer", checkListLinksScopes},
		{"ListLinks/ReturnsRevokedAndExpiredRowsToo", checkListLinksIncludesDeadRows},
		{"ListLinks/EmptyContainerIsNotAnError", checkListLinksEmpty},
		{"RevokeLink/StampsRevokedAt", checkRevokeLink},
		{"RevokeLink/IsIdempotentAndOverwritesTheTimestamp", checkRevokeLinkIdempotent},
		{"RevokeLink/UnknownIDReturnsErrLinkNotFound", checkRevokeLinkNotFound},
		{"ConsumeLink/IncrementsUseCount", checkConsumeLinkIncrements},
		{"ConsumeLink/StopsAtMaxUses", checkConsumeLinkStopsAtMaxUses},
		{"ConsumeLink/MaxUsesZeroIsUnlimited", checkConsumeLinkZeroMaxUses},
		{"ConsumeLink/RevokedLinkIsRefusedWithoutAnError", checkConsumeLinkRevoked},
		{"ConsumeLink/ExpiredLinkIsRefusedWithoutAnError", checkConsumeLinkExpired},
		{"ConsumeLink/TheExpiresAtInstantItselfIsExpired", checkConsumeLinkExpiryBoundary},
		{"ConsumeLink/NilExpiresAtNeverExpires", checkConsumeLinkNilExpiry},
		{"ConsumeLink/UnknownIDReturnsErrLinkNotFound", checkConsumeLinkNotFound},
	}
}

// checkCreateLinkRoundTrip asserts CreateLink returns what it stored and
// that both read paths — by id and by code — return the same record, with
// every field of [invite.Link] intact.
//
// Two of them get particular attention. Code must come back verbatim: the
// port says it is "stored in clear rather than hashed" precisely so a manage-
// links screen can redisplay it, and FindLinkByCode is a plain lookup on the
// stored value, so a store that transforms it breaks both. And the two
// nullable instants must round-trip as nil, since nil means "never expires"
// and "not revoked" — a store that substitutes a zero time for either turns
// a live link into an expired or revoked one.
func checkCreateLinkRoundTrip(t tb, st invite.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	expires := at.Add(24 * time.Hour)
	l := newLink(newID(), at)
	l.MaxUses = 5
	l.UseCount = 2
	l.ExpiresAt = &expires

	created := mustCreateLink(t, st, l)
	assertLinkEqual(t, "CreateLink returned", created, l)

	byID, err := st.FindLink(ctx, l.ID)
	wantNoErr(t, "FindLink", err)
	assertLinkEqual(t, "FindLink returned", byID, l)

	byCode, err := st.FindLinkByCode(ctx, l.Code)
	wantNoErr(t, "FindLinkByCode", err)
	assertLinkEqual(t, "FindLinkByCode returned", byCode, l)

	// The nil case for both nullable instants, on its own record: nil means
	// "never expires" and "not revoked", and must survive as nil.
	open := mustCreateLink(t, st, newLink(l.ContainerID, at))
	gotOpen, err := st.FindLink(ctx, open.ID)
	wantNoErr(t, "FindLink(a never-expiring, unrevoked link)", err)
	wantTimePtrEqual(t, "ExpiresAt of a never-expiring link", gotOpen.ExpiresAt, nil)
	wantTimePtrEqual(t, "RevokedAt of an unrevoked link", gotOpen.RevokedAt, nil)
	if gotOpen.MaxUses != 0 || gotOpen.UseCount != 0 {
		t.Fatalf("a fresh unlimited link came back MaxUses=%d UseCount=%d, want 0 and 0", gotOpen.MaxUses, gotOpen.UseCount)
	}
}

// assertLinkEqual compares every field of a Link, with the three instants by
// time.Time.Equal (nil-aware for the two nullable ones).
func assertLinkEqual(t tb, what string, got, want invite.Link) {
	t.Helper()
	if got.ID != want.ID {
		t.Fatalf("%s ID %q, want %q", what, got.ID, want.ID)
	}
	if got.ContainerID != want.ContainerID {
		t.Fatalf("%s ContainerID %q, want %q", what, got.ContainerID, want.ContainerID)
	}
	if got.Code != want.Code {
		t.Fatalf("%s Code %q, want %q — Code is stored in clear, not transformed", what, got.Code, want.Code)
	}
	if got.RoleKey != want.RoleKey {
		t.Fatalf("%s RoleKey %q, want %q — a lost role admits redeemers at the wrong one", what, got.RoleKey, want.RoleKey)
	}
	if got.CreatedBy != want.CreatedBy {
		t.Fatalf("%s CreatedBy %q, want %q", what, got.CreatedBy, want.CreatedBy)
	}
	if got.MaxUses != want.MaxUses {
		t.Fatalf("%s MaxUses %d, want %d — MaxUses is what bounds who gets in", what, got.MaxUses, want.MaxUses)
	}
	if got.UseCount != want.UseCount {
		t.Fatalf("%s UseCount %d, want %d", what, got.UseCount, want.UseCount)
	}
	wantTimePtrEqual(t, what+" ExpiresAt", got.ExpiresAt, want.ExpiresAt)
	wantTimePtrEqual(t, what+" RevokedAt", got.RevokedAt, want.RevokedAt)
	wantTimeEqual(t, what+" CreatedAt", got.CreatedAt, want.CreatedAt)
}

// checkLinkCodeUnique asserts [invite.Link.Code]'s uniqueness MUST: a second
// link taking a code another row already holds must be refused, and the code
// must still resolve to the original row.
//
// The colliding row is in a different container, so nothing else about it
// conflicts. What the refusal returns is not asserted; see the package doc.
//
// A shared code defeats ConsumeLink's single-winner property with no
// atomicity defect at all: Service.JoinViaLink resolves the code with
// FindLinkByCode and then consumes THAT row's id, so two concurrent
// redeemers can resolve different colliding rows and each atomically win its
// own ConsumeLink — a MaxUses:1 link admitting two people while every
// individual consume behaved perfectly.
func checkLinkCodeUnique(t tb, st invite.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	first := mustCreateLink(t, st, newLink(newID(), at))

	clash := newLink(newID(), at)
	clash.Code = first.Code
	if _, err := st.CreateLink(ctx, clash); err == nil {
		t.Fatalf("CreateLink with a code another link already holds returned nil — invite.Link.Code's uniqueness MUST is not enforced. Two rows sharing a code let two redeemers resolve DIFFERENT rows through FindLinkByCode and each win its own ConsumeLink, so a MaxUses:1 link admits two people")
	}

	got, err := st.FindLinkByCode(ctx, first.Code)
	wantNoErr(t, "FindLinkByCode after the rejected duplicate", err)
	if got.ID != first.ID {
		t.Fatalf("FindLinkByCode returned id %q, want the only row that should hold the code, %q", got.ID, first.ID)
	}
	if _, err := st.FindLink(ctx, clash.ID); err == nil {
		t.Fatalf("FindLink(the rejected row) returned nil error — a refused create must write nothing")
	}
}

// checkFindLinkNotFound asserts an id no link holds is ErrLinkNotFound.
func checkFindLinkNotFound(t tb, st invite.Store) {
	t.Helper()
	_, err := st.FindLink(context.Background(), newID())
	wantErrIs(t, "FindLink(unknown id)", err, invite.ErrLinkNotFound)
}

// checkFindLinkByCodeNotFound asserts a code no link holds is
// ErrLinkNotFound. This is the redemption path's miss.
func checkFindLinkByCodeNotFound(t tb, st invite.Store) {
	t.Helper()
	_, err := st.FindLinkByCode(context.Background(), newCode())
	wantErrIs(t, "FindLinkByCode(unknown code)", err, invite.ErrLinkNotFound)
}

// checkListLinksScopes asserts ListLinks returns every link in the named
// container and nothing from any other, compared as a set since order is
// unspecified.
func checkListLinksScopes(t tb, st invite.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	here, there := newID(), newID()

	a := mustCreateLink(t, st, newLink(here, at))
	b := mustCreateLink(t, st, newLink(here, at))
	elsewhere := mustCreateLink(t, st, newLink(there, at))

	list, err := st.ListLinks(ctx, here)
	wantNoErr(t, "ListLinks", err)
	wantSameIDs(t, "ListLinks", linkIDs(list), []string{a.ID, b.ID})

	other, err := st.ListLinks(ctx, there)
	wantNoErr(t, "ListLinks(the other container)", err)
	wantSameIDs(t, "ListLinks(the other container)", linkIDs(other), []string{elsewhere.ID})
}

// checkListLinksIncludesDeadRows asserts the port's "revoked or not, expired
// or not — the caller filters": a revoked link and an expired one are both
// still listed. A manage-links screen needs them in order to show what
// happened to a link someone is asking about, and an admin cannot revoke or
// audit a row the store hides.
func checkListLinksIncludesDeadRows(t tb, st invite.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	containerID := newID()

	live := mustCreateLink(t, st, newLink(containerID, at))

	expired := newLink(containerID, at)
	past := at.Add(-24 * time.Hour)
	expired.ExpiresAt = &past
	expired = mustCreateLink(t, st, expired)

	revoked := mustCreateLink(t, st, newLink(containerID, at))
	wantNoErr(t, "RevokeLink (fixture)", st.RevokeLink(ctx, revoked.ID, at))

	list, err := st.ListLinks(ctx, containerID)
	wantNoErr(t, "ListLinks", err)
	wantSameIDs(t, "ListLinks", linkIDs(list), []string{live.ID, expired.ID, revoked.ID})
}

// checkListLinksEmpty asserts a container with no links is not an error,
// read through len only.
func checkListLinksEmpty(t tb, st invite.Store) {
	t.Helper()
	list, err := st.ListLinks(context.Background(), newID())
	wantNoErr(t, "ListLinks(a container with no links)", err)
	if len(list) != 0 {
		t.Fatalf("ListLinks(a container with no links) returned %d row(s), want 0", len(list))
	}
}

// checkRevokeLink asserts RevokeLink stamps RevokedAt with the instant it
// was given — not with a clock of the store's own — and that the row is
// otherwise untouched.
func checkRevokeLink(t tb, st invite.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	l := mustCreateLink(t, st, newLink(newID(), at))

	revokedAt := at.Add(time.Minute)
	wantNoErr(t, "RevokeLink", st.RevokeLink(ctx, l.ID, revokedAt))

	got, err := st.FindLink(ctx, l.ID)
	wantNoErr(t, "FindLink", err)
	if got.RevokedAt == nil {
		t.Fatalf("RevokedAt = nil after RevokeLink, want the instant it was given")
	}
	wantTimeEqual(t, "RevokedAt", *got.RevokedAt, revokedAt)
	if got.Code != l.Code || got.MaxUses != l.MaxUses || got.UseCount != l.UseCount {
		t.Fatalf("RevokeLink changed more than RevokedAt: %+v, want the row it was given, %+v", got, l)
	}
}

// checkRevokeLinkIdempotent asserts the port's "revoking an already-revoked
// link overwrites the timestamp rather than erroring". Two tabs both hitting
// revoke must not produce an error for the second one.
func checkRevokeLinkIdempotent(t tb, st invite.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	l := mustCreateLink(t, st, newLink(newID(), at))

	first := at.Add(time.Minute)
	wantNoErr(t, "RevokeLink (first)", st.RevokeLink(ctx, l.ID, first))
	second := first.Add(time.Minute)
	wantNoErr(t, "RevokeLink (second, already revoked)", st.RevokeLink(ctx, l.ID, second))

	got, err := st.FindLink(ctx, l.ID)
	wantNoErr(t, "FindLink", err)
	if got.RevokedAt == nil {
		t.Fatalf("RevokedAt = nil after two RevokeLink calls")
	}
	wantTimeEqual(t, "RevokedAt after the second call", *got.RevokedAt, second)
}

// checkRevokeLinkNotFound asserts an id no link holds is ErrLinkNotFound,
// not a silent nil — revocation reports whether it revoked anything.
func checkRevokeLinkNotFound(t tb, st invite.Store) {
	t.Helper()
	err := st.RevokeLink(context.Background(), newID(), stamp())
	wantErrIs(t, "RevokeLink(unknown id)", err, invite.ErrLinkNotFound)
}

// checkConsumeLinkIncrements asserts the ordinary success path: each
// successful consume of an unlimited, unrevoked, never-expiring link reports
// ok=true and raises UseCount by exactly one. A store that reports ok=true
// without incrementing lets an unlimited link stay at zero forever, which
// looks harmless until the same code path is asked to enforce a limit.
func checkConsumeLinkIncrements(t tb, st invite.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	l := mustCreateLink(t, st, newLink(newID(), at))

	for i := 1; i <= 3; i++ {
		ok, err := st.ConsumeLink(ctx, l.ID, at)
		wantNoErr(t, "ConsumeLink", err)
		if !ok {
			t.Fatalf("ConsumeLink #%d on an unlimited, unrevoked, never-expiring link returned ok=false", i)
		}
		got, ferr := st.FindLink(ctx, l.ID)
		wantNoErr(t, "FindLink", ferr)
		if got.UseCount != i {
			t.Fatalf("UseCount = %d after %d successful consume(s), want %d", got.UseCount, i, i)
		}
	}
}

// checkConsumeLinkStopsAtMaxUses asserts the exhaustion predicate the port
// states — consume only while UseCount is BELOW MaxUses — at its boundary: a
// MaxUses:2 link pays out exactly twice, the third caller is refused with
// (false, nil), and UseCount does not creep past the limit.
//
// An off-by-one here (UseCount > MaxUses rather than >=) admits one person
// more than the link was minted to admit, every time, with no concurrency
// involved at all.
func checkConsumeLinkStopsAtMaxUses(t tb, st invite.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	l := newLink(newID(), at)
	l.MaxUses = 2
	l = mustCreateLink(t, st, l)

	for i := 1; i <= 2; i++ {
		ok, err := st.ConsumeLink(ctx, l.ID, at)
		wantNoErr(t, "ConsumeLink", err)
		if !ok {
			t.Fatalf("ConsumeLink #%d on a MaxUses:2 link returned ok=false, want true", i)
		}
	}

	ok, err := st.ConsumeLink(ctx, l.ID, at)
	wantNoErr(t, "ConsumeLink(exhausted)", err)
	if ok {
		t.Fatalf("ConsumeLink returned ok=true for the 3rd caller of a MaxUses:2 link — the use limit does not bound admission")
	}

	got, ferr := st.FindLink(ctx, l.ID)
	wantNoErr(t, "FindLink", ferr)
	if got.UseCount != 2 {
		t.Fatalf("UseCount = %d after 2 successful and 1 refused consume of a MaxUses:2 link, want 2", got.UseCount)
	}
}

// checkConsumeLinkZeroMaxUses asserts MaxUses 0 means unlimited, not
// "already exhausted". The port says so on the field and repeats it in
// ConsumeLink's own predicate; a store that reads 0 as a limit makes every
// unlimited link dead on arrival.
func checkConsumeLinkZeroMaxUses(t tb, st invite.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	l := mustCreateLink(t, st, newLink(newID(), at))

	const n = 5
	for i := 1; i <= n; i++ {
		ok, err := st.ConsumeLink(ctx, l.ID, at)
		wantNoErr(t, "ConsumeLink", err)
		if !ok {
			t.Fatalf("ConsumeLink #%d on a MaxUses:0 link returned ok=false — 0 means unlimited", i)
		}
	}

	got, ferr := st.FindLink(ctx, l.ID)
	wantNoErr(t, "FindLink", ferr)
	if got.UseCount != n {
		t.Fatalf("UseCount = %d after %d consumes of an unlimited link, want %d", got.UseCount, n, n)
	}
}

// checkConsumeLinkRevoked asserts a revoked link is refused, and refused the
// way the port specifies: ok=false with a NIL error, not one of the
// ErrLink... sentinels. ConsumeLink reports only ok=false for all three link
// reasons at once, because the check and the increment are a single atomic
// step; the service re-reads the record to decide which reason to surface.
// It also asserts nothing was consumed.
func checkConsumeLinkRevoked(t tb, st invite.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	l := mustCreateLink(t, st, newLink(newID(), at))
	wantNoErr(t, "RevokeLink (fixture)", st.RevokeLink(ctx, l.ID, at))

	ok, err := st.ConsumeLink(ctx, l.ID, at.Add(time.Minute))
	if err != nil {
		t.Fatalf("ConsumeLink(a revoked link) returned error %v, want (false, nil) — a refusal is not an error", err)
	}
	if ok {
		t.Fatalf("ConsumeLink returned ok=true for a revoked link — revocation does not stop admission")
	}

	got, ferr := st.FindLink(ctx, l.ID)
	wantNoErr(t, "FindLink", ferr)
	if got.UseCount != 0 {
		t.Fatalf("UseCount = %d after a refused consume of a revoked link, want 0", got.UseCount)
	}
}

// checkConsumeLinkExpired asserts a link whose ExpiresAt is in the past is
// refused with (false, nil) and consumes nothing.
func checkConsumeLinkExpired(t tb, st invite.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	l := newLink(newID(), at)
	past := at.Add(-time.Hour)
	l.ExpiresAt = &past
	l = mustCreateLink(t, st, l)

	ok, err := st.ConsumeLink(ctx, l.ID, at)
	if err != nil {
		t.Fatalf("ConsumeLink(an expired link) returned error %v, want (false, nil)", err)
	}
	if ok {
		t.Fatalf("ConsumeLink returned ok=true for a link that expired an hour ago")
	}

	got, ferr := st.FindLink(ctx, l.ID)
	wantNoErr(t, "FindLink", ferr)
	if got.UseCount != 0 {
		t.Fatalf("UseCount = %d after a refused consume of an expired link, want 0", got.UseCount)
	}
}

// checkConsumeLinkExpiryBoundary pins which side of ExpiresAt the deadline
// falls on: consumption succeeds only while now is STRICTLY before
// ExpiresAt, so the instant itself already counts as expired.
//
// That reading comes from the port's own field doc — [invite.Link.ExpiresAt]
// "is when the link stops being redeemable", so at that instant it has
// stopped, not one tick later — and from ConsumeLink's "unexpired at now".
// It is stated here because a boundary left to each backend's taste is
// exactly the kind of divergence a caller meets for the first time in
// production.
//
// The check drives both sides of the boundary against two separate links, so
// a store that simply refuses everything cannot pass: one microsecond before
// ExpiresAt must succeed, and ExpiresAt itself must not.
func checkConsumeLinkExpiryBoundary(t tb, st invite.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	expiry := at.Add(time.Hour)

	justBefore := newLink(newID(), at)
	justBefore.ExpiresAt = &expiry
	justBefore = mustCreateLink(t, st, justBefore)

	atTheInstant := newLink(justBefore.ContainerID, at)
	atTheInstant.ExpiresAt = &expiry
	atTheInstant = mustCreateLink(t, st, atTheInstant)

	ok, err := st.ConsumeLink(ctx, justBefore.ID, expiry.Add(-time.Microsecond))
	wantNoErr(t, "ConsumeLink(one microsecond before ExpiresAt)", err)
	if !ok {
		t.Fatalf("ConsumeLink returned ok=false one microsecond BEFORE ExpiresAt — a link is redeemable right up to its deadline")
	}

	ok, err = st.ConsumeLink(ctx, atTheInstant.ID, expiry)
	if err != nil {
		t.Fatalf("ConsumeLink(exactly at ExpiresAt) returned error %v, want (false, nil)", err)
	}
	if ok {
		t.Fatalf("ConsumeLink returned ok=true at exactly ExpiresAt — ExpiresAt is when the link STOPS being redeemable, so the instant itself is already expired")
	}
}

// checkConsumeLinkNilExpiry asserts a nil ExpiresAt means never expires, at
// any now the caller cares to pass — the port's "nil = never". A store that
// treats a missing expiry as an expired one kills every link minted without
// a deadline, which is the common case.
func checkConsumeLinkNilExpiry(t tb, st invite.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	l := mustCreateLink(t, st, newLink(newID(), at))

	ok, err := st.ConsumeLink(ctx, l.ID, at.Add(100*365*24*time.Hour))
	wantNoErr(t, "ConsumeLink(a link with no expiry, a century later)", err)
	if !ok {
		t.Fatalf("ConsumeLink returned ok=false for a link whose ExpiresAt is nil — nil means never expires")
	}
}

// checkConsumeLinkNotFound asserts the port's one explicit distinction on
// this method: an id no link holds is (false, ErrLinkNotFound), NOT a silent
// ok=false. The service tells "this code is not a link" apart from "this
// link cannot be used right now" on exactly that error.
func checkConsumeLinkNotFound(t tb, st invite.Store) {
	t.Helper()
	ok, err := st.ConsumeLink(context.Background(), newID(), stamp())
	wantErrIs(t, "ConsumeLink(unknown id)", err, invite.ErrLinkNotFound)
	if ok {
		t.Fatalf("ConsumeLink(unknown id) returned ok=true")
	}
}
