package memory_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/bernardoforcillo/authlayer/invite"
	"github.com/bernardoforcillo/authlayer/store/memory"
)

// Compile-time proof the memory store satisfies invite.Store.
var _ invite.Store = (*memory.InviteStore)(nil)

func newInviteStore() *memory.InviteStore {
	return memory.NewInviteStore()
}

// --- EmailInvite ---

func TestCreateAndFindEmailInvite(t *testing.T) {
	st := newInviteStore()
	ctx := context.Background()

	in := invite.EmailInvite{
		ID:          "inv1",
		ContainerID: "acme",
		Email:       "bob@example.com",
		RoleKey:     "member",
		TokenHash:   "hash1",
		InvitedBy:   "alice",
		ExpiresAt:   time.Now().Add(24 * time.Hour),
		CreatedAt:   time.Now(),
	}
	created, err := st.CreateEmailInvite(ctx, in)
	if err != nil {
		t.Fatalf("CreateEmailInvite: %v", err)
	}
	if created != in {
		t.Fatalf("CreateEmailInvite returned %+v, want %+v", created, in)
	}

	got, err := st.FindEmailInvite(ctx, "inv1")
	if err != nil {
		t.Fatalf("FindEmailInvite: %v", err)
	}
	if got != in {
		t.Fatalf("FindEmailInvite = %+v, want %+v", got, in)
	}
}

func TestFindEmailInviteNotFound(t *testing.T) {
	st := newInviteStore()
	_, err := st.FindEmailInvite(context.Background(), "nonesuch")
	if !errors.Is(err, invite.ErrInviteNotFound) {
		t.Fatalf("FindEmailInvite err = %v, want ErrInviteNotFound", err)
	}
}

func TestFindEmailInviteByTokenHash(t *testing.T) {
	st := newInviteStore()
	ctx := context.Background()

	in := invite.EmailInvite{ID: "inv1", ContainerID: "acme", TokenHash: "hash-abc"}
	if _, err := st.CreateEmailInvite(ctx, in); err != nil {
		t.Fatalf("CreateEmailInvite: %v", err)
	}
	// A second invite with a different hash must not be matched.
	if _, err := st.CreateEmailInvite(ctx, invite.EmailInvite{ID: "inv2", ContainerID: "acme", TokenHash: "hash-other"}); err != nil {
		t.Fatalf("CreateEmailInvite 2: %v", err)
	}

	got, err := st.FindEmailInviteByTokenHash(ctx, "hash-abc")
	if err != nil {
		t.Fatalf("FindEmailInviteByTokenHash: %v", err)
	}
	if got.ID != "inv1" {
		t.Fatalf("FindEmailInviteByTokenHash returned id %q, want inv1", got.ID)
	}
}

func TestFindEmailInviteByTokenHashNotFound(t *testing.T) {
	st := newInviteStore()
	_, err := st.FindEmailInviteByTokenHash(context.Background(), "nonesuch")
	if !errors.Is(err, invite.ErrInviteNotFound) {
		t.Fatalf("FindEmailInviteByTokenHash err = %v, want ErrInviteNotFound", err)
	}
}

func TestListEmailInvitesScopesToContainer(t *testing.T) {
	st := newInviteStore()
	ctx := context.Background()

	for _, in := range []invite.EmailInvite{
		{ID: "inv1", ContainerID: "acme", Email: "a@x.com"},
		{ID: "inv2", ContainerID: "acme", Email: "b@x.com"},
		{ID: "inv3", ContainerID: "globex", Email: "c@x.com"},
	} {
		if _, err := st.CreateEmailInvite(ctx, in); err != nil {
			t.Fatalf("create %s: %v", in.ID, err)
		}
	}

	got, err := st.ListEmailInvites(ctx, "acme")
	if err != nil {
		t.Fatalf("ListEmailInvites: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d invites, want 2: %+v", len(got), got)
	}
}

func TestListEmailInvitesEmptyContainerIsEmptyNotError(t *testing.T) {
	st := newInviteStore()
	got, err := st.ListEmailInvites(context.Background(), "nobody")
	if err != nil {
		t.Fatalf("ListEmailInvites: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("got %d invites for an unknown container, want 0", len(got))
	}
}

func TestDeleteEmailInvite(t *testing.T) {
	st := newInviteStore()
	ctx := context.Background()
	if _, err := st.CreateEmailInvite(ctx, invite.EmailInvite{ID: "inv1", ContainerID: "acme"}); err != nil {
		t.Fatalf("CreateEmailInvite: %v", err)
	}
	if err := st.DeleteEmailInvite(ctx, "inv1"); err != nil {
		t.Fatalf("DeleteEmailInvite: %v", err)
	}
	if _, err := st.FindEmailInvite(ctx, "inv1"); !errors.Is(err, invite.ErrInviteNotFound) {
		t.Fatalf("FindEmailInvite after delete err = %v, want ErrInviteNotFound", err)
	}
}

func TestDeleteEmailInviteNotFound(t *testing.T) {
	st := newInviteStore()
	err := st.DeleteEmailInvite(context.Background(), "nonesuch")
	if !errors.Is(err, invite.ErrInviteNotFound) {
		t.Fatalf("DeleteEmailInvite err = %v, want ErrInviteNotFound", err)
	}
}

// DeleteEmailInvitesFor is what makes re-inviting an address replace rather
// than duplicate: it must remove every invite for (container, email) and
// leave every other row — a different email in the same container, and the
// same email in a different container — untouched.
func TestDeleteEmailInvitesForRemovesOnlyMatchingRows(t *testing.T) {
	st := newInviteStore()
	ctx := context.Background()

	for _, in := range []invite.EmailInvite{
		{ID: "inv1", ContainerID: "acme", Email: "bob@example.com"},
		{ID: "inv2", ContainerID: "acme", Email: "bob@example.com"}, // duplicate of inv1
		{ID: "inv3", ContainerID: "acme", Email: "carol@example.com"},
		{ID: "inv4", ContainerID: "globex", Email: "bob@example.com"},
	} {
		if _, err := st.CreateEmailInvite(ctx, in); err != nil {
			t.Fatalf("create %s: %v", in.ID, err)
		}
	}

	if err := st.DeleteEmailInvitesFor(ctx, "acme", "bob@example.com"); err != nil {
		t.Fatalf("DeleteEmailInvitesFor: %v", err)
	}

	for _, id := range []string{"inv1", "inv2"} {
		if _, err := st.FindEmailInvite(ctx, id); !errors.Is(err, invite.ErrInviteNotFound) {
			t.Fatalf("FindEmailInvite(%s) err = %v, want ErrInviteNotFound", id, err)
		}
	}
	for _, id := range []string{"inv3", "inv4"} {
		if _, err := st.FindEmailInvite(ctx, id); err != nil {
			t.Fatalf("FindEmailInvite(%s) = %v, want it to survive", id, err)
		}
	}
}

func TestDeleteEmailInvitesForNoMatchesIsNotError(t *testing.T) {
	st := newInviteStore()
	if err := st.DeleteEmailInvitesFor(context.Background(), "acme", "nobody@example.com"); err != nil {
		t.Fatalf("DeleteEmailInvitesFor with no matches: %v", err)
	}
}

// --- Link ---

func TestCreateAndFindLink(t *testing.T) {
	st := newInviteStore()
	ctx := context.Background()

	l := invite.Link{
		ID:          "link1",
		ContainerID: "acme",
		Code:        "code-abc",
		RoleKey:     "member",
		CreatedBy:   "alice",
		MaxUses:     5,
		CreatedAt:   time.Now(),
	}
	created, err := st.CreateLink(ctx, l)
	if err != nil {
		t.Fatalf("CreateLink: %v", err)
	}
	if created != l {
		t.Fatalf("CreateLink returned %+v, want %+v", created, l)
	}

	got, err := st.FindLink(ctx, "link1")
	if err != nil {
		t.Fatalf("FindLink: %v", err)
	}
	if got != l {
		t.Fatalf("FindLink = %+v, want %+v", got, l)
	}
}

func TestFindLinkNotFound(t *testing.T) {
	st := newInviteStore()
	_, err := st.FindLink(context.Background(), "nonesuch")
	if !errors.Is(err, invite.ErrLinkNotFound) {
		t.Fatalf("FindLink err = %v, want ErrLinkNotFound", err)
	}
}

func TestFindLinkByCode(t *testing.T) {
	st := newInviteStore()
	ctx := context.Background()
	if _, err := st.CreateLink(ctx, invite.Link{ID: "link1", ContainerID: "acme", Code: "code-abc"}); err != nil {
		t.Fatalf("CreateLink: %v", err)
	}
	if _, err := st.CreateLink(ctx, invite.Link{ID: "link2", ContainerID: "acme", Code: "code-other"}); err != nil {
		t.Fatalf("CreateLink 2: %v", err)
	}

	got, err := st.FindLinkByCode(ctx, "code-abc")
	if err != nil {
		t.Fatalf("FindLinkByCode: %v", err)
	}
	if got.ID != "link1" {
		t.Fatalf("FindLinkByCode returned id %q, want link1", got.ID)
	}
}

func TestFindLinkByCodeNotFound(t *testing.T) {
	st := newInviteStore()
	_, err := st.FindLinkByCode(context.Background(), "nonesuch")
	if !errors.Is(err, invite.ErrLinkNotFound) {
		t.Fatalf("FindLinkByCode err = %v, want ErrLinkNotFound", err)
	}
}

func TestListLinksScopesToContainer(t *testing.T) {
	st := newInviteStore()
	ctx := context.Background()
	for _, l := range []invite.Link{
		{ID: "link1", ContainerID: "acme"},
		{ID: "link2", ContainerID: "acme"},
		{ID: "link3", ContainerID: "globex"},
	} {
		if _, err := st.CreateLink(ctx, l); err != nil {
			t.Fatalf("create %s: %v", l.ID, err)
		}
	}
	got, err := st.ListLinks(ctx, "acme")
	if err != nil {
		t.Fatalf("ListLinks: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d links, want 2: %+v", len(got), got)
	}
}

func TestListLinksEmptyContainerIsEmptyNotError(t *testing.T) {
	st := newInviteStore()
	got, err := st.ListLinks(context.Background(), "nobody")
	if err != nil {
		t.Fatalf("ListLinks: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("got %d links for an unknown container, want 0", len(got))
	}
}

func TestRevokeLinkStampsRevokedAt(t *testing.T) {
	st := newInviteStore()
	ctx := context.Background()
	if _, err := st.CreateLink(ctx, invite.Link{ID: "link1", ContainerID: "acme"}); err != nil {
		t.Fatalf("CreateLink: %v", err)
	}
	at := time.Now()
	if err := st.RevokeLink(ctx, "link1", at); err != nil {
		t.Fatalf("RevokeLink: %v", err)
	}
	got, err := st.FindLink(ctx, "link1")
	if err != nil {
		t.Fatalf("FindLink: %v", err)
	}
	if got.RevokedAt == nil || !got.RevokedAt.Equal(at) {
		t.Fatalf("RevokedAt = %v, want %v", got.RevokedAt, at)
	}
}

func TestRevokeLinkIsIdempotent(t *testing.T) {
	st := newInviteStore()
	ctx := context.Background()
	if _, err := st.CreateLink(ctx, invite.Link{ID: "link1", ContainerID: "acme"}); err != nil {
		t.Fatalf("CreateLink: %v", err)
	}
	first := time.Now()
	if err := st.RevokeLink(ctx, "link1", first); err != nil {
		t.Fatalf("first RevokeLink: %v", err)
	}
	second := first.Add(time.Hour)
	if err := st.RevokeLink(ctx, "link1", second); err != nil {
		t.Fatalf("second RevokeLink: %v", err)
	}
	got, err := st.FindLink(ctx, "link1")
	if err != nil {
		t.Fatalf("FindLink: %v", err)
	}
	if got.RevokedAt == nil || !got.RevokedAt.Equal(second) {
		t.Fatalf("RevokedAt = %v, want the overwritten %v", got.RevokedAt, second)
	}
}

func TestRevokeLinkNotFound(t *testing.T) {
	st := newInviteStore()
	err := st.RevokeLink(context.Background(), "nonesuch", time.Now())
	if !errors.Is(err, invite.ErrLinkNotFound) {
		t.Fatalf("RevokeLink err = %v, want ErrLinkNotFound", err)
	}
}

// --- ConsumeLink ---

func TestConsumeLinkNotFound(t *testing.T) {
	st := newInviteStore()
	ok, err := st.ConsumeLink(context.Background(), "nonesuch", time.Now())
	if ok {
		t.Fatal("ConsumeLink ok = true for a nonexistent link")
	}
	if !errors.Is(err, invite.ErrLinkNotFound) {
		t.Fatalf("ConsumeLink err = %v, want ErrLinkNotFound", err)
	}
}

func TestConsumeLinkIncrementsUseCount(t *testing.T) {
	st := newInviteStore()
	ctx := context.Background()
	if _, err := st.CreateLink(ctx, invite.Link{ID: "link1", ContainerID: "acme", MaxUses: 5}); err != nil {
		t.Fatalf("CreateLink: %v", err)
	}
	ok, err := st.ConsumeLink(ctx, "link1", time.Now())
	if err != nil {
		t.Fatalf("ConsumeLink: %v", err)
	}
	if !ok {
		t.Fatal("ConsumeLink ok = false, want true")
	}
	got, err := st.FindLink(ctx, "link1")
	if err != nil {
		t.Fatalf("FindLink: %v", err)
	}
	if got.UseCount != 1 {
		t.Fatalf("UseCount = %d, want 1", got.UseCount)
	}
}

// Boundary: with MaxUses 2 and UseCount 1, consumption must still succeed
// (one use remains); at UseCount 2 it must not (the limit is reached).
func TestConsumeLinkMaxUsesBoundary(t *testing.T) {
	st := newInviteStore()
	ctx := context.Background()
	if _, err := st.CreateLink(ctx, invite.Link{ID: "link1", ContainerID: "acme", MaxUses: 2}); err != nil {
		t.Fatalf("CreateLink: %v", err)
	}

	ok, err := st.ConsumeLink(ctx, "link1", time.Now()) // UseCount 0 -> 1
	if err != nil || !ok {
		t.Fatalf("first ConsumeLink: ok=%v err=%v, want ok=true", ok, err)
	}
	ok, err = st.ConsumeLink(ctx, "link1", time.Now()) // UseCount 1 -> 2, must still succeed
	if err != nil || !ok {
		t.Fatalf("second ConsumeLink: ok=%v err=%v, want ok=true", ok, err)
	}
	ok, err = st.ConsumeLink(ctx, "link1", time.Now()) // UseCount == MaxUses, must fail
	if err != nil {
		t.Fatalf("third ConsumeLink err = %v, want nil", err)
	}
	if ok {
		t.Fatal("third ConsumeLink ok = true at UseCount == MaxUses, want false")
	}

	got, err := st.FindLink(ctx, "link1")
	if err != nil {
		t.Fatalf("FindLink: %v", err)
	}
	if got.UseCount != 2 {
		t.Fatalf("UseCount = %d, want 2 (the third call must not have incremented it)", got.UseCount)
	}
}

func TestConsumeLinkMaxUsesZeroIsUnlimited(t *testing.T) {
	st := newInviteStore()
	ctx := context.Background()
	if _, err := st.CreateLink(ctx, invite.Link{ID: "link1", ContainerID: "acme", MaxUses: 0}); err != nil {
		t.Fatalf("CreateLink: %v", err)
	}
	for i := 0; i < 10; i++ {
		ok, err := st.ConsumeLink(ctx, "link1", time.Now())
		if err != nil || !ok {
			t.Fatalf("ConsumeLink #%d: ok=%v err=%v, want ok=true", i, ok, err)
		}
	}
	got, err := st.FindLink(ctx, "link1")
	if err != nil {
		t.Fatalf("FindLink: %v", err)
	}
	if got.UseCount != 10 {
		t.Fatalf("UseCount = %d, want 10", got.UseCount)
	}
}

func TestConsumeLinkRevokedFails(t *testing.T) {
	st := newInviteStore()
	ctx := context.Background()
	if _, err := st.CreateLink(ctx, invite.Link{ID: "link1", ContainerID: "acme", MaxUses: 5}); err != nil {
		t.Fatalf("CreateLink: %v", err)
	}
	if err := st.RevokeLink(ctx, "link1", time.Now()); err != nil {
		t.Fatalf("RevokeLink: %v", err)
	}
	ok, err := st.ConsumeLink(ctx, "link1", time.Now())
	if err != nil {
		t.Fatalf("ConsumeLink err = %v, want nil", err)
	}
	if ok {
		t.Fatal("ConsumeLink ok = true for a revoked link")
	}
}

func TestConsumeLinkExpiredFails(t *testing.T) {
	st := newInviteStore()
	ctx := context.Background()
	past := time.Now().Add(-time.Hour)
	if _, err := st.CreateLink(ctx, invite.Link{ID: "link1", ContainerID: "acme", MaxUses: 5, ExpiresAt: &past}); err != nil {
		t.Fatalf("CreateLink: %v", err)
	}
	ok, err := st.ConsumeLink(ctx, "link1", time.Now())
	if err != nil {
		t.Fatalf("ConsumeLink err = %v, want nil", err)
	}
	if ok {
		t.Fatal("ConsumeLink ok = true for a link expired in the past")
	}
}

// TestConsumeLinkExpiresAtEqualToNowIsExpired pins ConsumeLink's boundary
// convention at the instant of expiry: now.Before(ExpiresAt) is false when
// the two are exactly equal, so a link is already refused at its own
// ExpiresAt, not one tick past it. This is the opposite convention from
// PurgeExpired, which purges only strictly before its cutoff (a row exactly
// at the cutoff survives) — see the doc comments on both methods for why
// that asymmetry is intentional. Nothing pinned the now == ExpiresAt case
// before this test, so a refactor could flip the comparison operator
// (>= vs >) without any other test noticing.
func TestConsumeLinkExpiresAtEqualToNowIsExpired(t *testing.T) {
	st := newInviteStore()
	ctx := context.Background()
	at := time.Now()
	if _, err := st.CreateLink(ctx, invite.Link{ID: "link1", ContainerID: "acme", MaxUses: 5, ExpiresAt: &at}); err != nil {
		t.Fatalf("CreateLink: %v", err)
	}
	ok, err := st.ConsumeLink(ctx, "link1", at)
	if err != nil {
		t.Fatalf("ConsumeLink err = %v, want nil", err)
	}
	if ok {
		t.Fatal("ConsumeLink ok = true when now == ExpiresAt exactly, want false: the expiry instant itself is already expired")
	}
}

func TestConsumeLinkUnexpiredSucceeds(t *testing.T) {
	st := newInviteStore()
	ctx := context.Background()
	future := time.Now().Add(time.Hour)
	if _, err := st.CreateLink(ctx, invite.Link{ID: "link1", ContainerID: "acme", MaxUses: 5, ExpiresAt: &future}); err != nil {
		t.Fatalf("CreateLink: %v", err)
	}
	ok, err := st.ConsumeLink(ctx, "link1", time.Now())
	if err != nil {
		t.Fatalf("ConsumeLink: %v", err)
	}
	if !ok {
		t.Fatal("ConsumeLink ok = false for a link that has not expired yet")
	}
}

func TestConsumeLinkNilExpiresAtNeverExpires(t *testing.T) {
	st := newInviteStore()
	ctx := context.Background()
	if _, err := st.CreateLink(ctx, invite.Link{ID: "link1", ContainerID: "acme", MaxUses: 5, ExpiresAt: nil}); err != nil {
		t.Fatalf("CreateLink: %v", err)
	}
	// far in the future: a nil ExpiresAt must never trip the expiry check.
	ok, err := st.ConsumeLink(ctx, "link1", time.Now().Add(100*365*24*time.Hour))
	if err != nil {
		t.Fatalf("ConsumeLink: %v", err)
	}
	if !ok {
		t.Fatal("ConsumeLink ok = false for a link with nil ExpiresAt")
	}
}

// TestConsumeLinkConcurrencyExactlyOneWinner pins the observable contract: N
// goroutines race to consume a MaxUses:1 link, and exactly one of them must
// observe ok=true, the rest ok=false with no error, and the link's final
// UseCount must be 1. Every N goroutine is started ahead of time and blocked
// on a channel so they all enter ConsumeLink at effectively the same instant
// once it closes, maximizing contention.
//
// What this test does NOT reliably do is catch a broken, split-lock
// (read-then-write) ConsumeLink — read UseCount under one lock acquisition,
// decide, then write under a second. Measured directly: with that exact
// mutation in place, this test passed 20 times out of 20, including at 2000
// goroutines with the same channel barrier. The window between releasing the
// read lock and reacquiring it for the write is sub-microsecond on ordinary
// hardware, and Go's sync.Mutex fast path lets the same goroutine barge
// straight back onto an uncontended mutex before another goroutine's
// independent Lock() call can win it — so the interleaving this test needs
// essentially never happens on its own. A green run here is evidence the
// happy path works; it is not proof a given implementation is atomic.
//
// Two consequences of that, worth knowing before you rely on this test:
//
//  1. It is a logical (check-then-act) race, not a memory race: every
//     individual map read and write in the broken variant is still
//     separately mutex-protected, so `go test -race` sees nothing
//     unsynchronized and will not flag it either. Run -race anyway — it
//     catches a different class of mutation, such as dropping the locking
//     altogether — just not this one.
//  2. To actually exercise the window by hand (e.g. when reviewing a change
//     to ConsumeLink), widen it: insert a temporary delay — a
//     time.Sleep(time.Millisecond) is enough — between the unlocked read and
//     the second Lock() in the implementation under test. Never ship that
//     delay. With it, this same test fails hard and every time: all 500
//     goroutines observed ok=true, not merely more than one.
//
// The real guarantee that ConsumeLink is atomic is the implementation itself
// holding one lock across the entire check-and-write (see its doc comment in
// invite.go), not this test. This test still earns its place: it pins the
// contract callers depend on and will catch a grossly broken implementation
// (no locking, or an inverted comparison) — it just cannot be trusted alone
// to catch every way atomicity could be lost.
func TestConsumeLinkConcurrencyExactlyOneWinner(t *testing.T) {
	st := newInviteStore()
	ctx := context.Background()
	if _, err := st.CreateLink(ctx, invite.Link{ID: "link1", ContainerID: "acme", MaxUses: 1}); err != nil {
		t.Fatalf("CreateLink: %v", err)
	}

	const n = 500
	start := make(chan struct{})
	var wg sync.WaitGroup
	var mu sync.Mutex
	successes := 0
	errs := 0

	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			<-start
			ok, err := st.ConsumeLink(ctx, "link1", time.Now())
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs++
				return
			}
			if ok {
				successes++
			}
		}()
	}
	close(start)
	wg.Wait()

	if errs != 0 {
		t.Fatalf("got %d unexpected errors from ConsumeLink", errs)
	}
	if successes != 1 {
		t.Fatalf("got %d successful ConsumeLink calls against a MaxUses:1 link, want exactly 1", successes)
	}

	got, err := st.FindLink(ctx, "link1")
	if err != nil {
		t.Fatalf("FindLink: %v", err)
	}
	if got.UseCount != 1 {
		t.Fatalf("final UseCount = %d, want 1", got.UseCount)
	}
}

// --- PurgeExpired ---

func TestPurgeExpiredRemovesExpiredInvitesAndLinks(t *testing.T) {
	st := newInviteStore()
	ctx := context.Background()
	now := time.Now()
	past := now.Add(-time.Hour)
	future := now.Add(time.Hour)

	// Invites: one expired, one not.
	if _, err := st.CreateEmailInvite(ctx, invite.EmailInvite{ID: "inv1", ContainerID: "acme", ExpiresAt: past}); err != nil {
		t.Fatalf("create inv1: %v", err)
	}
	if _, err := st.CreateEmailInvite(ctx, invite.EmailInvite{ID: "inv2", ContainerID: "acme", ExpiresAt: future}); err != nil {
		t.Fatalf("create inv2: %v", err)
	}
	// Links: one expired, one not-yet-expired, one that never expires.
	if _, err := st.CreateLink(ctx, invite.Link{ID: "link1", ContainerID: "acme", ExpiresAt: &past}); err != nil {
		t.Fatalf("create link1: %v", err)
	}
	if _, err := st.CreateLink(ctx, invite.Link{ID: "link2", ContainerID: "acme", ExpiresAt: &future}); err != nil {
		t.Fatalf("create link2: %v", err)
	}
	if _, err := st.CreateLink(ctx, invite.Link{ID: "link3", ContainerID: "acme", ExpiresAt: nil}); err != nil {
		t.Fatalf("create link3: %v", err)
	}

	n, err := st.PurgeExpired(ctx, now)
	if err != nil {
		t.Fatalf("PurgeExpired: %v", err)
	}
	if n != 2 {
		t.Fatalf("PurgeExpired removed %d rows, want 2 (inv1, link1)", n)
	}

	if _, err := st.FindEmailInvite(ctx, "inv1"); !errors.Is(err, invite.ErrInviteNotFound) {
		t.Fatalf("inv1 err = %v, want ErrInviteNotFound (should be purged)", err)
	}
	if _, err := st.FindEmailInvite(ctx, "inv2"); err != nil {
		t.Fatalf("inv2 err = %v, want it to survive", err)
	}
	if _, err := st.FindLink(ctx, "link1"); !errors.Is(err, invite.ErrLinkNotFound) {
		t.Fatalf("link1 err = %v, want ErrLinkNotFound (should be purged)", err)
	}
	if _, err := st.FindLink(ctx, "link2"); err != nil {
		t.Fatalf("link2 err = %v, want it to survive", err)
	}
	if _, err := st.FindLink(ctx, "link3"); err != nil {
		t.Fatalf("link3 (never expires) err = %v, want it to survive", err)
	}
}

func TestPurgeExpiredNothingToPurge(t *testing.T) {
	st := newInviteStore()
	ctx := context.Background()
	future := time.Now().Add(time.Hour)
	if _, err := st.CreateEmailInvite(ctx, invite.EmailInvite{ID: "inv1", ContainerID: "acme", ExpiresAt: future}); err != nil {
		t.Fatalf("create inv1: %v", err)
	}
	n, err := st.PurgeExpired(ctx, time.Now())
	if err != nil {
		t.Fatalf("PurgeExpired: %v", err)
	}
	if n != 0 {
		t.Fatalf("PurgeExpired removed %d rows, want 0", n)
	}
}
