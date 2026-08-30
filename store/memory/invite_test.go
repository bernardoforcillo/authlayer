package memory_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/bernardoforcillo/authlayer/invite"
	"github.com/bernardoforcillo/authlayer/invite/invitetest"
	"github.com/bernardoforcillo/authlayer/store/memory"
)

// Compile-time proof the memory store satisfies invite.Store.
var _ invite.Store = (*memory.InviteStore)(nil)

func newInviteStore() *memory.InviteStore {
	return memory.NewInviteStore()
}

// TestInviteStoreSatisfiesTheStoreContract runs the exported
// [github.com/bernardoforcillo/authlayer/invite/invitetest] suite against
// this package's store: every documented obligation of invite.Store,
// including the ConsumeLink single-winner race this file used to drive from
// a local copy of the driver, and the three uniqueness constraints this
// store did not used to enforce at all.
//
// That local copy is gone, along with the thirty-odd per-method cases beside
// it. The suite is the one implementation of the contract now, shared with
// store/drops' live-PostgreSQL lane, which previously had to reimplement the
// same properties because an unexported helper in a _test.go file is
// reachable from nowhere else. Nothing in this file duplicates a check the
// suite makes; what remains below is what the suite deliberately does NOT
// assert — which error this backend answers a rejected duplicate with.
//
// What the suite's ConsumeLink single-winner race does NOT reliably do is
// catch a broken, split-lock (read-then-write) ConsumeLink — read UseCount
// under one lock acquisition, decide, then write under a second. Measured
// directly against this store, with that exact mutation in place, the race
// this file used to carry passed 20 times out of 20, including at 2000
// goroutines behind the same channel barrier: the window between releasing
// the read lock and reacquiring it for the write is sub-microsecond, and Go's
// sync.Mutex fast path lets the same goroutine barge straight back onto an
// uncontended mutex before another goroutine's independent Lock() call can
// win it. A green run there is evidence the happy path works; it is not proof
// this implementation is atomic.
//
// Two consequences of that, worth knowing before relying on the suite alone:
//
//  1. It is a logical (check-then-act) race, not a memory race: every
//     individual map read and write in the broken variant is still
//     separately mutex-protected, so `go test -race` sees nothing
//     unsynchronized and will not flag it either. Run -race anyway — it
//     catches a different class of mutation, such as dropping the locking
//     altogether — just not this one.
//  2. To exercise the window by hand when reviewing a change to ConsumeLink,
//     widen it: insert a temporary time.Sleep(time.Millisecond) between the
//     unlocked read and the second Lock() in the implementation under test.
//     Never ship that delay. With it, the suite's race fails hard and every
//     time — all goroutines observe ok=true, not merely more than one.
//
// The suite does carry one ConsumeLink check that catches a split
// implementation deterministically, whatever the timing:
// ConsumeLink/ConcurrentCallersOnAnUnlimitedLinkAllSucceed. With no limit to
// enforce every caller wins on any implementation, but a read-then-write
// loses increments — N callers each read the same UseCount and each write
// read+1 — so the stored count comes back far below N. That is not a
// probabilistic detector; the increments are lost whenever two callers
// overlap at all. The real guarantee that ConsumeLink is atomic is still the
// implementation holding one lock across the entire check-and-write (see its
// doc comment in invite.go), plus invitetest's own negative controls, which
// prove each check fails a store built with exactly the defect it names.
func TestInviteStoreSatisfiesTheStoreContract(t *testing.T) {
	invitetest.RunStoreContract(t, func(*testing.T) invite.Store { return newInviteStore() })
}

// --- the three uniqueness constraints, and what this backend answers with ---
//
// invitetest's contract suite already asserts that CreateEmailInvite and
// CreateLink REFUSE a colliding token hash, a colliding (container, email)
// pair and a colliding code; it deliberately does not assert which error they
// refuse with, because invite.Store classifies no conflict-on-create at all.
// These tests pin this store's own answers — memory.ErrTokenHashTaken,
// memory.ErrInviteEmailTaken and memory.ErrLinkCodeTaken, each matchable with
// errors.Is — and pin that none of them is mistaken for one of
// authlayer/invite's own sentinels, or for each other, since they name
// different columns.

func inviteFixture(id, containerID, email, tokenHash string) invite.EmailInvite {
	now := time.Now().UTC()
	return invite.EmailInvite{
		ID:          id,
		ContainerID: containerID,
		Email:       email,
		RoleKey:     "member",
		TokenHash:   tokenHash,
		InvitedBy:   "alice",
		ExpiresAt:   now.Add(24 * time.Hour),
		CreatedAt:   now,
	}
}

// TestCreateEmailInviteDuplicateTokenHashReturnsErrTokenHashTaken pins both
// halves of the refusal: the sentinel is ErrTokenHashTaken, and the row that
// already held the hash is left exactly as it was. The colliding invite is in
// a different container and for a different address, so only the hash
// collides.
func TestCreateEmailInviteDuplicateTokenHashReturnsErrTokenHashTaken(t *testing.T) {
	st := newInviteStore()
	ctx := context.Background()
	first := inviteFixture("inv1", "acme", "bob@example.com", "shared-hash")
	if _, err := st.CreateEmailInvite(ctx, first); err != nil {
		t.Fatalf("CreateEmailInvite(first): %v", err)
	}

	clash := inviteFixture("inv2", "globex", "carol@example.com", "shared-hash")
	_, err := st.CreateEmailInvite(ctx, clash)
	if !errors.Is(err, memory.ErrTokenHashTaken) {
		t.Fatalf("CreateEmailInvite(duplicate token hash) err = %v, want ErrTokenHashTaken", err)
	}
	if errors.Is(err, memory.ErrInviteEmailTaken) {
		t.Fatalf("CreateEmailInvite(duplicate token hash) err = %v, want it NOT to be ErrInviteEmailTaken — the pairs differ, only the hash collides", err)
	}

	got, err := st.FindEmailInviteByTokenHash(ctx, "shared-hash")
	if err != nil {
		t.Fatalf("FindEmailInviteByTokenHash: %v", err)
	}
	if got != first {
		t.Fatalf("FindEmailInviteByTokenHash = %+v, want the original row %+v — the refused write must not have disturbed it", got, first)
	}
	if _, err := st.FindEmailInvite(ctx, clash.ID); !errors.Is(err, invite.ErrInviteNotFound) {
		t.Fatalf("FindEmailInvite(the refused row) err = %v, want ErrInviteNotFound", err)
	}
}

// TestCreateEmailInviteDuplicatePairReturnsErrInviteEmailTaken pins the
// (ContainerID, Email) refusal, with a distinct token hash so only the pair
// collides, and pins that it is distinguishable from ErrTokenHashTaken — the
// two name different columns and a caller inspecting them must not be told
// the wrong one.
func TestCreateEmailInviteDuplicatePairReturnsErrInviteEmailTaken(t *testing.T) {
	st := newInviteStore()
	ctx := context.Background()
	first := inviteFixture("inv1", "acme", "bob@example.com", "hash-1")
	if _, err := st.CreateEmailInvite(ctx, first); err != nil {
		t.Fatalf("CreateEmailInvite(first): %v", err)
	}

	_, err := st.CreateEmailInvite(ctx, inviteFixture("inv2", "acme", "bob@example.com", "hash-2"))
	if !errors.Is(err, memory.ErrInviteEmailTaken) {
		t.Fatalf("CreateEmailInvite(duplicate container+email) err = %v, want ErrInviteEmailTaken", err)
	}
	if errors.Is(err, memory.ErrTokenHashTaken) {
		t.Fatalf("CreateEmailInvite(duplicate container+email) err = %v, want it NOT to be ErrTokenHashTaken — the hashes differ, only the pair collides", err)
	}

	got, err := st.FindEmailInvite(ctx, first.ID)
	if err != nil {
		t.Fatalf("FindEmailInvite: %v", err)
	}
	if got != first {
		t.Fatalf("FindEmailInvite = %+v, want the original row %+v", got, first)
	}
}

// TestCreateEmailInviteSameAddressInAnotherContainerIsAllowed pins that the
// constraint is on the PAIR, not on the address: the same person invited to a
// second container is two legitimate rows. An over-broad check here would
// break the ordinary case — one person, several organizations — and this
// store's own error would be the thing breaking it.
func TestCreateEmailInviteSameAddressInAnotherContainerIsAllowed(t *testing.T) {
	st := newInviteStore()
	ctx := context.Background()
	if _, err := st.CreateEmailInvite(ctx, inviteFixture("inv1", "acme", "bob@example.com", "hash-1")); err != nil {
		t.Fatalf("CreateEmailInvite(acme): %v", err)
	}
	if _, err := st.CreateEmailInvite(ctx, inviteFixture("inv2", "globex", "bob@example.com", "hash-2")); err != nil {
		t.Fatalf("CreateEmailInvite(globex, same address) = %v, want nil — the uniqueness obligation is on (ContainerID, Email)", err)
	}
}

// TestCreateLinkDuplicateCodeReturnsErrLinkCodeTaken pins the code refusal
// and that the original link still resolves by that code. The colliding link
// is in a different container, so only the code collides.
func TestCreateLinkDuplicateCodeReturnsErrLinkCodeTaken(t *testing.T) {
	st := newInviteStore()
	ctx := context.Background()
	first := invite.Link{ID: "link1", ContainerID: "acme", Code: "shared-code", RoleKey: "member", CreatedBy: "alice"}
	if _, err := st.CreateLink(ctx, first); err != nil {
		t.Fatalf("CreateLink(first): %v", err)
	}

	_, err := st.CreateLink(ctx, invite.Link{ID: "link2", ContainerID: "globex", Code: "shared-code", RoleKey: "admin", CreatedBy: "carol"})
	if !errors.Is(err, memory.ErrLinkCodeTaken) {
		t.Fatalf("CreateLink(duplicate code) err = %v, want ErrLinkCodeTaken", err)
	}
	if errors.Is(err, invite.ErrLinkNotFound) {
		t.Fatalf("CreateLink(duplicate code) err = %v, want it NOT to be invite.ErrLinkNotFound", err)
	}

	got, err := st.FindLinkByCode(ctx, "shared-code")
	if err != nil {
		t.Fatalf("FindLinkByCode: %v", err)
	}
	if got != first {
		t.Fatalf("FindLinkByCode = %+v, want the original row %+v", got, first)
	}
	if _, err := st.FindLink(ctx, "link2"); !errors.Is(err, invite.ErrLinkNotFound) {
		t.Fatalf("FindLink(the refused row) err = %v, want ErrLinkNotFound", err)
	}
}
