package memory_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bernardoforcillo/authlayer/auth"
	"github.com/bernardoforcillo/authlayer/store/memory"
)

// Compile-time proof the memory store satisfies auth.IdentityStore.
var _ auth.IdentityStore = (*memory.IdentityStore)(nil)

func mustCreate(t *testing.T, s *memory.IdentityStore, i auth.Identity) auth.Identity {
	t.Helper()
	got, err := s.CreateIdentity(context.Background(), i)
	if err != nil {
		t.Fatalf("CreateIdentity(%q): %v", i.ID, err)
	}
	return got
}

// --- CreateIdentity ---

// TestCreateIdentityStoresAndNormalizesTheEmail pins the one field this
// store rewrites on the way in. auth.Identity.Email's doc promises the
// address is normalized on write by CreateIdentity, so the promise has to be
// kept here rather than left to the caller — every other email path in this
// package normalizes, and an un-normalized identity row would compare
// unequal to the very user row it describes.
func TestCreateIdentityStoresAndNormalizesTheEmail(t *testing.T) {
	s := memory.NewIdentityStore()
	ctx := context.Background()

	got := mustCreate(t, s, auth.Identity{
		ID: "i1", UserID: "u1", Provider: "google", Subject: "sub-1",
		Email: "  Bob@Example.COM ",
	})
	if got.Email != "bob@example.com" {
		t.Fatalf("CreateIdentity returned Email = %q, want the normalized address", got.Email)
	}

	found, err := s.FindIdentityByProviderSubject(ctx, "google", "sub-1")
	if err != nil {
		t.Fatalf("FindIdentityByProviderSubject: %v", err)
	}
	if found.Email != "bob@example.com" {
		t.Fatalf("stored Email = %q, want the normalized address — the return value was normalized but the row was not", found.Email)
	}
}

// TestCreateIdentityRejectsADuplicateID pins the id-collision contract every
// Create* method in this package carries: a second row under an id that is
// already taken is auth.ErrIDTaken, never a silent overwrite of the row that
// is already there.
func TestCreateIdentityRejectsADuplicateID(t *testing.T) {
	s := memory.NewIdentityStore()
	ctx := context.Background()

	mustCreate(t, s, auth.Identity{ID: "i1", UserID: "u1", Provider: "google", Subject: "sub-1"})

	_, err := s.CreateIdentity(ctx, auth.Identity{ID: "i1", UserID: "u2", Provider: "github", Subject: "sub-2"})
	if !errors.Is(err, auth.ErrIDTaken) {
		t.Fatalf("second CreateIdentity err = %v, want ErrIDTaken", err)
	}

	// The original row must be exactly as it was: same user, same provider.
	got, err := s.FindIdentityByProviderSubject(ctx, "google", "sub-1")
	if err != nil {
		t.Fatalf("FindIdentityByProviderSubject after the refused write: %v", err)
	}
	if got.UserID != "u1" {
		t.Fatalf("row was overwritten: UserID = %q, want u1", got.UserID)
	}
}

// TestCreateIdentityRejectsADuplicateProviderSubject is the single most
// important property of this store. auth.Identity.Subject states it as a
// MUST on the port: one external account must never map to two local users.
// Without it, two rows can name the same (provider, subject) against
// DIFFERENT users, and a sign-in resolving that subject lands on whichever
// row the backend happens to return first — one Google account silently able
// to sign in as either of two people, decided by map iteration order.
func TestCreateIdentityRejectsADuplicateProviderSubject(t *testing.T) {
	s := memory.NewIdentityStore()
	ctx := context.Background()

	base := auth.Identity{ID: "i1", UserID: "u1", Provider: "google", Subject: "sub-1", Email: "a@example.com"}
	if _, err := s.CreateIdentity(ctx, base); err != nil {
		t.Fatalf("first CreateIdentity: %v", err)
	}

	other := auth.Identity{ID: "i2", UserID: "u2", Provider: "google", Subject: "sub-1", Email: "b@example.com"}
	if _, err := s.CreateIdentity(ctx, other); !errors.Is(err, auth.ErrIdentityLinked) {
		t.Fatalf("second CreateIdentity err = %v, want ErrIdentityLinked — one provider subject must never map to two users", err)
	}

	// And the refusal must be a refusal, not a partial write: the pair still
	// resolves to the original user.
	got, err := s.FindIdentityByProviderSubject(ctx, "google", "sub-1")
	if err != nil {
		t.Fatalf("FindIdentityByProviderSubject after the refused link: %v", err)
	}
	if got.UserID != "u1" {
		t.Fatalf("(google, sub-1) now resolves to %q, want u1 — the refused write re-pointed the link", got.UserID)
	}
	left, err := s.ListIdentitiesByUser(ctx, "u2")
	if err != nil {
		t.Fatalf("ListIdentitiesByUser(u2): %v", err)
	}
	if len(left) != 0 {
		t.Fatalf("u2 has %d identities, want 0 — the refused link was written anyway", len(left))
	}
}

// TestCreateIdentityAllowsEveryNonDuplicatePair is the positive control for
// the check above: uniqueness is on the PAIR, so the same subject at a
// different provider and a different subject at the same provider are both
// ordinary, allowed rows. A store that keyed on the subject alone — or on
// the provider alone — would pass the duplicate test above and fail here.
func TestCreateIdentityAllowsEveryNonDuplicatePair(t *testing.T) {
	s := memory.NewIdentityStore()

	mustCreate(t, s, auth.Identity{ID: "i1", UserID: "u1", Provider: "google", Subject: "sub-1"})
	// Same subject string, different provider.
	mustCreate(t, s, auth.Identity{ID: "i2", UserID: "u1", Provider: "github", Subject: "sub-1"})
	// Same provider, different subject, different user.
	mustCreate(t, s, auth.Identity{ID: "i3", UserID: "u2", Provider: "google", Subject: "sub-2"})
	// Nothing in the data model forbids a second identity at the same
	// provider for the same user — see DeleteIdentityIfNotLast's doc, which
	// is written around exactly that case.
	mustCreate(t, s, auth.Identity{ID: "i4", UserID: "u1", Provider: "google", Subject: "sub-3"})
}

// TestCreateIdentityComparesProviderAndSubjectByteForByte pins
// auth.Identity.Provider's and Subject's explicit "matched byte-for-byte;
// neither is normalized or case-folded" contract. Email is the one field
// this store folds; a store that also folded the provider or the subject
// would make two genuinely distinct external accounts collide.
func TestCreateIdentityComparesProviderAndSubjectByteForByte(t *testing.T) {
	s := memory.NewIdentityStore()
	ctx := context.Background()

	mustCreate(t, s, auth.Identity{ID: "i1", UserID: "u1", Provider: "google", Subject: "sub-1"})
	mustCreate(t, s, auth.Identity{ID: "i2", UserID: "u2", Provider: "Google", Subject: "sub-1"})
	mustCreate(t, s, auth.Identity{ID: "i3", UserID: "u3", Provider: "google", Subject: "SUB-1"})

	got, err := s.FindIdentityByProviderSubject(ctx, "google", "sub-1")
	if err != nil {
		t.Fatalf("FindIdentityByProviderSubject: %v", err)
	}
	if got.ID != "i1" {
		t.Fatalf("(google, sub-1) resolved to %q, want i1 — the lookup case-folded", got.ID)
	}
}

// --- FindIdentityByProviderSubject ---

// TestFindIdentityByProviderSubjectReportsAMiss pins the sentinel. A miss is
// the ordinary first step of the sign-in ladder, not an exceptional
// condition, so it must be a typed error the caller can branch on.
func TestFindIdentityByProviderSubjectReportsAMiss(t *testing.T) {
	s := memory.NewIdentityStore()
	ctx := context.Background()

	mustCreate(t, s, auth.Identity{ID: "i1", UserID: "u1", Provider: "google", Subject: "sub-1"})

	if _, err := s.FindIdentityByProviderSubject(ctx, "google", "nobody"); !errors.Is(err, auth.ErrIdentityNotFound) {
		t.Fatalf("unknown subject err = %v, want ErrIdentityNotFound", err)
	}
	if _, err := s.FindIdentityByProviderSubject(ctx, "github", "sub-1"); !errors.Is(err, auth.ErrIdentityNotFound) {
		t.Fatalf("known subject at another provider err = %v, want ErrIdentityNotFound", err)
	}
}

// --- ListIdentitiesByUser ---

// TestListIdentitiesByUserReturnsOnlyThatUsersRows pins the scoping half of
// the port contract: "every identity belonging to userID, and only that
// user's — never another's". A list that leaked another user's rows would
// hand the service layer a set it would then make an unlink decision from.
func TestListIdentitiesByUserReturnsOnlyThatUsersRows(t *testing.T) {
	s := memory.NewIdentityStore()
	ctx := context.Background()

	mustCreate(t, s, auth.Identity{ID: "i1", UserID: "u1", Provider: "google", Subject: "g1"})
	mustCreate(t, s, auth.Identity{ID: "i2", UserID: "u1", Provider: "github", Subject: "h1"})
	mustCreate(t, s, auth.Identity{ID: "i3", UserID: "u2", Provider: "google", Subject: "g2"})

	got, err := s.ListIdentitiesByUser(ctx, "u1")
	if err != nil {
		t.Fatalf("ListIdentitiesByUser: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d identities for u1, want 2", len(got))
	}
	for _, id := range got {
		if id.UserID != "u1" {
			t.Fatalf("ListIdentitiesByUser(u1) returned a row for %q", id.UserID)
		}
	}
}

// TestListIdentitiesByUserIsNotAnErrorWhenEmpty pins that "no identities" is
// an ordinary answer. It deliberately asserts only len() == 0, never
// got == nil: the port states the empty-vs-nil distinction is unspecified
// and that callers MUST use len(), so a test that pinned one of them here
// would be asserting a property the port explicitly refuses to promise, and
// would break a compliant backend that chose the other.
func TestListIdentitiesByUserIsNotAnErrorWhenEmpty(t *testing.T) {
	s := memory.NewIdentityStore()

	got, err := s.ListIdentitiesByUser(context.Background(), "nobody")
	if err != nil {
		t.Fatalf("ListIdentitiesByUser(unknown user) err = %v, want nil", err)
	}
	if len(got) != 0 {
		t.Fatalf("got %d identities for an unknown user, want 0", len(got))
	}
}

// --- TouchIdentity ---

// TestTouchIdentityStampsLastUsedAt pins the port's only mutation of an
// existing row.
func TestTouchIdentityStampsLastUsedAt(t *testing.T) {
	s := memory.NewIdentityStore()
	ctx := context.Background()

	created := mustCreate(t, s, auth.Identity{ID: "i1", UserID: "u1", Provider: "google", Subject: "g1"})
	if created.LastUsedAt != nil {
		t.Fatalf("a freshly created identity has LastUsedAt = %v, want nil — the link exists but has never been used", created.LastUsedAt)
	}

	now := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	if err := s.TouchIdentity(ctx, "i1", now); err != nil {
		t.Fatalf("TouchIdentity: %v", err)
	}

	got, err := s.FindIdentityByProviderSubject(ctx, "google", "g1")
	if err != nil {
		t.Fatalf("FindIdentityByProviderSubject: %v", err)
	}
	if got.LastUsedAt == nil || !got.LastUsedAt.Equal(now) {
		t.Fatalf("LastUsedAt = %v, want %v", got.LastUsedAt, now)
	}
}

// TestTouchIdentityReportsAMiss pins the sentinel for an id that names no
// row — a fail-closed signal the service layer propagates rather than
// swallows.
func TestTouchIdentityReportsAMiss(t *testing.T) {
	s := memory.NewIdentityStore()

	err := s.TouchIdentity(context.Background(), "nope", time.Now())
	if !errors.Is(err, auth.ErrIdentityNotFound) {
		t.Fatalf("TouchIdentity(unknown id) err = %v, want ErrIdentityNotFound", err)
	}
}

// --- DeleteIdentity ---

// TestDeleteIdentityRemovesExactlyOneRow pins the scope of the by-id delete:
// the row named, and nothing that merely resembles it — not the same user's
// other identity, not another user's row at the same provider. It is the
// method the service uses to RETRACT a row it wrote itself, so removing one
// row too many would delete a link somebody is relying on.
func TestDeleteIdentityRemovesExactlyOneRow(t *testing.T) {
	s := memory.NewIdentityStore()
	ctx := context.Background()

	mustCreate(t, s, auth.Identity{ID: "i1", UserID: "u1", Provider: "google", Subject: "g1"})
	mustCreate(t, s, auth.Identity{ID: "i2", UserID: "u1", Provider: "google", Subject: "g2"})
	mustCreate(t, s, auth.Identity{ID: "i3", UserID: "u2", Provider: "google", Subject: "g3"})

	if err := s.DeleteIdentity(ctx, "i1"); err != nil {
		t.Fatalf("DeleteIdentity(i1): %v", err)
	}
	if _, err := s.FindIdentityByProviderSubject(ctx, "google", "g1"); !errors.Is(err, auth.ErrIdentityNotFound) {
		t.Fatalf("the named row survived: err = %v, want ErrIdentityNotFound", err)
	}

	u1, err := s.ListIdentitiesByUser(ctx, "u1")
	if err != nil || len(u1) != 1 || u1[0].ID != "i2" {
		t.Fatalf("u1 rows = %+v (err %v), want only i2 — a by-id delete must not take the user's siblings", u1, err)
	}
	u2, err := s.ListIdentitiesByUser(ctx, "u2")
	if err != nil || len(u2) != 1 {
		t.Fatalf("u2 rows = %+v (err %v), want another user's row untouched", u2, err)
	}
}

// TestDeleteIdentityReportsAMiss pins that an unknown id is
// ErrIdentityNotFound rather than the silent success a delete-where-matching
// gives. SignInWith's compensating delete reads that answer: "the row I just
// wrote is already gone" is a different fact from "I removed it".
func TestDeleteIdentityReportsAMiss(t *testing.T) {
	s := memory.NewIdentityStore()

	if err := s.DeleteIdentity(context.Background(), "nope"); !errors.Is(err, auth.ErrIdentityNotFound) {
		t.Fatalf("DeleteIdentity(unknown id) err = %v, want ErrIdentityNotFound", err)
	}
}

// TestDeleteIdentityMakesNoReachabilityCheck pins the difference from
// DeleteIdentityIfNotLast, which is the whole reason both exist. This method
// removes a password-less account's only identity without complaint; the port
// doc says so, and an application that reached for it on a connected-accounts
// screen would produce exactly the lockout the other method refuses.
func TestDeleteIdentityMakesNoReachabilityCheck(t *testing.T) {
	s := memory.NewIdentityStore()
	ctx := context.Background()

	mustCreate(t, s, auth.Identity{ID: "i1", UserID: "u1", Provider: "google", Subject: "g1"})

	if err := s.DeleteIdentityIfNotLast(ctx, "u1", "google", false); !errors.Is(err, auth.ErrLastCredential) {
		t.Fatalf("control: DeleteIdentityIfNotLast err = %v, want ErrLastCredential", err)
	}
	if err := s.DeleteIdentity(ctx, "i1"); err != nil {
		t.Fatalf("DeleteIdentity must not apply the reachability check: %v", err)
	}
	rows, err := s.ListIdentitiesByUser(ctx, "u1")
	if err != nil || len(rows) != 0 {
		t.Fatalf("rows = %+v (err %v), want the row gone", rows, err)
	}
}

// --- DeleteIdentityIfNotLast ---

// TestDeleteIdentityIfNotLastReportsAMiss pins that "this user has no
// identity for that provider" is ErrIdentityNotFound and not the silent
// success a delete-where-matching would give.
func TestDeleteIdentityIfNotLastReportsAMiss(t *testing.T) {
	s := memory.NewIdentityStore()
	ctx := context.Background()

	mustCreate(t, s, auth.Identity{ID: "i1", UserID: "u1", Provider: "google", Subject: "g1"})
	// Another user's row at that provider must not satisfy the lookup.
	mustCreate(t, s, auth.Identity{ID: "i2", UserID: "u2", Provider: "github", Subject: "h2"})

	if err := s.DeleteIdentityIfNotLast(ctx, "u1", "github", true); !errors.Is(err, auth.ErrIdentityNotFound) {
		t.Fatalf("unlinking a provider the user has no identity for: err = %v, want ErrIdentityNotFound", err)
	}
	if err := s.DeleteIdentityIfNotLast(ctx, "nobody", "google", true); !errors.Is(err, auth.ErrIdentityNotFound) {
		t.Fatalf("unlinking for an unknown user: err = %v, want ErrIdentityNotFound", err)
	}
}

// TestDeleteIdentityIfNotLastRefusesTheLastWayIn is the edge spec §8.3
// names: no password hash and no other identity means removing this one
// leaves an account nothing in this package can ever sign in again. The
// refusal must also leave the row in place — a delete that reported
// ErrLastCredential *after* removing the row would be the lockout it claims
// to prevent, wearing an error message.
func TestDeleteIdentityIfNotLastRefusesTheLastWayIn(t *testing.T) {
	s := memory.NewIdentityStore()
	ctx := context.Background()

	mustCreate(t, s, auth.Identity{ID: "i1", UserID: "u1", Provider: "google", Subject: "g1"})

	if err := s.DeleteIdentityIfNotLast(ctx, "u1", "google", false); !errors.Is(err, auth.ErrLastCredential) {
		t.Fatalf("unlinking the only identity of a password-less user: err = %v, want ErrLastCredential", err)
	}

	left, err := s.ListIdentitiesByUser(ctx, "u1")
	if err != nil {
		t.Fatalf("ListIdentitiesByUser: %v", err)
	}
	if len(left) != 1 {
		t.Fatalf("%d identities left, want 1 — the refusal deleted the row anyway, which is the lockout it exists to prevent", len(left))
	}
}

// TestDeleteIdentityIfNotLastAllowsTheLastIdentityWhenTheUserHasAPassword is
// the userHasPassword half of the predicate. The guard is on whether the
// account stays REACHABLE, not on whether an identity survives, so a user
// with a password may unlink their only identity.
func TestDeleteIdentityIfNotLastAllowsTheLastIdentityWhenTheUserHasAPassword(t *testing.T) {
	s := memory.NewIdentityStore()
	ctx := context.Background()

	mustCreate(t, s, auth.Identity{ID: "i1", UserID: "u1", Provider: "google", Subject: "g1"})

	if err := s.DeleteIdentityIfNotLast(ctx, "u1", "google", true); err != nil {
		t.Fatalf("unlinking the only identity of a user WITH a password: err = %v, want nil", err)
	}
	left, err := s.ListIdentitiesByUser(ctx, "u1")
	if err != nil {
		t.Fatalf("ListIdentitiesByUser: %v", err)
	}
	if len(left) != 0 {
		t.Fatalf("%d identities left, want 0", len(left))
	}
}

// TestDeleteIdentityIfNotLastAllowsOneOfTwo is the other half: a sibling
// identity keeps the account reachable, so the unlink proceeds even with no
// password at all. It also pins the scope of the delete — only the named
// provider's row goes.
func TestDeleteIdentityIfNotLastAllowsOneOfTwo(t *testing.T) {
	s := memory.NewIdentityStore()
	ctx := context.Background()

	mustCreate(t, s, auth.Identity{ID: "i1", UserID: "u1", Provider: "google", Subject: "g1"})
	mustCreate(t, s, auth.Identity{ID: "i2", UserID: "u1", Provider: "github", Subject: "h1"})

	if err := s.DeleteIdentityIfNotLast(ctx, "u1", "google", false); err != nil {
		t.Fatalf("unlinking one of two identities: err = %v, want nil", err)
	}

	left, err := s.ListIdentitiesByUser(ctx, "u1")
	if err != nil {
		t.Fatalf("ListIdentitiesByUser: %v", err)
	}
	if len(left) != 1 || left[0].ID != "i2" {
		t.Fatalf("left = %v, want exactly the github row i2", left)
	}
}

// TestDeleteIdentityIfNotLastRemovesEveryRowForTheProvider pins the two
// halves of the port's "(userID, provider)" wording that a row-at-a-time
// implementation would get wrong. Nothing forbids a user holding two
// identities at the same provider, so:
//
//   - the delete removes BOTH of them — "unlink this provider from this
//     account", not "unlink an arbitrary one of these rows"; and
//   - the reachability test is on what would REMAIN after that, not on the
//     total row count. A password-less user whose only two identities are
//     both at one provider is left with nothing, so the unlink is refused
//     even though the store holds two rows for them.
func TestDeleteIdentityIfNotLastRemovesEveryRowForTheProvider(t *testing.T) {
	ctx := context.Background()

	// Refused: both rows are at the named provider, so nothing would remain.
	refused := memory.NewIdentityStore()
	mustCreate(t, refused, auth.Identity{ID: "i1", UserID: "u1", Provider: "google", Subject: "g1"})
	mustCreate(t, refused, auth.Identity{ID: "i2", UserID: "u1", Provider: "google", Subject: "g2"})

	if err := refused.DeleteIdentityIfNotLast(ctx, "u1", "google", false); !errors.Is(err, auth.ErrLastCredential) {
		t.Fatalf("unlinking a provider holding BOTH of a password-less user's identities: err = %v, want ErrLastCredential — the guard counted rows instead of survivors", err)
	}
	if left, _ := refused.ListIdentitiesByUser(ctx, "u1"); len(left) != 2 {
		t.Fatalf("%d identities left after the refusal, want 2", len(left))
	}

	// Allowed, and both rows go: a third identity elsewhere survives.
	allowed := memory.NewIdentityStore()
	mustCreate(t, allowed, auth.Identity{ID: "i1", UserID: "u1", Provider: "google", Subject: "g1"})
	mustCreate(t, allowed, auth.Identity{ID: "i2", UserID: "u1", Provider: "google", Subject: "g2"})
	mustCreate(t, allowed, auth.Identity{ID: "i3", UserID: "u1", Provider: "github", Subject: "h1"})

	if err := allowed.DeleteIdentityIfNotLast(ctx, "u1", "google", false); err != nil {
		t.Fatalf("unlinking a provider with a sibling elsewhere: err = %v, want nil", err)
	}
	left, err := allowed.ListIdentitiesByUser(ctx, "u1")
	if err != nil {
		t.Fatalf("ListIdentitiesByUser: %v", err)
	}
	if len(left) != 1 || left[0].ID != "i3" {
		t.Fatalf("left = %v, want only the github row i3 — one of the two google rows survived", left)
	}
}

// TestDeleteIdentityIfNotLastLeavesOtherUsersAlone pins that the delete is
// scoped by user as well as by provider. A delete keyed on the provider
// alone would pass every test above and quietly unlink strangers.
func TestDeleteIdentityIfNotLastLeavesOtherUsersAlone(t *testing.T) {
	s := memory.NewIdentityStore()
	ctx := context.Background()

	mustCreate(t, s, auth.Identity{ID: "i1", UserID: "u1", Provider: "google", Subject: "g1"})
	mustCreate(t, s, auth.Identity{ID: "i2", UserID: "u2", Provider: "google", Subject: "g2"})

	if err := s.DeleteIdentityIfNotLast(ctx, "u1", "google", true); err != nil {
		t.Fatalf("DeleteIdentityIfNotLast: %v", err)
	}

	left, err := s.ListIdentitiesByUser(ctx, "u2")
	if err != nil {
		t.Fatalf("ListIdentitiesByUser(u2): %v", err)
	}
	if len(left) != 1 || left[0].ID != "i2" {
		t.Fatalf("u2's identities = %v, want the untouched i2", left)
	}
}

// TestDeleteIdentityIfNotLastIsAtomicUnderConcurrency is the reason
// DeleteIdentityIfNotLast exists as a store method at all instead of a
// list-decide-delete sequence in the service layer.
//
// Two identities, no password. Two concurrent unlinks, one per provider.
// Exactly one must succeed; the other must get ErrLastCredential. If the
// check and the delete are not one step, BOTH callers read the identity
// list, BOTH see a sibling that will keep the account reachable, and BOTH
// delete — leaving an account with no identity and no password, which
// nothing in this package can ever sign in again. Both requests return
// success, so the lockout is permanent AND silent. This project has shipped
// that exact read-then-write shape four times (MarkRotated, invite's
// ConsumeLink, CreateSuccessorSession, DeleteSessionsByFamily) and closed it
// four times.
//
// Like TestMarkRotatedConcurrencyExactlyOneWinner, this is a logical
// (check-then-act) race, not a memory race: in the broken shape every
// individual map access is still separately mutex-protected, so -race sees
// nothing unsynchronized here. Run -race anyway — it catches the coarser
// mutation of dropping the locking altogether. The deterministic proof that
// the assertion below really rejects the split-lock shape is
// TestSplitLockIdentityStoreLocksTheUserOut, which drives a deliberately
// broken double through the exact interleaving with no timing dependence.
func TestDeleteIdentityIfNotLastIsAtomicUnderConcurrency(t *testing.T) {
	for round := range 200 {
		s := memory.NewIdentityStore()
		ctx := context.Background()
		mustCreate(t, s, auth.Identity{ID: "i1", UserID: "u1", Provider: "google", Subject: "g1"})
		mustCreate(t, s, auth.Identity{ID: "i2", UserID: "u1", Provider: "github", Subject: "h1"})

		var wg sync.WaitGroup
		errs := make([]error, 2)
		start := make(chan struct{})
		for i, p := range []string{"google", "github"} {
			wg.Add(1)
			go func(i int, p string) {
				defer wg.Done()
				<-start
				errs[i] = s.DeleteIdentityIfNotLast(ctx, "u1", p, false)
			}(i, p)
		}
		close(start)
		wg.Wait()

		left, err := s.ListIdentitiesByUser(ctx, "u1")
		if err != nil {
			t.Fatalf("round %d: ListIdentitiesByUser: %v", round, err)
		}
		if len(left) != 1 {
			t.Fatalf("round %d: %d identities left, want 1 — the user was locked out (errs: %v)", round, len(left), errs)
		}

		// The survivor count above is the property that matters, but the
		// outcome is fully determined either way: whichever caller reaches
		// the lock first deletes and returns nil, and the other then finds
		// nothing would remain and returns ErrLastCredential.
		nils, lasts := 0, 0
		for _, err := range errs {
			switch {
			case err == nil:
				nils++
			case errors.Is(err, auth.ErrLastCredential):
				lasts++
			default:
				t.Fatalf("round %d: unexpected error %v", round, err)
			}
		}
		if nils != 1 || lasts != 1 {
			t.Fatalf("round %d: %d successes and %d ErrLastCredential, want exactly one of each (errs: %v)", round, nils, lasts, errs)
		}
	}
}

// splitLockIdentityStore is a small, test-only double that deliberately
// implements DeleteIdentityIfNotLast with the split-lock shape the port's
// "It MUST be atomic" section forbids: read the user's rows and decide under
// mu, unlock, then take a SECOND acquisition to delete. It exists to make
// TestDeleteIdentityIfNotLastIsAtomicUnderConcurrency's assertion provably a
// real detector rather than a tautology — the same role splitLockStore plays
// for MarkRotated in auth_test.go, and built the same way, because the
// hand-run mutation experiment recorded there showed that a naive window in
// an in-process mutex is caught only 1-4% of the time. A committed test may
// not rest on odds like that.
//
// Only the two methods the control needs are implemented; it is never
// asserted to satisfy auth.IdentityStore.
type splitLockIdentityStore struct {
	mu         sync.Mutex
	identities map[string]auth.Identity

	// parked is CompareAndSwap'd by whichever caller reaches the gap first,
	// so exactly one caller ever blocks on gate — and the loser is not
	// blocked at the point of election, which a sync.Once would do,
	// deadlocking the control instead of letting the second caller through.
	// See splitLockStore.parked in auth_test.go for the full reasoning.
	parked   atomic.Bool
	parkedCh chan struct{} // closed once the first caller has parked
	gate     chan struct{} // closed by the test to release the parked caller
}

func newSplitLockIdentityStore() *splitLockIdentityStore {
	return &splitLockIdentityStore{
		identities: map[string]auth.Identity{},
		parkedCh:   make(chan struct{}),
		gate:       make(chan struct{}),
	}
}

func (s *splitLockIdentityStore) create(i auth.Identity) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.identities[i.ID] = i
}

func (s *splitLockIdentityStore) list(userID string) []auth.Identity {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]auth.Identity, 0)
	for _, i := range s.identities {
		if i.UserID == userID {
			out = append(out, i)
		}
	}
	return out
}

// DeleteIdentityIfNotLast is the deliberately broken shape: the scan and the
// reachability decision happen under mu, mu is released, and the delete
// takes a fresh acquisition. Each half is individually correct and
// individually locked; only their SEPARATION is the bug.
func (s *splitLockIdentityStore) DeleteIdentityIfNotLast(userID, provider string, userHasPassword bool) error {
	s.mu.Lock()
	var doomed []string
	survivors := 0
	for id, i := range s.identities {
		switch {
		case i.UserID != userID:
		case i.Provider == provider:
			doomed = append(doomed, id)
		default:
			survivors++
		}
	}
	s.mu.Unlock()

	if len(doomed) == 0 {
		return auth.ErrIdentityNotFound
	}
	if survivors == 0 && !userHasPassword {
		return auth.ErrLastCredential
	}

	if s.parked.CompareAndSwap(false, true) {
		close(s.parkedCh)
		<-s.gate
	}

	s.mu.Lock()
	for _, id := range doomed {
		delete(s.identities, id)
	}
	s.mu.Unlock()
	return nil
}

// TestSplitLockIdentityStoreLocksTheUserOut is the deterministic negative
// control for TestDeleteIdentityIfNotLastIsAtomicUnderConcurrency: it proves
// that test's "exactly one identity left" assertion actually rejects the
// split-lock shape, with no sleep and no timing dependence anywhere.
//
// The interleaving is forced rather than raced. Caller A unlinks "google",
// sees the github sibling, decides the account stays reachable, and parks
// before its delete. Caller B then runs to completion: it still sees BOTH
// rows, because A has not deleted yet, so it also sees a sibling, also
// decides the account stays reachable, and deletes github. A is released and
// deletes google. Two successes, zero identities, no password — the
// permanent silent lockout, reproduced on demand.
//
// It does not drive the real memory.IdentityStore: nothing outside a method
// can park a goroutine inside another method's own Unlock/Lock gap, which is
// exactly why the correct implementation cannot be forced to fail and why
// this control uses a double instead. See
// TestMarkRotatedConcurrencyExactlyOneWinner's doc for the longer version of
// that argument.
func TestSplitLockIdentityStoreLocksTheUserOut(t *testing.T) {
	s := newSplitLockIdentityStore()
	s.create(auth.Identity{ID: "i1", UserID: "u1", Provider: "google", Subject: "g1"})
	s.create(auth.Identity{ID: "i2", UserID: "u1", Provider: "github", Subject: "h1"})

	aDone := make(chan error, 1)
	go func() { aDone <- s.DeleteIdentityIfNotLast("u1", "google", false) }()

	<-s.parkedCh // A has decided and is parked in the gap.
	bErr := s.DeleteIdentityIfNotLast("u1", "github", false)
	close(s.gate)
	aErr := <-aDone

	if aErr != nil || bErr != nil {
		t.Fatalf("split-lock double: aErr = %v, bErr = %v; the control needs BOTH to succeed to reproduce the lockout", aErr, bErr)
	}

	left := s.list("u1")
	if len(left) != 0 {
		t.Fatalf("split-lock double left %d identities, want 0 — the control did not reproduce the lockout, so it proves nothing about the assertion", len(left))
	}

	// This is the assertion TestDeleteIdentityIfNotLastIsAtomicUnderConcurrency
	// makes. Against the broken store it must be FALSE — otherwise that test
	// would pass on a store that permanently locks users out.
	if len(left) == 1 {
		t.Fatal("the atomicity assertion held against a store that locked the user out — it does not detect this bug")
	}
}
