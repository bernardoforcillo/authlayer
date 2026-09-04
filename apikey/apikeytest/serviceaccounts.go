package apikeytest

import (
	"context"
	"errors"
	"time"

	"github.com/bernardoforcillo/authlayer/apikey"
)

func serviceAccountChecks() []check {
	return []check{
		{"CreateServiceAccount/RoundTrip", checkCreateServiceAccountRoundTrip},
		{"CreateServiceAccount/IDIsUnique", checkCreateServiceAccountIDUnique},
		{"FindServiceAccount/UnknownIDReturnsErrServiceAccountNotFound", checkFindServiceAccountNotFound},
		{"ListServiceAccounts/ScopesToTheContainer", checkListServiceAccountsScopes},
		{"ListServiceAccounts/ReturnsDisabledRowsToo", checkListServiceAccountsIncludesDisabled},
		{"ListServiceAccounts/EmptyContainerIsNotAnError", checkListServiceAccountsEmpty},
		{"SetServiceAccountDisabled/StampsDisabledAtAndUpdatedAt", checkSetDisabledStamps},
		{"SetServiceAccountDisabled/NilReEnables", checkSetDisabledNilReEnables},
		{"SetServiceAccountDisabled/UnknownIDReturnsErrServiceAccountNotFound", checkSetDisabledNotFound},
		{"DeleteServiceAccount/RemovesTheAccountAndItsKeys", checkDeleteServiceAccountCascades},
		{"DeleteServiceAccount/LeavesOtherAccountsAlone", checkDeleteServiceAccountIsScoped},
		{"DeleteServiceAccount/UnknownIDReturnsErrServiceAccountNotFound", checkDeleteServiceAccountNotFound},
	}
}

// checkCreateServiceAccountRoundTrip asserts CreateServiceAccount returns
// what it stored and that both read paths — by id and by container — return
// the same record: every field of [apikey.ServiceAccount] survives, the two
// timestamps by Equal and DisabledAt as nil. The port says the store stamps
// nothing of its own and drops nothing it was given; a Description dropped
// here is a management screen that cannot say what a key is for, and a
// CreatedBy dropped is an audit trail with no author.
func checkCreateServiceAccountRoundTrip(t tb, st apikey.Store) {
	t.Helper()
	ctx := context.Background()
	sa := newAccount(newID(), stamp())

	created := mustCreateAccount(t, st, sa)
	assertAccountEqual(t, "CreateServiceAccount returned", created, sa)

	byID, err := st.FindServiceAccount(ctx, sa.ID)
	wantNoErr(t, "FindServiceAccount", err)
	assertAccountEqual(t, "FindServiceAccount returned", byID, sa)

	list, err := st.ListServiceAccounts(ctx, sa.ContainerID)
	wantNoErr(t, "ListServiceAccounts", err)
	if len(list) != 1 {
		t.Fatalf("ListServiceAccounts returned %d row(s), want 1", len(list))
	}
	assertAccountEqual(t, "ListServiceAccounts returned", list[0], sa)
}

// assertAccountEqual compares every field of a ServiceAccount, timestamps by
// Equal so a backend returning them in another location still passes.
func assertAccountEqual(t tb, what string, got, want apikey.ServiceAccount) {
	t.Helper()
	if got.ID != want.ID {
		t.Fatalf("%s ID %q, want %q", what, got.ID, want.ID)
	}
	if got.ContainerID != want.ContainerID {
		t.Fatalf("%s ContainerID %q, want %q", what, got.ContainerID, want.ContainerID)
	}
	if got.Name != want.Name {
		t.Fatalf("%s Name %q, want %q", what, got.Name, want.Name)
	}
	if got.Description != want.Description {
		t.Fatalf("%s Description %q, want %q", what, got.Description, want.Description)
	}
	if got.CreatedBy != want.CreatedBy {
		t.Fatalf("%s CreatedBy %q, want %q — a lost author is an audit trail with no actor", what, got.CreatedBy, want.CreatedBy)
	}
	wantTimeEqual(t, what+" CreatedAt", got.CreatedAt, want.CreatedAt)
	wantTimeEqual(t, what+" UpdatedAt", got.UpdatedAt, want.UpdatedAt)
	wantTimePtrEqual(t, what+" DisabledAt", got.DisabledAt, want.DisabledAt)
}

// checkCreateServiceAccountIDUnique asserts a second create under an id the
// store already holds is refused with apikey.ErrIDTaken and leaves the
// original row untouched. The default generator never collides; a custom one
// might, and a silent overwrite would re-home every key of the first account
// onto the second's name and description.
func checkCreateServiceAccountIDUnique(t tb, st apikey.Store) {
	t.Helper()
	ctx := context.Background()
	first := mustCreateAccount(t, st, newAccount(newID(), stamp()))

	clash := newAccount(newID(), stamp())
	clash.ID = first.ID
	clash.Name = "impostor"
	if _, err := st.CreateServiceAccount(ctx, clash); !errors.Is(err, apikey.ErrIDTaken) {
		t.Fatalf("CreateServiceAccount with a taken id: error = %v, want ErrIDTaken", err)
	}
	got, err := st.FindServiceAccount(ctx, first.ID)
	wantNoErr(t, "FindServiceAccount", err)
	assertAccountEqual(t, "after the refused create, FindServiceAccount returned", got, first)
}

// checkFindServiceAccountNotFound asserts a miss is the sentinel the port
// names, not a zero record with a nil error — which a caller would take for
// an account in the zero container with no name.
func checkFindServiceAccountNotFound(t tb, st apikey.Store) {
	t.Helper()
	_, err := st.FindServiceAccount(context.Background(), newID())
	wantErrIs(t, "FindServiceAccount(unknown)", err, apikey.ErrServiceAccountNotFound)
}

// checkListServiceAccountsScopes asserts ListServiceAccounts returns exactly
// the accounts of the container asked for: two in one container, one in
// another, and the first container's list holds its two and not the third.
func checkListServiceAccountsScopes(t tb, st apikey.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	a, b := newID(), newID()
	a1 := mustCreateAccount(t, st, newAccount(a, at))
	a2 := mustCreateAccount(t, st, newAccount(a, at))
	b1 := mustCreateAccount(t, st, newAccount(b, at))

	list, err := st.ListServiceAccounts(ctx, a)
	wantNoErr(t, "ListServiceAccounts(a)", err)
	wantSameIDs(t, "ListServiceAccounts(a)", accountIDs(list), []string{a1.ID, a2.ID})

	list, err = st.ListServiceAccounts(ctx, b)
	wantNoErr(t, "ListServiceAccounts(b)", err)
	wantSameIDs(t, "ListServiceAccounts(b)", accountIDs(list), []string{b1.ID})
}

// checkListServiceAccountsIncludesDisabled asserts a disabled account is
// listed alongside the active ones: the port leaves filtering to the caller,
// and the management screen that re-enables an account needs to see it.
func checkListServiceAccountsIncludesDisabled(t tb, st apikey.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	containerID := newID()
	active := mustCreateAccount(t, st, newAccount(containerID, at))
	disabled := mustCreateAccount(t, st, newAccount(containerID, at))
	wantNoErr(t, "SetServiceAccountDisabled", st.SetServiceAccountDisabled(ctx, disabled.ID, &at, at))

	list, err := st.ListServiceAccounts(ctx, containerID)
	wantNoErr(t, "ListServiceAccounts", err)
	wantSameIDs(t, "ListServiceAccounts", accountIDs(list), []string{active.ID, disabled.ID})
}

// checkListServiceAccountsEmpty asserts a container with no accounts is an
// empty result, not an error.
func checkListServiceAccountsEmpty(t tb, st apikey.Store) {
	t.Helper()
	list, err := st.ListServiceAccounts(context.Background(), newID())
	wantNoErr(t, "ListServiceAccounts(empty container)", err)
	if len(list) != 0 {
		t.Fatalf("ListServiceAccounts(empty container) returned %d row(s), want 0", len(list))
	}
}

// checkSetDisabledStamps asserts SetServiceAccountDisabled writes BOTH
// timestamps it is handed — DisabledAt and UpdatedAt — and nothing else: the
// name, description and creator are unchanged after it.
func checkSetDisabledStamps(t tb, st apikey.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	sa := mustCreateAccount(t, st, newAccount(newID(), at))
	later := at.Add(time.Minute)

	wantNoErr(t, "SetServiceAccountDisabled", st.SetServiceAccountDisabled(ctx, sa.ID, &later, later))
	got, err := st.FindServiceAccount(ctx, sa.ID)
	wantNoErr(t, "FindServiceAccount", err)
	wantTimePtrEqual(t, "DisabledAt after disable", got.DisabledAt, &later)
	wantTimeEqual(t, "UpdatedAt after disable", got.UpdatedAt, later)
	want := sa
	want.DisabledAt = &later
	want.UpdatedAt = later
	assertAccountEqual(t, "after disable, FindServiceAccount returned", got, want)
}

// checkSetDisabledNilReEnables asserts a nil `at` clears DisabledAt — the
// re-enable path — while still advancing UpdatedAt, and that doing it to an
// already-active account is not an error.
func checkSetDisabledNilReEnables(t tb, st apikey.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	sa := mustCreateAccount(t, st, newAccount(newID(), at))
	t1 := at.Add(time.Minute)
	t2 := at.Add(2 * time.Minute)

	wantNoErr(t, "disable", st.SetServiceAccountDisabled(ctx, sa.ID, &t1, t1))
	wantNoErr(t, "re-enable", st.SetServiceAccountDisabled(ctx, sa.ID, nil, t2))
	got, err := st.FindServiceAccount(ctx, sa.ID)
	wantNoErr(t, "FindServiceAccount", err)
	if got.DisabledAt != nil {
		t.Fatalf("DisabledAt after re-enable = %v, want nil", *got.DisabledAt)
	}
	wantTimeEqual(t, "UpdatedAt after re-enable", got.UpdatedAt, t2)
	wantNoErr(t, "re-enable an active account", st.SetServiceAccountDisabled(ctx, sa.ID, nil, t2))
}

// checkSetDisabledNotFound asserts an unknown id is the sentinel, not a nil
// that would let a caller believe an account was disabled.
func checkSetDisabledNotFound(t tb, st apikey.Store) {
	t.Helper()
	at := stamp()
	err := st.SetServiceAccountDisabled(context.Background(), newID(), &at, at)
	wantErrIs(t, "SetServiceAccountDisabled(unknown)", err, apikey.ErrServiceAccountNotFound)
}

// checkDeleteServiceAccountCascades asserts the cascade MUST sequentially:
// after DeleteServiceAccount, the account is gone AND every key that named
// it is gone — by id, by hash, and from ListKeys. A key that outlived its
// account is a credential row for a principal nothing knows.
func checkDeleteServiceAccountCascades(t tb, st apikey.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	sa := mustCreateAccount(t, st, newAccount(newID(), at))
	k1 := mustCreateKey(t, st, newKey(sa, at))
	k2 := mustCreateKey(t, st, newKey(sa, at))

	wantNoErr(t, "DeleteServiceAccount", st.DeleteServiceAccount(ctx, sa.ID))

	_, err := st.FindServiceAccount(ctx, sa.ID)
	wantErrIs(t, "FindServiceAccount after delete", err, apikey.ErrServiceAccountNotFound)
	for _, k := range []apikey.Key{k1, k2} {
		if _, err := st.FindKey(ctx, k.ID); !errors.Is(err, apikey.ErrKeyNotFound) {
			t.Fatalf("FindKey(%s) after its account was deleted: error = %v, want ErrKeyNotFound — the key outlived its account", k.ID, err)
		}
		if _, err := st.FindKeyByHash(ctx, k.TokenHash); !errors.Is(err, apikey.ErrKeyNotFound) {
			t.Fatalf("FindKeyByHash after the account was deleted: error = %v, want ErrKeyNotFound — the key still resolves as a credential", err)
		}
	}
	keys, err := st.ListKeys(ctx, sa.ID)
	wantNoErr(t, "ListKeys after delete", err)
	if len(keys) != 0 {
		t.Fatalf("ListKeys after the account was deleted returned %d key(s), want 0", len(keys))
	}
}

// checkDeleteServiceAccountIsScoped asserts the cascade reaches exactly the
// deleted account's keys: another account in the same container keeps its
// record and its key.
func checkDeleteServiceAccountIsScoped(t tb, st apikey.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	containerID := newID()
	doomed := mustCreateAccount(t, st, newAccount(containerID, at))
	mustCreateKey(t, st, newKey(doomed, at))
	survivor := mustCreateAccount(t, st, newAccount(containerID, at))
	sk := mustCreateKey(t, st, newKey(survivor, at))

	wantNoErr(t, "DeleteServiceAccount", st.DeleteServiceAccount(ctx, doomed.ID))

	if _, err := st.FindServiceAccount(ctx, survivor.ID); err != nil {
		t.Fatalf("the other account was deleted too: %v", err)
	}
	if _, err := st.FindKey(ctx, sk.ID); err != nil {
		t.Fatalf("the other account's key was deleted too: %v", err)
	}
}

// checkDeleteServiceAccountNotFound asserts an unknown id — and a second
// delete of a just-deleted one — is the sentinel: the answer is rows-affected
// gated, so a caller can tell a delete that happened from one that named
// nothing.
func checkDeleteServiceAccountNotFound(t tb, st apikey.Store) {
	t.Helper()
	ctx := context.Background()
	wantErrIs(t, "DeleteServiceAccount(unknown)", st.DeleteServiceAccount(ctx, newID()), apikey.ErrServiceAccountNotFound)

	sa := mustCreateAccount(t, st, newAccount(newID(), stamp()))
	wantNoErr(t, "DeleteServiceAccount", st.DeleteServiceAccount(ctx, sa.ID))
	wantErrIs(t, "second DeleteServiceAccount", st.DeleteServiceAccount(ctx, sa.ID), apikey.ErrServiceAccountNotFound)
}
