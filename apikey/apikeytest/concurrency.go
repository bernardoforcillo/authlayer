package apikeytest

import (
	"context"
	"errors"
	"sync"

	"github.com/bernardoforcillo/authlayer/apikey"
)

func concurrencyChecks() []check {
	return []check{
		{"CreateKey/ConcurrentCreatesOfOneHashAdmitExactlyOne", checkConcurrentCreateKeyOneHash},
		{"CreateServiceAccount/ConcurrentCreatesOfOneIDAdmitExactlyOne", checkConcurrentCreateAccountOneID},
		{"DeleteServiceAccount/ConcurrentDeletesAdmitExactlyOneWinner", checkConcurrentDeleteAccountOneWinner},
		{"DeleteServiceAccount/NoKeyOutlivesItsAccount", checkNoKeyOutlivesItsAccount},
	}
}

// release runs fn on RaceGoroutines goroutines held behind one channel
// barrier, so they arrive at the contended statement together rather than
// trickling in, and waits for all of them.
func release(fn func(i int)) {
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range RaceGoroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			fn(i)
		}()
	}
	close(start)
	wg.Wait()
}

// checkConcurrentCreateKeyOneHash releases RaceGoroutines CreateKey calls,
// each a distinct key for a distinct account but all carrying ONE token
// hash, and requires exactly one to succeed. This is the uniqueness MUST
// under the condition it exists for: a check-then-write that is not atomic
// lets several pass the check before any writes, and the table ends up with
// several keys that one plaintext resolves to. What this catches every time
// is a store with no hash check at all; a split-lock check with a
// sub-microsecond window it catches only sometimes — see the package doc.
func checkConcurrentCreateKeyOneHash(t tb, st apikey.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	hash := newHash()
	accounts := make([]apikey.ServiceAccount, RaceGoroutines)
	for i := range accounts {
		accounts[i] = mustCreateAccount(t, st, newAccount(newID(), at))
	}

	var mu sync.Mutex
	winners := 0
	release(func(i int) {
		k := newKey(accounts[i], at)
		k.TokenHash = hash
		if _, err := st.CreateKey(ctx, k); err == nil {
			mu.Lock()
			winners++
			mu.Unlock()
		}
	})
	if winners != 1 {
		t.Fatalf("%d of %d concurrent CreateKey calls for one token hash succeeded, want exactly 1 — the hash-uniqueness check is not atomic with the write", winners, RaceGoroutines)
	}
	// And the table agrees: exactly one row answers the hash.
	got, err := st.FindKeyByHash(ctx, hash)
	wantNoErr(t, "FindKeyByHash after the race", err)
	found := 0
	for _, sa := range accounts {
		keys, err := st.ListKeys(ctx, sa.ID)
		wantNoErr(t, "ListKeys after the race", err)
		found += len(keys)
	}
	if found != 1 {
		t.Fatalf("%d key row(s) exist after the race, want exactly 1 (the one FindKeyByHash returned, %s)", found, got.ID)
	}
}

// checkConcurrentCreateAccountOneID releases RaceGoroutines
// CreateServiceAccount calls sharing one id and requires exactly one
// success, the rest ErrIDTaken — the atomic-check MUST on the id.
func checkConcurrentCreateAccountOneID(t tb, st apikey.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	id := newID()
	containerID := newID()

	var mu sync.Mutex
	winners, refused := 0, 0
	release(func(int) {
		sa := newAccount(containerID, at)
		sa.ID = id
		_, err := st.CreateServiceAccount(ctx, sa)
		mu.Lock()
		defer mu.Unlock()
		switch {
		case err == nil:
			winners++
		case errors.Is(err, apikey.ErrIDTaken):
			refused++
		}
	})
	if winners != 1 {
		t.Fatalf("%d of %d concurrent CreateServiceAccount calls for one id succeeded, want exactly 1", winners, RaceGoroutines)
	}
	if refused != RaceGoroutines-1 {
		t.Fatalf("%d losers reported ErrIDTaken, want %d — a loser was told something other than the sentinel", refused, RaceGoroutines-1)
	}
	list, err := st.ListServiceAccounts(ctx, containerID)
	wantNoErr(t, "ListServiceAccounts after the race", err)
	if len(list) != 1 {
		t.Fatalf("%d account row(s) exist after the race, want 1", len(list))
	}
}

// checkConcurrentDeleteAccountOneWinner releases RaceGoroutines
// DeleteServiceAccount calls on one account and requires exactly one nil,
// every other caller ErrServiceAccountNotFound: the rows-affected gate, so a
// caller can trust that a nil means THEY removed it.
func checkConcurrentDeleteAccountOneWinner(t tb, st apikey.Store) {
	t.Helper()
	ctx := context.Background()
	sa := mustCreateAccount(t, st, newAccount(newID(), stamp()))
	mustCreateKey(t, st, newKey(sa, stamp()))

	var mu sync.Mutex
	winners, refused := 0, 0
	release(func(int) {
		err := st.DeleteServiceAccount(ctx, sa.ID)
		mu.Lock()
		defer mu.Unlock()
		switch {
		case err == nil:
			winners++
		case errors.Is(err, apikey.ErrServiceAccountNotFound):
			refused++
		}
	})
	if winners != 1 {
		t.Fatalf("%d of %d concurrent DeleteServiceAccount calls reported success, want exactly 1", winners, RaceGoroutines)
	}
	if refused != RaceGoroutines-1 {
		t.Fatalf("%d losers reported ErrServiceAccountNotFound, want %d", refused, RaceGoroutines-1)
	}
}

// checkNoKeyOutlivesItsAccount is the cascade MUST under concurrency, as a
// linearizability property: for RaceRounds rounds, a CreateKey for an
// account races that account's DeleteServiceAccount, and afterwards the
// store must be in a state some SERIAL order of the two calls could have
// produced — the account gone and the key gone (create first, then delete
// cascaded it away; or delete first and the create refused), never the
// account gone and the key present. The roles are swapped between rounds so
// neither call systematically starts first.
//
// A delete that removes the keys and THEN the account with a gap between
// lets a create land in the gap: the key is written against an account that
// still exists, then the account goes and the key stays — a credential row
// for a principal nothing knows. The window in a real split implementation
// is sub-microsecond, so this catches a grossly non-atomic store every time
// and a subtly non-atomic one only sometimes; see the package doc.
func checkNoKeyOutlivesItsAccount(t tb, st apikey.Store) {
	t.Helper()
	ctx := context.Background()
	for round := range RaceRounds {
		at := stamp()
		sa := mustCreateAccount(t, st, newAccount(newID(), at))
		k := newKey(sa, at)

		start := make(chan struct{})
		var wg sync.WaitGroup
		var createErr, deleteErr error
		create := func() {
			defer wg.Done()
			<-start
			_, createErr = st.CreateKey(ctx, k)
		}
		del := func() {
			defer wg.Done()
			<-start
			deleteErr = st.DeleteServiceAccount(ctx, sa.ID)
		}
		wg.Add(2)
		if round%2 == 0 {
			go create()
			go del()
		} else {
			go del()
			go create()
		}
		close(start)
		wg.Wait()

		if deleteErr != nil {
			t.Fatalf("round %d: DeleteServiceAccount of an existing account failed: %v", round, deleteErr)
		}
		if createErr != nil && !errors.Is(createErr, apikey.ErrServiceAccountNotFound) {
			t.Fatalf("round %d: CreateKey failed with %v, want nil or ErrServiceAccountNotFound", round, createErr)
		}
		if _, err := st.FindServiceAccount(ctx, sa.ID); !errors.Is(err, apikey.ErrServiceAccountNotFound) {
			t.Fatalf("round %d: the account survived its delete: %v", round, err)
		}
		if _, err := st.FindKey(ctx, k.ID); !errors.Is(err, apikey.ErrKeyNotFound) {
			t.Fatalf("round %d: a key exists for an account that does not (CreateKey error was %v) — the cascade is not atomic with the delete", round, createErr)
		}
		if _, err := st.FindKeyByHash(ctx, k.TokenHash); !errors.Is(err, apikey.ErrKeyNotFound) {
			t.Fatalf("round %d: the orphan key still resolves by hash: %v", round, err)
		}
	}
}
