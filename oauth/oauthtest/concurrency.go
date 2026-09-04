package oauthtest

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/bernardoforcillo/authlayer/oauth"
)

func concurrencyChecks() []check {
	return []check{
		{"RedeemCode/ConcurrentCallersAdmitExactlyOneWinner", checkRedeemCodeOneWinner},
		{"SetDeviceStatus/ConcurrentCallersAdmitExactlyOneWinner", checkSetDeviceStatusOneWinner},
		{"MarkRefreshRotated/ConcurrentCallersAdmitExactlyOneWinner", checkMarkRotatedOneWinner},
		{"CreateCode/ConcurrentCreatesOfOneHashAdmitExactlyOne", checkConcurrentCreateCodeOneHash},
		{"CreateRefreshToken/ConcurrentCreatesOfOneHashAdmitExactlyOne", checkConcurrentCreateRefreshOneHash},
		{"CreateDeviceAuthorization/ConcurrentCreatesOfOneUserCodeAdmitExactlyOne", checkConcurrentCreateDeviceOneUserCode},
		{"DeleteClient/ConcurrentDeletesAdmitExactlyOneWinner", checkConcurrentDeleteClientOneWinner},
		{"DeleteClient/NoGrantOutlivesItsClient", checkNoGrantOutlivesItsClient},
	}
}

// release runs fn on RaceGoroutines goroutines held behind one channel
// barrier, so they arrive at the contended statement together rather than
// trickling in, and waits for all of them. The goroutines never touch the
// tb: every check tallies under a mutex and asserts afterwards.
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

// tally counts the outcomes of one race under a mutex.
type tally struct {
	mu       sync.Mutex
	winners  int
	losers   int
	failures int
	firstErr error
}

func (c *tally) record(won bool, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	switch {
	case err != nil:
		c.failures++
		if c.firstErr == nil {
			c.firstErr = err
		}
	case won:
		c.winners++
	default:
		c.losers++
	}
}

// wantOneWinner asserts a compare-and-set race produced exactly one winner
// and no errors.
func wantOneWinner(t tb, what string, round int, c *tally) {
	t.Helper()
	if c.failures != 0 {
		t.Fatalf("round %d: %d of %d concurrent %s calls returned an error, first: %v — losing the race is (row, false, nil), not an error", round, c.failures, RaceGoroutines, what, c.firstErr)
	}
	if c.winners != 1 {
		t.Fatalf("round %d: %d of %d concurrent %s calls reported won=true against one row, want exactly 1 — the compare-and-set is not atomic", round, c.winners, RaceGoroutines, what)
	}
}

// checkRedeemCodeOneWinner is [oauth.Store.RedeemCode]'s central MUST:
// however many exchanges present one code at once, exactly one may see
// won=true. A read-then-write lets several see the code unredeemed and
// several mint, after which the replay OAuth 2.1 says must revoke the grant
// is never observed. The stored RedeemedAt must be the one instant every
// caller raced with. How reliably this catches a SUBTLY non-atomic backend
// depends on the contention the suite can create — see the package doc.
func checkRedeemCodeOneWinner(t tb, st oauth.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	c := mustCreateClient(t, st, newClient(newID(), at))
	g := mustCreateGrant(t, st, newGrant(c, newID(), at))
	for round := range massRaceRounds {
		code := mustCreateCode(t, st, newCode(g, at))
		shared := at.Add(time.Duration(round+1) * time.Minute)
		var tl tally
		release(func(int) {
			_, won, err := st.RedeemCode(ctx, code.CodeHash, shared)
			tl.record(won, err)
		})
		wantOneWinner(t, "RedeemCode", round, &tl)
		got, _, err := st.RedeemCode(ctx, code.CodeHash, shared.Add(time.Hour))
		wantNoErr(t, "RedeemCode after the race", err)
		wantTimePtrEqual(t, "stored RedeemedAt", got.RedeemedAt, &shared)
	}
}

// checkSetDeviceStatusOneWinner is [oauth.Store.SetDeviceStatus]'s MUST
// under contention: half the callers approve and half deny one pending
// authorization at once, and exactly one may win. The end state must be
// the winner's — approved with its grant, or denied with none.
func checkSetDeviceStatusOneWinner(t tb, st oauth.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	c := mustCreateClient(t, st, newClient(newID(), at))
	for round := range massRaceRounds {
		d := mustCreateDevice(t, st, newDevice(c, at))
		grants := make([]oauth.Grant, RaceGoroutines)
		for i := range grants {
			grants[i] = mustCreateGrant(t, st, newGrant(c, newID(), at))
		}
		var tl tally
		var mu sync.Mutex
		winner := -1
		release(func(i int) {
			to, grantID := oauth.DeviceStatusApproved, grants[i].ID
			if i%2 == 1 {
				to, grantID = oauth.DeviceStatusDenied, ""
			}
			won, err := st.SetDeviceStatus(ctx, d.ID, oauth.DeviceStatusPending, to, grantID, at)
			tl.record(won, err)
			if won {
				mu.Lock()
				winner = i
				mu.Unlock()
			}
		})
		wantOneWinner(t, "SetDeviceStatus", round, &tl)
		got, err := st.FindDeviceByCodeHash(ctx, d.DeviceCodeHash)
		wantNoErr(t, "FindDeviceByCodeHash after the race", err)
		if winner%2 == 0 {
			if got.Status != oauth.DeviceStatusApproved || got.GrantID != grants[winner].ID {
				t.Fatalf("round %d: caller %d won the approval but the row reads status=%q grant=%q", round, winner, got.Status, got.GrantID)
			}
		} else if got.Status != oauth.DeviceStatusDenied || got.GrantID != "" {
			t.Fatalf("round %d: caller %d won the denial but the row reads status=%q grant=%q", round, winner, got.Status, got.GrantID)
		}
	}
}

// checkMarkRotatedOneWinner is [oauth.Store.MarkRefreshRotated]'s central
// MUST, exactly auth.Store.MarkRotated's: exactly one of RaceGoroutines
// concurrent callers presenting one refresh token may see ok=true, and the
// stored RotatedAt must be the one instant they raced with.
func checkMarkRotatedOneWinner(t tb, st oauth.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	c := mustCreateClient(t, st, newClient(newID(), at))
	g := mustCreateGrant(t, st, newGrant(c, newID(), at))
	for round := range massRaceRounds {
		rt := mustCreateRefresh(t, st, newRefresh(g, at))
		shared := at.Add(time.Duration(round+1) * time.Minute)
		var tl tally
		release(func(int) {
			_, won, err := st.MarkRefreshRotated(ctx, rt.TokenHash, shared)
			tl.record(won, err)
		})
		wantOneWinner(t, "MarkRefreshRotated", round, &tl)
		got, err := st.FindRefreshTokenByHash(ctx, rt.TokenHash)
		wantNoErr(t, "FindRefreshTokenByHash after the race", err)
		wantTimePtrEqual(t, "stored RotatedAt", got.RotatedAt, &shared)
	}
}

// checkConcurrentCreateCodeOneHash releases RaceGoroutines CreateCode calls
// for distinct grants but ONE code hash and requires exactly one success:
// the uniqueness MUST under the condition it exists for. A check-then-write
// that is not atomic lets several pass the check before any writes.
func checkConcurrentCreateCodeOneHash(t tb, st oauth.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	c := mustCreateClient(t, st, newClient(newID(), at))
	grants := make([]oauth.Grant, RaceGoroutines)
	for i := range grants {
		grants[i] = mustCreateGrant(t, st, newGrant(c, newID(), at))
	}
	hash := newHash()
	var mu sync.Mutex
	winners := 0
	release(func(i int) {
		code := newCode(grants[i], at)
		code.CodeHash = hash
		if _, err := st.CreateCode(ctx, code); err == nil {
			mu.Lock()
			winners++
			mu.Unlock()
		}
	})
	if winners != 1 {
		t.Fatalf("%d of %d concurrent CreateCode calls for one code hash succeeded, want exactly 1 — the hash-uniqueness check is not atomic with the write", winners, RaceGoroutines)
	}
	if _, _, err := st.RedeemCode(ctx, hash, at); err != nil {
		t.Fatalf("RedeemCode after the race: %v", err)
	}
}

// checkConcurrentCreateRefreshOneHash is the same race on a refresh token
// hash.
func checkConcurrentCreateRefreshOneHash(t tb, st oauth.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	c := mustCreateClient(t, st, newClient(newID(), at))
	grants := make([]oauth.Grant, RaceGoroutines)
	for i := range grants {
		grants[i] = mustCreateGrant(t, st, newGrant(c, newID(), at))
	}
	hash := newHash()
	var mu sync.Mutex
	winners := 0
	release(func(i int) {
		rt := newRefresh(grants[i], at)
		rt.TokenHash = hash
		if _, err := st.CreateRefreshToken(ctx, rt); err == nil {
			mu.Lock()
			winners++
			mu.Unlock()
		}
	})
	if winners != 1 {
		t.Fatalf("%d of %d concurrent CreateRefreshToken calls for one hash succeeded, want exactly 1 — the hash-uniqueness check is not atomic with the write", winners, RaceGoroutines)
	}
	if _, err := st.FindRefreshTokenByHash(ctx, hash); err != nil {
		t.Fatalf("FindRefreshTokenByHash after the race: %v", err)
	}
}

// checkConcurrentCreateDeviceOneUserCode is the same race on a user code:
// distinct device-code hashes, one user code, one success.
func checkConcurrentCreateDeviceOneUserCode(t tb, st oauth.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	c := mustCreateClient(t, st, newClient(newID(), at))
	userCode := newUserCode()
	var mu sync.Mutex
	winners := 0
	release(func(int) {
		d := newDevice(c, at)
		d.UserCode = userCode
		if _, err := st.CreateDeviceAuthorization(ctx, d); err == nil {
			mu.Lock()
			winners++
			mu.Unlock()
		}
	})
	if winners != 1 {
		t.Fatalf("%d of %d concurrent CreateDeviceAuthorization calls for one user code succeeded, want exactly 1 — the user-code uniqueness check is not atomic with the write", winners, RaceGoroutines)
	}
	if _, err := st.FindDeviceByUserCode(ctx, userCode); err != nil {
		t.Fatalf("FindDeviceByUserCode after the race: %v", err)
	}
}

// checkConcurrentDeleteClientOneWinner releases RaceGoroutines DeleteClient
// calls on one client and requires exactly one nil, every other caller
// ErrClientNotFound: the rows-affected gate, so a caller can trust that a
// nil means THEY removed it.
func checkConcurrentDeleteClientOneWinner(t tb, st oauth.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	c := mustCreateClient(t, st, newClient(newID(), at))
	mustCreateGrant(t, st, newGrant(c, newID(), at))
	var mu sync.Mutex
	winners, refused := 0, 0
	release(func(int) {
		err := st.DeleteClient(ctx, c.ID)
		mu.Lock()
		defer mu.Unlock()
		switch {
		case err == nil:
			winners++
		case errors.Is(err, oauth.ErrClientNotFound):
			refused++
		}
	})
	if winners != 1 {
		t.Fatalf("%d of %d concurrent DeleteClient calls reported success, want exactly 1", winners, RaceGoroutines)
	}
	if refused != RaceGoroutines-1 {
		t.Fatalf("%d losers reported ErrClientNotFound, want %d", refused, RaceGoroutines-1)
	}
}

// checkNoGrantOutlivesItsClient is the cascade MUST under concurrency, as a
// linearizability property: for RaceRounds rounds, a CreateGrant for a
// client races that client's DeleteClient, and afterwards the store must be
// in a state some SERIAL order could have produced — the client gone and
// the grant gone (create first, then the delete cascaded it away; or delete
// first and the create refused), never the client gone and the grant
// present. The roles are swapped between rounds so neither call
// systematically starts first — closing a channel readies its waiters in
// order and the last goroutine started is overwhelmingly the first to run,
// so an unswapped race explores essentially one interleaving.
func checkNoGrantOutlivesItsClient(t tb, st oauth.Store) {
	t.Helper()
	ctx := context.Background()
	for round := range RaceRounds {
		at := stamp()
		c := mustCreateClient(t, st, newClient(newID(), at))
		g := newGrant(c, newID(), at)

		start := make(chan struct{})
		var wg sync.WaitGroup
		var createErr, deleteErr error
		create := func() {
			defer wg.Done()
			<-start
			_, createErr = st.CreateGrant(ctx, g)
		}
		del := func() {
			defer wg.Done()
			<-start
			deleteErr = st.DeleteClient(ctx, c.ID)
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
			t.Fatalf("round %d: DeleteClient of an existing client failed: %v", round, deleteErr)
		}
		if createErr != nil && !errors.Is(createErr, oauth.ErrClientNotFound) {
			t.Fatalf("round %d: CreateGrant failed with %v, want nil or ErrClientNotFound", round, createErr)
		}
		if _, err := st.FindClient(ctx, c.ID); !errors.Is(err, oauth.ErrClientNotFound) {
			t.Fatalf("round %d: the client survived its delete: %v", round, err)
		}
		if _, err := st.FindGrant(ctx, g.ID); !errors.Is(err, oauth.ErrGrantNotFound) {
			t.Fatalf("round %d: a grant exists for a client that does not (CreateGrant error was %v) — the cascade is not atomic with the delete", round, createErr)
		}
	}
}
