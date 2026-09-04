package oauthtest

import (
	"context"
	"errors"
	"time"

	"github.com/bernardoforcillo/authlayer/oauth"
)

func deviceChecks() []check {
	return []check{
		{"CreateDeviceAuthorization/RoundTrip", checkCreateDeviceRoundTrip},
		{"CreateDeviceAuthorization/IDIsUnique", checkCreateDeviceIDUnique},
		{"CreateDeviceAuthorization/DeviceCodeHashIsUnique", checkCreateDeviceHashUnique},
		{"CreateDeviceAuthorization/UserCodeIsUnique", checkCreateDeviceUserCodeUnique},
		{"CreateDeviceAuthorization/UnknownClientIsRefused", checkCreateDeviceRefusesOrphan},
		{"FindDeviceByCodeHash/UnknownHashReturnsErrDeviceNotFound", checkFindDeviceByHashNotFound},
		{"FindDeviceByUserCode/UnknownCodeReturnsErrDeviceNotFound", checkFindDeviceByUserCodeNotFound},
		{"SetDeviceStatus/TransitionsWhenTheStatusMatches", checkSetDeviceStatusWins},
		{"SetDeviceStatus/RefusesWhenTheStatusDiffers", checkSetDeviceStatusLoses},
		{"SetDeviceStatus/WritesTheGrantOnlyOnApproval", checkSetDeviceStatusGrantID},
		{"SetDeviceStatus/UnknownIDReturnsErrDeviceNotFound", checkSetDeviceStatusNotFound},
		{"TouchDevicePoll/StampsLastPolledAt", checkTouchDevicePollStamps},
		{"TouchDevicePoll/UnknownIDReturnsErrDeviceNotFound", checkTouchDevicePollNotFound},
	}
}

// assertDeviceEqual compares every field of a DeviceAuthorization.
func assertDeviceEqual(t tb, what string, got, want oauth.DeviceAuthorization) {
	t.Helper()
	if got.ID != want.ID || got.DeviceCodeHash != want.DeviceCodeHash || got.UserCode != want.UserCode ||
		got.ClientID != want.ClientID || got.Scope != want.Scope || got.Status != want.Status ||
		got.GrantID != want.GrantID || got.Interval != want.Interval {
		t.Fatalf("%s %+v, want %+v", what, got, want)
	}
	wantTimePtrEqual(t, what+" LastPolledAt", got.LastPolledAt, want.LastPolledAt)
	wantTimeEqual(t, what+" ExpiresAt", got.ExpiresAt, want.ExpiresAt)
	wantTimeEqual(t, what+" CreatedAt", got.CreatedAt, want.CreatedAt)
}

// checkCreateDeviceRoundTrip asserts CreateDeviceAuthorization returns what
// it stored and both lookups return the same record, for the pending
// default (no grant, never polled) and for an approved row with a grant
// and a poll stamp.
func checkCreateDeviceRoundTrip(t tb, st oauth.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	c := mustCreateClient(t, st, newClient(newID(), at))
	pending := mustCreateDevice(t, st, newDevice(c, at))
	g := mustCreateGrant(t, st, newGrant(c, newID(), at))
	approved := newDevice(c, at)
	approved.Status = oauth.DeviceStatusApproved
	approved.GrantID = g.ID
	polled := at.Add(time.Minute)
	approved.LastPolledAt = &polled
	created := mustCreateDevice(t, st, approved)
	assertDeviceEqual(t, "CreateDeviceAuthorization returned", created, approved)

	for _, want := range []oauth.DeviceAuthorization{pending, approved} {
		byHash, err := st.FindDeviceByCodeHash(ctx, want.DeviceCodeHash)
		wantNoErr(t, "FindDeviceByCodeHash", err)
		assertDeviceEqual(t, "FindDeviceByCodeHash returned", byHash, want)
		byCode, err := st.FindDeviceByUserCode(ctx, want.UserCode)
		wantNoErr(t, "FindDeviceByUserCode", err)
		assertDeviceEqual(t, "FindDeviceByUserCode returned", byCode, want)
	}
}

// checkCreateDeviceIDUnique asserts a second row under a taken id is
// ErrIDTaken and the original survives.
func checkCreateDeviceIDUnique(t tb, st oauth.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	c := mustCreateClient(t, st, newClient(newID(), at))
	first := mustCreateDevice(t, st, newDevice(c, at))
	clash := newDevice(c, at)
	clash.ID = first.ID
	_, err := st.CreateDeviceAuthorization(ctx, clash)
	wantErrIs(t, "CreateDeviceAuthorization(taken id)", err, oauth.ErrIDTaken)
	got, err := st.FindDeviceByCodeHash(ctx, first.DeviceCodeHash)
	wantNoErr(t, "FindDeviceByCodeHash", err)
	assertDeviceEqual(t, "the original row after the refused create", got, first)
}

// checkCreateDeviceHashUnique asserts a second row under a taken device
// code hash FAILS and the original is untouched. Which error is not
// asserted.
func checkCreateDeviceHashUnique(t tb, st oauth.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	c := mustCreateClient(t, st, newClient(newID(), at))
	first := mustCreateDevice(t, st, newDevice(c, at))
	clash := newDevice(c, at)
	clash.DeviceCodeHash = first.DeviceCodeHash
	if _, err := st.CreateDeviceAuthorization(ctx, clash); err == nil {
		t.Fatalf("CreateDeviceAuthorization accepted a second row under a taken device code hash")
	}
	got, err := st.FindDeviceByCodeHash(ctx, first.DeviceCodeHash)
	wantNoErr(t, "FindDeviceByCodeHash", err)
	if got.ID != first.ID {
		t.Fatalf("the hash resolves to %s, want the original row %s", got.ID, first.ID)
	}
}

// checkCreateDeviceUserCodeUnique asserts a second row under a taken user
// code FAILS and the original is untouched: a person types the code, and
// two rows sharing it would have them approve whichever came back first.
func checkCreateDeviceUserCodeUnique(t tb, st oauth.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	c := mustCreateClient(t, st, newClient(newID(), at))
	first := mustCreateDevice(t, st, newDevice(c, at))
	clash := newDevice(c, at)
	clash.UserCode = first.UserCode
	if _, err := st.CreateDeviceAuthorization(ctx, clash); err == nil {
		t.Fatalf("CreateDeviceAuthorization accepted a second row under a taken user code")
	}
	got, err := st.FindDeviceByUserCode(ctx, first.UserCode)
	wantNoErr(t, "FindDeviceByUserCode", err)
	if got.ID != first.ID {
		t.Fatalf("the user code resolves to %s, want the original row %s", got.ID, first.ID)
	}
}

// checkCreateDeviceRefusesOrphan asserts a row naming no client is
// ErrClientNotFound and nothing is written.
func checkCreateDeviceRefusesOrphan(t tb, st oauth.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	d := newDevice(newClient(newID(), at), at) // client never created
	_, err := st.CreateDeviceAuthorization(ctx, d)
	wantErrIs(t, "CreateDeviceAuthorization(unknown client)", err, oauth.ErrClientNotFound)
	if _, err := st.FindDeviceByCodeHash(ctx, d.DeviceCodeHash); !errors.Is(err, oauth.ErrDeviceNotFound) {
		t.Fatalf("the refused row is readable: %v", err)
	}
}

// checkFindDeviceByHashNotFound asserts an unknown hash is ErrDeviceNotFound.
func checkFindDeviceByHashNotFound(t tb, st oauth.Store) {
	t.Helper()
	_, err := st.FindDeviceByCodeHash(context.Background(), newHash())
	wantErrIs(t, "FindDeviceByCodeHash(unknown)", err, oauth.ErrDeviceNotFound)
}

// checkFindDeviceByUserCodeNotFound asserts an unknown user code is
// ErrDeviceNotFound.
func checkFindDeviceByUserCodeNotFound(t tb, st oauth.Store) {
	t.Helper()
	_, err := st.FindDeviceByUserCode(context.Background(), newUserCode())
	wantErrIs(t, "FindDeviceByUserCode(unknown)", err, oauth.ErrDeviceNotFound)
}

// checkSetDeviceStatusWins asserts a transition whose from matches the
// stored status reports won=true and persists the new status; and that
// the next transition in the chain (approved → redeemed) does too.
func checkSetDeviceStatusWins(t tb, st oauth.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	c := mustCreateClient(t, st, newClient(newID(), at))
	d := mustCreateDevice(t, st, newDevice(c, at))
	g := mustCreateGrant(t, st, newGrant(c, newID(), at))

	won, err := st.SetDeviceStatus(ctx, d.ID, oauth.DeviceStatusPending, oauth.DeviceStatusApproved, g.ID, at)
	wantNoErr(t, "SetDeviceStatus(pending→approved)", err)
	if !won {
		t.Fatalf("SetDeviceStatus(pending→approved) on a pending row reported won=false")
	}
	got, err := st.FindDeviceByCodeHash(ctx, d.DeviceCodeHash)
	wantNoErr(t, "FindDeviceByCodeHash", err)
	if got.Status != oauth.DeviceStatusApproved || got.GrantID != g.ID {
		t.Fatalf("after approval: status=%q grant=%q, want approved/%s", got.Status, got.GrantID, g.ID)
	}
	won, err = st.SetDeviceStatus(ctx, d.ID, oauth.DeviceStatusApproved, oauth.DeviceStatusRedeemed, "", at)
	wantNoErr(t, "SetDeviceStatus(approved→redeemed)", err)
	if !won {
		t.Fatalf("SetDeviceStatus(approved→redeemed) on an approved row reported won=false")
	}
	got, err = st.FindDeviceByCodeHash(ctx, d.DeviceCodeHash)
	wantNoErr(t, "FindDeviceByCodeHash", err)
	if got.Status != oauth.DeviceStatusRedeemed || got.GrantID != g.ID {
		t.Fatalf("after redemption: status=%q grant=%q, want redeemed/%s (the grant must survive the second transition)", got.Status, got.GrantID, g.ID)
	}
}

// checkSetDeviceStatusLoses asserts a transition whose from does not match
// is (false, nil) and writes nothing — a deny after an approve does not
// undo the approval, and the loser is not told it succeeded.
func checkSetDeviceStatusLoses(t tb, st oauth.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	c := mustCreateClient(t, st, newClient(newID(), at))
	d := mustCreateDevice(t, st, newDevice(c, at))
	g := mustCreateGrant(t, st, newGrant(c, newID(), at))
	_, err := st.SetDeviceStatus(ctx, d.ID, oauth.DeviceStatusPending, oauth.DeviceStatusApproved, g.ID, at)
	wantNoErr(t, "SetDeviceStatus(approve)", err)

	won, err := st.SetDeviceStatus(ctx, d.ID, oauth.DeviceStatusPending, oauth.DeviceStatusDenied, "", at)
	wantNoErr(t, "SetDeviceStatus(deny after approve)", err)
	if won {
		t.Fatalf("SetDeviceStatus(pending→denied) on an approved row reported won=true — the compare is missing")
	}
	got, err := st.FindDeviceByCodeHash(ctx, d.DeviceCodeHash)
	wantNoErr(t, "FindDeviceByCodeHash", err)
	if got.Status != oauth.DeviceStatusApproved || got.GrantID != g.ID {
		t.Fatalf("the losing transition wrote: status=%q grant=%q", got.Status, got.GrantID)
	}
}

// checkSetDeviceStatusGrantID asserts grantID is written only when to is
// approved: a denial carrying a grant id (by mistake) must not attach one.
func checkSetDeviceStatusGrantID(t tb, st oauth.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	c := mustCreateClient(t, st, newClient(newID(), at))
	d := mustCreateDevice(t, st, newDevice(c, at))
	g := mustCreateGrant(t, st, newGrant(c, newID(), at))
	won, err := st.SetDeviceStatus(ctx, d.ID, oauth.DeviceStatusPending, oauth.DeviceStatusDenied, g.ID, at)
	wantNoErr(t, "SetDeviceStatus(deny)", err)
	if !won {
		t.Fatalf("SetDeviceStatus(pending→denied) on a pending row reported won=false")
	}
	got, err := st.FindDeviceByCodeHash(ctx, d.DeviceCodeHash)
	wantNoErr(t, "FindDeviceByCodeHash", err)
	if got.Status != oauth.DeviceStatusDenied || got.GrantID != "" {
		t.Fatalf("after denial: status=%q grant=%q, want denied and no grant", got.Status, got.GrantID)
	}
}

// checkSetDeviceStatusNotFound asserts an unknown id is ErrDeviceNotFound,
// never (false, nil), which would be indistinguishable from a loss.
func checkSetDeviceStatusNotFound(t tb, st oauth.Store) {
	t.Helper()
	_, err := st.SetDeviceStatus(context.Background(), newID(), oauth.DeviceStatusPending, oauth.DeviceStatusApproved, newID(), stamp())
	wantErrIs(t, "SetDeviceStatus(unknown)", err, oauth.ErrDeviceNotFound)
}

// checkTouchDevicePollStamps asserts TouchDevicePoll writes exactly
// LastPolledAt and nothing else.
func checkTouchDevicePollStamps(t tb, st oauth.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	c := mustCreateClient(t, st, newClient(newID(), at))
	d := mustCreateDevice(t, st, newDevice(c, at))
	polled := at.Add(time.Second)
	wantNoErr(t, "TouchDevicePoll", st.TouchDevicePoll(ctx, d.ID, polled))
	got, err := st.FindDeviceByCodeHash(ctx, d.DeviceCodeHash)
	wantNoErr(t, "FindDeviceByCodeHash", err)
	want := d
	want.LastPolledAt = &polled
	assertDeviceEqual(t, "FindDeviceByCodeHash after TouchDevicePoll", got, want)
}

// checkTouchDevicePollNotFound asserts an unknown id is ErrDeviceNotFound.
func checkTouchDevicePollNotFound(t tb, st oauth.Store) {
	t.Helper()
	wantErrIs(t, "TouchDevicePoll(unknown)", st.TouchDevicePoll(context.Background(), newID(), stamp()), oauth.ErrDeviceNotFound)
}
