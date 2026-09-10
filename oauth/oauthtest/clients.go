package oauthtest

import (
	"context"
	"errors"
	"time"

	"github.com/bernardoforcillo/authlayer/oauth"
)

func clientChecks() []check {
	return []check{
		{"CreateClient/RoundTrip", checkCreateClientRoundTrip},
		{"CreateClient/IDIsUnique", checkCreateClientIDUnique},
		{"FindClient/UnknownIDReturnsErrClientNotFound", checkFindClientNotFound},
		{"ListClients/ScopesToTheContainer", checkListClientsScopes},
		{"ListClients/ReturnsDisabledRowsToo", checkListClientsIncludesDisabled},
		{"ListClients/EmptyContainerIsNotAnError", checkListClientsEmpty},
		{"UpdateClient/ReplacesTheMutableFieldsOnly", checkUpdateClient},
		{"UpdateClient/UnknownIDReturnsErrClientNotFound", checkUpdateClientNotFound},
		{"DeleteClient/RemovesTheClientAndEverythingOfIt", checkDeleteClientCascades},
		{"DeleteClient/LeavesOtherClientsAlone", checkDeleteClientScoped},
		{"DeleteClient/UnknownIDReturnsErrClientNotFound", checkDeleteClientNotFound},
	}
}

// assertClientEqual compares every field of a Client: strings and the bool
// exactly, the three string lists element for element, the Permissions
// blob byte for byte with nil and empty alike, instants by Equal.
func assertClientEqual(t tb, what string, got, want oauth.Client) {
	t.Helper()
	if got.ID != want.ID || got.ContainerID != want.ContainerID || got.Name != want.Name ||
		got.SecretHash != want.SecretHash || got.Public != want.Public ||
		got.ServiceAccountID != want.ServiceAccountID || got.CreatedBy != want.CreatedBy {
		t.Fatalf("%s %+v, want %+v", what, got, want)
	}
	wantStringsEqual(t, what+" RedirectURIs", got.RedirectURIs, want.RedirectURIs)
	wantStringsEqual(t, what+" GrantTypes", got.GrantTypes, want.GrantTypes)
	wantStringsEqual(t, what+" Scopes", got.Scopes, want.Scopes)
	wantBytesEqual(t, what+" Permissions", got.Permissions, want.Permissions)
	wantTimeEqual(t, what+" CreatedAt", got.CreatedAt, want.CreatedAt)
	wantTimeEqual(t, what+" UpdatedAt", got.UpdatedAt, want.UpdatedAt)
	wantTimePtrEqual(t, what+" DisabledAt", got.DisabledAt, want.DisabledAt)
}

// checkCreateClientRoundTrip asserts CreateClient returns what it stored and
// that FindClient and ListClients return the same record, for both shapes a
// client takes: a confidential, container-owned one with every field set,
// and an application-level public one whose container, secret, service
// account and creator are all empty — the shape dynamic registration
// writes, and the one a backend with nullable id columns must not reject.
// The lists and the Permissions blob must come back exactly: a redirect
// URI list is an exact-match allowlist and the blob is a cap.
func checkCreateClientRoundTrip(t tb, st oauth.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	full := newClient(newID(), at)
	disabled := at.Add(time.Minute)
	full.DisabledAt = &disabled
	created := mustCreateClient(t, st, full)
	assertClientEqual(t, "CreateClient returned", created, full)
	public := mustCreateClient(t, st, newPublicClient(at))

	for _, want := range []oauth.Client{full, public} {
		got, err := st.FindClient(ctx, want.ID)
		wantNoErr(t, "FindClient", err)
		assertClientEqual(t, "FindClient returned", got, want)
		list, err := st.ListClients(ctx, want.ContainerID)
		wantNoErr(t, "ListClients", err)
		wantSameIDs(t, "ListClients", clientIDs(list), []string{want.ID})
		assertClientEqual(t, "ListClients returned", list[0], want)
	}
}

// checkCreateClientIDUnique asserts a second client under a taken id is
// ErrIDTaken and the original row survives untouched.
func checkCreateClientIDUnique(t tb, st oauth.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	first := mustCreateClient(t, st, newClient(newID(), at))
	clash := newClient(newID(), at)
	clash.ID = first.ID
	clash.Name = "impostor"
	_, err := st.CreateClient(ctx, clash)
	wantErrIs(t, "CreateClient(taken id)", err, oauth.ErrIDTaken)
	got, err := st.FindClient(ctx, first.ID)
	wantNoErr(t, "FindClient", err)
	assertClientEqual(t, "the original client after the refused create", got, first)
}

// checkFindClientNotFound asserts an unknown id is ErrClientNotFound, not a
// zero record with a nil error.
func checkFindClientNotFound(t tb, st oauth.Store) {
	t.Helper()
	_, err := st.FindClient(context.Background(), newID())
	wantErrIs(t, "FindClient(unknown)", err, oauth.ErrClientNotFound)
}

// checkListClientsScopes asserts ListClients returns exactly the clients
// of the container asked for — and that "" selects the application-level
// clients and nothing else, so an organization's list never shows another
// organization's clients or the operator's.
func checkListClientsScopes(t tb, st oauth.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	acme, globex := newID(), newID()
	a1 := mustCreateClient(t, st, newClient(acme, at))
	a2 := mustCreateClient(t, st, newClient(acme, at))
	g1 := mustCreateClient(t, st, newClient(globex, at))
	app := mustCreateClient(t, st, newPublicClient(at))

	list, err := st.ListClients(ctx, acme)
	wantNoErr(t, "ListClients(acme)", err)
	wantSameIDs(t, "ListClients(acme)", clientIDs(list), []string{a1.ID, a2.ID})
	list, err = st.ListClients(ctx, globex)
	wantNoErr(t, "ListClients(globex)", err)
	wantSameIDs(t, "ListClients(globex)", clientIDs(list), []string{g1.ID})
	list, err = st.ListClients(ctx, "")
	wantNoErr(t, `ListClients("")`, err)
	wantSameIDs(t, `ListClients("")`, clientIDs(list), []string{app.ID})
}

// checkListClientsIncludesDisabled asserts a disabled client is listed:
// the port leaves filtering to the caller, and a management screen must
// show what it can re-enable.
func checkListClientsIncludesDisabled(t tb, st oauth.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	containerID := newID()
	live := mustCreateClient(t, st, newClient(containerID, at))
	dead := newClient(containerID, at)
	dead.DisabledAt = &at
	mustCreateClient(t, st, dead)
	list, err := st.ListClients(ctx, containerID)
	wantNoErr(t, "ListClients", err)
	wantSameIDs(t, "ListClients", clientIDs(list), []string{live.ID, dead.ID})
}

// checkListClientsEmpty asserts a container with no clients yields an
// empty result and no error.
func checkListClientsEmpty(t tb, st oauth.Store) {
	t.Helper()
	list, err := st.ListClients(context.Background(), newID())
	wantNoErr(t, "ListClients(empty)", err)
	if len(list) != 0 {
		t.Fatalf("ListClients on an empty container returned %d row(s), want 0", len(list))
	}
}

// checkUpdateClient asserts UpdateClient replaces every mutable field with
// the value handed in — including emptying a list and clearing DisabledAt
// — and leaves ID, ContainerID, Public, CreatedBy and CreatedAt as they
// were, whatever the update carried for them.
func checkUpdateClient(t tb, st oauth.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	orig := newClient(newID(), at)
	orig.DisabledAt = &at
	mustCreateClient(t, st, orig)

	upd := orig
	upd.ContainerID = newID() // immutable: must be ignored
	upd.Public = true         // immutable: must be ignored
	upd.CreatedBy = newID()   // immutable: must be ignored
	upd.CreatedAt = at.Add(-time.Hour)
	upd.Name = "renamed"
	upd.SecretHash = newHash()
	upd.RedirectURIs = nil
	upd.GrantTypes = []string{oauth.GrantDeviceCode}
	upd.Scopes = []string{"project:read"}
	upd.ServiceAccountID = ""
	upd.Permissions = nil
	upd.UpdatedAt = at.Add(time.Minute)
	upd.DisabledAt = nil
	wantNoErr(t, "UpdateClient", st.UpdateClient(ctx, upd))

	want := upd
	want.ContainerID, want.Public, want.CreatedBy, want.CreatedAt = orig.ContainerID, orig.Public, orig.CreatedBy, orig.CreatedAt
	got, err := st.FindClient(ctx, orig.ID)
	wantNoErr(t, "FindClient", err)
	assertClientEqual(t, "FindClient after UpdateClient", got, want)
}

// checkUpdateClientNotFound asserts an update of an unknown id is
// ErrClientNotFound rather than a silent nil.
func checkUpdateClientNotFound(t tb, st oauth.Store) {
	t.Helper()
	err := st.UpdateClient(context.Background(), newClient(newID(), stamp()))
	wantErrIs(t, "UpdateClient(unknown)", err, oauth.ErrClientNotFound)
}

// checkDeleteClientCascades asserts DeleteClient removes the client and
// every grant, code, device authorization and refresh token naming it —
// every row readable by any lookup is gone afterwards.
func checkDeleteClientCascades(t tb, st oauth.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	c := mustCreateClient(t, st, newClient(newID(), at))
	user := newID()
	g := mustCreateGrant(t, st, newGrant(c, user, at))
	code := mustCreateCode(t, st, newCode(g, at))
	dev := mustCreateDevice(t, st, newDevice(c, at))
	rt := mustCreateRefresh(t, st, newRefresh(g, at))

	wantNoErr(t, "DeleteClient", st.DeleteClient(ctx, c.ID))

	if _, err := st.FindClient(ctx, c.ID); !errors.Is(err, oauth.ErrClientNotFound) {
		t.Fatalf("the client survived its delete: %v", err)
	}
	if _, err := st.FindGrant(ctx, g.ID); !errors.Is(err, oauth.ErrGrantNotFound) {
		t.Fatalf("a grant outlived its client: %v — the cascade is missing grants", err)
	}
	list, err := st.ListGrantsByUser(ctx, user)
	wantNoErr(t, "ListGrantsByUser", err)
	if len(list) != 0 {
		t.Fatalf("ListGrantsByUser still lists %d grant(s) of a deleted client", len(list))
	}
	if _, _, err := st.RedeemCode(ctx, code.CodeHash, at); !errors.Is(err, oauth.ErrCodeNotFound) {
		t.Fatalf("a code outlived its client: %v — the cascade is missing codes", err)
	}
	if _, err := st.FindDeviceByCodeHash(ctx, dev.DeviceCodeHash); !errors.Is(err, oauth.ErrDeviceNotFound) {
		t.Fatalf("a device authorization outlived its client: %v — the cascade is missing device authorizations", err)
	}
	if _, err := st.FindRefreshTokenByHash(ctx, rt.TokenHash); !errors.Is(err, oauth.ErrRefreshNotFound) {
		t.Fatalf("a refresh token outlived its client: %v — the cascade is missing refresh tokens", err)
	}
}

// checkDeleteClientScoped asserts the cascade reaches the deleted client's
// rows only: another client in the same container, its grant, code, device
// authorization and refresh token all survive.
func checkDeleteClientScoped(t tb, st oauth.Store) {
	t.Helper()
	ctx := context.Background()
	at := stamp()
	containerID := newID()
	doomed := mustCreateClient(t, st, newClient(containerID, at))
	mustCreateGrant(t, st, newGrant(doomed, newID(), at))
	other := mustCreateClient(t, st, newClient(containerID, at))
	g := mustCreateGrant(t, st, newGrant(other, newID(), at))
	code := mustCreateCode(t, st, newCode(g, at))
	dev := mustCreateDevice(t, st, newDevice(other, at))
	rt := mustCreateRefresh(t, st, newRefresh(g, at))

	wantNoErr(t, "DeleteClient", st.DeleteClient(ctx, doomed.ID))

	if _, err := st.FindClient(ctx, other.ID); err != nil {
		t.Fatalf("the other client was deleted: %v", err)
	}
	if _, err := st.FindGrant(ctx, g.ID); err != nil {
		t.Fatalf("the other client's grant was deleted: %v", err)
	}
	if _, _, err := st.RedeemCode(ctx, code.CodeHash, at); err != nil {
		t.Fatalf("the other client's code was deleted: %v", err)
	}
	if _, err := st.FindDeviceByCodeHash(ctx, dev.DeviceCodeHash); err != nil {
		t.Fatalf("the other client's device authorization was deleted: %v", err)
	}
	if _, err := st.FindRefreshTokenByHash(ctx, rt.TokenHash); err != nil {
		t.Fatalf("the other client's refresh token was deleted: %v", err)
	}
}

// checkDeleteClientNotFound asserts deleting an unknown id — and deleting
// a client a second time — is ErrClientNotFound: a rows-affected answer.
func checkDeleteClientNotFound(t tb, st oauth.Store) {
	t.Helper()
	ctx := context.Background()
	wantErrIs(t, "DeleteClient(unknown)", st.DeleteClient(ctx, newID()), oauth.ErrClientNotFound)
	c := mustCreateClient(t, st, newClient(newID(), stamp()))
	wantNoErr(t, "DeleteClient", st.DeleteClient(ctx, c.ID))
	wantErrIs(t, "second DeleteClient", st.DeleteClient(ctx, c.ID), oauth.ErrClientNotFound)
}
