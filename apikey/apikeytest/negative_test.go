package apikeytest

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/bernardoforcillo/authlayer/apikey"
)

// gap is how long the deliberately non-atomic doubles below hold their
// check-then-write window open. A real split implementation's window is
// sub-microsecond, far too narrow for a control whose whole job is to prove a
// check bites; widening it to milliseconds makes each control deterministic.
// What these controls therefore prove is that the check DETECTS the defect
// when the interleaving occurs, not that it forces the interleaving on a
// subtly broken backend — a limit the checks' own doc comments state.
const gap = 5 * time.Millisecond

// ── The non-compliant doubles ───────────────────────────────────────────
//
// Each is exactly one defect away from [refStore]: it embeds one and
// overrides a single method (or the two halves of one policy) with a
// deliberately wrong shape.

// droppedFields loses an account's Description and a key's Permissions on
// the way in — the cap, in the key's case, so a restricted key is stored
// unrestricted.
type droppedFields struct{ *refStore }

func (s droppedFields) CreateServiceAccount(ctx context.Context, sa apikey.ServiceAccount) (apikey.ServiceAccount, error) {
	sa.Description = ""
	return s.refStore.CreateServiceAccount(ctx, sa)
}

func (s droppedFields) CreateKey(ctx context.Context, k apikey.Key) (apikey.Key, error) {
	k.Permissions = nil
	return s.refStore.CreateKey(ctx, k)
}

// overwritingAccountIDs accepts a second account under a taken id.
type overwritingAccountIDs struct{ *refStore }

func (s overwritingAccountIDs) CreateServiceAccount(_ context.Context, sa apikey.ServiceAccount) (apikey.ServiceAccount, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.accounts[sa.ID] = sa
	return sa, nil
}

// overwritingKeyIDs accepts a second key under a taken id.
type overwritingKeyIDs struct{ *refStore }

func (s overwritingKeyIDs) CreateKey(_ context.Context, k apikey.Key) (apikey.Key, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.accounts[k.ServiceAccountID]; !ok {
		return apikey.Key{}, apikey.ErrServiceAccountNotFound
	}
	if s.hashTaken(k.TokenHash) {
		return apikey.Key{}, errDuplicateTokenHash
	}
	s.keys[k.ID] = k
	return k, nil
}

// sharedTokenHashes lets two keys hold one token hash — the uniqueness MUST
// on [apikey.Key.TokenHash].
type sharedTokenHashes struct{ *refStore }

func (s sharedTokenHashes) CreateKey(_ context.Context, k apikey.Key) (apikey.Key, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, taken := s.keys[k.ID]; taken {
		return apikey.Key{}, apikey.ErrIDTaken
	}
	if _, ok := s.accounts[k.ServiceAccountID]; !ok {
		return apikey.Key{}, apikey.ErrServiceAccountNotFound
	}
	s.keys[k.ID] = k
	return k, nil
}

// orphanKeys writes a key for an account that does not exist.
type orphanKeys struct{ *refStore }

func (s orphanKeys) CreateKey(_ context.Context, k apikey.Key) (apikey.Key, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, taken := s.keys[k.ID]; taken {
		return apikey.Key{}, apikey.ErrIDTaken
	}
	if s.hashTaken(k.TokenHash) {
		return apikey.Key{}, errDuplicateTokenHash
	}
	s.keys[k.ID] = k
	return k, nil
}

// silentNotFound answers every miss with a zero record and a nil error.
type silentNotFound struct{ *refStore }

func (s silentNotFound) FindServiceAccount(ctx context.Context, id string) (apikey.ServiceAccount, error) {
	sa, err := s.refStore.FindServiceAccount(ctx, id)
	if errors.Is(err, apikey.ErrServiceAccountNotFound) {
		return apikey.ServiceAccount{}, nil
	}
	return sa, err
}

func (s silentNotFound) FindKey(ctx context.Context, id string) (apikey.Key, error) {
	k, err := s.refStore.FindKey(ctx, id)
	if errors.Is(err, apikey.ErrKeyNotFound) {
		return apikey.Key{}, nil
	}
	return k, err
}

func (s silentNotFound) FindKeyByHash(ctx context.Context, h string) (apikey.Key, error) {
	k, err := s.refStore.FindKeyByHash(ctx, h)
	if errors.Is(err, apikey.ErrKeyNotFound) {
		return apikey.Key{}, nil
	}
	return k, err
}

// listsIgnoreTheScope returns every row of each kind whatever id was asked
// for — a cross-tenant leak for accounts, a cross-account leak for keys.
type listsIgnoreTheScope struct{ *refStore }

func (s listsIgnoreTheScope) ListServiceAccounts(context.Context, string) ([]apikey.ServiceAccount, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []apikey.ServiceAccount
	for _, sa := range s.accounts {
		out = append(out, sa)
	}
	return out, nil
}

func (s listsIgnoreTheScope) ListKeys(context.Context, string) ([]apikey.Key, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []apikey.Key
	for _, k := range s.keys {
		out = append(out, k)
	}
	return out, nil
}

// listsFilterForTheCaller hides disabled accounts, and revoked or expired
// keys, doing the filtering the port leaves to the caller.
type listsFilterForTheCaller struct{ *refStore }

func (s listsFilterForTheCaller) ListServiceAccounts(ctx context.Context, containerID string) ([]apikey.ServiceAccount, error) {
	all, err := s.refStore.ListServiceAccounts(ctx, containerID)
	if err != nil {
		return nil, err
	}
	var out []apikey.ServiceAccount
	for _, sa := range all {
		if sa.DisabledAt == nil {
			out = append(out, sa)
		}
	}
	return out, nil
}

func (s listsFilterForTheCaller) ListKeys(ctx context.Context, id string) ([]apikey.Key, error) {
	all, err := s.refStore.ListKeys(ctx, id)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	var out []apikey.Key
	for _, k := range all {
		if k.RevokedAt != nil || (k.ExpiresAt != nil && !now.Before(*k.ExpiresAt)) {
			continue
		}
		out = append(out, k)
	}
	return out, nil
}

// findByHashFiltersForTheCaller hides revoked and expired keys from the
// authentication lookup, so every dead key presents as unknown.
type findByHashFiltersForTheCaller struct{ *refStore }

func (s findByHashFiltersForTheCaller) FindKeyByHash(ctx context.Context, h string) (apikey.Key, error) {
	k, err := s.refStore.FindKeyByHash(ctx, h)
	if err != nil {
		return apikey.Key{}, err
	}
	now := time.Now().UTC()
	if k.RevokedAt != nil || (k.ExpiresAt != nil && !now.Before(*k.ExpiresAt)) {
		return apikey.Key{}, apikey.ErrKeyNotFound
	}
	return k, nil
}

// emptyListIsAnError reports an empty result as a not-found error.
type emptyListIsAnError struct{ *refStore }

func (s emptyListIsAnError) ListServiceAccounts(ctx context.Context, containerID string) ([]apikey.ServiceAccount, error) {
	out, err := s.refStore.ListServiceAccounts(ctx, containerID)
	if err == nil && len(out) == 0 {
		return nil, apikey.ErrServiceAccountNotFound
	}
	return out, err
}

func (s emptyListIsAnError) ListKeys(ctx context.Context, id string) ([]apikey.Key, error) {
	out, err := s.refStore.ListKeys(ctx, id)
	if err == nil && len(out) == 0 {
		return nil, apikey.ErrKeyNotFound
	}
	return out, err
}

// setDisabledDoesNotStamp reports success without writing anything: every
// disable appears to work and no account is ever disabled.
type setDisabledDoesNotStamp struct{ *refStore }

func (s setDisabledDoesNotStamp) SetServiceAccountDisabled(_ context.Context, id string, _ *time.Time, _ time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.accounts[id]; !ok {
		return apikey.ErrServiceAccountNotFound
	}
	return nil
}

// setDisabledIgnoresNil never clears DisabledAt, so nothing re-enables.
type setDisabledIgnoresNil struct{ *refStore }

func (s setDisabledIgnoresNil) SetServiceAccountDisabled(ctx context.Context, id string, at *time.Time, now time.Time) error {
	if at == nil {
		s.mu.Lock()
		defer s.mu.Unlock()
		sa, ok := s.accounts[id]
		if !ok {
			return apikey.ErrServiceAccountNotFound
		}
		sa.UpdatedAt = now
		s.accounts[id] = sa
		return nil
	}
	return s.refStore.SetServiceAccountDisabled(ctx, id, at, now)
}

// silentSetDisabled answers nil when no row matched.
type silentSetDisabled struct{ *refStore }

func (s silentSetDisabled) SetServiceAccountDisabled(ctx context.Context, id string, at *time.Time, now time.Time) error {
	if err := s.refStore.SetServiceAccountDisabled(ctx, id, at, now); err != nil && !errors.Is(err, apikey.ErrServiceAccountNotFound) {
		return err
	}
	return nil
}

// deleteAccountKeepsKeys removes the account and leaves its keys — the
// cascade MUST dropped entirely.
type deleteAccountKeepsKeys struct{ *refStore }

func (s deleteAccountKeepsKeys) DeleteServiceAccount(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.accounts[id]; !ok {
		return apikey.ErrServiceAccountNotFound
	}
	delete(s.accounts, id)
	return nil
}

// overbroadDeleteAccount cascades to every key in the account's CONTAINER
// rather than the account's own.
type overbroadDeleteAccount struct{ *refStore }

func (s overbroadDeleteAccount) DeleteServiceAccount(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	sa, ok := s.accounts[id]
	if !ok {
		return apikey.ErrServiceAccountNotFound
	}
	for kid, k := range s.keys {
		if k.ContainerID == sa.ContainerID {
			delete(s.keys, kid)
		}
	}
	delete(s.accounts, id)
	return nil
}

// silentDeleteAccount answers nil to a delete that removed nothing — the
// rows-affected gate removed.
type silentDeleteAccount struct{ *refStore }

func (s silentDeleteAccount) DeleteServiceAccount(ctx context.Context, id string) error {
	if err := s.refStore.DeleteServiceAccount(ctx, id); err != nil && !errors.Is(err, apikey.ErrServiceAccountNotFound) {
		return err
	}
	return nil
}

// revokeDoesNotStamp reports success without writing RevokedAt.
type revokeDoesNotStamp struct{ *refStore }

func (s revokeDoesNotStamp) RevokeKey(_ context.Context, id string, _ time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.keys[id]; !ok {
		return apikey.ErrKeyNotFound
	}
	return nil
}

// revokeRefusesASecondTime treats an already-revoked key as an error.
type revokeRefusesASecondTime struct{ *refStore }

func (s revokeRefusesASecondTime) RevokeKey(_ context.Context, id string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.keys[id]
	if !ok {
		return apikey.ErrKeyNotFound
	}
	if k.RevokedAt != nil {
		return apikey.ErrKeyRevoked
	}
	k.RevokedAt = &now
	s.keys[id] = k
	return nil
}

// silentRevoke answers nil when no row matched.
type silentRevoke struct{ *refStore }

func (s silentRevoke) RevokeKey(ctx context.Context, id string, now time.Time) error {
	if err := s.refStore.RevokeKey(ctx, id, now); err != nil && !errors.Is(err, apikey.ErrKeyNotFound) {
		return err
	}
	return nil
}

// touchDoesNotStamp reports success without writing LastUsedAt.
type touchDoesNotStamp struct{ *refStore }

func (s touchDoesNotStamp) TouchKey(_ context.Context, id string, _ time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.keys[id]; !ok {
		return apikey.ErrKeyNotFound
	}
	return nil
}

// silentTouch answers nil when no row matched.
type silentTouch struct{ *refStore }

func (s silentTouch) TouchKey(ctx context.Context, id string, now time.Time) error {
	if err := s.refStore.TouchKey(ctx, id, now); err != nil && !errors.Is(err, apikey.ErrKeyNotFound) {
		return err
	}
	return nil
}

// overbroadDeleteKey removes every key of the named key's account.
type overbroadDeleteKey struct{ *refStore }

func (s overbroadDeleteKey) DeleteKey(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	target, ok := s.keys[id]
	if !ok {
		return apikey.ErrKeyNotFound
	}
	for kid, k := range s.keys {
		if k.ServiceAccountID == target.ServiceAccountID {
			delete(s.keys, kid)
		}
	}
	return nil
}

// silentDeleteKey answers nil when no row matched.
type silentDeleteKey struct{ *refStore }

func (s silentDeleteKey) DeleteKey(ctx context.Context, id string) error {
	if err := s.refStore.DeleteKey(ctx, id); err != nil && !errors.Is(err, apikey.ErrKeyNotFound) {
		return err
	}
	return nil
}

// purgeInclusiveExpiry purges a key expiring exactly AT the cutoff.
type purgeInclusiveExpiry struct{ *refStore }

func (s purgeInclusiveExpiry) PurgeExpired(_ context.Context, before time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for id, k := range s.keys {
		if (k.ExpiresAt != nil && !k.ExpiresAt.After(before)) || (k.RevokedAt != nil && k.RevokedAt.Before(before)) {
			delete(s.keys, id)
			n++
		}
	}
	return n, nil
}

// purgeIgnoresRevocation purges on expiry only, so revoked keys pile up.
type purgeIgnoresRevocation struct{ *refStore }

func (s purgeIgnoresRevocation) PurgeExpired(_ context.Context, before time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for id, k := range s.keys {
		if k.ExpiresAt != nil && k.ExpiresAt.Before(before) {
			delete(s.keys, id)
			n++
		}
	}
	return n, nil
}

// purgeEverything treats a nil ExpiresAt as "expired at the dawn of time".
type purgeEverything struct{ *refStore }

func (s purgeEverything) PurgeExpired(_ context.Context, before time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for id, k := range s.keys {
		if k.ExpiresAt == nil || k.ExpiresAt.Before(before) {
			delete(s.keys, id)
			n++
		}
	}
	return n, nil
}

// purgeMiscounts reports one row more than it removed.
type purgeMiscounts struct{ *refStore }

func (s purgeMiscounts) PurgeExpired(ctx context.Context, before time.Time) (int, error) {
	n, err := s.refStore.PurgeExpired(ctx, before)
	return n + 1, err
}

// splitHashCheck checks the hash under one lock acquisition and writes under
// a second, with a gap between — the non-atomic shape the concurrent-create
// race exists to catch.
type splitHashCheck struct{ *refStore }

func (s splitHashCheck) CreateKey(_ context.Context, k apikey.Key) (apikey.Key, error) {
	s.mu.Lock()
	_, idTaken := s.keys[k.ID]
	_, hasAccount := s.accounts[k.ServiceAccountID]
	hashTaken := s.hashTaken(k.TokenHash)
	s.mu.Unlock()
	if idTaken {
		return apikey.Key{}, apikey.ErrIDTaken
	}
	if !hasAccount {
		return apikey.Key{}, apikey.ErrServiceAccountNotFound
	}
	if hashTaken {
		return apikey.Key{}, errDuplicateTokenHash
	}
	time.Sleep(gap)
	s.mu.Lock()
	s.keys[k.ID] = k
	s.mu.Unlock()
	return k, nil
}

// splitIDCheck is the same defect on the account id.
type splitIDCheck struct{ *refStore }

func (s splitIDCheck) CreateServiceAccount(_ context.Context, sa apikey.ServiceAccount) (apikey.ServiceAccount, error) {
	s.mu.Lock()
	_, taken := s.accounts[sa.ID]
	s.mu.Unlock()
	if taken {
		return apikey.ServiceAccount{}, apikey.ErrIDTaken
	}
	time.Sleep(gap)
	s.mu.Lock()
	s.accounts[sa.ID] = sa
	s.mu.Unlock()
	return sa, nil
}

// splitDeleteAccount decides "the row exists" under one lock and deletes
// under another, so every concurrent caller is told it won.
type splitDeleteAccount struct{ *refStore }

func (s splitDeleteAccount) DeleteServiceAccount(_ context.Context, id string) error {
	s.mu.Lock()
	_, ok := s.accounts[id]
	s.mu.Unlock()
	if !ok {
		return apikey.ErrServiceAccountNotFound
	}
	time.Sleep(gap)
	s.mu.Lock()
	for kid, k := range s.keys {
		if k.ServiceAccountID == id {
			delete(s.keys, kid)
		}
	}
	delete(s.accounts, id)
	s.mu.Unlock()
	return nil
}

// nonAtomicCascade deletes the keys, releases the lock, then deletes the
// account: a CreateKey landing in the gap is written against an account that
// still exists and outlives it.
type nonAtomicCascade struct{ *refStore }

func (s nonAtomicCascade) DeleteServiceAccount(_ context.Context, id string) error {
	s.mu.Lock()
	if _, ok := s.accounts[id]; !ok {
		s.mu.Unlock()
		return apikey.ErrServiceAccountNotFound
	}
	for kid, k := range s.keys {
		if k.ServiceAccountID == id {
			delete(s.keys, kid)
		}
	}
	s.mu.Unlock()
	time.Sleep(gap)
	s.mu.Lock()
	delete(s.accounts, id)
	s.mu.Unlock()
	return nil
}

// ── Driving a check and capturing its verdict ──────────────────────────

// recorder is a [tb] that records failures instead of reporting them to the
// test framework, so a check can be run against a store that is SUPPOSED to
// fail it. Fatalf calls runtime.Goexit, exactly as testing.T.Fatalf does.
type recorder struct {
	mu       sync.Mutex
	failures []string
}

func (r *recorder) Helper()                           {}
func (r *recorder) Logf(string, ...any)               {}
func (r *recorder) Errorf(format string, args ...any) { r.record(format, args) }

func (r *recorder) Fatalf(format string, args ...any) {
	r.record(format, args)
	runtime.Goexit()
}

func (r *recorder) record(format string, args []any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.failures = append(r.failures, fmt.Sprintf(format, args...))
}

// runCheck runs one check against st and reports what it complained about.
// The check runs in its own goroutine so the recorder's Fatalf can end it
// with runtime.Goexit the way testing.T.Fatalf would.
func runCheck(c check, st apikey.Store) []string {
	r := &recorder{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		c.fn(r, st)
	}()
	<-done
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.failures...)
}

func findCheck(t *testing.T, name string) check {
	t.Helper()
	for _, c := range storeContractChecks() {
		if c.name == name {
			return c
		}
	}
	t.Fatalf("no check named %q — the negative-control table names a check that does not exist", name)
	return check{}
}

// TestTheReferenceStorePassesTheContract is the control on the controls
// below. [refStore] is a correct store, so [RunStoreContract] must pass it
// end to end; if it did not, a non-compliant double failing a check would
// prove nothing about the defect injected into it.
func TestTheReferenceStorePassesTheContract(t *testing.T) {
	RunStoreContract(t, func(*testing.T) apikey.Store { return newRefStore() })
}

// TestEveryContractCheckHasANegativeControl fails if a check is added to the
// suite without a row in the table below. A check nothing is known to fail is
// a check that might assert nothing at all, and that is invisible from a
// green run.
func TestEveryContractCheckHasANegativeControl(t *testing.T) {
	covered := map[string]bool{}
	for _, tc := range negativeControls() {
		covered[tc.check] = true
	}
	for _, c := range storeContractChecks() {
		if !covered[c.name] {
			t.Errorf("check %q has no negative control — add a store that fails it to negativeControls()", c.name)
		}
	}
}

// negativeControl pairs a deliberately broken store with the one check that
// must catch its defect.
type negativeControl struct {
	defect   string
	check    string
	newStore func() apikey.Store
}

func negativeControls() []negativeControl {
	return []negativeControl{
		{"CreateServiceAccount drops the Description", "CreateServiceAccount/RoundTrip", func() apikey.Store { return droppedFields{newRefStore()} }},
		{"a second account may take a taken id", "CreateServiceAccount/IDIsUnique", func() apikey.Store { return overwritingAccountIDs{newRefStore()} }},
		{"FindServiceAccount answers a miss with a zero record and no error", "FindServiceAccount/UnknownIDReturnsErrServiceAccountNotFound", func() apikey.Store { return silentNotFound{newRefStore()} }},
		{"ListServiceAccounts ignores the container", "ListServiceAccounts/ScopesToTheContainer", func() apikey.Store { return listsIgnoreTheScope{newRefStore()} }},
		{"ListServiceAccounts hides disabled accounts", "ListServiceAccounts/ReturnsDisabledRowsToo", func() apikey.Store { return listsFilterForTheCaller{newRefStore()} }},
		{"ListServiceAccounts reports an empty container as an error", "ListServiceAccounts/EmptyContainerIsNotAnError", func() apikey.Store { return emptyListIsAnError{newRefStore()} }},
		{"SetServiceAccountDisabled writes nothing", "SetServiceAccountDisabled/StampsDisabledAtAndUpdatedAt", func() apikey.Store { return setDisabledDoesNotStamp{newRefStore()} }},
		{"SetServiceAccountDisabled never clears DisabledAt", "SetServiceAccountDisabled/NilReEnables", func() apikey.Store { return setDisabledIgnoresNil{newRefStore()} }},
		{"SetServiceAccountDisabled answers nil when no row matched", "SetServiceAccountDisabled/UnknownIDReturnsErrServiceAccountNotFound", func() apikey.Store { return silentSetDisabled{newRefStore()} }},
		{"DeleteServiceAccount leaves the account's keys behind", "DeleteServiceAccount/RemovesTheAccountAndItsKeys", func() apikey.Store { return deleteAccountKeepsKeys{newRefStore()} }},
		{"DeleteServiceAccount cascades to the whole container's keys", "DeleteServiceAccount/LeavesOtherAccountsAlone", func() apikey.Store { return overbroadDeleteAccount{newRefStore()} }},
		{"DeleteServiceAccount answers nil when no row matched", "DeleteServiceAccount/UnknownIDReturnsErrServiceAccountNotFound", func() apikey.Store { return silentDeleteAccount{newRefStore()} }},
		{"CreateKey drops the key's Permissions", "CreateKey/RoundTrip", func() apikey.Store { return droppedFields{newRefStore()} }},
		{"a second key may take a taken id", "CreateKey/IDIsUnique", func() apikey.Store { return overwritingKeyIDs{newRefStore()} }},
		{"two keys may share one token hash", "CreateKey/TokenHashIsUnique", func() apikey.Store { return sharedTokenHashes{newRefStore()} }},
		{"CreateKey writes a key for an account that does not exist", "CreateKey/UnknownAccountIsRefused", func() apikey.Store { return orphanKeys{newRefStore()} }},
		{"FindKeyByHash answers a miss with a zero record and no error", "FindKeyByHash/UnknownHashReturnsErrKeyNotFound", func() apikey.Store { return silentNotFound{newRefStore()} }},
		{"FindKeyByHash hides revoked and expired keys", "FindKeyByHash/ReturnsRevokedAndExpiredRowsToo", func() apikey.Store { return findByHashFiltersForTheCaller{newRefStore()} }},
		{"FindKey answers a miss with a zero record and no error", "FindKey/UnknownIDReturnsErrKeyNotFound", func() apikey.Store { return silentNotFound{newRefStore()} }},
		{"ListKeys ignores the account", "ListKeys/ScopesToTheAccount", func() apikey.Store { return listsIgnoreTheScope{newRefStore()} }},
		{"ListKeys hides revoked and expired keys", "ListKeys/ReturnsRevokedAndExpiredRowsToo", func() apikey.Store { return listsFilterForTheCaller{newRefStore()} }},
		{"ListKeys reports an account with no keys as an error", "ListKeys/EmptyAccountIsNotAnError", func() apikey.Store { return emptyListIsAnError{newRefStore()} }},
		{"RevokeKey writes nothing", "RevokeKey/StampsRevokedAt", func() apikey.Store { return revokeDoesNotStamp{newRefStore()} }},
		{"RevokeKey refuses a second revocation", "RevokeKey/IsIdempotent", func() apikey.Store { return revokeRefusesASecondTime{newRefStore()} }},
		{"RevokeKey answers nil when no row matched", "RevokeKey/UnknownIDReturnsErrKeyNotFound", func() apikey.Store { return silentRevoke{newRefStore()} }},
		{"TouchKey writes nothing", "TouchKey/StampsLastUsedAt", func() apikey.Store { return touchDoesNotStamp{newRefStore()} }},
		{"TouchKey answers nil when no row matched", "TouchKey/UnknownIDReturnsErrKeyNotFound", func() apikey.Store { return silentTouch{newRefStore()} }},
		{"DeleteKey removes every key of the account", "DeleteKey/RemovesExactlyOneRow", func() apikey.Store { return overbroadDeleteKey{newRefStore()} }},
		{"DeleteKey answers nil when no row matched", "DeleteKey/UnknownIDReturnsErrKeyNotFound", func() apikey.Store { return silentDeleteKey{newRefStore()} }},
		{"PurgeExpired purges a key expiring exactly at the cutoff", "PurgeExpired/CutoffIsStrictOnExpiry", func() apikey.Store { return purgeInclusiveExpiry{newRefStore()} }},
		{"PurgeExpired ignores revocation", "PurgeExpired/CutoffIsStrictOnRevocation", func() apikey.Store { return purgeIgnoresRevocation{newRefStore()} }},
		{"PurgeExpired purges live keys with no expiry", "PurgeExpired/LeavesLiveKeysAndEveryAccountAlone", func() apikey.Store { return purgeEverything{newRefStore()} }},
		{"PurgeExpired miscounts", "PurgeExpired/NothingToPurgeReturnsZero", func() apikey.Store { return purgeMiscounts{newRefStore()} }},
		{"CreateKey checks the hash under one lock and writes under another", "CreateKey/ConcurrentCreatesOfOneHashAdmitExactlyOne", func() apikey.Store { return splitHashCheck{newRefStore()} }},
		{"CreateServiceAccount checks the id under one lock and writes under another", "CreateServiceAccount/ConcurrentCreatesOfOneIDAdmitExactlyOne", func() apikey.Store { return splitIDCheck{newRefStore()} }},
		{"DeleteServiceAccount decides under one lock and deletes under another", "DeleteServiceAccount/ConcurrentDeletesAdmitExactlyOneWinner", func() apikey.Store { return splitDeleteAccount{newRefStore()} }},
		{"DeleteServiceAccount deletes the keys, releases the lock, then the account", "DeleteServiceAccount/NoKeyOutlivesItsAccount", func() apikey.Store { return nonAtomicCascade{newRefStore()} }},
	}
}

// TestTheContractRejectsNonCompliantStores runs the whole suite against each
// double, requires the named check to have failed, and logs every check
// that failed so the blast radius of each defect is on the record.
func TestTheContractRejectsNonCompliantStores(t *testing.T) {
	for _, tc := range negativeControls() {
		t.Run(tc.defect, func(t *testing.T) {
			want := findCheck(t, tc.check)

			var caught []string
			var firstMessage string
			for _, c := range storeContractChecks() {
				failures := runCheck(c, tc.newStore())
				if len(failures) == 0 {
					continue
				}
				caught = append(caught, c.name)
				if c.name == want.name {
					firstMessage = failures[0]
				}
			}
			sort.Strings(caught)

			if firstMessage == "" {
				t.Fatalf("%s PASSED %s — the check does not catch this defect. Checks that did fail: %v", tc.defect, tc.check, caught)
			}
			t.Logf("%s\n  caught by %s: %s\n  all checks that failed: %v", tc.defect, tc.check, firstMessage, caught)
		})
	}
}
