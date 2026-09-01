package memory

import (
	"context"
	"time"

	"github.com/bernardoforcillo/authlayer/auth"
)

// This file is [MFAStore]'s trusted-device half: the seven auth.MFAStore
// methods that persist auth.TrustedDevice. They live beside the factors and
// the recovery codes because they are the same optional port — a trusted
// device is only ever "skip the second factor" — and they follow the same
// discipline as every other method on this type: mu is held for the whole
// body, so no check-then-write can be split by a concurrent call.
//
// Only the token's HASH is ever stored. This type hashes nothing and has no
// way to recover a plaintext token from what it holds; see
// auth.TrustedDevice.TokenHash.

// CreateTrustedDevice stores d and returns it unchanged.
//
// auth.ErrIDTaken when d.ID is already in use, and the same sentinel when
// d.TokenHash already belongs to another row — the port leaves the second
// case's sentinel unspecified, so reusing ErrIDTaken is a compliant choice
// and keeps this store from inventing one of its own.
//
// The token-hash check is not optional bookkeeping: without it two rows
// could share a hash, and FindTrustedDeviceByHash would then return
// whichever the map iteration reached first — so WHICH ACCOUNT a token skips
// the second factor for would be decided by row order. store/drops enforces
// it with a UNIQUE constraint; this is that constraint, expressed as a scan
// under the same lock as the write.
//
// Deciding before writing is compliant here for the reason every other
// check-then-write in this package is: a Go map assignment has no
// independent failure mode, so there is no condition under which these
// checks pass while the write below fails on its own.
func (s *MFAStore) CreateTrustedDevice(_ context.Context, d auth.TrustedDevice) (auth.TrustedDevice, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.devices[d.ID]; ok {
		return auth.TrustedDevice{}, auth.ErrIDTaken
	}
	for _, existing := range s.devices {
		if existing.TokenHash == d.TokenHash {
			return auth.TrustedDevice{}, auth.ErrIDTaken
		}
	}
	s.devices[d.ID] = d
	return d, nil
}

// FindTrustedDeviceByHash returns the device whose TokenHash equals
// tokenHash, or auth.ErrTrustedDeviceNotFound when no row does.
//
// It filters by neither user nor expiry: both are the service's decisions,
// made on the row this returns, and folding either in here would make this
// method refuse for a reason it cannot report.
func (s *MFAStore) FindTrustedDeviceByHash(_ context.Context, tokenHash string) (auth.TrustedDevice, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, d := range s.devices {
		if d.TokenHash == tokenHash {
			return d, nil
		}
	}
	return auth.TrustedDevice{}, auth.ErrTrustedDeviceNotFound
}

// ListTrustedDevices returns every device belonging to userID — expired ones
// included — and only that user's. A user with none yields an empty,
// non-nil slice and a nil error, but callers MUST NOT depend on which of
// empty or nil they get: the port leaves that unspecified and store/drops
// returns the other. Order follows Go map iteration and is therefore
// randomised.
func (s *MFAStore) ListTrustedDevices(_ context.Context, userID string) ([]auth.TrustedDevice, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]auth.TrustedDevice, 0)
	for _, d := range s.devices {
		if d.UserID == userID {
			out = append(out, d)
		}
	}
	return out, nil
}

// DeleteTrustedDevice removes the one device named by id, or returns
// auth.ErrTrustedDeviceNotFound when id matches no row. It performs no
// ownership check — this port is never told who is asking, and
// auth.Service.RevokeTrustedDevice establishes that before calling here.
func (s *MFAStore) DeleteTrustedDevice(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.devices[id]; !ok {
		return auth.ErrTrustedDeviceNotFound
	}
	delete(s.devices, id)
	return nil
}

// DeleteTrustedDevicesByUser removes every device belonging to userID, and
// only that user's. Matching no rows is SUCCESS: this is the primitive every
// sweep in auth.Service.ChangePassword's matrix calls, and a remediation
// path must not fail because the account had nothing to revoke.
func (s *MFAStore) DeleteTrustedDevicesByUser(_ context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, d := range s.devices {
		if d.UserID == userID {
			delete(s.devices, id)
		}
	}
	return nil
}

// TouchTrustedDevice stamps LastUsedAt with now for the device named by id,
// reporting whether a row was stamped. An unknown id is (false, nil), never
// an error.
//
// The lookup and the stamp share one acquisition of mu, which is what lets
// auth.Service.LoginWithTrustedDevice read the false as "this device is
// gone": a DeleteTrustedDevice that lands first is fully visible here, so a
// revoked device never skips a second factor on the strength of a row that
// no longer exists.
func (s *MFAStore) TouchTrustedDevice(_ context.Context, id string, now time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.devices[id]
	if !ok {
		return false, nil
	}
	d.LastUsedAt = &now
	s.devices[id] = d
	return true, nil
}

// PurgeExpiredTrustedDevices removes every device whose ExpiresAt is
// strictly before `before`, across every user, and reports how many went.
// The cutoff is taken literally and is not clamped to the present, the same
// contract AuthStore.PurgeExpired carries.
func (s *MFAStore) PurgeExpiredTrustedDevices(_ context.Context, before time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for id, d := range s.devices {
		if d.ExpiresAt.Before(before) {
			delete(s.devices, id)
			n++
		}
	}
	return n, nil
}
