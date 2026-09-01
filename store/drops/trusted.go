package dropsstore

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/bernardoforcillo/drops/pg"

	"github.com/bernardoforcillo/authlayer/auth"
)

// This file is [MFAStore]'s trusted-device half: the seven auth.MFAStore
// methods that persist auth.TrustedDevice against the `trusted_devices`
// table [MFASchema] declares. They live on the MFA store because they are
// the same optional port — a trusted device is only ever "skip the second
// factor" — and they follow the same discipline as every other statement in
// this package: one statement per decision, uniqueness left to the database,
// and no policy of any kind.
//
// Only the token's HASH is stored. This type hashes nothing and holds no way
// to recover a plaintext token from what it has; a dump of this table is a
// list of expiry dates and labels, not a list of second-factor bypasses.

// CreateTrustedDevice inserts d and returns it unchanged — a single INSERT
// with no preliminary SELECT, so the uniqueness decision and the write are
// one step.
//
// A unique violation is classified via [isPrimaryKeyViolation], the same way
// [IdentityStore.CreateIdentity] and [AuthStore.CreateSession] classify
// theirs: auth.ErrIDTaken when the row's own id already exists, and
// otherwise the driver's error unchanged. The "otherwise" here is
// UNIQUE (token_hash) — [MFASchema]'s only other unique-enforcing constraint
// on this table — which the port deliberately leaves unclassified, exactly
// as it leaves [auth.Session.TokenHash]'s: no caller distinguishes the two,
// and the service never presents a hash it did not just generate.
//
// An existing row is therefore never silently replaced or re-pointed at
// another user. That is not tidiness: it is how one person's cookie would
// otherwise end up skipping somebody else's second factor.
func (st *MFAStore) CreateTrustedDevice(ctx context.Context, d auth.TrustedDevice) (auth.TrustedDevice, error) {
	_, err := st.db.Insert(st.s.TrustedDevices).Row(st.s.devices.row(d)...).Exec(ctx)
	if err == nil {
		return d, nil
	}
	if !errors.Is(err, pg.ErrUniqueViolation) {
		return auth.TrustedDevice{}, err
	}
	if isPrimaryKeyViolation(err) {
		return auth.TrustedDevice{}, fmt.Errorf("%w: %w", auth.ErrIDTaken, err)
	}
	return auth.TrustedDevice{}, err
}

// FindTrustedDeviceByHash loads the device whose token_hash matches, mapping
// drops' ErrNoRows to auth.ErrTrustedDeviceNotFound. The hash is matched
// byte-for-byte.
//
// At most one row can match, and that is enforced by the database rather
// than assumed: [MFASchema]'s UNIQUE (token_hash) is what makes "the hit IS
// the device" a fact rather than a coin flip over row order — see that
// type's doc, and auth.TrustedDevice.TokenHash for the MUST it discharges.
//
// It filters by neither user nor expiry. Both are the service's decisions,
// made on the row this returns (see auth.Service.trustedDeviceAtSignIn), and
// folding either in here would make this method refuse for a reason it
// cannot report.
func (st *MFAStore) FindTrustedDeviceByHash(ctx context.Context, tokenHash string) (auth.TrustedDevice, error) {
	var d auth.TrustedDevice
	err := st.db.Select().From(st.s.TrustedDevices).
		Where(st.s.devices.eq("token_hash", tokenHash)).
		One(ctx, &d)
	if err != nil {
		return auth.TrustedDevice{}, mapNoRows(err, auth.ErrTrustedDeviceNotFound)
	}
	return d, nil
}

// ListTrustedDevices returns every device belonging to userID — expired ones
// included — and only that user's. A user with none yields nil, not an error
// — callers MUST use len() rather than a nil comparison, since store/memory
// returns an empty non-nil slice for the same case and the port leaves the
// choice unspecified. Order is whatever the server returns and is likewise
// unspecified.
//
// The user_id predicate is served by [MFASchema]'s index on that column, and
// this is the hotter of that index's two callers: every "your trusted
// devices" screen, and the ownership scan auth.Service.RevokeTrustedDevice
// performs on every revocation.
func (st *MFAStore) ListTrustedDevices(ctx context.Context, userID string) ([]auth.TrustedDevice, error) {
	var out []auth.TrustedDevice
	if err := st.db.Select().From(st.s.TrustedDevices).
		Where(st.s.devices.eq("user_id", userID)).
		All(ctx, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// DeleteTrustedDevice removes the one row named by id — a single DELETE
// keyed on the primary key — reporting auth.ErrTrustedDeviceNotFound when it
// affects no row.
//
// It performs no ownership check and could not: this port is never told who
// is asking. auth.Service.RevokeTrustedDevice establishes that first, by
// scanning the caller's own devices, exactly as auth.Service.RevokeSession
// does for sessions.
func (st *MFAStore) DeleteTrustedDevice(ctx context.Context, id string) error {
	res, err := st.db.Delete(st.s.TrustedDevices).
		Where(st.s.devices.eq("id", id)).
		Exec(ctx)
	return affectedOrErr(res, err, auth.ErrTrustedDeviceNotFound)
}

// DeleteTrustedDevicesByUser removes every device belonging to userID, and
// only that user's, in one DELETE.
//
// Matching no rows is SUCCESS rather than auth.ErrTrustedDeviceNotFound —
// deliberately, and the port says so: this is the primitive every
// remediation path in auth.Service.ChangePassword's sweep matrix calls, and
// a password change must not fail because the account had no devices to
// revoke.
func (st *MFAStore) DeleteTrustedDevicesByUser(ctx context.Context, userID string) error {
	_, err := st.db.Delete(st.s.TrustedDevices).
		Where(st.s.devices.eq("user_id", userID)).
		Exec(ctx)
	return err
}

// TouchTrustedDevice stamps last_used_at with now for the row named by id,
// reporting whether a row was stamped:
//
//	UPDATE <trusted_devices> SET last_used_at = $1 WHERE id = $2
//
// Zero rows affected is (false, nil), never an error, and that bool is a
// decision rather than a report. auth.Service.LoginWithTrustedDevice calls
// this after resolving the device and before minting the session, and reads
// false as "this device is gone": a DeleteTrustedDevice that commits between
// the two makes the UPDATE match nothing, so the sign-in falls back to the
// ordinary second-factor challenge instead of skipping a factor on the
// strength of a row that no longer exists.
//
// now is bound through a *time.Time so it takes colSet.bind's nullable path
// (see columns.go); the value is never nil here, so the column moves from
// NULL to a timestamp and never back — "never used" is a state a device
// leaves once.
func (st *MFAStore) TouchTrustedDevice(ctx context.Context, id string, now time.Time) (bool, error) {
	res, err := st.db.Update(st.s.TrustedDevices).
		Set(st.s.devices.bind("last_used_at", &now)).
		Where(st.s.devices.eq("id", id)).
		Exec(ctx)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// PurgeExpiredTrustedDevices deletes every device whose expires_at is
// strictly before `before`, across every user, and reports how many rows
// went — the same shape and the same literal, unclamped cutoff
// [AuthStore.PurgeExpired] carries for sessions and verifications.
//
// It is housekeeping rather than a security boundary: an expired device is
// already refused by auth.Service.LoginWithTrustedDevice, which compares
// ExpiresAt against the service clock on every sign-in, long before this
// removes the row.
func (st *MFAStore) PurgeExpiredTrustedDevices(ctx context.Context, before time.Time) (int, error) {
	res, err := st.db.Delete(st.s.TrustedDevices).
		Where(pg.Lt(st.s.devices.col("expires_at"), before)).
		Exec(ctx)
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, err
	}
	return int(n), nil
}
