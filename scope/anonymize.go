package scope

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

// DepartureCause says why a membership is ending.
type DepartureCause int

const (
	// DepartedLeft: the user left on their own ([Service.LeaveContainer] or
	// [Service.LeaveContainerAnonymized]).
	DepartedLeft DepartureCause = iota
	// DepartedRemoved: another member removed them ([Service.RemoveMember]).
	DepartedRemoved
	// DepartedAccount: their account is being deleted or anonymized
	// ([Service.RemoveUser], [Service.RemoveUserAnonymized]).
	DepartedAccount
)

// Departure describes a membership that is about to end.
type Departure struct {
	ContainerID string
	UserID      string
	Cause       DepartureCause
	// Anonymize is true when the departure was requested with scrubbing:
	// the user left through [Service.LeaveContainerAnonymized], or the
	// account is being anonymized. The application should then strip what
	// identifies the person from the records it keeps about their time in
	// this container (display names, avatars, per-container profile text)
	// and relabel attributions with Pseudonym.
	Anonymize bool
	// Pseudonym is a stable label for this user IN THIS CONTAINER, derived
	// with [WithPseudonymKey]: the same user always maps to the same value
	// here, but a different value in every other container, and it cannot be
	// reversed to the user id without the key. Empty when no key is
	// configured. Use it to keep a former member's contributions attributable
	// ("former member 3f9a…") without keeping the person.
	Pseudonym string
}

// Anonymizer is the application's hook for scrubbing a user's identity from
// its own records when a membership ends. authlayer's scope tables hold ids
// and roles, not personal data — the person is the user row (see the auth
// package's AnonymizeAccount) and whatever per-container profile the
// application stores — so the engine cannot scrub that itself; it tells the
// application exactly when, for whom and how to.
//
// It is called for EVERY departure (Anonymize says whether to scrub), before
// the membership is removed, so the application can still read what it needs.
// A non-nil error aborts the departure and nothing has been removed. It must
// tolerate being called more than once for the same membership: a retried
// account removal calls it again.
type Anonymizer interface {
	Anonymize(ctx context.Context, d Departure) error
}

// AnonymizerFunc adapts a function to [Anonymizer].
type AnonymizerFunc func(ctx context.Context, d Departure) error

// Anonymize implements [Anonymizer].
func (f AnonymizerFunc) Anonymize(ctx context.Context, d Departure) error { return f(ctx, d) }

// WithAnonymizer installs an [Anonymizer]. nil restores the default (no
// callback).
func WithAnonymizer(a Anonymizer) Option {
	return func(c *config) { c.anonymizer = a }
}

// WithPseudonymKey sets the secret [Departure.Pseudonym] is derived from
// (HMAC-SHA256 over the container id and user id). Keep it as secret as any
// signing key: anyone holding it can test whether a given user id matches a
// pseudonym. Rotating it changes every future pseudonym but not the ones
// already written. An empty key leaves Pseudonym empty.
func WithPseudonymKey(key []byte) Option {
	return func(c *config) { c.pseudonymKey = append([]byte(nil), key...) }
}

// Pseudonym returns the label a user would get in a container, or "" when no
// key is configured. It is the value [Departure.Pseudonym] carries, exposed
// so an application can compute it later, for a record it relabels in a
// batch job.
func (s *Service[C, M, PC, PM]) Pseudonym(containerID, userID string) string {
	if len(s.cfg.pseudonymKey) == 0 {
		return ""
	}
	mac := hmac.New(sha256.New, s.cfg.pseudonymKey)
	mac.Write([]byte(containerID))
	mac.Write([]byte{0})
	mac.Write([]byte(userID))
	return hex.EncodeToString(mac.Sum(nil)[:16])
}

func (s *Service[C, M, PC, PM]) depart(ctx context.Context, containerID, userID string, cause DepartureCause, anonymize bool) error {
	if s.cfg.anonymizer == nil {
		return nil
	}
	return s.cfg.anonymizer.Anonymize(ctx, Departure{
		ContainerID: containerID,
		UserID:      userID,
		Cause:       cause,
		Anonymize:   anonymize,
		Pseudonym:   s.Pseudonym(containerID, userID),
	})
}

// LeaveContainerAnonymized is [Service.LeaveContainer] with scrubbing: the
// caller leaves, and the [Anonymizer] is told to strip their identity from
// the application's records of their time here ([Departure.Anonymize]). The
// emitted [MemberRemoved] event has Anonymized set. The same last-owner
// protection applies.
func (s *Service[C, M, PC, PM]) LeaveContainerAnonymized(ctx context.Context) error {
	return s.leave(ctx, true)
}

// RemoveUserAnonymized is [Service.RemoveUser] for an account being
// anonymized rather than deleted: the same all-or-nothing removal, with every
// [Departure] flagged Anonymize and every [MemberRemoved] event flagged
// Anonymized.
func (s *Service[C, M, PC, PM]) RemoveUserAnonymized(ctx context.Context, userID string) error {
	return s.removeUser(ctx, userID, true)
}
