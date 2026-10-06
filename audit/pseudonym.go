package audit

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
)

// KeyStore holds one secret key per data subject, for the pseudonyms
// [WithSubjectKeys] writes into the log. Deleting a subject's key is what
// erases them from the log: the events stay, sealed and verifiable, but the
// pseudonym on them can no longer be recomputed from the person's id, so
// nothing links the events to the person. Keep the keys where erasure reaches
// — not in a backup that outlives the deletion request.
type KeyStore interface {
	// Key returns the subject's key, or ErrNotFound.
	Key(ctx context.Context, subject string) ([]byte, error)
	// PutKey stores key as the subject's key unless one exists, and returns
	// the key now stored, so two concurrent first writes agree.
	PutKey(ctx context.Context, subject string, key []byte) ([]byte, error)
	// DeleteKey removes the subject's key. A subject with none is not an
	// error.
	DeleteKey(ctx context.Context, subject string) error
}

// PseudonymPrefix starts every pseudonym this package writes.
const PseudonymPrefix = "ps_"

// WithSubjectKeys makes the Service pseudonymize people at write time. Every
// person id an event carries — Actor.ID, OnBehalfOf and the ID of a
// ResourceUser resource — is replaced by HMAC-SHA256(subject key, id), and
// Actor.Display is dropped, so the stored log never holds a person's id.
// Actors of type ActorSystem, ActorServiceAccount and ActorAnonymous are not
// people and keep their ids.
//
// Reads translate back: a [Filter]'s Member, ActorID and user Resource.ID are
// given as real ids and pseudonymized the same way before the Store is asked,
// so one person's trail is still one query. [Service.Forget] deletes the key
// and the trail becomes unreachable. A caller that must display who did what
// resolves names from its own user table by id before pseudonymization is
// applied, or keeps the pseudonyms next to its users with [Service.Pseudonym].
//
// What this does not reach: ids inside Request and Changes, which are free
// JSON. Keep person ids out of them (the audithook adapters do), or drop the
// fields at the source.
func WithSubjectKeys(ks KeyStore) Option { return func(c *config) { c.keys = ks } }

func (s *Service) isPerson(actorType string) bool {
	switch actorType {
	case ActorSystem, ActorServiceAccount, ActorAnonymous:
		return false
	}
	return true
}

func pseudonym(key []byte, id string) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(id))
	return PseudonymPrefix + hex.EncodeToString(m.Sum(nil))[:32]
}

// forgottenPseudonym matches no event: what a lookup for a subject without a
// key is translated to.
const forgottenPseudonym = PseudonymPrefix + "forgotten"

// pseudonymFor returns id's pseudonym, creating the subject's key when create
// is set. Without a key it returns ErrNotFound.
func (s *Service) pseudonymFor(ctx context.Context, id string, create bool) (string, error) {
	key, err := s.cfg.keys.Key(ctx, id)
	if errors.Is(err, ErrNotFound) && create {
		fresh := make([]byte, 32)
		if _, err := rand.Read(fresh); err != nil {
			return "", err
		}
		key, err = s.cfg.keys.PutKey(ctx, id, fresh)
	}
	if err != nil {
		return "", err
	}
	return pseudonym(key, id), nil
}

// Pseudonym returns the pseudonym events about id carry, or ErrNotFound when
// the person has no key: they never appeared in the log, or were forgotten.
// It is how an application keeps a pseudonym next to its own user record.
func (s *Service) Pseudonym(ctx context.Context, id string) (string, error) {
	if s.cfg.keys == nil {
		return "", fmt.Errorf("%w: no KeyStore, see WithSubjectKeys", ErrInvalidEvent)
	}
	return s.pseudonymFor(ctx, id, false)
}

// Forget erases a person from the audit log: it deletes their key, so no
// event can be linked to them any more, and their trail is unreachable
// through a Filter. The events themselves — and every seal — are untouched.
// It is idempotent. Errors: the KeyStore's, and ErrInvalidEvent when the
// Service has none.
func (s *Service) Forget(ctx context.Context, id string) error {
	if s.cfg.keys == nil {
		return fmt.Errorf("%w: no KeyStore, see WithSubjectKeys", ErrInvalidEvent)
	}
	if id == "" {
		return fmt.Errorf("%w: empty id", ErrInvalidEvent)
	}
	return s.cfg.keys.DeleteKey(ctx, id)
}

// pseudonymizeEvent replaces the people in e.
func (s *Service) pseudonymizeEvent(ctx context.Context, e *Event) error {
	if s.cfg.keys == nil {
		return nil
	}
	swap := func(id *string) error {
		if *id == "" {
			return nil
		}
		p, err := s.pseudonymFor(ctx, *id, true)
		if err != nil {
			return err
		}
		*id = p
		return nil
	}
	if s.isPerson(e.Actor.Type) {
		if err := swap(&e.Actor.ID); err != nil {
			return err
		}
		e.Actor.Display = ""
	}
	if err := swap(&e.OnBehalfOf); err != nil {
		return err
	}
	if e.Resource.Type == ResourceUser {
		return swap(&e.Resource.ID)
	}
	return nil
}

// translateFilter turns the real ids of f into the pseudonyms stored.
func (s *Service) translateFilter(ctx context.Context, f Filter) (Filter, error) {
	if s.cfg.keys == nil {
		return f, nil
	}
	swap := func(id *string) error {
		if *id == "" {
			return nil
		}
		p, err := s.pseudonymFor(ctx, *id, false)
		if errors.Is(err, ErrNotFound) {
			*id = forgottenPseudonym
			return nil
		}
		if err != nil {
			return err
		}
		*id = p
		return nil
	}
	if err := swap(&f.Member); err != nil {
		return f, err
	}
	if err := swap(&f.ActorID); err != nil {
		return f, err
	}
	if f.Resource.Type == ResourceUser {
		if err := swap(&f.Resource.ID); err != nil {
			return f, err
		}
	}
	return f, nil
}
