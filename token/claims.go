package token

import (
	"encoding/json"
	"fmt"
)

// Audience is the RFC 7519 §4.1.3 "aud" claim: the recipients a token is
// intended for. The RFC allows two encodings — a single case-sensitive
// string, or an array of them — and both are in use in the wild, so this
// type reads either: [Audience.UnmarshalJSON] accepts a JSON string, an
// array of strings, or null. It writes the compact form back: a
// one-element Audience marshals as a bare string, anything longer as an
// array, so a token issued for one audience is the shape most verifiers
// were written against.
//
// [Claims.Audience] is omitempty, so a nil or empty Audience is absent from
// the payload entirely. Nothing in this package checks it; a verifier that
// cares compares it against its own identifier — see [Audience.Contains].
type Audience []string

// Contains reports whether aud names a — the check a verifier makes against
// its own identifier. A nil or empty Audience contains nothing.
func (a Audience) Contains(aud string) bool {
	for _, v := range a {
		if v == aud {
			return true
		}
	}
	return false
}

// MarshalJSON writes a bare string for exactly one audience and an array
// otherwise. An empty Audience writes an empty array, though
// [Claims.Audience]'s omitempty means it never reaches the payload.
func (a Audience) MarshalJSON() ([]byte, error) {
	if len(a) == 1 {
		return json.Marshal(a[0])
	}
	return json.Marshal([]string(a))
}

// UnmarshalJSON accepts a string, an array of strings, or null (which
// leaves a nil). Any other JSON value — a number, an object, an array with
// a non-string element — is an error, which [Parse] surfaces as
// [ErrMalformedToken].
func (a *Audience) UnmarshalJSON(b []byte) error {
	if string(b) == "null" {
		*a = nil
		return nil
	}
	if len(b) > 0 && b[0] == '"' {
		var one string
		if err := json.Unmarshal(b, &one); err != nil {
			return fmt.Errorf("authlayer/token: aud: %w", err)
		}
		*a = Audience{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return fmt.Errorf("authlayer/token: aud must be a string or an array of strings: %w", err)
	}
	*a = Audience(many)
	return nil
}

// Actor is the RFC 8693 §4.1 "act" claim: in a delegated token, the party
// acting on behalf of [Claims.Subject]. Subject is the actor's own subject
// identifier — a service account id, say — and ClientID the OAuth client it
// acted through, when there was one. The RFC allows a nested "act" for
// chains of delegation; this type does not, deliberately: authlayer's
// delegation is one level, and a struct that could nest would be a claim
// nothing here can honour.
type Actor struct {
	// Subject is the actor's "sub": who is acting.
	Subject string `json:"sub"`
	// ClientID is RFC 8693's "client_id" inside "act": the client the
	// actor acted through. Empty when there was none.
	ClientID string `json:"client_id,omitempty"`
}
