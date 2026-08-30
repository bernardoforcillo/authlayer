// Package emailnorm holds the single definition of what "the same email
// address" means to this library.
//
// It exists so
// [github.com/bernardoforcillo/authlayer/auth.NormalizeEmail] and
// [github.com/bernardoforcillo/authlayer/invite.NormalizeEmail] cannot drift
// apart. The two packages must agree byte for byte: an application binds an
// invitation to its recipient by comparing an address one package stored
// against an address the other did, and a rule that differs by so much as a
// trimmed tab turns that comparison into a refused legitimate recipient.
// They cannot simply share one exported function, because invite
// deliberately takes no dependency on auth — see invite's package doc for
// why that is load-bearing rather than incidental — so they share this
// instead, and the exported pair are wrappers with nothing of their own in
// them.
package emailnorm

import "strings"

// Normalize trims leading and trailing whitespace from s and lowercases it.
//
// This is the rule and nothing else; the two exported wrappers carry the
// doc that says where it is applied and what applying it buys.
func Normalize(s string) string { return strings.ToLower(strings.TrimSpace(s)) }
