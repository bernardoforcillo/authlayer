// Package token mints and verifies the two token types authlayer sessions
// use: opaque bearer tokens for refresh tokens, and a hand-rolled,
// single-algorithm HS256 JWT for short-lived access tokens.
//
// # Opaque tokens
//
// [GenerateOpaque] draws 32 bytes from crypto/rand and returns the
// hex-encoded plaintext alongside the hex-encoded sha256 of that plaintext.
// Store only the hash — as, say, a session row's refresh-token-hash column —
// and return the plaintext to the caller exactly once. A database that could
// be read back into a valid token would make every backup and every replica
// a bearer credential; [HashOpaque] is what a lookup hashes a presented token
// through before comparing it to that stored hash.
//
// # Why a hand-rolled JWT is safe here, and only here
//
// The two classic JWT vulnerabilities are "alg: none" (accepting an unsigned
// token as if it were verified) and algorithm confusion, where a verifier
// keyed by a value meant for one algorithm — classically an RSA public key —
// is tricked into using that value as an HMAC secret for a different one.
// Both require the same enabling mistake: a parser that takes its algorithm
// from the token it is verifying, and dispatches on it.
//
// [Parse] does not do that. It supports exactly one algorithm, HS256, and
// checks the token's header "alg" field for exact equality with the literal
// string "HS256" before it decodes, verifies, or trusts anything else about
// the token. There is no "none" branch to take and no second algorithm for a
// key meant for one to be replayed against, because there is no dispatch on
// the header at all beyond that single equality check — every other alg
// value, including a missing one or a differently-cased one, is rejected
// through the same line. That equality check is the entire justification for
// hand-rolling this instead of taking a dependency on a general-purpose JWT
// library: a general-purpose parser supports many algorithms by design,
// which is exactly the surface both attacks need and this one refuses to
// have. If this package is ever "generalised" to accept more than one
// algorithm, both vulnerabilities come back — don't.
package token

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// GenerateOpaque returns a new opaque bearer token: 32 bytes read from
// crypto/rand, hex-encoded as plain, and hash set to HashOpaque(plain).
//
// Persist only hash — for example as a session's refresh-token-hash column —
// and hand plain to the caller once, at issuance. There is no way to recover
// plain from hash later; a lookup instead hashes a presented token with
// [HashOpaque] and compares that against the stored hash.
func GenerateOpaque() (plain, hash string, err error) {
	var b [32]byte
	if _, rerr := rand.Read(b[:]); rerr != nil {
		return "", "", fmt.Errorf("authlayer/token: generate opaque token: %w", rerr)
	}
	plain = hex.EncodeToString(b[:])
	hash = HashOpaque(plain)
	return plain, hash, nil
}

// HashOpaque returns the hex-encoded sha256 of plain. Session lookup code
// calls this on a token presented by a client and compares the result
// against a stored hash — the presented plaintext itself is never compared
// against anything.
func HashOpaque(plain string) string {
	sum := sha256.Sum256([]byte(plain))
	return hex.EncodeToString(sum[:])
}
