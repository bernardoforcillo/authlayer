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
// Nothing in this package does that. Every parser here supports exactly one
// algorithm, fixed when it was CONSTRUCTED, and checks the token's header
// "alg" field for exact equality with that one literal before it decodes,
// verifies, or trusts anything else about the token. There is no "none"
// branch to take and no second algorithm for a key meant for one to be
// replayed against, because there is no dispatch on the header at all
// beyond that single equality check — every other alg value, including a
// missing one or a differently-cased one, is rejected through the same
// line with [ErrUnsupportedAlgorithm]. That equality check is the entire
// justification for hand-rolling this instead of taking a dependency on a
// general-purpose JWT library: a general-purpose parser supports many
// algorithms by design and picks between them per token, which is exactly
// the surface both attacks need and this one refuses to have.
//
// # Two signers, still one algorithm each
//
// The package offers two algorithms — HS256 through [Parse] and [HS256],
// EdDSA through [EdDSA] — and the argument above survives that only because
// of WHERE the choice is made. It is made once, by the caller, in the
// constructor it picks, and a [Signer] never changes its mind for a token:
// an [HS256] signer refuses a token whose header says "EdDSA", an [EdDSA]
// signer refuses one whose header says "HS256", and both refuse "none",
// each through the same one-line equality check against its own literal.
// Handing an EdDSA public key to an HS256 signer as if it were a secret is
// impossible by type — an HS256 signer takes byte slices it will use ONLY
// as HMAC keys, an EdDSA signer takes [crypto/ed25519] types it will use
// ONLY for Ed25519 — and the reverse forgery, an HMAC computed with a
// public key's bytes under a header claiming "EdDSA", fails at the EdDSA
// signer on signature length before it is ever verified. What this package
// still does not have, and must not grow, is a parser that reads "alg" and
// picks a signer from it: THAT is the dispatch both attacks need, and a
// Signer that accepted both algorithms would be exactly it. Add a third
// algorithm as a third constructor if it is ever needed; never as a second
// branch in an existing Parse.
//
// The same reasoning extends to the key, not just the header: [Issue],
// [Parse] and [HS256] all refuse any HMAC key shorter than 32 bytes. A nil
// or undersized key — the realistic failure mode being an unset environment
// variable — is computable by an attacker, which is "alg: none" reached
// through the key instead of the header. See [minKeyLen]. [EdDSA] refuses
// key material of the wrong size the same way, with [ErrInvalidKey].
//
// # When EdDSA, and the JWKS
//
// HS256 needs the verifier to hold the signing secret, so it fits exactly
// one shape: the party that mints a token is the only party that checks
// it. As soon as anything else must verify — another service, an agent, an
// MCP client, a gateway in front of the application — sharing the secret
// makes every verifier an issuer. [EdDSA] is for that case: the private key
// stays with the issuer, the public half is published as an RFC 7517 JWK
// Set through [PublicKeySetter], and a verifier constructs [EdDSAVerifier]
// from it via [JWKS.PublicKeys] and holds nothing it could sign with.
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
