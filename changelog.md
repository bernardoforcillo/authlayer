# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project aims to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
once a 1.0 is cut. Until then, minor versions may break API.

## [Unreleased]

### Added

- **`token.Signer`, EdDSA and the JWKS** (`authlayer/token`). A `Signer`
  interface — `Issue(claims, ttl)`, `Parse(raw)`, `Alg()` — with two
  constructors and **one algorithm each**. `HS256(keys...)` is the released
  `Issue`/`Parse` free functions behind the interface, unchanged, refusing
  fewer than one key or any key under 32 bytes with `ErrKeyTooShort` at
  construction. `EdDSA(kid, priv, verifiers)` signs Ed25519 (`crypto/ed25519`,
  no new dependency) with a `kid` header; `Parse` *requires* a `kid` naming a
  key it holds — the new sentinel `ErrUnknownKey` otherwise — and checks the
  signature only against that one key. `verifiers` are additional public keys
  by kid, which is how a key rotates. `PublicKeySetter` is implemented by the
  EdDSA signer only and returns an RFC 7517 / RFC 8037 `JWKS` (`kty` `OKP`,
  `crv` `Ed25519`, `use` `sig`, `alg` `EdDSA`); `JWKS.PublicKeys` reads one
  back and `EdDSAVerifier(keys)` builds the verify-only half a party that is
  not the issuer holds — its `Issue` always fails. `ErrInvalidKey` is the
  second new sentinel, for unusable key material at construction.

  **The single-algorithm argument in the package doc is preserved, and the
  package doc says how.** Each signer compares the header's `alg` to its own
  one literal and refuses the other's tokens with `ErrUnsupportedAlgorithm`;
  the classic confusion — an HMAC computed with the public key's bytes under
  a header claiming `EdDSA` — fails on signature length before verification.
  What must never be added is a parser that reads `alg` and picks a signer
  from it. Tests pin both refusal directions, the confusion forgery, an
  unknown `kid`, rotation through verifiers, and the JWKS wire shape.

  `Claims` gains the OAuth-shaped claims RFC 9068 and RFC 8693 name — `iss`,
  `aud` (an `Audience` type that unmarshals a string or an array and marshals
  a bare string for one recipient), `jti`, `client_id`, `scope`, and `act`
  (an `Actor{Subject, ClientID}`). **All `omitempty`, none interpreted**: a
  test pins that the pre-existing payload, and the HS256 header, are
  byte-identical when none is set.

- **`auth.WithSigner`, `WithAccessTTL` and `Service.Signer()`**
  (`authlayer/auth`). `WithSigner(s token.Signer)` replaces the HS256 signer
  `WithJWT` builds — the two fill one slot and the last applied wins — and
  `WithAccessTTL(d)` carries the access-token lifetime `WithJWT`'s second
  argument used to, for a deployment that has no HMAC keys to pass.
  `Signer()` hands the configured signer back, so a sibling package minting
  tokens this `Service` must accept signs with the same key material, and so
  an application can serve the JWKS. `Login`, `Refresh` and
  `VerifyAccessToken` all go through the signer. **`WithJWT` is unchanged in
  every observable way**: it builds a `token.HS256` signer, ignores a key list
  with any unusable key exactly as before, and a `Service` with no signer at
  all still fails closed with `token.ErrKeyTooShort` — the sentinel a missing
  HMAC key has always produced — so the tests that pin that path pass
  unmodified. `VerifyAccessToken` additionally hands back `ErrUnknownKey`,
  unwrapped, from an EdDSA signer.

- **Lifecycle hooks** (`authlayer/auth`). `WithHooks(h ...Hook)`, with `Hook`,
  `HookFunc`, `Event` and `EventKind` in exactly `scope`'s shape, so one audit
  sink consumes both packages. **Twenty-four kinds**: `SignedUp`,
  `EmailVerified`, `LoggedIn`, `LoginFailed`, `MFAChallenged`,
  `SessionRefreshed`, `TokenReuseDetected`, `LoggedOut`, `LoggedOutAll`,
  `SessionRevoked`, `PasswordChanged`, `PasswordReset`, `EmailChanged`,
  `MagicLinkRedeemed`, `IdentityLinked`, `IdentityUnlinked`, `MFAEnrolled`,
  `MFADisabled`, `PasskeyRegistered`, `PasskeyDeleted`, `DeviceTrusted`,
  `TrustedDeviceRevoked`, `AccountDeleted`, `AccountAnonymized`. Every path
  that mints a session emits `LoggedIn` with the door in `Detail` —
  `password`, `trusted_device`, `mfa`, `magic_link`, `external_identity`,
  `passkey` — and `Detail` is a **closed vocabulary**, exported as `Detail*`
  constants, never free text.

  **Hooks fire after the mutation and before the return, and a hook error
  propagates**, exactly as in `scope`. The consequence is stated on `Hook`
  rather than left to be discovered: nothing in `auth` runs in a transaction,
  so a failing `LoggedIn` hook leaves a live `Session` whose refresh token the
  caller never received. On a failure event — `LoginFailed`,
  `TokenReuseDetected` — the hook's error is **joined** to the refusal, so
  `errors.Is` still matches `ErrInvalidCredentials` or `ErrTokenReuse`.

  **What deliberately emits nothing.** The enumeration-hardened request paths
  — `SignUp`'s duplicate branch, `RequestPasswordReset`, `RequestMagicLink`
  and `RequestEmailChange` — emit **no event on either branch**, because a
  hook is a caller-visible side effect whose cost differs between branches
  only if the application makes it, and that is not this package's to risk;
  the redemptions do emit. `LoginFailed` carries the attempted **IP and never
  the attempted address** — a failed-login log keyed by address is a list of
  which addresses exist. An account `RequestMagicLink` provisions therefore
  gets no `SignedUp`; its first event is the `MagicLinkRedeemed` that signs it
  in. **Emission changes no Store-call sequence and no error**: the existing
  suite passes unchanged, and a `Service` whose hooks return `nil` is
  observably identical to one built before hooks existed. A new runnable tour,
  `examples/hooks`, prints every event of a sign-up-to-sign-out flow against
  an EdDSA signer and then publishes and verifies its JWKS.

- **Magic links — passwordless sign-in** (`authlayer/auth`). Two new methods on
  the existing `auth.Service`: `RequestMagicLink(ctx, email, ip) (token, ok,
  error)` and `RedeemMagicLink(ctx, token, ip, userAgent) (LoginResult,
  error)`, over a fourth `Verification` purpose, `magic_link`. Three options —
  `WithMagicLinkTTL` (15 minutes), `WithMagicLinkRateLimiter` (address-keyed)
  and `WithMagicLinkProvisioning` (off).

  **The token is not a step towards a credential — it is one**, and every rule
  here follows from that. Its default lifetime is the shortest of the four
  purposes. `RedeemMagicLink` burns it via `Store.DeleteVerification`
  **before** anything is issued, so two people clicking one forwarded link do
  not both get in — and a link quoted in a reply or read out of a shared
  mailbox is how a second click happens with no attacker doing anything
  clever. Expiry and purpose are checked *ahead* of the burn, so neither
  destroys the token; without the purpose check a `password_reset` token,
  which grants only the right to *set* a password, would be exchangeable
  directly for a live session.

  `RequestMagicLink` carries `RequestPasswordReset`'s enumeration property
  unchanged: identical call sequence, identical error set, `("", false, nil)`
  for an unregistered address, and every branch-exclusive write's failure
  folded into that same shape. The caller's obligation is identical too, and
  is the one thing this package cannot enforce — **a fixed response regardless
  of `ok`**. Re-issue invalidates the account's previous link, so at most one
  is live, with `RequestPasswordReset`'s identical griefing cost: anyone who
  merely knows an address can kill a victim's unclicked link by looping calls,
  and `WithMagicLinkRateLimiter` is what bounds it. A denial from that limiter
  returns `("", false, nil)`, never `ErrRateLimited`.

  A successful redemption **stamps `EmailVerifiedAt`** when it is unset, on
  the same argument that makes a completed reset stamp: the link was only ever
  deliverable to the address it was minted for. Both of `ResetPassword`'s
  guards apply — an already-verified address keeps its original timestamp, and
  an account whose address moved since the mint is not certified at all — and
  `RedeemMagicLink` deliberately does not consult `WithRequireVerifiedEmail`,
  since a redemption **is** the proof that option demands.

  Two exposures are stated rather than smoothed over.
  `WithMagicLinkProvisioning(true)` lets anyone who can receive mail create an
  account for any address they control — the exposure an open `SignUp`
  endpoint already has, with the rate limiter as the control rather than the
  option's absence — and it **reverses** the timing residual, since the
  unknown branch then performs an extra `CreateUser`; the sign of the
  difference flips, it does not disappear. No figures have been measured for
  this flow specifically, and none of `RequestPasswordReset`'s are quoted as
  though they had been. Separately, with provisioning on and the `users` table
  specifically failing writes while `verifications` stays healthy, the two
  branches are distinguishable — the fold is the better of two imperfect
  options, not a complete answer.

- **Account deletion — two postures** (`authlayer/auth`).
  `DeleteAccount(ctx, userID, currentPassword)` removes the row;
  `AnonymizeAccount(ctx, userID, currentPassword)` keeps it and scrubs it.
  `UserBase` gains `DeletedAt *time.Time`, and
  `WithAccountDeletionHook(func(ctx, userID) error)` is where the application's
  own cleanup goes. See **Changed** for the four `auth.Store` methods and the
  migration they require, which are breaking.

  **Choose on one question: does anything outside authlayer still hold the user
  id?** An audit trail, an order history, a foreign key. If so, removing the
  row leaves those pointing at nothing. Either way the original address is free
  for a new sign-up immediately, and the new account gets a **new id**.

  **The hook fires first and may refuse.** It runs before any authlayer row is
  touched, and an error from it aborts the whole call — fail closed, because a
  half-deleted account is worse than an undeleted one. It is where your own
  tables go, and critically the `scope` memberships authlayer cannot reach from
  here. It must tolerate running again, and it is not told which posture is
  running.

  **The order is fail-safe and is not negotiable**: re-authenticate (or take
  the no-password branch), the hook, `DeleteSessionsByUser` — access stops
  here — `DeleteVerificationsByUser` (by *user*, so `signup` goes too, which no
  other sweep in this package touches), every linked identity, then the user
  row **last**. A failure part-way leaves an account that cannot be logged into
  and cannot be refreshed into, and that is still there to retry the whole call
  against. The reverse order would leave the data gone and the sessions live.

  **None of it is atomic, and it cannot be**: `Store` exposes no transaction,
  the identities live behind a different port that may be a different backend,
  and the hook reaches tables authlayer has no connection to. What the order
  buys is that every reachable partial state falls on the same side, and the
  returned error is the signal to run the call again — the two by-user sweeps
  treat "matched no rows" as success, the identity sweep treats an
  already-removed row as success, and `MarkUserDeleted` is idempotent. A
  `Service` with no `IdentityStore` sweeps no identities and reports no error.

  **Re-authentication is required only when the account has a password.** An
  account with none — OAuth-provisioned, or magic-link-provisioned — cannot
  supply one and proceeds on the caller's authority. Stated plainly rather than
  implied: not every deletion these methods perform is re-authenticated, and
  the application is what authenticated the caller.

  **A stamped account is refused by eleven authentication entry points**, each
  carrying its own explicit check rather than sharing a guard, so that removing
  any one of them fails exactly one test: `Login`, `Refresh`, `ChangePassword`,
  `RequestEmailChange`, `ResetPassword`, `VerifyEmail`, `RequestPasswordReset`,
  `RequestMagicLink`, `RedeemMagicLink`, `SignInWith` (on **both** rungs) and
  `LinkIdentity`. `LinkIdentity` is in that list because it *arms* a way in
  rather than using one — the scrub clears the password, so an identity linked
  afterwards would be the account's only credential. **No new sentinel:**
  `ErrUserNotFound` is the refusal, already in each of those methods'
  documented error sets, with `Login` answering `ErrInvalidCredentials` after
  `Hasher.Dummy` so a stamped account is indistinguishable in error and cost
  from a wrong password. `RequestPasswordReset` and `RequestMagicLink` keep
  their `("", false, nil)` and gain nothing, because a distinguishable refusal
  there would tell an anonymous caller that a particular address had been
  anonymized.

  The scrubbed address is `deleted-<user id>@example.invalid` — derived from
  the id, which is the only value already unique across the table, so two
  anonymizations can never collide on `email`'s UNIQUE constraint, and under a
  domain RFC 2606 §2 reserves so it can never be delegated.

  **Neither posture revokes an access token already issued.** It is a stateless
  signed JWT this package never looks up. A device holding one keeps working
  for the remainder of its own TTL — 15 minutes by default — after either
  method returns. That is the single hole in "no one may authenticate as this
  account, by any route", it is bounded, and closing it sooner needs the
  per-request `sid`-claim lookup already documented for `LogoutAll`.

- **The sweep matrix is documented in one place** (`authlayer/auth`), on
  `Service.ChangePassword` under *The sweep matrix*, and is the single source
  of truth for which action destroys which credential: **eleven paths against
  five credential kinds** — the three token purposes, the external identity and
  the session. **Every cell has a test, the deliberate non-sweeps included.**
  It is one table rather than a rule inferred method by method because the last
  time it lived only as an assumption spread across five method docs, it got
  filled in for two of its three columns and the third was a full account
  takeover — and the columns have since grown to five while the features
  filling them were built on branches that could not see each other.

- **`examples/magiclink` and `examples/deletion` — runnable tours of both.**
  Database-free, over `store/memory`, and asserting rather than narrating:
  every claim panics if the code stops holding it, so a regression fails CI
  instead of quietly making the prose wrong. Both run in CI's examples step.
  `examples/magiclink` demonstrates the identical shape of the known and
  unknown branches, the re-issue, the burn, the purpose check, the stamp, the
  `ChangePassword` that disarms a parked link and the `Logout` that
  deliberately does not, and what provisioning exposes. `examples/deletion`
  demonstrates the hook firing first, a hook error aborting with the account
  fully intact, a wrong password removing nothing, the hard cascade in order,
  the identity sweep on both postures, and the access token neither posture
  revokes.

- **Documentation: two readme sections, two docs-site pages, and every count
  re-derived.** `## Magic links` and `## Account deletion` in the readme;
  `/authentication/magic-links` and `/authentication/account-deletion` on the
  site, both with every Go block compiled and run by `docs/_verify` against a
  pinned stdout. The counts this milestone moved were re-derived from source
  rather than adjusted by eye, and corrected everywhere they appeared:
  `auth.Store` is **twenty-two methods with eleven MUSTs** (was seven of
  eighteen), `auth/authtest` is **sixty-five checks of which seven are races**
  (was six of fifty-two), and its own negative controls are **twenty-eight
  non-compliant stores in thirty-three defect/check cases** (was fifteen and
  nineteen). Three claims were corrected rather than renumbered: "adding a
  nineteenth method to `auth.Store` would break every third-party backend" was
  the stated reason `IdentityStore` is a separate port, and deletion then added
  four methods to that same port — both decisions are right, and the rule is
  that identities are functionality and deletion is not; `SignInWith`'s
  compensating-delete disclosure said `auth.Store` has no method that deletes a
  user, which it now does; and the linearizability sentence in the
  contract-suite docs named the wrong checks.

- **External identities — "sign in with Google/GitHub/…"** (`authlayer/auth`).
  Four new methods on the existing `auth.Service` — `SignInWith`,
  `LinkIdentity`, `UnlinkIdentity`, `ListIdentities` — over a new `Identity`
  record and the `ExternalIdentity` / `SignInRequest` / `SignInResult` types.
  authlayer owns the `identities` table, the resolution ladder and the session
  issue; the application runs the OAuth/OIDC dance.

  **The boundary is the feature.** authlayer stores **no** provider access
  token and **no** provider refresh token, exchanges no authorization code,
  and is not an API client. An identity row is `(provider, subject, email)`
  plus `created_at` and `last_used_at`, and there is no token column to leak:
  a dump of that table cannot be replayed against a provider on a user's
  behalf. No new module requirement — no `x/oauth2`, no vendor SDK.

  `SignInWith` resolves in two rungs, in this order. `(provider, subject)`
  first: a hit **is** the account, so changing an address at the provider
  never re-routes an existing link — and, the security half, an attacker who
  can make a provider assert a victim's address cannot re-route an identity
  they already control onto the victim's account. Only on a miss does the
  address decide, from `Identity.Email` or `SignInRequest.FallbackEmail`,
  provisioning a password-less account when nobody holds it and applying the
  linking policy when somebody does. A `FallbackEmail` is never credited with
  the provider's `EmailVerified`, since that flag is a claim about the address
  the provider actually returned — **and it may provision a new account but
  may never link to an existing one**, under every policy including
  `LinkAlways`. The provider vouched for no address on that path, so the one
  being matched is the caller's own value; linking on it would attach an
  external account to somebody else's local account on the strength of a
  string the caller typed. The rule sits above the policy switch rather than
  inside it, and `LinkAlways`'s blessing of "a first-party IdP no third party
  can make assert an arbitrary address" is about a provider's assertions and
  does not reach a path with none.

  `WithLinking` governs that **implicit** link and nothing else.
  `LinkVerified` — the default, and deliberately `Linking`'s zero value, so a
  caller who configures nothing gets the safe policy — requires the provider
  to have asserted the address verified **and** the local account to be
  verified already, because each half alone is forgeable by exactly the route
  the other closes. `LinkNever` refuses every implicit link. `LinkAlways` is
  documented as unsafe for any provider you do not fully control: it is the
  "an email match is authentication" behaviour that hands an account to
  anyone who can make a provider assert its address. An unknown mode
  **panics** at construction rather than falling back to a policy nobody
  chose.

  `LinkIdentity` is **not** gated by that policy, on purpose: it is the
  documented remedy for `ErrLinkRequiresVerification`, performed after the
  application has authenticated the user some other way, and a policy that
  blocked the remedy would make the error a dead end — under `LinkNever`, no
  identity could ever be linked at all. `UnlinkIdentity` refuses to remove an
  account's last way in (`ErrLastCredential`), and the check and the delete
  are one atomic step inside the store rather than a read-then-write in the
  service, because a split there is a permanent, silent lockout with both
  callers told they succeeded. The question it asks is whether the account can
  **authenticate**, not whether a hash is stored: under
  `WithRequireVerifiedEmail(true)` `Login` refuses an unverified account, so a
  hash on one is not a way in. A successful unlink also revokes **every**
  session the account holds — removing a credential and revoking nothing would
  leave a session minted through the removed identity rotating for its full
  refresh TTL — while both refusals stay total, since the delete runs first.

  Two consequences are stated rather than smoothed over. An account
  provisioned by an external sign-in holds **no password at all** — `Login`
  refuses it and `ChangePassword` cannot help, since it needs a current
  password — so `RequestPasswordReset` → `ResetPassword` is its only route to
  a first one, pinned end to end by test. And `SignInResult.Created` is not
  the disclosure-free flag an earlier draft of this entry called it: reaching
  it takes a completed dance, but on the `FallbackEmail` path the address is
  the caller's, so success-versus-`ErrLinkRequiresVerification` answers
  whether that address is registered, at a cost of one throwaway provider
  account per probe. `SignInWith` consults no rate limiter, so that belongs at
  the callback.

  The cross-store window is closed where it can be. The linking decision reads
  the account from `Store` and writes the identity to `IdentityStore`, which
  may be different backends with no transaction spanning them; a concurrent
  `UpdateUserEmail` would otherwise leave the identity attached to an account
  that no longer holds the asserted address at all, with rung 1 resolving that
  subject to it forever. A **compensating re-read** after the write retracts
  the row when the address moved, which needs no transaction; re-reading the
  address covers the `EmailVerifiedAt` the decision stood on too, since
  nothing in `Service` clears that field without also moving the address. What
  remains is disclosed: a retraction whose own delete fails leaves the row and
  says so.

  One window is **disclosed rather than closed**. On the provisioning branch
  `Store.CreateUser` commits before `CreateIdentity` runs, so a transient
  identity-backend failure leaves a user row holding the address with no
  password and no identity, and every retry of an assertion the provider did
  not mark verified is then refused. It is recoverable —
  `RequestPasswordReset` → `ResetPassword` gives that account a password and
  certifies the address — and pinned by test so the disclosure is checked.
  Compensating would need a "delete this user" method on `auth.Store`, a
  nineteenth on a port that shipped in `v0.1.0`, which is exactly what
  `IdentityStore` exists to avoid.

- **`auth.IdentityStore` is a separate, OPTIONAL port**, wired with
  `auth.WithIdentityStore` — six methods: `CreateIdentity`,
  `FindIdentityByProviderSubject`, `ListIdentitiesByUser`, `TouchIdentity`,
  `DeleteIdentity`, `DeleteIdentityIfNotLast`.

  `DeleteIdentity` is the by-id sibling and makes **no** reachability check:
  it is how the service retracts a row it wrote itself and how
  `ResetPassword` sweeps identities after committing a new password. An
  application's connected-accounts screen owes `DeleteIdentityIfNotLast`
  instead.

  It was deliberately **not** added to `auth.Store`. That interface shipped in
  `v0.1.0`; adding a nineteenth method to it would break every third-party
  backend that already implements it, the day after the release that invited
  them to. This project already had the pattern — `invite.Store` is its own
  port, and `NewAuthStore` / `NewInviteStore` are separate constructors — so
  identities follow it. An application offering no external sign-in wires
  nothing, creates no table, and gets `ErrOAuthNotConfigured` from all four
  service methods rather than a nil dereference.

  Three **MUST**s, each naming what breaks without it. `(Provider, Subject)`
  is unique across every row, or one external account maps to two local users
  and a sign-in resolving that subject lands on whichever row the backend
  returns first. `CreateIdentity` decides the conflict from the write attempt
  itself, never from a separate read a concurrent link could race.
  `DeleteIdentityIfNotLast` makes its reachability check and its delete one
  atomic step — the read-then-write shape this project has shipped and closed
  four times elsewhere, and the reason `userHasPassword` is a parameter rather
  than a lookup (the identity store owns `identities` and must never be handed
  the credential table). The value can only go stale in the fail-closed
  direction for the hash itself, since no `Service` method removes a password;
  under `WithRequireVerifiedEmail(true)` the *verified* half can move the
  other way inside `VerifyEmail`'s email-change path, which the port documents
  along with the reset that recovers from it.

- **`store/memory` and `store/drops` both implement it.**
  `memory.NewIdentityStore()` holds one mutex across every method body and
  enforces both uniqueness rules its port declares.
  `dropsstore.NewIdentityStore(db)` owns one table:

  ```
  identities  id PK (uuid by default), user_id, provider, subject, email,
              created_at, last_used_at NULL,
              UNIQUE (provider, subject), INDEX (user_id)
  ```

  **`UNIQUE (provider, subject)`** is what makes `ErrIdentityLinked` a
  guarantee rather than advice, and what fails the loser of two concurrent
  first sign-ins for the same new external account. It is composite, so
  `CREATE TABLE` cannot carry it; `CreateSchema` emits it as a guarded
  `ALTER TABLE`, the idiom the invite schema already uses. **`INDEX (user_id)`**
  serves `ListIdentitiesByUser` and the locking `SELECT` inside every unlink,
  and a live `EXPLAIN` test proves the planner picks it, with a control that
  drops the index and requires the plan to degrade.

  `DeleteIdentityIfNotLast` is a transaction there, not a single conditional
  `DELETE`: a statement is atomic with respect to the rows it *writes*, but
  this decision is about the sibling rows an `EXISTS` subquery reads, and
  under `READ COMMITTED` that subquery neither locks what it reads nor sees a
  concurrent uncommitted delete — so both callers would delete. A per-user
  advisory transaction lock plus `SELECT … FOR UPDATE` is what makes it
  serial, and `TestDeleteIdentityIfNotLastIsAtomicUnderConcurrencyLive` is
  the live test that guards it.
  `WithIdentityNames` renames the table, and `WithIdentityTextLibraryIDs()`
  retypes both id columns for a non-UUID `auth.WithIDGenerator` — it must be
  passed alongside `WithAuthTextLibraryIDs()`, since `identities.user_id`
  references `users.id`.

- **Six new sentinels** in `authlayer/auth`, bringing that package to
  twenty-four: `ErrIdentityNotFound`, `ErrIdentityLinked`,
  `ErrLinkRequiresVerification`, `ErrLastCredential`,
  `ErrProviderSubjectRequired` and `ErrOAuthNotConfigured`. Two orderings are
  part of the contract rather than incidental: `ErrUserNotFound` wins over
  `ErrIdentityLinked` in `LinkIdentity`, because the account is read before
  the pair is looked up and no row may be left pointing at a user that does
  not exist; and `ErrProviderSubjectRequired` is raised by **both** entry
  points before any store is touched, because a blank subject is not a value
  that misses — it is a key every account at that provider would collide on.
  `ListIdentities` on an unknown user id returns an **empty list**, not
  `ErrUserNotFound`, so it cannot answer "does this account exist?".

- **`examples/oauth` — a runnable tour of all of it.** Database-free, over
  `store/memory`, with a fake provider struct standing in for the OAuth
  client. It demonstrates rather than describes: a first sign-in provisioning
  an account (`Created: true`); the same `(provider, subject)` signing the
  same user in; the provider changing its reported address and the link not
  moving; an unverified assertion claiming an existing verified account being
  refused with `ErrLinkRequiresVerification`, writing no identity row and
  issuing no session; the same assertion linked explicitly afterwards on a
  `LinkNever` service, proving the policy does not gate the remedy;
  `UnlinkIdentity` refusing an account's last credential; and an
  OAuth-provisioned account reaching its first password through the reset
  flow. It runs in the readme's `Checks` block and in CI alongside the other
  three.

- **Documentation: a readme `## OAuth` section and four docs-site pages.**
  The readme section leads with the boundary, then the ladder, the three
  linking modes, `ErrLastCredential` and the no-password consequence; every
  fenced `go` block in it is extracted programmatically, compiled, run, and
  diffed against the values it claims. The docs site gains an **External
  identities** group — overview, signing in, the linking policy, connected
  accounts — grouped as a feature domain of its own rather than folded into
  Authentication, because it carries a separate optional port, its own table
  and its own error family. Every Go sample on those pages is compiled, run
  and its stdout pinned by `go run ./docs/_verify`. `storage/schema` now
  prints the `identities` table from `NewIdentitySchema` itself, so its
  columns and constraints cannot drift from the code.

- **`examples/reset` — a runnable tour of the password lifecycle.**
  `RequestPasswordReset`, `ResetPassword` and `RequestEmailChange` appeared in
  zero fenced `go` blocks and in neither example, so a newcomer implementing
  "forgot my password" — the commonest reason to reach for this library — had
  prose, a signature, and nothing that runs. This one runs against
  `store/memory`, needs no database, and demonstrates each property rather
  than describing it: a reset request for a known and an unknown address
  returning the identical `(token, ok, nil)` shape, with no error on the
  unknown one; `ErrMissingIP` on a blank ip; a re-issue invalidating the
  previous token; a redemption burning its token and revoking every session;
  a completed reset stamping `EmailVerifiedAt` on an account that never
  confirmed its address — the only way out of `WithRequireVerifiedEmail(true)`,
  since this package exposes no verification resend — and leaving an existing
  stamp alone on the next one; `RequestEmailChange` refusing a wrong current
  password, and `VerifyEmail` then redeeming the result with no authentication
  at all; and a reset token parked by an attacker being swept by the victim's
  `ChangePassword`. It is referenced from the readme's Authentication section,
  its password-lifecycle section, the `Packages` table, the `Checks` block and
  CI.

- **The readme names its imports.** Not one fenced block showed an `import`
  line: `dropsstore` appeared in six snippets with its path given nowhere,
  `memory` living at `store/memory` was not guessable, and the production
  wiring snippet — `db := pg.New(stdlib.New(sqlDB))`, this project's only
  production-store guidance — needed three imports the document never named,
  two of them packages both called `stdlib`, one of those a blank import whose
  driver name (`"pgx"`) was also unstated. There is now an `Imports` section
  listing every path the snippets use, with the three non-guessable ones
  called out; the Authentication section carries its own block, because the
  table of contents links straight to it and every snippet there opens with
  `memory.NewAuthStore()`, documented 440 lines earlier; and the `store/drops`
  wiring snippet is written out as a compiling function with its own imports.

- **Continuous integration** (`.github/workflows/ci.yml`) — the gate this
  project ran by hand through v0.1.0 now runs on GitHub Actions, on every push
  and every pull request: `go build`, `go vet` with and without
  `-tags integration`, a `gofmt -l` check, `golangci-lint` pinned to the
  version the gate was last run with, and `go test ./... -count=1`. Two
  additions beyond the hand gate. The unit tests also run under `-race`,
  which they never had in CI — this package's correctness rests on a
  compare-and-set session rotation and a mutex-guarded memory store. And the
  live PostgreSQL lane runs too, against a `postgres:17-alpine` service
  container holding a dedicated `authlayer_test` database, so the
  drop-and-recreate the live fixtures perform has a database it exclusively
  owns. That lane is where several of this project's Criticals were found; a
  CI that skipped it would not protect the thing that needed protecting. The
  Go version comes from `go.mod`'s own directive via
  `setup-go`'s `go-version-file`, so it cannot drift from the module.

- **A text-library-ids escape hatch** (`authlayer/store/drops`) —
  `WithTextLibraryIDs()`, `WithInviteTextLibraryIDs()` and
  `WithAuthTextLibraryIDs()` type the ids authlayer mints for itself — `id`,
  `container_id`, `parent_id`, and the auth store's
  `users`/`sessions`/`verifications` ids — as `text` rather than `uuid`. This
  is what makes `scope.WithIDGenerator` and `auth.WithIDGenerator` true rather
  than merely constrained: v0.1.0 typed those columns `uuid`
  unconditionally, so a ULID, a database sequence, or a readable `usr_a1b2c3`
  failed the first write with `SQLSTATE 22P02` and both options carried a
  documented warning saying so. The auth store's option deliberately moves
  `sessions.user_id` and `verifications.user_id` with `users.id`, since it owns
  the table they reference — a hatch that moved only the three primary keys
  would have fixed `SignUp` and broken `Login`. `WithTextUserIDs` and
  `WithInviteTextUserIDs` remain separate options answering a separate
  question (pointing the RBAC half at an existing non-UUID user table), and
  the two families compose.

  **`uuid` remains the default everywhere**, since authlayer generates UUIDv7,
  and the live lane asserts that in both directions by reading
  `information_schema` back. `CreateSchema` emits the correct `CREATE TABLE`
  in either mode and stays idempotent; like every other part of that call it
  will not retype a table that already exists, so choose before the tables are
  created or retype the columns in your own migration.

  Proven against live PostgreSQL, not only in schema-shape unit tests:
  `TestTextLibraryIDsRoundTripANonUUIDGeneratorLive` drives one ULID generator
  through a full sign-up / verify / login / refresh arc and a full
  organization / member / custom-role arc with the options on, reading every
  value back; `TestNonUUIDIDGeneratorFailsAgainstDropsLive` and
  `TestNonUUIDIDGeneratorFailsAgainstTheScopeStoreLive` pin the `22P02`
  without them.

- **`auth/authtest` — an exported contract-test suite for `auth.Store`**
  (`authtest.RunStoreContract(t, newStore)`). `auth.Store` is an eighteen-method
  port, seven of whose methods carry a normative **MUST**; until now those were
  enforced by prose and by the two backends this repository happens to ship, so
  a third-party backend author had no way to check their work. The suite covers
  every one of them plus the ordinary behavioural contract — error
  classification, email normalization on every read and write path, and
  `PurgeExpired`'s strict cutoff. Six of its fifty-two checks are races, because the
  obligations behind them are unreachable sequentially: `MarkRotated`'s single
  winner; `CreateUser`'s and `UpdateUserEmail`'s one-address-one-account
  atomicity, one check each; a `MarkEmailVerified` racing the `UpdateUserEmail`
  that moves the address out from under it; a `CreateSuccessorSession` racing
  the family revocation that must not leave it alive; and concurrent revocations
  of one family. Points the port
  leaves unspecified are deliberately not asserted. Fifteen negative controls —
  each a store exactly one defect away from a correct one, paired into nineteen
  defect/check cases — assert the suite *fails* a non-compliant implementation;
  without them a suite that passes everything would look identical to one that
  works. Two of the seven are only partly reachable from outside the port and
  the package doc says so rather than implying coverage: `CreateUser`'s
  requirement that `ErrEmailTaken` come from the write attempt rather than a
  separately-authorized read is a property of the backend's failure topology,
  invisible to a caller, so only its atomicity consequence is asserted; and
  `DeleteSessionsByFamily`'s serialization **MUST** is asserted through its
  consequence, because forcing the lock-order inversion needs backend-specific
  SQL on a second connection. `store/drops` carries that one itself.
- **Token-hash uniqueness is part of that suite**, as
  `CreateSession/TokenHashIsUnique` and `CreateVerification/TokenHashIsUnique`.
  `Session.TokenHash` and `Verification.TokenHash` carry their **MUST** on the
  record type rather than on a method, and a backend that satisfies every
  method obligation and skips these is still wrong: a shared hash defeats
  `MarkRotated`'s single-winner contract *with no atomicity defect at all*,
  because two concurrent callers each atomically win a different one of the
  colliding rows. It shipped briefly as a separate entry point,
  `RunTokenHashUniquenessContract`, because `store/memory` did not enforce it —
  the backend changed instead (see below), and the second entry point is gone.
  What a rejected duplicate *returns* is still not asserted, since the port
  classifies only `ErrIDTaken` there.

- **`invite/invitetest` — an exported contract-test suite for `invite.Store`**
  (`invitetest.RunStoreContract(t, newStore)`), the same shape and the same
  placement as `auth/authtest`. `invite.Store` had no exported contract at all,
  and the obligations it carries are the ones that bound *who gets in*: forty-three
  checks cover every one of them plus the ordinary behavioural contract — error
  classification, `ConsumeLink`'s three refusal reasons, `PurgeExpired`'s strict
  cutoff and its two "leave it alone" cases.

  Eight of the forty-three are races. `ConsumeLink`'s single winner against a
  `MaxUses: 1` link is the one a Critical earlier in this project was about; two
  more drive its ceiling against a `MaxUses: 4` link and, deterministically, the
  lost update a read-then-write suffers on an *unlimited* one, where every caller
  wins on any implementation but a split write leaves `UseCount` far below N
  whatever the timing. `DeleteEmailInvite`'s at-most-one-nil claim is next — the
  gate `AcceptInvite`'s one-time-credential property rests on — then each of the
  three uniqueness constraints under concurrent creates, and finally a
  `DeleteEmailInvitesFor` racing the `CreateEmailInvite` that re-invites the same
  address, which asserts a linearizability property: a create reporting success
  while the container ends up holding no invitation for that address is reachable
  by no serial order of the two calls. That one alternates its two goroutines'
  roles by round, because closing a channel readies waiters LIFO and a fixed
  assignment explores essentially one interleaving — the trap that let two
  `authtest` checks pass their own broken stores.

  Thirty-two negative controls — each a store exactly one defect away from a
  correct one, paired into forty-four defect/check cases — assert the suite
  *fails* a non-compliant implementation, and a further test fails if a check is
  ever added without one. Points the port leaves unspecified are deliberately not
  asserted, and the package doc says plainly what the suite cannot reach:
  `ConsumeLink`'s MUST names two acceptable *shapes*, and which one a backend
  used is invisible to a caller, so only the consequences are checked.

- **Three uniqueness **MUST**s are now stated on `invite.EmailInvite` and
  `invite.Link`**, and are part of that suite: `EmailInvite.TokenHash`,
  `Link.Code`, and `EmailInvite`'s `(ContainerID, Email)` pair. `store/drops`
  has enforced all three as `UNIQUE` constraints from the start and the port
  said nothing about any of them — the divergence this work closes was
  discovered from that gap, not from a failing test. The first two defeat
  `ConsumeLink`'s and `DeleteEmailInvite`'s single-winner properties *with no
  atomicity defect at all*: two rows sharing a `Code` means two concurrent
  redeemers resolve different rows through `FindLinkByCode` and each atomically
  wins the one it picked, so a `MaxUses: 1` link admits two people. The third is
  what makes re-inviting an address replace rather than duplicate when two such
  calls race. It is a constraint on the *pair* — the same person invited to two
  containers is two legitimate rows — and the suite checks that too, so an
  over-broad reading cannot pass.

  `CreateEmailInvite`, `DeleteEmailInvite` and `CreateLink` also gained explicit
  **MUST**s they were relied on for but did not state: refusing a colliding
  write atomically with performing it, and (for `DeleteEmailInvite`) the
  rows-affected gate `Service.AcceptInvite`'s doc already described as the only
  thing standing between one emailed token and two admissions. `ConsumeLink`'s
  expiry boundary is now written down as well — strictly before `ExpiresAt`,
  with the instant itself already expired — which both backends already
  implemented and neither port sentence said.

### Changed

- **BREAKING (Store port): four new methods on `auth.Store`.** `DeleteUser`,
  `DeleteVerificationsByUser`, `DeleteSessionsByUser` and `MarkUserDeleted`.
  The port shipped in `v0.1.0` with eighteen methods and now has twenty-two, so
  **every third-party backend must grow all four to keep compiling** — a
  compiler error naming exactly which. Both shipped backends implement them,
  and `auth/authtest` covers each with checks a third-party backend can run
  against itself.

  This goes the **opposite way** from how `auth.IdentityStore` was added, and
  the difference is deliberate rather than an inconsistency. Identities are
  *functionality*: a deployment that never offers a social login never needs
  one, and a backend that cannot store one is still a complete backend for
  every deployment that does not — so charging every existing backend for a
  feature most will never enable buys nothing. Deletion is not functionality in
  that sense: every deployment eventually has to remove an account, because a
  user asked, because a regulator requires it, or because the row is garbage,
  so a `Store` that silently could not is not one anybody can finish deploying.
  Putting deletion behind an optional port would have asserted the opposite.

  The three record-kind deletes are **separate methods rather than one
  `DeleteAccount`**, for the same reason the port has no transactions: a
  `Store` is pure persistence, and the order of the cascade is a policy
  decision belonging to the caller, which sequences it fail-safe. Four of the
  eleven MUSTs on the port are new with them:

  - `DeleteUser` removes the user row **only** and MUST NOT cascade to that
    user's sessions or verifications. A backend whose
    `FOREIGN KEY ... ON DELETE CASCADE` does the sweep as a side effect has
    taken the sequencing decision away from the caller and made it
    unobservable — a caller that skipped the sweeps entirely and one that ran
    them in the right order look identical afterwards, against that backend and
    no other.
  - `DeleteVerificationsByUser` MUST filter on `userID` **alone**, never on a
    list of purposes it knows about. `Purpose` is an open string the port
    neither validates nor enumerates, so a fan-out over
    `DeleteVerificationsByUserAndPurpose` does not satisfy it: no such list can
    be complete, and a purpose added by a later flow would walk straight
    through the sweep.
  - `DeleteSessionsByUser` inherits **both** of `DeleteSessionsByFamily`'s
    MUSTs unchanged, because a whole-user revocation is a superset of a family
    one. The survivor an autocommit `DELETE` would leave on a backend whose
    `CreateSuccessorSession` holds a row lock is a fully rotating refresh token
    for an account whose owner has just asked for it to be deleted.
  - `MarkUserDeleted` MUST be a **single atomic step** — all five field writes
    landing together. The two halves fail in opposite directions and both are
    security-relevant: *stamped but not scrubbed* leaves an account every entry
    point already refuses while its address is still hostage and its credential
    digest still stored, and *scrubbed but not stamped* leaves a row that
    reports as **live** with an address derived from the user id, which is not
    a secret — a caller who guesses it can drive a password reset against an
    account that was supposed to be closed.

  The two by-user sweeps answer a match of zero rows with `nil`; `DeleteUser`
  answers `ErrUserNotFound`, because a caller deleting an account needs to know
  whether there was one.

- **BREAKING (schema): `users` gains a `deleted_at` column.** On PostgreSQL it
  is `timestamptz` and nullable, and `store/drops`' `CreateSchema` emits it —
  **on a fresh table only.** An existing deployment must run one migration by
  hand before upgrading:

  ```sql
  ALTER TABLE users ADD COLUMN IF NOT EXISTS deleted_at timestamptz;
  ```

  (with the real table name if `WithAuthNames` moved it). `CreateSchema` can
  self-heal a missing constraint or index, because those are statements it
  issues separately; it **cannot** self-heal a missing column, because a column
  lives inside the `CREATE TABLE IF NOT EXISTS` that no-ops in full against a
  table that already exists. Run against an unmigrated table it therefore
  **reports success while leaving the column absent** — every statement it
  issued genuinely succeeded, and there is nothing it could return that would
  say otherwise. The first `CreateUser` afterwards then fails with SQLSTATE
  `42703` (`undefined_column`), because every `INSERT` names `deleted_at` and
  so does `MarkUserDeleted`'s `UPDATE`. It fails loudly rather than degrading
  quietly, which is the intended direction. **No `DEFAULT`**: `NULL` — not
  anonymized — is what every existing row must hold, and a test pins that a row
  predating the column reads back `DeletedAt` nil.

- **`ChangePassword`, `ResetPassword` and `LogoutAll` now sweep `magic_link`
  tokens too** (`authlayer/auth`), alongside the `password_reset` and
  `email_change` purposes they already swept, and **redeeming an
  `email_change` now sweeps pending magic links** alongside pending reset
  tokens. Both are the same argument as before, applied to the credential the
  milestone added: a `magic_link` token does not let its holder *set* a
  credential, it **is** one, so a link left armed hands the account back the
  moment a rotation finishes. The `email_change` half matters more than it
  looks, because `RedeemMagicLink` does not refuse a link whose recorded
  address no longer matches the account's — it merely declines to re-stamp
  `EmailVerifiedAt` and signs the holder in anyway — so that sweep is the only
  thing between an abandoned mailbox and a live session.

  `Logout` and `RevokeSession` still sweep **nothing**, and that is a rule
  rather than an omission: sweeping there would break "request a link on your
  laptop, sign that laptop out, click it on your phone". All of these sweeps
  remain **sequential-only**, with `RequestMagicLink` joining
  `RequestPasswordReset` and `RequestEmailChange` as a call whose genuinely
  concurrent `CreateVerification` can still mint a token that survives.

- **`ResetPassword` now disconnects every external identity on the account**
  (`authlayer/auth`), and `ChangePassword` deliberately does not.

  A reset is *unauthenticated* recovery: whoever redeemed the token proved
  control of an address and nothing else — no password, no session, no device
  — so it is the one path that must assume every other credential on the
  account is hostile, exactly as it already assumes every session is. An
  external identity is such a credential, and the only one nothing else in the
  package can reach. Without the sweep the documented recovery did not
  recover: an attacker who had provisioned an account holding the victim's
  address kept signing in through their identity after the victim reset the
  password, logged in and called `LogoutAll`, and the victim's own reset even
  certified the address, unblocking `LinkVerified` for the attacker's later
  assertions.

  `ChangePassword` does not sweep, because its caller was already
  authenticated and it is a routine action; that is the same split the package
  already draws between `Logout` and `LogoutAll`. The identity sweep runs
  **before** the session revocation, since an identity left live while the
  revocation runs can mint a session it has already passed — pinned by a
  call-order test, because both orderings leave identical rows behind.

  **Consequence: after a password reset, connected accounts must be linked
  again.** Either the user signs in with the provider once more (rung 2
  re-applies the policy against an address the reset has just certified) or
  the application calls `LinkIdentity`. A `Service` built without
  `WithIdentityStore` sweeps nothing and reports no error.

- **`scope.WithIDGenerator` and `auth.WithIDGenerator` no longer document a
  constraint they no longer have.** Both carried a section headed "A generator
  MUST produce UUID-parseable ids to use store/drops"; both now name the
  option to pass instead. The readme's `Ids` section, its `store/drops` and
  auth-store sections, and its scope options table say the same. The
  behaviour those paragraphs described is still the default and is still
  pinned by test — what changed is that it is now a default with a documented
  way out, rather than a limit.

- **`store/memory`'s `AuthStore` now enforces `Session.TokenHash` and
  `Verification.TokenHash` uniqueness**, which `auth.Store` requires of a
  backend and which this store previously deferred to `store/drops` (its
  package doc said so). The port's own text is why that did not hold: a shared
  hash breaks `MarkRotated`'s single-winner contract with no atomicity defect
  at all, which is the property refresh rotation rests on, and a caller who
  developed against `store/memory` and deployed against `store/drops` met the
  divergence for the first time in production. `CreateSession`,
  `CreateSuccessorSession` and `CreateVerification` now reject a colliding hash
  under the same acquisition of `mu` as the write, exactly as `CreateUser`'s
  email check already worked.
- **New: `memory.ErrTokenHashTaken`**, what those three methods return on a
  collision. Deliberately not `auth.ErrIDTaken` and not a new `auth` sentinel:
  `auth.Store`'s error contract classifies exactly one conflict on the
  `Create*` methods — an id that already identifies a row of that same kind —
  and explicitly leaves token-hash uniqueness to the backend's own constraint.
  `store/drops` answers the same case with the driver's `pg.ErrUniqueViolation`
  unwrapped; both backends now agree the write must fail, and neither pretends
  the port classifies it.
- **`store/drops`' live lane no longer reimplements the `MarkRotated` contract.**
  It ran an independent copy because the original lived in an unexported helper
  in a `_test.go` file, reachable from nowhere else; both backends now run the
  same exported suite. The backend-specific live tests — the ones that stage a
  lock ordering with raw SQL on a second connection, which no port-level suite
  can express — are unchanged.

- **`store/memory`'s `InviteStore` now enforces all three of `invite.Store`'s
  uniqueness constraints** — `EmailInvite.TokenHash`, `(ContainerID, Email)`
  and `Link.Code` — which `store/drops` has always had as `UNIQUE` and which
  this store's package doc used to say it deliberately deferred. That is the
  same develop-here/deploy-there divergence the `AuthStore` change above closed,
  in the package that motivated it: a caller could develop against
  `store/memory` and meet a constraint violation for the first time in
  production. `CreateEmailInvite` and `CreateLink` now reject a colliding write
  under the same acquisition of `mu` as the write itself, so two concurrent
  callers contending for a hash, a pair or a code cannot both succeed.

  `memory.ErrTokenHashTaken` is reused for `EmailInvite.TokenHash` — the same
  column meaning and the same failure as the two `auth` ones, and a caller
  always knows which store it called — and two new package-local sentinels name
  the constraints it does not cover: **`memory.ErrInviteEmailTaken`** and
  **`memory.ErrLinkCodeTaken`**. All three are backend-level errors rather than
  port sentinels, for a stronger version of `ErrTokenHashTaken`'s own reason:
  `invite.Store` classifies *no* conflict-on-create at all, so there is nothing
  to reuse and inventing a meaning for an existing sentinel would tell a caller
  something false. `store/drops` answers the same three cases with the driver's
  `pg.ErrUniqueViolation` unwrapped, and a live test pins that.

  **One divergence is recorded rather than closed**: `store/drops` types an
  invite's and a link's `id` as a `PRIMARY KEY`, so re-using one is a unique
  violation there, while `memory.InviteStore` overwrites the row. `invite.Store`
  documents no id-collision contract and `authlayer/invite` has no sentinel for
  one (unlike `auth.ErrIDTaken`), so the backend is not entitled to invent
  either; the service mints a fresh UUIDv7 for every record. It is written down
  in `memory.InviteStore`'s doc and in the readme instead of being closed
  silently or left unmentioned.

- **`store/memory`'s and `store/drops`' invite tests no longer each carry their
  own copy of the contract.** Roughly thirty per-method cases in
  `store/memory/invite_test.go` and six live tests in
  `store/drops/invite_integration_test.go` — the lifecycle pair, the
  `ConsumeLink` boundaries, `PurgeExpired`, and the two single-winner races —
  are replaced by one `invitetest.RunStoreContract` call each. What stays is
  what the shared suite deliberately does not assert: which sentinel
  `store/memory` answers a duplicate with, and that `store/drops` answers with
  `pg.ErrUniqueViolation`, plus the backend-specific DDL test that reads the
  three constraints back out of `pg_constraint`.

- **`auth.NormalizeEmail` now documents the limitation it accepts.** RFC 5321
  makes an address's LOCAL part case-sensitive and this library deliberately
  does not, so a provider's verification of `MIKE@EXAMPLE.COM` is credited to
  `mike@example.com`; and Go's simple lowercasing maps a few non-ASCII runes
  onto ASCII ones (`U+212A KELVIN SIGN` → `k`, `U+0130` → `i`) while leaving
  ones full case folding would collapse (`U+017F`) alone. Harmless with the
  case-insensitive providers everyone configures; a real bridge with a
  case-sensitive OIDC provider or SMTPUTF8 mailboxes. The rule is unchanged —
  it is shared with `invite` and applied by every store on both sides, and the
  alternative reinstates the duplicate-account failure it exists to prevent —
  and the behaviour is now pinned by test rather than described.

### Fixed

- **`invite` performed no email normalization at all**, while `auth` passed
  every address through `auth.NormalizeEmail` (trim, lowercase) on both sides
  of every read and write. The `(ContainerID, Email)` uniqueness `invite.Store`
  states as a **MUST** was therefore byte-exact, so
  `erin@example.com` and `Erin@Example.com` were two *different* pairs: both
  invitations were written, both tokens were live, and the sweep
  `InviteByEmail` performs first (`DeleteEmailInvitesFor`) matched only the
  spelling it was handed. "Re-inviting an address replaces rather than
  duplicates" — which the port states as a MUST — silently did not hold across
  casing, and the consequence is the one that constraint exists to prevent:
  an admin revoking the row they recognise on a pending-invitations screen
  leaves the other one redeemable, at the invited role, with nothing anywhere
  reporting that it is still out there. No concurrency required.

  Two further consequences. The readme's recipient-binding advice — compare
  `PreviewInvite`'s address against the accepting user's own verified address
  — did not work as written: `Preview.Email` came back verbatim while
  `auth.UserBase.Email` was normalized, so a raw `==` **refused a legitimate
  recipient** invited as `Bob@Example.com`. That failed closed, so it was not a
  hole, but it was wrong. And `PreviewInvite` and `ListInvites` handed the
  address back exactly as it went in, so a management screen showed two rows
  nobody would read as duplicates.

  Normalization now goes where `auth` put it — in the service **and** in every
  backend, with the obligation written on the port:

  - `invite.NormalizeEmail` is new and exported, byte for byte
    `auth.NormalizeEmail`. Both are now wrappers over one unexported
    implementation (`internal/emailnorm`) so they cannot drift. They are two
    functions rather than one because `invite` deliberately takes **no
    dependency on `auth`** — that is a security argument in `invite`'s own
    package doc (it stores no users, so it cannot check a recipient), not an
    accident, and importing `auth` to reach a two-line string function would
    have falsified it.
  - `invite.EmailInvite` gains an **"Addresses are normalized"** MUST: a Store
    must apply it to every address it writes or matches. That makes it the
    fourth obligation stated on a record type rather than a method, and
    `invite.Store`'s count goes from seven MUSTs to eight.
    `CreateEmailInvite` normalizes before the uniqueness check and the write
    and returns the normalized record; `DeleteEmailInvitesFor` normalizes
    before it matches.
  - `Service.InviteByEmail` normalizes before either store call, so an
    application going through the service is covered whatever its backend
    does. The obligation stays on the port because a Store is reachable
    directly and the constraint it guards lives there — the same
    belt-and-braces `auth` has always had.
  - `store/memory` and `store/drops` both comply. `store/drops` keeps a plain
    equality predicate on `email`: the column now holds only normalized
    values, so the `UNIQUE (container_id, email)` index stays usable and no
    `lower(email)` functional index is needed. **No schema change** —
    `CreateSchema`'s DDL is byte-identical.
  - `invitetest` grows three checks —
    `CreateEmailInvite/NormalizesTheAddress`,
    `CreateEmailInvite/ContainerEmailPairIsUniqueAcrossSpelling` and
    `DeleteEmailInvitesFor/NormalizesTheAddress` — bringing it to 46, eight of
    them still races. Two new negative controls, one per side of the
    obligation, assert each check actually bites: a store that writes
    addresses verbatim, and one that sweeps byte-exactly.

  **Migrating a v0.1.0 database.** This changes what gets stored, and rows
  written by v0.1.0 may hold a non-normalized address that a normalized lookup
  will no longer match. The symptom is not data loss: those rows stay listable
  and their tokens stay redeemable, and revoking by id still works. What breaks
  is replacement — re-inviting `Erin@Example.com` now writes
  `erin@example.com`, which does not match the legacy row, so the legacy
  invitation survives alongside the new one and you are back in exactly the
  state this fix removes. `store/memory` needs nothing; it starts empty. For
  `store/drops`, run this once against your invitations table (named
  `organization_invites` by default — use whatever you passed to
  `WithInviteNames`):

  ```sql
  -- 1. Look before you delete. Every group returned is a set of rows this
  --    defect created: two or more live invitations for one person.
  SELECT container_id, lower(btrim(email)) AS normalized,
         count(*), array_agg(email), array_agg(id)
  FROM organization_invites
  GROUP BY 1, 2
  HAVING count(*) > 1;

  -- 2. Keep the newest invitation per (container, normalized address) and
  --    drop the rest. This DELETES live invitations: their emailed tokens
  --    stop working, so re-invite anyone you drop. Skip this step and step 3
  --    will fail on UNIQUE (container_id, email), which is the constraint
  --    doing its job.
  DELETE FROM organization_invites a
  USING organization_invites b
  WHERE a.container_id = b.container_id
    AND lower(btrim(a.email)) = lower(btrim(b.email))
    AND (a.created_at, a.id) < (b.created_at, b.id);

  -- 3. Fold what is left. Tokens are unaffected — only the email column
  --    changes, and acceptance looks up by token_hash.
  UPDATE organization_invites
  SET email = lower(btrim(email))
  WHERE email <> lower(btrim(email));
  ```

  Run steps 2 and 3 in one transaction. If step 1 returns no rows and step 3
  reports `UPDATE 0`, you were never affected and there is nothing to do — the
  migration is only needed by a deployment that actually received mixed-case
  or padded addresses. The `auth` tables are untouched: they have always been
  normalized. Invite **links** are untouched too; they carry no address.

  One caveat, for ASCII-only correctness: PostgreSQL's `lower()` is
  locale-dependent and `btrim()` with no second argument strips spaces only,
  while Go's `strings.ToLower`/`strings.TrimSpace` are Unicode-aware. The two
  agree on every ASCII address. If your table holds addresses with non-ASCII
  local parts or exotic whitespace, verify the fold in a transaction and roll
  back before committing.

- **Four readme snippets that did not compile.** The RBAC quick start — the
  first snippet anyone copies — declared `ok` and never read it (`declared and
  not used`); the `Context` snippet redeclared both `userID` and `orgID` with
  `:=`; the `Checking permissions` snippet used `:=` for three successive
  assignments to one `err`; and the invitation-link snippet redeclared `owner`
  while its prose said it continued the block above. The values these snippets
  claimed were all correct — the code around them was not.

  Every fenced `go` block in the readme is now extracted programmatically and
  compiled: 30 of the 34 are executed and every `//` output claim in them is
  diffed against the run, two are compiled but not executed (the `store/drops`
  wiring, which needs a live PostgreSQL, and the `auth/authtest` snippet,
  which is a `*testing.T` function), and the two remaining are the import
  blocks themselves — used verbatim as the extracted programs' own imports, so
  a missing or surplus path fails the build. That is how the four above were
  found, and it is why the extraction is programmatic rather than a hand copy.

- **The `Ids` snippet passed `ulid.Make` straight to `WithIDGenerator`**,
  which takes a `func() string`; `github.com/oklog/ulid/v2`'s `Make` returns a
  `ulid.ULID`. The module is now named in the snippet and the adapter is
  written out. This one is not covered by the extraction above — authlayer
  does not depend on that module and a doc example is not a reason to start.

- **"Nullable columns are not supported yet" was never true of `*time.Time`.**
  The readme's `store/drops` section, `docs/storage/postgres` and
  `docs/authorization/custom-scopes` all said pointers panic at construction
  and that nullable columns are unsupported. `store/drops`' own panic message
  lists `*time.Time (nullable)` among the supported types, `colSet.add` types
  such a column without `NOT NULL`, and `bind` renders a nil one as the SQL
  `NULL` keyword — which is exactly how `users.email_verified_at`,
  `sessions.rotated_at` and now `identities.last_used_at` work, all three of
  them printed as `NULL` columns on the schema page of the same site. All
  three places now say what the code does: `*time.Time` is accepted and is the
  one nullable shape; any *other* pointer panics, with the column and the type
  named.

## [0.1.0] - 2026-08-29

### Added

- **Runnable end-to-end example** (`examples/auth`) — `go run ./examples/auth`
  wires `auth` + `org` + `invite` over `store/memory` and prints a trace: sign
  up, verify the address, log in, verify the access token, create an
  organization, invite a second user by email, sign that user up and accept,
  authorize, refresh, log out. It is also the one place the `auth`/`invite`
  seam is written down — `invite.New` takes the generic `*scope.Service`, so
  the expression is `invite.New(orgSvc.Service, ...)`, reaching the field
  `org.Service` embeds. `examples/basic` still covers the RBAC half alone.
- **Per-action query guards** (`authlayer/scope`) — `Service.PermissionGuard`
  restricts a table's rows to the containers where the subject holds a specific
  `(resource, action)` grant, rather than to those they merely belong to. The
  container set is resolved through the same ladder `Can` uses, so a guard and
  an in-memory check agree for every container where the subject holds a
  membership whose role key resolves, and every known divergence denies rather
  than leaks. An empty set renders as a false predicate, a missing subject is
  `pg.ErrSubjectMissing`, a nil column is an error rather than a panic, and a
  store failure aborts the query instead of narrowing it to nothing.
- **`Service.ContainersWith`** (`authlayer/scope`) — the same answer as a plain
  `[]string`, exported so a hot path can hoist the id set out of the guard. A
  membership whose role key resolves to nothing denies its own container only,
  not the whole call. Like `HasPermission` it takes the user id as an argument
  and checks nothing about the caller, so do not expose it directly to end
  users.
- **`MemberStanding`** (`authlayer/scope`, re-exported as `org.MemberStanding`)
  — a flattened container/role/owner row, fetched by the drops store in a
  single join.
- **UUIDv7 identifiers** (`authlayer/internal/uid`) — a dependency-free RFC 9562
  generator, now the default for containers and custom roles. Time-ordered, so
  ids sort in creation order and a primary-key index stays dense.
  `WithIDGenerator` still overrides it — but only with a generator whose
  output PostgreSQL's `uuid` parser accepts, if `store/drops` is the backend;
  see the `store/drops` entry below.
- **Generic PostgreSQL store** (`authlayer/store/drops`) — `Store[C, M]` derives
  its columns from the `drop:` tags of the container and member types and takes
  its table names from `WithNames`, so a new scope instance needs no new store.
  `WithTextUserIDs` keeps the user-id columns — `user_id`, `owner_id`,
  `invited_by`, `created_by` — as `text` for consumers using only the RBAC half
  against a non-UUID user table. The ids authlayer mints for itself (`id`,
  `container_id`, `parent_id`) stay `uuid` either way, which is the constraint
  `scope.WithIDGenerator` and `auth.WithIDGenerator` inherit: a generator
  returning a ULID or a sequence number fails the first write with
  `SQLSTATE 22P02`, at the store rather than at construction, and `store/memory`
  accepts it happily — so it is invisible until deployment. Both docs now say
  so, and both behaviours are pinned by test. A container or member
  type missing a required `drop:` tag, or carrying an unsupported field type, is
  now rejected at construction with the type and the tag named, rather than
  nil-dereferencing at the first query.
- **Nested scopes** (`authlayer/scope`) — a container can now sit inside
  another (a team inside an organization, a project inside a team) via
  `WithParent(parent, inherit)` and `WithContainerResource(resource)`. The
  container type embeds the new `NestedBase` (adds the parent link on top of
  `ContainerBase`) and satisfies the new `Nested` interface; `ParentScope` is
  the narrow view a child needs of its parent — `*Service` satisfies it
  through the newly exported `Service.Standing`. An `Inheritance` function
  projects a subject's parent standing onto the child as grant *names*,
  recompiled against the child's own `Access` — never as bits, since a
  `Permission` is a bitset over one `Statements` space and a parent's bits
  mean nothing in a child's. `InheritElevation` (the default when `WithParent`
  is given no projection) confers standing on nobody but the truly elevated —
  the owner alone, under a default role set, since the built-in `admin` role
  is deliberately kept short of full permission; `InheritWhen` builds a
  projection conferring elevation on anyone whose parent standing grants a
  named capability, for "whoever may manage teams administers each team." `New`
  panics when `WithParent` is given a container type that does not embed
  `NestedBase` — the same construction-time-bug treatment
  `access.Access.NewRole` gives a mis-declared default role. **Nesting also
  changes `Service.CreateContainer`: on a parented scope it now performs a
  permission check against the parent (`<containerResource>:create`, or
  elevated parent standing) before creating anything, where the unparented
  form performs no check at all** — a caller wiring `WithParent` for the first
  time should expect this.
- **`Service.Standing`** (`authlayer/scope`) — exported: the same resolution
  `Can` performs (a subject's permissions in a container, and whether they are
  elevated there), reading nothing from the context and checking nothing about
  the caller, like `HasPermission`. Exists so a nested scope's parent can be
  asked through `ParentScope`; do not expose it directly to end users.
- **`Policy.MembersFromParent`** (`authlayer/scope`) — on by default; in a
  nested scope, refuses `AddMember` with the new `ErrNotParentMember` when the
  target holds no standing in the parent — you cannot be on a team without
  being in the organization that owns it. Effective only where `WithParent` is
  configured; the owner membership `CreateContainer` seeds is not checked
  separately, since creating a container in a parent already requires standing
  there.
- **`access.Access.Union`** — combines several permissions into the set
  granting every pair any of them grants. A permission from a foreign
  `Statements` is rejected rather than silently misread; the zero Permission is
  accepted and contributes nothing. Backs nested scopes, where a member's own
  role permissions merge with the grants projected from their parent standing.
- **`access.Permission.IsZero`** — reports whether a permission grants nothing
  at all, the counterpart to `IsFull`. Needed because a projection can return a
  non-empty grant map that still confers nothing
  (`map[string][]access.Action{"doc": nil}` validates and compiles) — "the map
  is non-empty" and "something was actually granted" are different questions,
  and standing resolution in a nested scope needs the second one.
- **`team`** (`authlayer/team`) — a nested "team" instance of the engine, teams
  living inside organizations. Mirrors `org`'s shape: `Team` / `Member`
  (embedding `NestedBase` / `MemberBase`), `NewAccess`, `New` (wires
  `WithParent`/`WithContainerResource` itself so a caller cannot forget
  either), `CreateTeam`, `WithTeam`/`TeamFrom`, and team-flavoured error
  aliases including `ErrNotParentMember`. `ParentStatements` names what the
  parent organization's `Access` must declare (`team:create`) for anyone but
  the org owner to create a team — merge it into `org.NewAccess`'s statements.
- **`invite`** (`authlayer/invite`) — a new package admitting a person who has
  no standing in a scope yet, by a credential rather than a direct
  `AddMember` call. `InviteByEmail` mints a one-time **bearer** token — it
  pays out at most once, but to whoever presents it: acceptance never compares
  the accepting subject to `EmailInvite.Email`, which is a delivery hint and
  an audit record, since `invite` stores no users and takes no dependency on
  `auth`, so it has no verified address to compare against. (`auth`, below,
  does store users — this package simply cannot see them.) Bind an invitation to its recipient in your own
  application if you need that, using `PreviewInvite` to read the invited
  address without consuming the token. Only the token's sha256 is persisted
  (`EmailInvite.TokenHash`), since the token is
  emailed once and never redisplayed to anyone, including the inviter — a
  database leak of the row cannot be replayed into admission. `CreateLink`
  mints a reusable link bounded by an explicit `MaxUses` (0 meaning
  unlimited) and `ExpiresAt` (nil meaning never); `Link.Code` is stored in
  clear, because a link's whole purpose is to be re-displayed on a "manage
  invite links" screen and a hash would make that impossible — a link's
  security instead comes from `MaxUses`, `ExpiresAt` and revocation, weighed
  atomically by `Store.ConsumeLink`. `AcceptInvite` and `JoinViaLink` redeem
  a credential and call the new `scope.Service.GrantMembership` (see below)
  to admit: both claim the credential atomically FIRST — `AcceptInvite` via
  the rows-affected-gated `Store.DeleteEmailInvite`, `JoinViaLink` via the
  atomic `Store.ConsumeLink` — and admit SECOND, so a failure after the claim
  burns the credential and admits no one (under-admission) rather than
  risking a credential paying out twice (over-admission); accepting is
  therefore not safe to retry with the same token. On a **nested** scope that
  matters more than it sounds: under the default `Policy.MembersFromParent`,
  `GrantMembership` returns `scope.ErrNotParentMember` for an invitee who does
  not already hold standing in the parent, deterministically — so a team
  invitation sent to someone not yet in the organization burns itself every
  time. Admit people to the parent first, or clear `MembersFromParent` for
  that scope. Delivery is entirely the
  caller's own responsibility: `InviteByEmail` returns the plain token
  exactly once, and authlayer knows no base URL and owns no transport;
  `WithNotifier` is optional sugar over calling a `Notifier` yourself right
  after. `ListLinks` keeps a link's `Code` in the result only when the caller
  holds `invite:create` — the same permission `CreateLink` requires, so a
  reader granted `invite:read` alone sees no code at all — AND is elevated or
  the link's role resolves to a permission set that is a `SubsetOf` their own
  current standing; everything else is blanked. Both halves are load-bearing,
  not cosmetic. The standing half exists because `invite:read` sits on the
  merged control-statement surface and so is granted to the built-in `admin`
  automatically (see the next entry), and `admin` is deliberately not
  `IsFull`; without it a non-elevated admin could read the owner's link code
  in clear, leave the container, and rejoin at the owner role through
  `JoinViaLink`, since `GrantMembership` runs no escalation check of its own.
  The capability half exists because a reader with `invite:read` and no
  `invite:create` could not have minted *any* link, so handing them a working
  code would make read imply admit and let them admit arbitrary third
  parties. `WithRecheckInviterOnAccept` (default
  `true`) re-runs the privilege-escalation guard against the inviter's
  CURRENT standing before `AcceptInvite`/`JoinViaLink` admit anyone, so a
  since-demoted or since-departed inviter's pending invitation stops paying
  out, at the cost that a pending invitation dies when its inviter leaves the
  container. `PurgeExpired` deletes every expired invite and link across
  every container the `Store` holds, for a cron; it performs no
  authorization and reads neither a subject nor a container from the
  context. `CreateLink` refuses a negative `maxUses` with
  `ErrInvalidMaxUses` rather than minting a link that can never be redeemed
  (0 still means unlimited). Seven new sentinel errors:
  `ErrInviteNotFound`, `ErrInviteExpired`, `ErrLinkNotFound`,
  `ErrLinkRevoked`, `ErrLinkExpired`, `ErrLinkExhausted`,
  `ErrInvalidMaxUses`.
  `store/memory` and `store/drops` each ship a reference `invite.Store`
  implementation, the latter with its own `CreateSchema`.
- **`scope.Service.GrantMembership`** (`authlayer/scope`) — admits a user to a
  container at a role, performing NO check that any actor is entitled to do
  so: no `member:create`, no privilege-escalation guard. It exists for
  invitation acceptance, where the person being admitted has no standing to
  check and the inviter is not present to have one — every actor-facing rule
  was already applied when the credential was minted. **This is a
  deliberately unchecked admission path**: it is only as safe as whatever
  decided to call it, must never be exposed to end users, and must never be
  reachable from a path a principal could reach without holding a credential
  minted for exactly this container and role — `invite.Service.ListLinks`'s
  redaction is what makes that true there, and anything else calling this
  owes the same care. Rules that are not about the actor still apply: a
  duplicate is `ErrAlreadyMember`, an unresolvable role is `ErrRoleNotFound`,
  and under `Policy.MembersFromParent` the user must already hold standing in
  the parent scope. It emits `MemberAdded`, so that event now has two sources
  rather than one — and on this path `Event.ActorID` is the **admitted** user,
  equal to `TargetID`, since the call reads no ctx subject and there is no
  actor to name (the inviter authorized it at mint time and is not present).
  An audit hook therefore cannot distinguish an invitation-based admission
  from a self-add on the event alone, and the invitation's `InvitedBy` never
  reaches the hook; record that attribution when the invitation is minted if
  you need it.
- **`invite` control statements** (`authlayer/scope`) — `ControlStatements`
  and `NewAccess` now declare the `invite` resource (`create`, `read`,
  `delete`) on every scope's merged permission surface, for the `invite`
  package's own mint/list/revoke checks; the engine itself checks none of
  it. **This widens the built-in `admin` role automatically**: `admin` is
  defined as "every declared pair except `<container>:delete`", so every
  `admin` — new and previously seeded — gains `invite:create`, `invite:read`
  and `invite:delete` the moment this version is adopted, with no code
  change required. An application that treats `admin`'s current grant set as
  fixed should account for that before upgrading.
- **`scope.Service.RolePermissions`** and **`scope.Service.Container`**
  (`authlayer/scope`) — two new exported primitives, added so `invite` (or
  any other package built on `scope`) can ask the engine's own questions
  instead of reconstructing an approximation of them. `RolePermissions`
  resolves a role key to its permission set exactly the way every
  permission check in the engine does — a code-defined role first, then a
  custom role loaded from the store — and answers a strictly larger question
  than `ListRoles`: `ListRoles` enumerates only the three hardcoded defaults
  plus a container's *stored* custom roles, so a code-defined role
  registered directly with `access.Access.NewRole` resolves through
  `RolePermissions` but is invisible to `ListRoles`, and approximating the
  former from the latter would silently treat such a role as nonexistent.
  `Container` loads a container by id, returning the whole record — it
  exists because `GrantMembership` returns only the new membership, not the
  container the invitee was just admitted to, and invitation acceptance
  needs to hand one back. Like `Standing` and `HasPermission`, neither reads
  anything from the context nor checks that the caller is entitled to ask —
  do not expose either directly to end users.
- **`token`** (`authlayer/token`) — opaque bearer tokens and a hand-rolled,
  single-algorithm HS256 JWT, standard library only. `GenerateOpaque` draws
  32 bytes from `crypto/rand` and returns the hex plaintext alongside its hex
  sha256, so a session row stores only what `HashOpaque` recomputes from a
  presented token and a database read cannot be replayed into a credential.
  `Issue`/`Parse` are deliberately not a general-purpose JWT library: `Parse`
  supports exactly one algorithm and compares the header's `alg` to the
  literal `"HS256"` before verifying a signature or decoding a payload, so
  neither `alg: none` nor RS256/HS256 key confusion has a dispatch to
  exploit. That single check is the entire justification for hand-rolling
  rather than taking a dependency, and generalising this package to a second
  algorithm brings both attacks back. The same reasoning covers the key: both
  functions refuse an HMAC key under 32 bytes (RFC 7518 §3.2) with
  `ErrKeyTooShort`, nil and empty included, because an unset `JWT_SECRET` is
  `alg: none` reached through the key parameter instead of the header — and
  `Parse` refuses the whole call if *any* key in its list is short rather
  than quietly skipping it. Signatures are compared with `hmac.Equal`, and
  every segment is decoded with strict (canonical) base64, so one token has
  exactly one valid encoding and the raw string is usable as a denylist or
  replay-cache key. `Parse` accepts a list of keys and tries each while
  `Issue` always signs with the first, which is how a signing key rotates.
  `Claims.Extra` nests application-defined claims under a single `"ext"`
  object rather than merging them into the top level, so an extender cannot
  shadow `sub`, `sid`, `email`, `iat` or `exp` — structurally, not by
  denylist. Six sentinel errors: `ErrMalformedToken`,
  `ErrUnsupportedAlgorithm`, `ErrInvalidSignature`, `ErrExpiredToken`,
  `ErrKeyTooShort`, `ErrInvalidTTL`.
- **`password`** (`authlayer/password`) — the `Hasher` port
  (`Hash` / `Verify` / `Dummy`) with a bcrypt implementation, plus `Rules`,
  `DefaultRules` and `Validate` for a strength policy. `Verify` returns false
  rather than panicking for an empty, truncated or foreign hash, so whatever
  a datastore returns can be passed through unvalidated. `Dummy` runs a real
  bcrypt comparison against a throwaway hash and discards the outcome; its
  only purpose is to spend comparable time on a user-not-found path so
  response latency does not reveal whether an address is registered.
  Discarding the result is the point — deleting the call because "it does
  nothing" silently reinstates the timing oracle. `DefaultRules` is 12
  characters requiring an uppercase letter, a lowercase letter, a digit, and
  one character that is neither a letter, a digit, nor whitespace; whitespace
  remains legal anywhere in a password but does not satisfy `RequireSpecial`,
  so padding a three-character password with spaces cannot certify it
  compliant. `Validate` returns the names of the failed rules
  (`min_length`, `upper`, `lower`, `digit`, `special`) in a fixed order
  rather than an error, and this package defines no sentinels. `Bcrypt(0)`
  means bcrypt's own default cost; any other value passes through, so
  bcrypt's rules apply — 1–3 are silently promoted to the default by the
  library, above 31 is an error from `Hash`.
- **`auth`** (`authlayer/auth`) — authlayer now owns identity: a user record,
  its password credential, revocable server-side sessions, and the one-time
  tokens for signup confirmation, email change and password reset. **This
  ends the "authlayer stores no users" invariant** — but only for consumers
  that use this package. `scope`, `org`, `team` and `invite` are unchanged
  and still carry a user id as an opaque value with no foreign key to
  anything. Unlike `scope.Service`, `auth.Service` is **not** generic over an
  application type: a container is genuinely application-shaped, a credential
  record is not. `auth.UserBase` (id, normalized email, `EmailVerifiedAt`,
  password hash, timestamps) is the whole record the package needs and the
  whole record it persists, so an application's profile fields stay in its own
  tables, keyed by `UserBase.ID`, and authlayer's migrations never own a
  product-shaped column.
  `auth.NormalizeEmail` (trim, lowercase) is applied on every read and write,
  so a case or whitespace variant can neither create a duplicate nor slip
  past a uniqueness check. The surface is `SignUp`, `VerifyEmail`, `Login`,
  `Refresh`, `VerifyAccessToken`, `Logout`, `LogoutAll`, `ListSessions`,
  `RevokeSession`, `User`, `ChangePassword`, `RequestPasswordReset`,
  `ResetPassword`, `RequestEmailChange` and `PurgeExpired`, configured through
  `WithHasher`, `WithRules`, `WithJWT`, `WithRefreshTTL`,
  `WithVerificationTTL`, `WithPasswordResetTTL`, `WithClock`,
  `WithIDGenerator`, `WithRateLimiter`, `WithPasswordResetRateLimiter`,
  `WithRequireVerifiedEmail` and `WithClaimsExtender`.
  `Login` and `Refresh` both return a `LoginResult` — user, access token,
  refresh token — rather than one returning a named struct and the other a
  positional tuple whose two same-typed token strings a caller can transpose
  silently. `VerifyAccessToken` verifies against the keys `WithJWT` already
  holds, so an application does not keep a second copy of the key material for
  the one operation it performs per request; it returns `token`'s own
  sentinels, and its `SessionID` claim is what `ChangePassword`'s
  `currentSessionID` consumes. `User(ctx, id)` is the read path that scrubs
  `PasswordHash`, which `Store.FindUserByID` — previously the only exported
  way to read a user — does not. `PurgeExpired` is a pass-through so a caller
  holding only the `Service` can run the housekeeping this package requires;
  retained predecessor rows are removed by nothing else. The four token
  lifetimes each have an option: `WithJWT`, `WithRefreshTTL`,
  `WithVerificationTTL` (24h default, covering `signup` and `email_change`)
  and `WithPasswordResetTTL` (1h default). Every duration option ignores a
  non-positive value and keeps its default. `WithJWT` validates the WHOLE key
  list, not just `keys[0]`, and ignores one containing any unusable key
  exactly as it ignores a nil one: `token.Issue` checks only the key it signs
  with while `token.Parse` refuses a call whose list contains a short key, so
  a `Service` built from `{good, short}` would otherwise mint access tokens it
  could never verify — every login succeeding and every subsequent request
  failing. The floor is not restated here; each key is checked by asking
  `token.Issue`.
  **Revocation is per-family.** `LogoutAll`, `ChangePassword`,
  `ResetPassword`, `RevokeSession` and reuse detection all revoke whole
  session families, because rotated-but-unexpired rows are retained and are
  what makes a replay detectable. `RevokeSession` takes a session id but
  revokes that id's family — a family is one login's rotation chain, and
  `ListSessions` returns rotation history (about 97 rows per device per day
  at the default TTL), so revoking one listed row signed nobody out. A
  family is not a guarantee of one *device*: `Refresh` inherits the
  predecessor's `UserAgent`/`IP`, so a rotated stolen token wears the
  victim's fingerprint inside the victim's own family.
  `Logout` presented a *superseded* token likewise revokes the family rather
  than deleting the row a replay would trip over; presented a current token
  it stays a single-session logout.
  **What "revocable" does and does not mean:** revoking a session removes the
  refresh token's row, so `Refresh` on it fails immediately and
  `ListSessions` stops reporting it — but it does **not** invalidate an
  access token already issued for that session. That token is a stateless
  JWT this package never looks up, so a device holding one keeps working
  until it expires, up to 15 minutes on the default TTL. Every "signs out
  every device" guarantee in this package — `LogoutAll`, `RevokeSession`,
  `ChangePassword`, `ResetPassword`, and reuse-triggered family revocation —
  carries that bound. The `sid` claim (`token.Claims.SessionID`) is the hook
  for closing it: an application needing sooner-than-TTL revocation looks
  `sid` up in the `Store` per request, which this package deliberately leaves
  as the caller's choice rather than imposing a round trip on every request.
  **Refresh rotation with reuse detection:** each refresh supersedes the
  presented token and mints a successor in the same `FamilyID`; presenting an
  already-rotated token is a replay, and since a stolen token being replayed
  and a client retrying a raced request are indistinguishable here, every
  replay revokes the **entire family** and returns `ErrTokenReuse`. An
  *expired* token is ordinary end-of-life, is `ErrTokenInvalid`, and leaves
  the family intact. Two `Store` methods carry the atomicity that makes this
  hold under concurrency, each documented as a MUST with the failure it
  prevents: `MarkRotated` is a compare-and-set exactly one concurrent caller
  wins, and its result — never a `RotatedAt` read a moment earlier — is what
  authorizes minting; `CreateSuccessorSession` then persists the successor
  only if the predecessor row still exists, so `Refresh` returns
  `ErrSessionRevoked` rather than resurrecting a family revoked in the window
  between the two. Both windows stay closed only insofar as the backend
  honours the atomicity the port demands; both shipped stores do.
  Where a backend's answer is checkable, it is checked: a `Session` handed
  back with no `FamilyID` leaves nothing to revoke, so every path that
  revokes a family fails closed with `ErrStoreContract` rather than issuing a
  revocation on an empty key that matches no rows — firing the alarm, or
  reporting a device signed out, while containment silently no-ops. Three
  paths reach it: `Refresh` on a reported replay, `Logout` of a superseded
  token, and `RevokeSession`. Only `Refresh` has a second signal worth
  keeping, so only there is it wrapped alongside `ErrTokenReuse`; the other
  two return it alone. `ErrTokenReuse` returned ALONE still means the family
  is already revoked; wrapped, it means a replay was detected and the family
  may still be live.
  **Enumeration-safe sign-up:** `SignUp` returns
  `(SignUpResult{Created: false}, nil)` for an address already registered —
  never an error — and holds the property by construction rather than by
  argument: the password is validated before the address is looked up, and
  every `Store` call after `CreateUser` runs on both branches with its result
  discarded on the duplicate one, so no failure is reachable on one branch
  only. A probe never disturbs the real accountholder's pending verification,
  and the duplicate branch hands back the **zero** `User` rather than the
  account it found, whose `ID`, `CreatedAt` and `EmailVerifiedAt` would each
  answer "is this address registered?" on their own; `PasswordHash` is cleared
  on the branch that does populate `User` (and carries `json:"-"` on
  `UserBase`). The caller must emit a fixed response regardless of the
  outcome — stronger than "don't branch on `Created`", since `Created`,
  `VerifyToken`'s presence, whether `User` is populated and the wall clock are
  all observable — or the property is lost at the transport layer.
  `RequestPasswordReset` returns `(token, ok, nil)` and never errors merely
  because an address is unknown; a denial from the address-keyed limiter
  returns that same shape rather than `ErrRateLimited`, which would itself be
  an oracle. What remains is timing: a known address answers several times
  slower than an unknown one, because the known branch performs two extra
  writes. The measurement is a test rather than a claim —
  `TestRequestPasswordResetTimingChannelLive` in `store/drops`' integration
  lane reports it — and what reproduces is the shape: the two distributions
  are disjoint at the known branch's 5th percentile against the unknown
  branch's 95th. On one machine that was a 3.3–8.7 ms known median against
  0.5–1.0 ms, roughly 5.5–12×; absolute figures vary by host and even by day
  on the same host, and a deployment's gap is wider still to the extent
  autovacuum is behind. Table size does not widen it: `verifications` carries
  an index on `(user_id, purpose)`, so the invalidating `DELETE` reads one
  user's rows instead of scanning the table — 40,000 other users' pending
  tokens moved the known branch's floor from 2.3–2.5 ms to 4.7–5.0 ms without
  that index and left it unchanged with it.
  `WithPasswordResetRateLimiter` is what bounds that sampling, and it also
  bounds the flip side of re-issue invalidation — anyone who knows an address
  can destroy that account's pending reset link by looping requests. There is
  no default limiter of either kind: the zero configuration rate-limits
  nothing, and a wired limiter that returns an error denies, since an
  authentication decision that cannot be made must fail closed.
  **The password lifecycle:** `ChangePassword` requires the current password
  and spares only the caller's own session family (an empty or foreign
  `currentSessionID` revokes everything — the fail-closed direction);
  `ResetPassword` claims the verification before applying it, so a failure
  after the claim burns the token rather than leaving it redeemable twice,
  and then revokes every session. A completed reset also stamps
  `EmailVerifiedAt` when it is not already set — **after** the revocation, not
  before, so a failure in that optional audit stamp cannot return an error
  having rotated the credential while leaving every session, a thief's
  included, still refreshable: a reset token is only ever
  deliverable to the address it was minted for, so redeeming one proves
  control of that address. That is the only way out of
  `WithRequireVerifiedEmail(true)` for an address whose signup mail was lost
  or was claimed by someone who does not own it, since authlayer exposes no
  resend path. An already-verified address keeps its original timestamp, and
  an account whose address changed since the token was minted is not
  certified at all. Both also invalidate every outstanding
  `password_reset` **and** `email_change` token for the account, closing two
  doors: the attacker who requested a reset link and waited keeps a way in for
  its whole TTL even after the victim changes their password, and — the
  stronger of the two — an `email_change` token lives 24 hours rather than
  one and is redeemed by `VerifyEmail` with no authentication at all, moving
  the account to an address from which the victim cannot recover, since
  `Login` and `RequestPasswordReset` both look accounts up by email.
  **`LogoutAll` sweeps both purposes too**, after revoking the sessions:
  "sign out of every device" is what a user clicks on spotting an intruder, so
  it must leave nothing armed that undoes it, and sweeping only on the two
  credential paths meant the takeover survived it. `Logout` and
  `RevokeSession` sweep **nothing**, deliberately — they are per-device and
  routine, and sweeping there would break a flow with no attacker in it:
  request an email change on a desktop, sign that desktop out, click the link
  that arrives on a phone. Each says so in its own doc.
  **The mirror holds as well:** redeeming an `email_change` invalidates the
  account's outstanding `password_reset` tokens, because a reset link is
  deliverable to exactly one address and moving the account away from it must
  not leave a link in the abandoned mailbox able to reset the credential at
  the new one. That redemption does *not* revoke sessions: `VerifyEmail` is
  unauthenticated by construction, so a sign-out-everywhere effect there would
  hand a denial-of-service lever to anyone who obtains the link, and arming
  the token already cost the current password — `LogoutAll` is the
  authenticated control for that. **Every sweep is sequential only:** nothing
  orders them against a `RequestPasswordReset` or `RequestEmailChange` whose
  own `CreateVerification` is genuinely concurrent, and such a token can still
  survive and later redeem; closing that would need a transaction spanning
  both, which the `Store` port does not offer. **`RequestEmailChange` requires
  the current password**, exactly as `ChangePassword` does and with the same
  timing discipline (a credential-less account spends a comparable `Dummy` and
  gets the same `ErrInvalidCredentials`; a caller who fails the check is not
  told whether the address they proposed even parsed). Arming a rotation of
  the account's login identifier is the same kind of act as rotating its
  password, and `VerifyEmail` redeems the result with no authentication at
  all — so without the check a briefly-held session, or a leaked 15-minute
  access token, bought a 24-hour account takeover. It performs
  no address pre-check — uniqueness is enforced atomically at redemption
  instead, because a pre-check was an unrate-limited "is this registered?"
  oracle for any authenticated caller. Eighteen sentinel errors:
  `ErrUserNotFound`, `ErrEmailTaken`, `ErrIDTaken`, `ErrSessionNotFound`,
  `ErrVerificationNotFound`, `ErrEmailMismatch`, `ErrWeakPassword`,
  `ErrInvalidCredentials`, `ErrEmailNotVerified`, `ErrRateLimited`,
  `ErrMissingIP`, `ErrVerificationExpired`, `ErrVerificationPurpose`,
  `ErrTokenInvalid`, `ErrTokenReuse`, `ErrSessionRevoked`,
  `ErrEmailRequired`, `ErrStoreContract`. `store/memory` and `store/drops`
  each ship a reference
  `auth.Store`; `Store.PurgeExpired` sweeps expired sessions and
  verifications for a cron, and never removes users.
- **Auth persistence** (`authlayer/store/memory`, `authlayer/store/drops`) —
  `memory.NewAuthStore()` is the reference in-process implementation: every
  method holds one mutex for its entire body, so every atomicity MUST the port
  states is satisfied and no check-then-write can be split, and it enforces
  one-account-per-normalized-email plus the id-collision contract on every
  `Create*`. Like `NewInviteStore` it defers the `token_hash` uniqueness the
  port requires of a backend to the SQL store. `dropsstore.NewAuthStore(db)` persists three
  tables — `users` (`UNIQUE (email)`), `sessions`
  (`UNIQUE (token_hash)`, `INDEX (family_id)`) and `verifications`
  (`UNIQUE (token_hash)`, `INDEX (user_id, purpose)`) — renameable via
  `WithAuthNames`, with its own `CreateSchema` and `Schema()`. All three
  constraints are load-bearing: `UNIQUE (email)` is what `SignUp` reads
  "already registered" off, and the two hash constraints keep a token lookup
  single-row. So are both indexes: `family_id` keeps every `LogoutAll`
  iteration off a table scan, and `(user_id, purpose)` keeps
  `RequestPasswordReset`'s invalidating `DELETE` off one — the second is a
  security index, since a scan there widens that method's disclosed timing
  channel in proportion to the pending tokens held for every user. `email` is declared
  both inline and as a named guarded `ALTER TABLE`, because
  `CREATE TABLE IF NOT EXISTS` is a no-op against a pre-existing table and
  the `ALTER` is what self-heals one created by hand or by an older version.
  Unlike the RBAC and invite stores this one offers no text-user-id option —
  it owns the `users` table its `user_id` columns reference. No foreign keys
  are declared between the three tables.

### Changed

- **BREAKING (grants): every `admin` silently gains `invite:*` on adoption.**
  `ControlStatements` now declares the `invite` resource, and the built-in
  `admin` role is derived from the merged surface as "every declared pair
  except `<container>:delete`" — so every `admin`, new and previously seeded,
  holds `invite:create`, `invite:read` and `invite:delete` the moment this
  version is adopted, with no code change and no migration to notice. Nothing
  in a running deployment announces it. An application that treats `admin`'s
  grant set as fixed should account for it before upgrading; define a custom
  role if `admin` must not mint invitations. Listed in full under **Added**
  (`invite` control statements), and repeated here because the widening lands
  on existing installations rather than only on new ones.
- **BREAKING (Store port): two new methods.** `ContainerStore` gains
  `ListUserContainers` and `MemberStore` gains `ListUserStandings`. Both ship
  implemented in `store/memory` and `store/drops`; a third-party Store must add
  them. `ListUserStandings` should be one join, not a query per container — it
  runs on every guarded query.
- **BREAKING (schema): id columns are now `uuid`.** Every id authlayer
  generates is a UUIDv7 and its column is typed `uuid` rather than `text`.
  `CreateSchema` on a fresh database needs nothing; on an existing one the old
  ids are 24 hex characters, too short for the 32 hex digits `uuid` requires,
  so widen before casting rather than casting directly — `ALTER TABLE <t>
  ALTER COLUMN <col> TYPE uuid USING lpad(<col>, 32, '0')::uuid` — and apply
  that to every column holding or referencing an id, not just the primary
  keys: `organization_members.container_id` and
  `organization_roles.container_id` need the same widen-and-cast, combined
  with the rename below rather than as a separate migration. The columns
  holding a user id are `uuid` by default too — `organizations.owner_id` as
  much as `organization_members.user_id`, since authlayer generates user ids
  as well; a non-UUID user table should pass `dropsstore.WithTextUserIDs()`
  instead of rewriting them.
- **BREAKING (schema): the membership and role container column is now
  `container_id`.** It follows `scope.MemberBase`'s own `drop:` tag; the
  hand-written schema previously called it `organization_id`. Migrate with
  `ALTER TABLE organization_members RENAME COLUMN organization_id TO
  container_id` and likewise for `organization_roles`.
- **BREAKING (schema): the roles UNIQUE constraint is renamed.** Its name is now
  derived from the roles table name, so `organization_roles_org_key` becomes
  `organization_roles_container_key` — and a second scope instance gets
  `<its_roles_table>_container_key` rather than colliding on the organization
  one. Immaterial if you let `CreateSchema` build the tables; if you own them,
  `ALTER TABLE organization_roles RENAME CONSTRAINT organization_roles_org_key
  TO organization_roles_container_key`.
- **BREAKING (API): `dropsstore.New` takes type parameters.**
  `dropsstore.New(db)` becomes
  `dropsstore.New[org.Organization, org.Member](db)`. `dropsstore.NewSchema`
  likewise. `Schema.Organizations` is now `Schema.Containers`.

### Fixed

- **`Can`/`Authorize` now deny zero actions even for an elevated actor.**
  `authorize()` only checked `Allows()` when the actor was not elevated, so
  `Can(ctx, resource)` called with no actions returned `true` for an owner, or
  for any role whose permissions were full — contradicting the readme's own
  "Zero actions denies — there is nothing to authorize" and disagreeing with
  `ContainersWith`, which already denied this case unconditionally. Zero
  actions is now denied before the elevated short-circuit runs, so `Can`
  returns `false` and `Authorize` returns `ErrForbidden` for an elevated actor
  too. This aligns `Can`/`Authorize` with the documented rule and with
  `access.Permission.Allows`, which has always treated zero actions the same
  way. A caller that relied on the old pass-through — asking an elevated actor
  "may you touch this resource at all?" via a zero-action call — now gets a
  denial, and must name at least one action.
- **`CreateSchema` now emits the composite constraints it declares.** drops'
  `CreateTableIfNotExists` writes column definitions only, so the members
  `PRIMARY KEY (container_id, user_id)` and the roles
  `UNIQUE (container_id, key)` lived in the in-memory table registry and never
  reached the database. Since the engine relies on the database to enforce both
  — it does not pre-check — a second `AddMember` inserted a duplicate row and
  returned `nil` instead of `ErrAlreadyMember`, and two custom roles could share
  a `(container, key)` with different permission sets. `CreateSchema` now
  follows each `CREATE TABLE` with idempotent `ALTER TABLE ... ADD CONSTRAINT`
  statements, so it stays safe to re-run. Databases created by an earlier
  version need the constraints added by hand — re-running `CreateSchema` does
  it, once any duplicate rows are cleared.

### Dependencies

- **`golang.org/x/crypto` v0.55.0 — new, and the only addition.** Pulled in by
  `password` for bcrypt, and by nothing else: `go list -deps ./auth` reaches
  `golang.org/x/crypto/bcrypt` and its `blowfish` package and no further, so
  `auth` and `password` add no drops or pgx dependency of their own. `token`
  and `access` remain standard library only. The JWT and the UUIDv7 generator
  are hand-written specifically so no JWT or UUID library enters the graph.
- `github.com/bernardoforcillo/drops` v0.6.0 (was v0.5.0 at 0.0.1).
- `github.com/jackc/pgx/v5` v5.10.0 (PostgreSQL stores only), unchanged.
- Go 1.26+.

## [0.0.1] - 2026-07-25

Initial release. Milestone 1: scope RBAC — code-defined permission statements,
hybrid default + custom roles, permission checks, a privilege-escalation guard,
lifecycle hooks, and query-level guards. Authentication (credentials, sessions,
OAuth) is not part of this release.

### Added

- **Access-control engine** (`authlayer/access`) — the standard-library-only
  core. `Statements` compiles a `resource → actions` surface into stable bit
  indices; `Permission` is an immutable bitset over it with `Allows` (AND across
  actions), `IsFull`, and `SubsetOf`; `Access` binds statements to a registry of
  named `Role` values and builds permissions from grant maps. Undeclared grants
  fail closed and fail loudly — `NewRole` panics (a mis-declared code-defined
  role is a startup bug) while `Permission` returns an error (runtime and
  DB-sourced grants are validated, not trusted).
- **Name-based permission encoding** (`authlayer/access`) — `Permission.Encode`
  serialises grants as newline-separated `resource:action` tokens and
  `Access.Decode` re-resolves them against the statements in force at decode
  time. Adding, removing, or reordering resources therefore never
  re-interprets a permission persisted earlier: a deleted capability is dropped
  from stored roles and everything else keeps its meaning. A token without a
  `:` separator is treated as corruption and errors.
- **Generic scope engine** (`authlayer/scope`) — `Service[C, M]` over a
  caller-supplied container and member type. Embed `ContainerBase` /
  `MemberBase` to inherit the identity and audit fields the engine stamps and
  reads, and add your own columns alongside. A scope is any authorization
  boundary — an organization, a team, a project — with an owner and members
  holding exactly one role each.
- **Permission checks** (`authlayer/scope`) — `Authorize` (sentinel errors, so a
  handler can distinguish denied from not-a-member from no-such-container),
  `Can` (boolean; folds `ErrForbidden` and `ErrNotMember` into `false` while
  still surfacing real failures), and `HasPermission` (out-of-band, asking about
  a user who is not the context subject). Standing resolves per call with no
  caching, so a permission change takes effect immediately.
- **Hybrid roles** (`authlayer/scope`) — the `owner`, `admin` and `member`
  defaults are defined in code, derived from the merged statement surface (so
  they grow with the application's resources), reserved, and immutable at
  runtime. On top of them each container defines its own **custom roles** via
  `CreateRole` / `UpdateRole` / `DeleteRole` / `ListRoles`, persisted as encoded
  grants and invisible to every other container. `DeleteRole` refuses a role
  that still has members rather than cascading.
- **Membership management** (`authlayer/scope`) — `CreateContainer` (stamps base
  fields and seeds the owner's membership in one transaction), `AddMember`,
  `ChangeMemberRole`, `RemoveMember`, `LeaveContainer`, `ListMembers`, and
  `TransferOwnership` (owner-only; the recipient must already be a member).
- **Privilege-escalation guard** (`authlayer/scope`) — an actor may not grant a
  role exceeding their own permissions, mint or update a custom role with powers
  they lack, or remove a member more powerful than themselves. Implemented as
  `Permission.SubsetOf`; elevated actors are exempt. Reported as
  `ErrPrivilegeEscalation`.
- **Configurable policy** (`authlayer/scope`) — `Policy` bundles `Escalation`
  (`EscalationStrict` / `EscalationAllowEqual` / `EscalationOff`),
  `LastOwnerLocked` (the owner cannot be removed, demoted, or leave), and
  `OwnerBypass` (the owner holds full permissions regardless of their role key,
  so a mis-configured container stays recoverable). All three default on.
- **Lifecycle hooks** (`authlayer/scope`) — `Hook` / `HookFunc` observe eight
  `Event` kinds (`ContainerCreated`, `MemberAdded`, `MemberRoleChanged`,
  `MemberRemoved`, `RoleCreated`, `RoleUpdated`, `RoleDeleted`,
  `OwnershipTransferred`) for audit, webhooks, cache invalidation, or a
  transactional outbox. A hook returning an error aborts the operation, and for
  `CreateContainer` rolls the whole transaction back.
- **Context-carried subject and scope** (`authlayer/scope`) — `WithSubject` /
  `WithScope` and their accessors, built on drops' own `pg.WithSubject` /
  `pg.WithTenant` keys so one context drives both the in-memory decision and
  drops' query guards. A missing subject or scope is an error, never a silent
  allow.
- **Query-level filtering** (`authlayer/scope`) — `MembershipGuard` returns a
  drops `pg.Guard` that restricts a table's rows to the context subject's
  containers, mounted with `entity.AuthorizeWith`. Coarse, membership-level
  filtering; a missing subject fails closed.
- **Service options** (`authlayer/scope`) — `WithPolicy`, `WithHooks`
  (accumulating), `WithClock` (deterministic tests), and `WithIDGenerator`
  (swap the default 24-hex-char `crypto/rand` id for UUIDv7, ULIDs, or whatever
  the schema expects).
- **Store port** (`authlayer/scope`) — `Store[C, M]`, composed from
  `ContainerStore`, `MemberStore` and `RoleStore` so a backend or decorator can
  override a slice of it, plus `WithTx`. Stores are pure persistence: they
  authorize nothing and never interpret permission bytes, but owe the engine the
  documented sentinel error on each lookup miss.
- **Organization RBAC** (`authlayer/org`) — the ready-made instance of the
  engine with the container fixed to `Organization` (name + unique slug) and the
  member to `Member`, so callers get organization RBAC without writing a type
  parameter. Adds `CreateOrganization` and `WithOrg`, and re-exports the scope
  types, options, and errors under organization-flavoured names as aliases —
  `org.ErrOrgNotFound` *is* `scope.ErrContainerNotFound`.
- **In-memory store** (`authlayer/store/memory`) — a concurrency-safe, generic,
  zero-dependency `Store` for development, tests, and examples, and the
  reference implementation of the contract. `WithTx` approximates a transaction
  by snapshot-and-restore under a mutex.
- **PostgreSQL store** (`authlayer/store/drops`) — a drops-backed `org.Store`
  over three tables (`organizations`, `organization_members` with a composite
  `(organization_id, user_id)` primary key, and `organization_roles`). Unique
  constraints are load-bearing: they turn concurrent double-inserts into
  `ErrSlugTaken` / `ErrAlreadyMember` / `ErrRoleKeyTaken`. `CreateSchema` is a
  dev/test convenience (create-only, never alter); `Schema` exposes the tables
  for migrations and guards, and `MembershipGuard` fills in the junction for
  you. Real transactions via `WithTx`. No foreign key to a users table is
  declared — authlayer does not own one.
- **Sentinel errors** (`authlayer/scope`) — fourteen documented sentinels
  comparable with `errors.Is`, grouped for HTTP mapping: not-found, denied,
  conflict/invariant, and caller-bug.
- **Runnable example** (`examples/basic`) — a database-free tour of statements,
  default and custom roles, permission checks, and the escalation guard:
  `go run ./examples/basic`.
- **Integration test** (`store/drops`) — a live end-to-end test behind the
  `integration` build tag, so the default `go test ./...` stays database-free:
  `AUTHLAYER_TEST_DSN='postgres://…' go test -tags integration ./store/drops/`.
- **Documentation** — a doc comment on every exported symbol, package-level
  overviews for each package, and a `readme.md` documenting the full feature
  surface.

### Dependencies

- `github.com/bernardoforcillo/drops` v0.5.0
- `github.com/jackc/pgx/v5` v5.10.0 (PostgreSQL store only)
- Go 1.26+

[Unreleased]: https://github.com/bernardoforcillo/authlayer/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/bernardoforcillo/authlayer/compare/v0.0.1...v0.1.0
[0.0.1]: https://github.com/bernardoforcillo/authlayer/releases/tag/v0.0.1
