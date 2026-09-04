# authlayer

Reusable authentication & authorization for Go, built on
[`drops`](https://github.com/bernardoforcillo/drops) — so you stop rewriting the
same authz logic in every project.

> **Status: early.** Milestone 1 shipped **scope RBAC**: code-defined
> permission statements, hybrid default + custom roles, permission checks, a
> privilege-escalation guard, lifecycle hooks, and query-level guards.
> Milestone 2 adds [invitations](#invitations), the
> [authentication core](#authentication) — users, password credentials,
> revocable sessions with refresh-token rotation, and email verification —
> and [external identities](#oauth): "sign in with Google/GitHub/…", linked
> to a local account through an optional port. authlayer stores **no**
> provider tokens and runs no part of the OAuth dance itself.
> Milestone 3 adds [magic links](#magic-links) — passwordless sign-in, where
> the emailed token *is* the credential — and
> [account deletion](#account-deletion) in a hard and a soft posture. The
> soft one needs a new `users.deleted_at` column, and both need four new
> methods on `auth.Store`; see `changelog.md` for the migration.

```sh
go get github.com/bernardoforcillo/authlayer
```

Requires Go 1.26+. `access` and `token` are standard-library only; `password`
(and so `auth`) adds `golang.org/x/crypto` for bcrypt and nothing else; the
RBAC engine pulls in `drops`, and `pgx/v5` comes with the PostgreSQL store.

## Contents

- [The model](#the-model) · [Imports](#imports) · [Quick start](#quick-start)
- [Statements & permissions](#statements--permissions) · [Roles](#roles) ·
  [How a decision is made](#how-a-decision-is-made)
- [Context](#context) · [Checking permissions](#checking-permissions) ·
  [Managing members](#managing-members) · [Custom roles](#custom-roles)
- [Privilege escalation](#the-privilege-escalation-guard) ·
  [Policy](#policy) · [Hooks & events](#hooks--events) · [Options](#options)
- [Query-level filtering](#query-level-filtering) · [Storage](#storage) ·
  [Custom scopes](#custom-scopes) · [Nested scopes](#nested-scopes)
- [Invitations](#invitations) ·
  [Service accounts & API keys](#service-accounts--api-keys) ·
  [Authentication](#authentication) · [Magic links](#magic-links) · [OAuth](#oauth) ·
  [Account deletion](#account-deletion) · [Errors](#errors) ·
  [Packages](#packages)

## The model

- **Scopes.** A scope is an authorization boundary — an organization, a team, a
  project — with an owner and members. The engine is generic over the container
  and member types; `org` is the ready-made organization instance, and most
  callers never write a type parameter.
- **Statements.** You declare the permission surface in code as
  `resource → actions` (e.g. `member: [create, update, delete]`). Compiled to a
  bitset for O(1) checks; stored role permissions are serialised by *name*, so
  evolving the statement set never corrupts saved roles.
- **Hybrid roles.** `owner`, `admin` and `member` are defined in code and seeded
  automatically. On top of them, each container can define **custom roles** at
  runtime, persisted through the store.
- **One role per member.** No stacking — a member's effective permissions are
  always exactly one role's, which keeps them auditable. The owner and any role
  granting everything bypass fine-grained checks. A privilege-escalation guard
  stops anyone granting more than they hold.
- **Two enforcement points.** An in-memory decision (`Can` / `Authorize` /
  `HasPermission`) *and* a drops `pg.Guard` that filters rows at the database.
  Both read the acting subject and the active scope from the same `context`.
- **Users are opt-in, and the credential record is fixed.** The RBAC half —
  `scope`, `org`, `team`, `invite` — stores no users and declares no foreign
  key to yours: a user id is a value it carries, never one it validates
  against a schema of its own. [`auth`](#authentication) is the half that
  *does* own a `users` table (plus `sessions` and `verifications`), and unlike
  the engine's containers it is **not** generic over your type. A container is
  genuinely application-shaped, so `scope` takes yours; a credential record is
  not. `auth.UserBase` — id, email, verification stamp, password hash,
  timestamps — is the whole record `auth` needs and the whole record it
  persists, so your profile fields live in your own tables and authlayer's
  migrations never own a column your product's shape decides.
  Use the RBAC half alone and nothing about users changes. Ids authlayer mints
  are UUIDv7 and their columns are `uuid` by default;
  `dropsstore.WithTextUserIDs()` is the escape hatch for pointing the
  **RBAC** store at a non-UUID user table of your own, and
  `dropsstore.WithTextLibraryIDs()` the one for a non-UUID
  [`WithIDGenerator`](#ids) of your own. The auth store has no
  text-*user*-id option, because there it owns the `users` table being
  referenced, but it does have `dropsstore.WithAuthTextLibraryIDs()`, which
  moves all five of its id columns together.

## Imports

Snippets below name packages rather than repeating an import block each time,
so here is the whole set once. Three of these are not guessable from the
identifier they introduce, which is why this section exists at all: `memory`
lives at `store/memory`, `store/drops` declares `package dropsstore`, and the
PostgreSQL wiring needs **two different packages both called `stdlib`**.

```go
import (
    "github.com/bernardoforcillo/authlayer/access"
    "github.com/bernardoforcillo/authlayer/auth"
    "github.com/bernardoforcillo/authlayer/auth/authtest"
    "github.com/bernardoforcillo/authlayer/invite"
    "github.com/bernardoforcillo/authlayer/org"
    "github.com/bernardoforcillo/authlayer/scope"
    "github.com/bernardoforcillo/authlayer/team"
    "github.com/bernardoforcillo/authlayer/token"

    "github.com/bernardoforcillo/authlayer/store/memory"           // memory.New, NewInviteStore, NewAuthStore, NewIdentityStore
    dropsstore "github.com/bernardoforcillo/authlayer/store/drops" // package name is dropsstore, not drops

    // Only the PostgreSQL store needs these three — see Storage.
    "github.com/bernardoforcillo/drops/pg"     // pg.New, pg.Guard, pg.AnyOf, pg.OwnerGuard
    "github.com/bernardoforcillo/drops/stdlib" // stdlib.New: wraps a *sql.DB as a drops driver
    _ "github.com/jackc/pgx/v5/stdlib"         // registers the "pgx" database/sql driver
)
```

The last two are the trap. `drops/stdlib` is used **by name** —
`stdlib.New(sqlDB)` — and `pgx/v5/stdlib` is **blank-imported** purely for its
`init`, which is what makes `sql.Open("pgx", dsn)` resolve; only one of them
can hold the identifier `stdlib`, and it is the drops one. The
[`store/drops` wiring snippet](#storedrops) writes both out in full rather
than leaving you to work that out.

Snippets also use `context`, `database/sql`, `errors`, `fmt` and `time` from
the standard library. Where a snippet needs an import beyond this list, it
carries its own block.

## Quick start

```go
ac := org.NewAccess(map[string][]access.Action{
    "project": {"create", "read", "update", "delete"}, // your app's resources
})
svc := org.New(ac, memory.New[org.Organization, org.Member]()) // swap for drops

ctx := org.WithSubject(context.Background(), "alice")
acme, _ := svc.CreateOrganization(ctx, "Acme", "acme") // alice becomes owner

alice := org.WithOrg(ctx, acme.ID)
svc.AddMember(alice, "bob", org.RoleAdmin)

bob := org.WithOrg(org.WithSubject(context.Background(), "bob"), acme.ID)
canAddMember, _ := svc.Can(bob, org.ResourceMember, org.ActionCreate)
canDeleteOrg, _ := svc.Can(bob, org.ResourceOrganization, org.ActionDelete)
fmt.Println(canAddMember, canDeleteOrg) // true false
```

A full, database-free tour is in [`examples/basic`](examples/basic/main.go);
[`examples/auth`](examples/auth/main.go) does the same for the whole library
wired together — sign-up through log-out, with an org and an invitation in the
middle — and [`examples/reset`](examples/reset/main.go) covers the recovery
flows the other two do not: password reset and email change.

```sh
go run ./examples/basic
go run ./examples/auth
go run ./examples/reset
```

## Statements & permissions

`access.Statements` is the permission surface — the complete set of things that
*can* be granted. Nothing outside it is grantable, so a typo denies rather than
silently allows.

```go
ac := org.NewAccess(map[string][]access.Action{
    "project": {"create", "read", "update", "delete"},
    "billing": {"read", "update"},
})
```

`org.NewAccess` merges your statements with the built-in **control statements**
the engine enforces on its own operations:

| Resource       | Actions                    | Checked by                             |
|----------------|----------------------------|----------------------------------------|
| `organization` | `update`, `delete`         | your handlers (declared, not enforced) |
| `member`       | `create`, `update`, `delete` | `AddMember`, `ChangeMemberRole`, `RemoveMember` |
| `role`         | `create`, `update`, `delete` | `CreateRole`, `UpdateRole`, `DeleteRole` |
| `invite`       | `create`, `read`, `delete` | the [`invite`](#invitations) package's own mint/list/revoke calls — the engine itself checks none of it |
| `service_account` | `create`, `read`, `update`, `delete` | the [`apikey`](#service-accounts--api-keys) package's own calls — likewise declared here, checked there |

`organization:update` / `organization:delete` are declared so your own "rename
the org" and "delete the org" handlers have something to check with `Authorize`,
and so `admin` can be defined as "everything except deleting the container".

An `access.Permission` is an immutable set of grants over those statements, held
as a bitset:

```go
p.Allows("project", "create", "update") // AND across actions; false if undeclared
p.IsFull()                              // grants every declared pair
p.SubsetOf(other)                       // backs the escalation guard
p.Encode()                              // "project:create\nproject:update"
```

**Encoding is by name, not bit index.** `Encode` writes newline-separated
`resource:action` tokens and `Access.Decode` re-resolves them against the
statements in force at decode time. Adding, removing, or reordering resources
therefore never re-interprets a permission persisted earlier — a capability you
delete is dropped from stored roles, and everything else keeps its meaning.

Grants that name an undeclared pair fail loudly, and *where* they fail depends on
where they came from: `Access.NewRole` panics (a mis-declared code-defined role
is a startup bug), while `Access.Permission` returns an error (runtime and
DB-sourced grants must be validated, not trusted).

The `access` package stands alone if you want just the engine:

```go
st := access.NewStatements(map[string][]access.Action{"doc": {"read", "write"}})
ac := access.New(st)
ac.NewRole("viewer", map[string][]access.Action{"doc": {"read"}})
viewer, _ := ac.Role("viewer")
viewer.Permissions.Allows("doc", "write") // false
```

## Roles

**Default roles** are code, identical in every container, and seeded by
`NewAccess`. They are derived from the merged statement surface, so they grow
automatically as your app declares more resources:

| Key      | Grants                                            | Notes |
|----------|---------------------------------------------------|-------|
| `owner`  | everything                                        | `IsFull`, so it bypasses fine-grained checks and the escalation guard |
| `admin`  | everything except `<container>:delete`            | not full, so the escalation guard still applies |
| `member` | nothing                                           | standing only: can list members and roles, change nothing |

They are reserved — a custom role may not reuse a default key, and none can be
updated or deleted at runtime.

**Custom roles** are per-container, defined at runtime, and stored as encoded
grants. A custom role in one container is invisible to every other, so two
tenants can both define an `editor` that means different things.

## How a decision is made

Every check resolves the actor's **standing** in a container:

1. Load the container → `ErrContainerNotFound` if absent.
2. If `OwnerBypass` is on and the actor owns it → **elevated**, full permissions.
   No membership lookup, no role resolution.
3. Load the membership → `ErrNotMember` if absent.
4. Resolve the role key: a code-defined default if the registry knows it,
   otherwise a custom role loaded from the store and decoded → `ErrRoleNotFound`
   if neither.
5. The actor is **elevated** if the resolved permission set is full.

An elevated actor passes every fine-grained check naming at least one action,
*and* the escalation guard. Everyone else must hold every requested
`(resource, action)` pair. A check naming no actions denies everyone, elevated
included — there is nothing to authorize.

Nothing is cached. Every check hits the store for the container, the membership,
and (for custom roles) the role record — so a permission change takes effect
immediately and there is no invalidation to get wrong. Wrap the `Store`, not the
`Service`, if you need fewer round trips.

## Context

The acting subject and the active scope travel on the `context`, not as
arguments, so one context drives both the in-memory decision and drops' query
guards. authlayer reuses drops' own keys (`pg.WithSubject` / `pg.WithTenant`).

```go
ctx = org.WithSubject(ctx, userID) // who is acting
ctx = org.WithOrg(ctx, orgID)      // which organization

userID, haveSubject := org.SubjectFrom(ctx)
orgID, haveOrg := org.OrgFrom(ctx)
```

A missing subject is `ErrSubjectMissing`; a missing scope is `ErrOrgMissing`.
Neither is ever a silent allow. `CreateOrganization` is the one operation that
needs no scope — there is no organization yet.

## Checking permissions

```go
// Boolean form: folds "forbidden" and "not a member" into false.
ok, err := svc.Can(ctx, "project", org.ActionDelete)

// Error form: distinguishes 403-denied from 403-not-a-member from 404.
err = svc.Authorize(ctx, "project", org.ActionCreate, org.ActionUpdate)

// Out-of-band: ask about a user who is not the ctx subject.
ok, err = svc.HasPermission(ctx, orgID, "carol", map[string][]access.Action{
    "project": {"create"},
    "billing": {"read"},
})
```

- Multiple actions are an **AND**, not an OR. Zero actions denies — there is
  nothing to authorize.
- `Can` returning a non-nil error means the question could not be *answered*
  (missing context, store failure). That is not a denial; check `err` first.
- `HasPermission` reads nothing from the context and performs no check that the
  *caller* may ask, so keep it out of end-user-facing paths. An empty request map
  returns true for any member.

## Managing members

All of these read the actor and scope from the context.

| Call | Requires | Notes |
|---|---|---|
| `CreateOrganization(ctx, name, slug)` | subject only | caller becomes owner; no permission check — gate it upstream |
| `AddMember(ctx, userID, roleKey)` | `member:create` + escalation guard | `ErrAlreadyMember` on a duplicate |
| `ChangeMemberRole(ctx, userID, roleKey)` | `member:update` + escalation guard | owner cannot be demoted under `LastOwnerLocked` |
| `RemoveMember(ctx, userID)` | `member:delete` + escalation guard *on the target's role* | refuses a target who outranks you; **equal ranks may remove each other** |
| `LeaveContainer(ctx)` | membership only | owner cannot leave under `LastOwnerLocked` |
| `ListMembers(ctx)` | membership only | non-members get `ErrNotMember`, not an empty list |
| `TransferOwnership(ctx, userID)` | **owner only** | target must already be a member |

`TransferOwnership` moves `owner_id` and nothing else — neither membership's role
key changes, so the outgoing owner keeps whatever role they were stored with.
Demote them afterwards if you want that.

## Custom roles

```go
_, err := svc.CreateRole(ctx, "editor", "Editor", map[string][]access.Action{
    "project": {"create", "update"},
})
_, err  = svc.UpdateRole(ctx, "editor", "Editor", grants) // replaces wholesale
err      = svc.DeleteRole(ctx, "editor")
roles, _ := svc.ListRoles(ctx)
```

- `key` is what gets stored on memberships; `name` is a display label.
- `UpdateRole` **replaces** the grant set rather than merging, and takes effect
  immediately for every member holding the role — permissions are resolved per
  check, never copied onto the membership.
- `DeleteRole` refuses a role that still has members (`ErrRoleInUse`) rather than
  cascading and silently stripping them.
- Default roles are immutable (`ErrDefaultRole`).
- `ListRoles` returns the three defaults (`IsDefault: true`) followed by the
  container's custom roles, each with a resolved `access.Permission` — enough to
  drive a role editor without a second lookup. It is *not* the full set of
  assignable roles: a role registered in code with `access.Access.NewRole` is
  assignable but not enumerated here. Use `RolePermissions` to resolve a
  specific key.

## The privilege-escalation guard

Delegated administration must not be a ladder. Unless elevated, an actor may not:

- add a member with a role more powerful than their own,
- change a member to such a role,
- remove a member more powerful than themselves,
- create or update a custom role granting powers they lack.

The check is `granted.SubsetOf(actor)`, and a violation is
`ErrPrivilegeEscalation`. Owners and full-permission roles are exempt — for them
every set is trivially a subset.

```go
// bob is an admin: he cannot mint a role that can delete the organization.
_, err := svc.CreateRole(bob, "superadmin", "Super", map[string][]access.Action{
    org.ResourceOrganization: {org.ActionDelete},
})
errors.Is(err, org.ErrPrivilegeEscalation) // true
```

## Policy

```go
svc := org.New(ac, store, org.WithPolicy(org.Policy{
    Escalation:        scope.EscalationStrict,
    LastOwnerLocked:   true,
    MembersFromParent: true,
    OwnerBypass:       false, // the only deviation from the defaults
}))
```

| Field | Default | Effect |
|---|---|---|
| `Escalation` | `EscalationStrict` | `EscalationOff` disables the guard entirely. `EscalationAllowEqual` currently behaves like `Strict` — it is reserved for future "strictly-less" semantics. |
| `LastOwnerLocked` | `true` | Owner cannot be removed, demoted, or leave. Ownership still moves via `TransferOwnership`. |
| `MembersFromParent` | `true` | In a [nested scope](#nested-scopes), `AddMember` refuses a user with no standing in the parent (`ErrNotParentMember`). No effect without `WithParent`. |
| `OwnerBypass` | `true` | Owner gets full permissions regardless of their role key, so a mis-configured container is always recoverable. |

`WithPolicy` replaces the policy wholesale — it does not merge — so pass a fully
populated struct. The zero `Policy` is *not* the defaults.

`invite.Service` is configured separately, through its own `Option`s rather
than through `Policy`/`WithPolicy` — an `invite.Service` and the
`scope.Service` it wraps are configured independently. It takes four:

| Option | Purpose |
|---|---|
| `WithRecheckInviterOnAccept(b)` | Default `true`. Re-check the inviter's *current* standing before admitting anyone. See [Invitations](#invitations) for what turning it off trades away. |
| `WithInviteExpiry(d)` | How long a freshly minted email invite stays acceptable; default seven days. Links take their expiry per-link, at `CreateLink`. |
| `WithNotifier(n)` | Deliver each minted invitation; default nil sends nothing. Sugar over calling a `Notifier` yourself. |
| `WithTokens(gen)` | Override the token/code generator. **Tests only** — `gen` is the entire source of unguessability for every credential the service mints. |

## Hooks & events

Hooks fire after a mutation is applied but before the call returns, for audit
trails, webhooks, cache invalidation, or a transactional outbox.

```go
svc := org.New(ac, store, org.WithHooks(scope.HookFunc(
    func(ctx context.Context, e scope.Event) error {
        return audit.Write(ctx, e.Kind, e.ContainerID, e.ActorID, e.TargetID)
    },
)))
```

| Kind | Emitted by | `TargetID` / `RoleKey` |
|---|---|---|
| `ContainerCreated` | `CreateOrganization` | — (`ActorID` is the new owner) |
| `MemberAdded` | `AddMember`, `GrantMembership` | added user / their role (on `GrantMembership`, `ActorID` equals the added user — see below) |
| `MemberRoleChanged` | `ChangeMemberRole` | member / new role |
| `MemberRemoved` | `RemoveMember`, `LeaveContainer` | removed user (equals `ActorID` on a leave) |
| `RoleCreated` / `RoleUpdated` / `RoleDeleted` | the role calls | — / the role key |
| `OwnershipTransferred` | `TransferOwnership` | incoming owner (`ActorID` is the outgoing one) |

`ActorID` is the ctx subject for every operation that resolves one.
`GrantMembership` is the exception: it reads nothing from the context and sets
`ActorID` to the *admitted* user, the same value as `TargetID`. That is the
only honest answer available — it exists for [invitation](#invitations)
acceptance, where the invitee is the one calling and the inviter who
authorized it decided at mint time and is not present. So an audit hook cannot
tell an invitation-based admission from a self-add on the event alone, and the
invitation's `InvitedBy` never reaches the hook. Record that attribution when
the invitation is minted if you need it.

A hook returning an error **aborts the operation**. For `CreateOrganization` that
rolls back the whole transaction — container, owner membership, and all. For the
other operations the store change is already committed while the caller sees an
error, so keep non-retryable side effects out of hooks and return `nil` for
best-effort work like logging. Hooks run in registration order on the caller's
goroutine; the first error stops the chain.

## Options

| Option | Purpose |
|---|---|
| `WithPolicy(p)` | Replace the authorization policy. |
| `WithHooks(h...)` | Append lifecycle hooks (accumulates across calls). |
| `WithClock(fn)` | Timestamp source; default `time.Now().UTC()`. Inject a fixed clock for deterministic tests. |
| `WithIDGenerator(fn)` | Id source for containers and custom roles; default is UUIDv7 from `crypto/rand`. A non-UUID generator needs `dropsstore.WithTextLibraryIDs()` on `store/drops` — see [Ids](#ids). |
| `WithParent(p, inherit)` | [Nest](#nested-scopes) this scope inside another, resolving standing through `p` and projecting it with `inherit`. |
| `WithContainerResource(res)` | Name this scope's own container resource, so a [nested](#nested-scopes) `CreateContainer` knows what `<res>:create` to check for in the parent. |

Options apply at construction and never after, so a `Service` is immutable once
built.

## Query-level filtering

In-memory checks answer "may this user do X?". A guard answers "which rows may
this user see?" — pushed into SQL so a `SELECT` can never return another
tenant's rows.

```go
projects.AuthorizeWith(st.MembershipGuard(projectsTbl.Col("organization_id")))
// SELECT ... WHERE "organization_id" IN (
//     SELECT "container_id" FROM "organization_members" WHERE "user_id" = $subject)
```

`st.MembershipGuard` is the drops store's convenience — it fills in the junction
table and its columns. The general form works against any membership table:

```go
guard := org.MembershipGuard(membersTbl,
    membersTbl.Col("user_id"), membersTbl.Col("container_id"),
    projectsTbl.Col("organization_id"))
```

The subject comes from the same context as the permission checks, and a missing
subject fails closed (`pg.ErrSubjectMissing`).

`MembershipGuard` is coarse: it asks only whether the subject is a member. To
filter by a specific permission, use `PermissionGuard`:

```go
projects.AuthorizeWith(svc.PermissionGuard(
    projectsTbl.Col("organization_id"), "project", org.ActionDelete))
// WHERE "organization_id" IN ($1, $2)   -- only the orgs granting project:delete
```

It resolves the container set through the same ladder `Can` uses, so the guard
and an in-memory check agree for every container where the subject holds a
membership whose role key resolves. Where they diverge — an unresolvable role
key, a missing container row, an owner with no membership row of their own —
the guard denies rather than leaks. A subject with no qualifying containers
renders as a false predicate — no rows, never all rows — a missing subject is
`pg.ErrSubjectMissing`, and a store failure aborts the query rather than
narrowing it to nothing.

The cost is one round trip per guarded query, plus one lookup per distinct
`(container, role key)` pair naming a custom role — a custom role belongs to one
container, so the same key in two containers is two lookups. The rendered `IN`
list also binds one parameter per qualifying container.
`svc.ContainersWith(ctx, userID, resource, actions...)` is the same answer as a
plain `[]string`, so a hot endpoint can hoist it:

```go
ids, err := svc.ContainersWith(ctx, userID, "project", org.ActionDelete)
```

`ContainersWith` takes the user id as an argument rather than from the context,
so — like `HasPermission` — it performs no check that the *caller* is entitled
to ask, and its answer enumerates that user's memberships and how privileged
they are in each. Do not expose it directly to end users. `PermissionGuard` is
the safe form: it reads the subject from the context.

**In a [nested scope](#nested-scopes), neither consults the parent.**
`ContainersWith` resolves membership-based standing only — it does not walk
the parent rung `Can` applies. An organization admin who can administer a team
purely through inheritance, holding no membership row of their own in that
team, gets no row for it here and no rows from a `PermissionGuard` built over
it, even though `Can`, `Authorize` and `Standing` all admit them in that same
container: `Can` says yes, the guard says no. That is a known gap, not a
deliberate rule — do not build a nested scope's row-level filtering on the
assumption that it mirrors `Can`.

Guards compose, so "rows I created, or rows in an organization where I may
delete projects" is:

```go
projects.AuthorizeWith(pg.AnyOf(
    pg.OwnerGuard{Owner: projectsTbl.Col("created_by")},
    svc.PermissionGuard(projectsTbl.Col("organization_id"), "project", org.ActionDelete),
))
```

## Storage

`scope.Store` is the persistence port: containers, members, roles, a
transaction, and the user-scoped lookups `ListUserContainers` and
`ListUserStandings` — the latter backing `PermissionGuard`. It is composed
from `ContainerStore`, `MemberStore` and `RoleStore`, so a backend or a
decorator (caching, metrics) can override a slice of it by embedding the rest.

A store is *pure persistence*. The engine stamps ids, owners and timestamps,
resolves roles, and runs every authorization check before calling in; the store
never authorizes anything and never interprets permission bytes. What it does
owe the engine is the right sentinel error when a lookup finds nothing —
`ErrNotMember` rather than a generic not-found — because the engine branches on
those. Each method's contract is documented on the interface.

`invite.Store`, `apikey.Store` and `auth.Store` are separate ports with the
same discipline, and so is the optional `auth.IdentityStore` behind
[external identities](#oauth) — a port of its own rather than six more methods
on `auth.Store`, which is released. Both backends implement all five.
`auth.Store` is the strictest of them:
eleven of its twenty-two methods carry an explicit **MUST**, each naming the
failure it prevents. They are not all the same kind of obligation, and the
difference matters to anyone writing a third-party backend.

**Five demand atomicity** — `MarkRotated`, `CreateSuccessorSession`,
`MarkEmailVerified`, `UpdateUserEmail` and `MarkUserDeleted`. Splitting any of
them into a read and a later write reopens a security hole rather than merely
narrowing a race: two successful rotations of one token, a successor
resurrecting a family that was revoked mid-rotation, an address certified that
nobody proved control of, two accounts sharing one address. That last one has
nothing above it to catch it — `RequestEmailChange` deliberately does *not*
pre-check the new address, because a pre-check there would be an
un-rate-limited "is this address registered?" oracle for any authenticated
caller, so `UpdateUserEmail` at redemption is the only enforcement point there
is.

`MarkUserDeleted` is the newest of the five and the one whose two halves fail
in *opposite* directions, which is why its five field writes have to land
together. Stamped but not scrubbed: every entry point already refuses the row
while it still holds the real address and the live password hash, so the user
was told the account was anonymized and it is not. Scrubbed but not stamped:
the address has already moved while `DeletedAt` is still nil, so the row
reports as a **live** account whose address is derived from the user id — not
a secret — and a caller who guesses it can drive a password-reset flow against
an account that was supposed to be closed. See
[Account deletion](#account-deletion).

**Two are what `SignUp`'s enumeration safety leans on** — `CreateUser` must
decide `ErrEmailTaken` from the same attempt that performs the write, and
`FindUserByEmail` must read its own writes. Either one violated turns a
single `SignUp` call into an "is this address registered?" oracle from inside
the store, where no amount of care in `SignUp` itself can see it.

**Two demand the opposite of the rest: an *extra* read, and
serialization.** `DeleteSessionsByFamily` carries two **MUST**s that apply to
any backend whose `CreateSuccessorSession` holds a row-level lock on the
predecessor for a transaction's duration — the shape `store/drops` uses.
A single autocommit `DELETE FROM sessions WHERE family_id = $1` is **not
sufficient** there: its snapshot is taken *before* it waits for that lock, so
once unblocked it deletes only what existed at the earlier instant and misses
the successor committed while it waited — leaving a revoked family with one
live, fully rotating session. Such a backend must re-snapshot *after* the
wait (a `SELECT ... FOR UPDATE` over the family's rows, then the `DELETE`,
in one transaction), and must *additionally* serialize concurrent calls on
the same family, because that locking `SELECT` has no ordering guarantee and
two callers can deadlock each other. A per-family advisory transaction lock
taken before the `SELECT` is sufficient; an `ORDER BY` on the `SELECT` is
not, since the `DELETE` that follows has no ordering of its own. A backend
whose `CreateSuccessorSession` takes no such lock — `store/memory`, whose
single mutex spans both methods' whole bodies — has no gap to close and owes
neither. `DeleteSessionsByUser` inherits both **MUST**s unchanged, because a
whole-user revocation is a superset of a family one, and the survivor it would
otherwise leave is a fully rotating refresh token for an account whose owner
has just asked for it to be deleted — the worst moment for one to outlive its
sweep.

**Two more constrain the shape of the deletion cascade, and both are about
what a backend must *not* quietly do for you.** `DeleteUser` removes the user
row **only** and must not cascade to that user's sessions or verifications: a
backend whose `ON DELETE CASCADE` performs the sweep as a side effect has
taken the ordering decision away from the caller and made it unobservable, so
a caller that skipped the sweeps and one that ran them in the right order look
identical — against that backend and no other. `DeleteVerificationsByUser`
must filter on `userID` **alone**, never on a list of purposes it knows about:
`Purpose` is an open string this port neither validates nor enumerates, so a
fan-out over `DeleteVerificationsByUserAndPurpose` cannot satisfy it, and a
purpose added by a later flow — or minted by a deployment itself — would walk
straight through the sweep. The two by-user sweeps both answer a match of zero
rows with `nil` — matching nothing is the ordinary case — while `DeleteUser`
answers `ErrUserNotFound`, because a caller deleting an account needs to know
whether there was one.

Separately, `Session.TokenHash` and `Verification.TokenHash` each carry a
uniqueness **MUST** on the record type rather than on a method — a `UNIQUE`
constraint in a SQL backend. `MarkRotated`'s single-winner contract breaks
without it *with no atomicity defect at all*, so a backend that satisfies
every method obligation above and skips these is still wrong.

All of them are written on the port as requirements with their consequences
spelled out, because they constrain any third-party backend as much as the
two shipped ones — see [Authentication](#enumeration-safe-sign-up).

`invite.Store` carries eight **MUST**s of its own, and they are all about the
same thing: bounding *who gets in*. **Four are on methods.** `ConsumeLink`
must make its check and its increment one atomic step, or a `MaxUses: 1` link
admits everyone who clicks it at once. `DeleteEmailInvite` must be
rows-affected gated, because that gate — not any check above it — is what
makes one emailed token pay out once; `AcceptInvite` claims first and grants
second precisely so it is the only thing that has to hold. And
`CreateEmailInvite` and `CreateLink` must refuse a write that would break a
uniqueness constraint, atomically with performing it.

**Four more are on the record types**, because they constrain the shape of
the table rather than the behaviour of one call: `EmailInvite.TokenHash`,
`Link.Code`, and `EmailInvite`'s `(ContainerID, Email)` pair — `UNIQUE`
constraints in a SQL backend — plus the normalized form `EmailInvite.Email`
may hold. The first two defeat the single-winner
properties above *with no atomicity defect at all*: two rows sharing a `Code`
means two concurrent redeemers resolve **different** rows through
`FindLinkByCode` and each atomically wins `ConsumeLink` on the row it picked,
so the limit bounds nothing while every individual consume behaves perfectly.
`TokenHash` is the same story for an emailed token and `DeleteEmailInvite`.
The third is what makes re-inviting an address replace rather than duplicate
when two such calls race — without it a container holds two live tokens where
its pending-invitations screen shows one row, and revoking the visible one
leaves the other redeemable. It is a constraint on the *pair*: the same person
invited to two containers is two legitimate rows.

The fourth is what makes the third mean anything. A store must apply
`invite.NormalizeEmail` (trim, lowercase — byte for byte `auth.NormalizeEmail`)
to every address it writes or matches: `CreateEmailInvite` before the
uniqueness check and the write, `DeleteEmailInvitesFor` before it matches.
Without that the pair constraint is byte-exact, so `erin@example.com` and
`Erin@Example.com` are two *different* pairs — both writes succeed, both tokens
are live, and the sweep the re-invite performs first matches only the spelling
it was handed. That is the same incomplete pending-invitations screen and the
same surviving token as above, reached with no concurrency at all.
`invite.Service.InviteByEmail` normalizes too, before either store call, so an
application going through the service is covered whatever its backend does; the
obligation is still on the port, because a store is reachable directly and the
constraint it guards lives there. `invite` normalized nothing at all through
v0.1.0 — see the changelog for the one-time data migration a database written
by that version needs.

### `store/memory`

An in-process, generic store backed by maps. Zero dependencies, concurrency
safe, and the reference implementation of the contract — use it for development,
tests, and examples. It does not enforce uniqueness of your own fields (a slug,
say), and its `WithTx` approximates a transaction by snapshot-and-restore under
a mutex. `memory.NewInviteStore()`, `memory.NewAuthStore()` and
`memory.NewIdentityStore()` are the `invite.Store`, `auth.Store` and
`auth.IdentityStore` counterparts. The auth one enforces every uniqueness
constraint its port describes — one account per normalized email, no id
collision on any `Create*`, and the `token_hash` uniqueness `auth.Store`
requires of a backend on both `Session` and `Verification`, reported as
`memory.ErrTokenHashTaken`. The invite one enforces all three of its port's uniqueness constraints, and
normalizes addresses on both sides so the pair one bites on a person rather
than on a spelling: `EmailInvite.TokenHash` (also `memory.ErrTokenHashTaken` —
same column meaning, same failure), `(ContainerID, Email)` as
`memory.ErrInviteEmailTaken`, and `Link.Code` as `memory.ErrLinkCodeTaken`.

Both used to defer those to `store/drops`, which has always had them as
`UNIQUE` constraints; that left a caller who developed here and deployed there
meeting the constraint for the first time in production, so it went away.
A collision gets a backend-level error rather than a port sentinel because
`auth.Store` classifies only `ErrIDTaken` on the `Create*` methods and
`invite.Store` classifies no conflict-on-create at all — `store/drops` answers
the same cases with the driver's own unique violation. Both stores satisfy
every atomicity MUST their ports state by holding one mutex for each method's
entire body, so no check-then-write can be split by a concurrent call.

`memory.NewIdentityStore()` follows the same discipline and enforces both of
its port's uniqueness rules — `Identity.ID` and the `(Provider, Subject)` pair.
For it the single-acquisition rule is not a habit but the point of the type:
`DeleteIdentityIfNotLast` decides and deletes under one lock, and a split there
[locks a user out permanently](#unlinking-and-the-last-credential).

One divergence from `store/drops` remains, in the invite store, and is
recorded rather than closed: `store/drops` types an invite's and a link's `id`
as a `PRIMARY KEY`, so re-using one is a unique violation there, while
`memory.InviteStore` keys its maps by ID and a create under an id already
present overwrites the row. `invite.Store` documents no id-collision contract
and `authlayer/invite` has no sentinel for one (unlike `auth.ErrIDTaken`), so
nothing in the backend is entitled to invent one; the service mints a fresh
UUIDv7 for every record, so the case does not arise in practice.

### `store/drops`

The PostgreSQL store, generic over the container and member types:

```
organizations         id PK (uuid by default), name, slug UNIQUE, owner_id,
                      created_at, updated_at
organization_members  (container_id, user_id) PK, role_key, joined_at
organization_roles    id PK, container_id, key, name, permissions BYTEA,
                      created_at, UNIQUE (container_id, key)
```

This is the one place production wiring is written down, so it is written out
in full — imports included, because two of the packages involved are both
named `stdlib` and one of them is imported only for its side effect:

```go
import (
    "context"
    "database/sql"

    "github.com/bernardoforcillo/drops/pg"
    "github.com/bernardoforcillo/drops/stdlib" // used by name: wraps a *sql.DB
    _ "github.com/jackc/pgx/v5/stdlib"         // blank: registers the "pgx" driver

    "github.com/bernardoforcillo/authlayer/org"
    dropsstore "github.com/bernardoforcillo/authlayer/store/drops"
)

func newOrgService(ctx context.Context, dsn string) (*org.Service, error) {
    sqlDB, err := sql.Open("pgx", dsn) // "pgx" comes from the blank import above
    if err != nil {
        return nil, err
    }
    db := pg.New(stdlib.New(sqlDB))                        // a drops handle
    st := dropsstore.New[org.Organization, org.Member](db) // the scope.Store
    if err := st.CreateSchema(ctx); err != nil {           // or use your own migrations
        return nil, err
    }
    return org.New(org.NewAccess(nil), st), nil
}
```

`drops/stdlib` is the adapter that turns a `database/sql` handle into a drops
driver; `pgx/v5/stdlib` is the pgx driver itself, blank-imported so that its
`init` registers the name `sql.Open` is given. Neither is optional, and only
one of them can own the identifier `stdlib`.

Columns are derived from the `drop:` tags on your types, so a different scope
needs only table names:

```go
teams := dropsstore.New[team.Team, team.Member](db, dropsstore.WithNames(
    dropsstore.Names{Containers: "teams", Members: "team_members", Roles: "team_roles"}))
```

Fields must be `string`, `time.Time`, `*time.Time`, `[]byte`, `int` or `int32`
— or a named type over `string`, `int` or `int32`. Anything else, any other
pointer included, panics at construction with the column and the type named.
`*time.Time` is the one nullable shape: it drops the `NOT NULL`, and a nil
pointer is written as the SQL `NULL` keyword rather than a parameter — it is
what `email_verified_at`, `rotated_at` and `last_used_at` are.
A field with no `drop:` tag (or `drop:"-"`) is not persisted, and your container
type must tag `id`, `owner_id`, `created_at` and `updated_at` while your member
type must tag `container_id`, `user_id`, `role_key` and `joined_at` — embedding
`scope.ContainerBase` and `scope.MemberBase` does that for you, and a type that
misses one is rejected at construction rather than at the first query.

Ids authlayer generates are UUIDv7 and their columns are `uuid` by default. So
are the columns holding a user id — `owner_id` as much as `user_id` — since
authlayer generates user ids too. Two independent options retype them, because
the two questions are independent:

| Option | Retypes | Reach for it when |
|---|---|---|
| `WithTextUserIDs()` | `user_id`, `owner_id` (and `invited_by`, `created_by` via `WithInviteTextUserIDs()`) | You use only the RBAC half, against an existing user table whose ids are not UUIDs. |
| `WithTextLibraryIDs()` | `id`, `container_id`, `parent_id` | You overrode `WithIDGenerator` with something a `uuid` column will not hold — see [Ids](#ids). |

They compose, and a deployment minting non-UUID ids for both wants both.
`CreateSchema` emits the right `CREATE TABLE` either way, but — like
everything else it does — it will not retype a table that already exists, so
choose before the tables are created or retype the columns in your own
migration.

The unique constraints are load-bearing: they are what turn a concurrent
double-insert into `ErrSlugTaken`, `ErrAlreadyMember` or `ErrRoleKeyTaken`
instead of a duplicate row, because the engine does not pre-check any of the
three. `CreateSchema` emits them — including the composite
`PRIMARY KEY (container_id, user_id)` on the members table and
`UNIQUE (container_id, key)` on the roles table, which a `CREATE TABLE` cannot
carry — and keep them if you own these tables in your own migrations instead.
Every statement it issues is idempotent, so the call is safe to re-run, but it
only ever adds what is missing: a table that already exists with different
columns or constraints is left as it stands, so `CreateSchema` will not migrate
an existing schema forward. `st.Schema()` exposes the table definitions if you
would rather generate the DDL.

`dropsstore.NewInviteStore(db)`, `dropsstore.NewAuthStore(db)` and
`dropsstore.NewIdentityStore(db)` are separate stores over their own tables,
each with its own `CreateSchema` and `Schema()`. The identity one owns a single
table and is described under [OAuth](#the-identities-table); an application
that offers no external sign-in never constructs it and never creates it. The
auth one owns three:

```
users          id PK (uuid by default), email UNIQUE, email_verified_at,
               password_hash, created_at, updated_at, deleted_at
sessions       id PK, user_id, token_hash UNIQUE, family_id, expires_at,
               created_at, rotated_at, user_agent, ip, INDEX (family_id)
verifications  id PK, user_id, token_hash UNIQUE, purpose, email, expires_at,
               created_at, INDEX (user_id, purpose)
```

Both indexes are load-bearing too. `sessions (family_id)` is what keeps
`DeleteSessionsByFamily`'s two statements — and therefore every `LogoutAll`
iteration — off a table scan. `verifications (user_id, purpose)` is what keeps
`DeleteVerificationsByUserAndPurpose` off one, and that one is a *security*
index: it runs on every `RequestPasswordReset` **and every
[`RequestMagicLink`](#magic-links)**, so without it the residual timing
channel above grows with the number of pending tokens held for all users.
`CreateSchema` emits both as `CREATE INDEX IF NOT EXISTS`, so it self-heals a
table missing one.

`users.deleted_at` is the one column `CreateSchema` **cannot** self-heal, and
an existing deployment has to run one migration by hand before upgrading:

```sql
ALTER TABLE users ADD COLUMN IF NOT EXISTS deleted_at timestamptz;
```

A constraint or an index can be added by a statement `CreateSchema` issues
separately; a *column* lives inside the `CREATE TABLE IF NOT EXISTS` that
no-ops in full against a table that already exists. `CreateSchema` against an
unmigrated table therefore reports success while leaving the column absent —
every statement it issued genuinely succeeded — and the first `CreateUser`
afterwards fails with SQLSTATE `42703` (`undefined_column`), because every
`INSERT` names `deleted_at` and so does `MarkUserDeleted`'s `UPDATE`. It fails
loudly rather than degrading quietly, which is the intended direction. Use the
real table name if `WithAuthNames` moved it; `timestamptz` and nullable, with
**no `DEFAULT`**, because `NULL` — not anonymized — is what every existing row
must hold.

All three UNIQUE constraints are load-bearing. `UNIQUE (email)` is what
`SignUp` reads "already registered" off, so without it the duplicate branch
never fires and enumeration safety has nothing to be safe about; the two
`token_hash` constraints keep a hash lookup single-row and turn a generation
bug into a loud error instead of an ambiguous multi-row match. `email` is
declared *both* inline and as a named `ALTER TABLE`, because
`CREATE TABLE IF NOT EXISTS` is a no-op against a table that already exists —
so the guarded `ALTER` is what self-heals a users table created by an older
version or by hand. The `family_id` index is not decoration either: every
family revocation reads and locks by it, and `LogoutAll` runs one transaction
per family. `AuthNames` / `WithAuthNames` rename the three tables if `users`
is already taken in your database. Unlike the RBAC and invite stores, this one
has no text-*user*-id option — it owns the `users` table its `user_id` columns
point at, so a `user_id` typed differently from `users.id` could never be
self-consistent. What it has instead is `WithAuthTextLibraryIDs()`, one option
that retypes all five id columns — `users.id`, `sessions.id`,
`verifications.id`, and the two `user_id` columns referencing the first — so a
non-UUID [`auth.WithIDGenerator`](#ids) works here too. A hatch that moved only
the first three would fix `SignUp` and then break `Login`.

No foreign keys are declared — not to a users table from the RBAC side, which
authlayer does not own, and not between the three auth tables either, matching
every other schema here.

A live end-to-end test lives behind a build tag, so the default `go test ./...`
stays database-free:

```sh
AUTHLAYER_TEST_DSN='postgres://…?sslmode=disable' go test -tags integration ./store/drops/
```

> **This lane is destructive and wants the database to itself.** It `DROP`s
> the auth, RBAC and invite tables in the target database on the way in and
> rebuilds them, so point `AUTHLAYER_TEST_DSN` at a scratch database, never at
> anything you care about. It also expects **exclusive** use of it: two copies
> running at once — or anything else writing those tables — will fail each
> other in ways that look like product bugs (`relation ... does not exist`
> mid-run, timing measurements polluted by the other client's writes).

### Writing your own `auth.Store`

`auth.Store` is the strictest port in this library — eleven of its twenty-two
methods carry a **MUST**, and the [Storage](#storage) section above says what
each one costs when it is violated. Those requirements bind a third-party
backend exactly as much as the two shipped ones, so they ship as an executable
suite rather than as prose alone:

```go
import "github.com/bernardoforcillo/authlayer/auth/authtest"

func TestMyStoreSatisfiesTheAuthContract(t *testing.T) {
    authtest.RunStoreContract(t, func(t *testing.T) auth.Store {
        return myStoreWithEmptyTables(t)   // called once per check
    })
}
```

The factory must hand back a store with **no** users, sessions or verifications
in it — several checks assert counts over the whole table — and may register
teardown with `t.Cleanup` or call `t.Skip`. Ids are UUIDv7 and every address is
unique per call, so the suite runs unchanged against a backend that types its id
columns as `uuid`. If your store opens connections on demand, raise your pool
limits and warm it to `authtest.RaceGoroutines` connections first: goroutines
that trickle in across a connection-setup window never actually contend, which
silently weakens every race in the suite.

Seven of the sixty-five checks are races, because the obligations behind them
are unreachable sequentially: `MarkRotated`'s single winner; `CreateUser`'s and
`UpdateUserEmail`'s one-address-one-account atomicity, one check each; a
`MarkEmailVerified` racing the `UpdateUserEmail` that moves the address out from
under it; a reader watching `MarkUserDeleted` for a row caught half-anonymized;
a `CreateSuccessorSession` racing the family revocation that must not
leave it alive; and concurrent revocations of one family. Three of them — the
`MarkEmailVerified` one, the `MarkUserDeleted` one and the
`CreateSuccessorSession`-versus-revocation pair — assert a *linearizability*
property rather than a timing guess: the end state each rejects is one no
serial order of the two calls can produce.

Two things it does **not** do, stated here rather than left to be discovered:

- `CreateUser`'s MUST is that `ErrEmailTaken` comes from the same attempt that
  performs the write, so a condition denying writes but not reads cannot make a
  duplicate address answer faster than a new one. Whether your backend consulted
  a separate read first is invisible to a caller — the port itself permits an
  in-process map to check first, precisely because its write cannot fail on its
  own. The suite asserts the observable consequence (two concurrent creates of
  one address, one winner); the read-authorization half is for review, not test.
- `DeleteSessionsByFamily`'s serialization MUST is asserted only through its
  consequence: concurrent calls on one family must all succeed and leave no
  survivors. Forcing the lock-order inversion needs backend-specific SQL on a
  second connection, which no port-level suite can write. `store/drops` carries
  that test itself.

Token-hash uniqueness is *in* that suite, not an extra alongside it.
`Session.TokenHash` and `Verification.TokenHash` carry their **MUST** on the
record type rather than on a method, and a backend that satisfies every method
obligation and skips these is still wrong — a shared hash defeats
`MarkRotated`'s single winner with no atomicity defect at all. It was briefly a
second entry point, `RunTokenHashUniquenessContract`, because `store/memory`
declined the obligation; that backend now enforces it and the entry point is
gone, since shipping the check as opt-in told the next in-memory backend author
it was optional.

The suite's own tests include twenty-eight deliberately non-compliant stores —
one whose `MarkRotated` lets every caller win, one whose `CreateUser` checks
then writes non-atomically, one whose `DeleteSessionsByFamily` snapshots the
family before it waits, one whose `DeleteUser` cascades to the user's sessions,
one whose `MarkUserDeleted` scrubs under one lock and stamps under another —
paired into thirty-three defect/check cases, each asserted to **fail** the
check that covers it. A contract suite that passes everything is worthless, and
that is not visible without controls.

### Writing your own `invite.Store`

`invite.Store`'s eight **MUST**s — four on methods, four on the record types
— are listed in [Storage](#storage) above, along with what each one costs when
it is violated. They ship as an executable suite too, built the same way and
placed the same way:

```go
import "github.com/bernardoforcillo/authlayer/invite/invitetest"

func TestMyStoreSatisfiesTheInviteContract(t *testing.T) {
    invitetest.RunStoreContract(t, func(t *testing.T) invite.Store {
        return myStoreWithEmptyTables(t)   // called once per check
    })
}
```

The factory must hand back a store with **no** email invites and no links in
it — several checks assert counts over the whole table — and may register
teardown with `t.Cleanup` or call `t.Skip`. Ids and container ids are UUIDv7,
and addresses, token hashes and codes are unique per call unless a check is
deliberately forcing a collision, so the suite runs unchanged against a backend
that types its id columns as `uuid`. If your store opens connections on demand,
raise your pool limits and warm it to `invitetest.RaceGoroutines` connections
first: goroutines that trickle in across a connection-setup window never
actually contend, which silently weakens every race in the suite.

Eight of the forty-six checks are races, because the obligations behind them
are unreachable sequentially: `ConsumeLink`'s single winner against a
`MaxUses: 1` link, its ceiling against a `MaxUses: 4` one, and the lost update
its increment must not have on an unlimited one; `DeleteEmailInvite`'s
at-most-one-nil claim; each of the three uniqueness constraints under
concurrent creates; and a `DeleteEmailInvitesFor` racing the
`CreateEmailInvite` that re-invites the same address. That last one asserts a
*linearizability* property rather than a timing guess — the end state it
rejects (the create reporting success while the container ends up holding no
invitation for the address) is one no serial order of the two calls can
produce.

Points the port leaves unspecified are deliberately not asserted: list order,
empty-slice-versus-nil, and — for every one of the three uniqueness checks —
*which error* a rejected duplicate comes back as, since `invite.Store`
classifies no conflict-on-create at all and the two shipped backends answer
differently on purpose. Each of those checks requires only that the write
failed and that the original row survived it.

One thing it does **not** do, stated here rather than left to be discovered:
`ConsumeLink`'s MUST names the two acceptable shapes (one `UPDATE ... WHERE`
whose rows-affected count *is* `ok`, or one critical section spanning the check
and the write), and which shape your backend used is invisible to a caller. The
suite asserts the consequences. Two of them — one winner against `MaxUses: 1`,
exactly four against `MaxUses: 4` — catch a grossly non-atomic implementation
every time and a subtly non-atomic one only sometimes: `store/memory` measured
a deliberately split-lock `ConsumeLink` passing that race 20 times out of 20,
even at 2000 goroutines. The third is the deterministic one. Against an
*unlimited* link every caller wins on any implementation, but a read-then-write
loses increments — N callers each read the same `UseCount` and each write
`read+1` — so the stored count comes back far below N whatever the timing. Run
all three; none of them proves the mechanism.

The suite's own tests include thirty-four deliberately non-compliant stores —
one whose `ConsumeLink` decides under one lock and increments under a second,
one that lets two links share a code, one that reads `MaxUses: 0` as exhausted
rather than unlimited, one that stores an invited address verbatim — paired
into forty-seven defect/check cases, each asserted to **fail** the check
that covers it. A further test fails if a check is ever added without a control,
so a check that asserts nothing cannot slip in green.

### Writing your own `apikey.Store`

`apikey.Store`'s three **MUST**s — `Key.TokenHash` unique across every row,
`DeleteServiceAccount`'s cascade atomic with the delete, `CreateKey` refusing a
key naming no account — ship as an executable suite too, built the same way
and placed the same way:

```go
import "github.com/bernardoforcillo/authlayer/apikey/apikeytest"

func TestMyStoreSatisfiesTheAPIKeyContract(t *testing.T) {
    apikeytest.RunStoreContract(t, func(t *testing.T) apikey.Store {
        return myStoreWithEmptyTables(t)   // called once per check
    })
}
```

The factory must hand back a store with **no** service accounts and no keys
in it, and may register teardown with `t.Cleanup` or call `t.Skip`. Ids,
container ids and creator ids are UUIDv7, and token hashes are unique per
call unless a check is deliberately forcing a collision, so the suite runs
unchanged against a backend that types its id columns as `uuid`. Warm your
pool to `apikeytest.RaceGoroutines` connections first, for the reason given
above.

Four of the thirty-seven checks are races: one winner among concurrent
creates of one token hash, one among concurrent creates of one account id,
one among concurrent deletes of one account, and the cascade as a
*linearizability* property — a `CreateKey` racing the `DeleteServiceAccount`
of its account, after which the store must be in a state some serial order
could have produced, never the account gone and the key present. That last
one catches a grossly non-atomic cascade every time and a subtly non-atomic
one only sometimes, for the reason `ConsumeLink`'s races do; against
`store/drops` the property is carried by one transaction plus an
`ON DELETE CASCADE` backstop, against `store/memory` by one mutex
acquisition. Points the port leaves unspecified — list order,
empty-slice-versus-nil, and *which error* a rejected duplicate hash comes
back as — are not asserted.

The suite's own tests include thirty-seven deliberately non-compliant stores,
one per check — one that lets two keys share a hash, one that writes a key for
an account that does not exist, one whose cascade deletes the keys, releases
the lock, then the account — each asserted to **fail** the check that covers
it, and a further test fails if a check is ever added without a control.

## Custom scopes

`org` fixes the container type to `Organization` and the member type to `Member`.
For a different boundary — teams, projects, workspaces — or extra fields on a
membership, embed the bases in your own types and use `scope` directly:

```go
type Team struct {
    scope.ContainerBase        // id, owner_id, created_at, updated_at
    Name     string `drop:"name"`
    ParentID string `drop:"parent_id"`
}

type TeamMember struct {
    scope.MemberBase           // container_id, user_id, role_key, joined_at
    InvitedBy string `drop:"invited_by"`
}

ac  := scope.NewAccess("team", appStatements) // "team" is the container resource
svc := scope.New[Team, TeamMember](ac, teamStore)

team, _ := svc.CreateContainer(ctx, Team{Name: "Platform"})
```

The engine reads and stamps the base fields and leaves yours alone; drops
flattens the embedded struct when persisting. `org`'s source is short and is the
worked example of doing this.

If a scope's own standing should also be reachable *from* a parent container's
standing — rather than `ParentID` being just another field you happen to
store — don't roll it by hand; embed `scope.NestedBase` instead and see
[Nested scopes](#nested-scopes) below.

## Nested scopes

A scope can sit inside another — a team inside an organization, a project
inside a team — so that standing in the parent can confer standing in the
child. `team` is the worked example, teams nested one level inside `org`:

```go
orgSvc  := org.New(org.NewAccess(team.ParentStatements()), memory.New[org.Organization, org.Member]())
teamSvc := team.New(team.NewAccess(nil), memory.New[team.Team, team.Member](), orgSvc)

ctx := org.WithSubject(context.Background(), "alice")
acme, _ := orgSvc.CreateOrganization(ctx, "Acme", "acme") // alice becomes owner

alice := org.WithOrg(ctx, acme.ID)
platform, _ := teamSvc.CreateTeam(alice, "Platform") // alice owns the org, so she owns the team too
```

`team.ParentStatements()` — merged into `org.NewAccess`'s statements above —
declares `team:create` on the *organization's* surface, so an organization
role (not only the owner) can be granted the right to create a team. Skipping
that merge is not a startup error: `CreateTeam` still works for the org owner,
since ownership always bypasses the check; every other member is refused with
nothing in the error to say why.

**Bits never cross a scope boundary.** An `access.Permission` is a bitset over
one package's `Statements`, so a parent's bits mean nothing in a child's
statement space — inheritance therefore never projects bits, only *grant
names*, which the child recompiles against its own `Access`.

The zero-config default confers standing on nobody but the truly elevated:
under `org.NewAccess`'s default roles that is the **owner alone**, via
ownership. The built-in `admin` role is deliberately kept short of full
permission (it excludes `organization:delete`, so the escalation guard still
applies to it), so a plain admin inherits nothing in a team by default. To
extend administration to whoever can manage teams — what most applications
actually want — declare that capability on the organization's own surface
(`team:update`, say — this is separate from, and in addition to,
`team.ParentStatements()`'s `team:create`) and install your own projection.
Both halves are required: the grant has to actually be on the organization's
surface, or the projection has nothing to find and confers standing on
nobody — silently, since an undeclared pair just reads as "not granted":

```go
statements := team.ParentStatements()
statements[team.ResourceTeam] = append(statements[team.ResourceTeam], team.ActionUpdate)
orgSvc := org.New(org.NewAccess(statements), memory.New[org.Organization, org.Member]())

teamSvc := team.New(team.NewAccess(nil), memory.New[team.Team, team.Member](), orgSvc,
    scope.WithParent(orgSvc, scope.InheritWhen(team.ResourceTeam, team.ActionUpdate)))
```

Now any organization member holding `team:update` — an admin, by default,
since `org.NewAccess` grants every declared pair but `organization:delete` to
`admin` — administers every team in the organization without joining one.

`Policy.MembersFromParent` (on by default) requires a user being added to the
child to already hold standing in the parent: `AddMember` on a team refuses a
non-member of the organization with `ErrNotParentMember`, rather than the team
quietly acquiring members the organization has never heard of.

Nesting also changes `CreateContainer`: on a parented scope it performs a
permission check against the parent (`<containerResource>:create`, or elevated
parent standing) before creating anything, where the unparented form performs
no check at all — expect that difference the first time you wire
`WithParent`.

A nested check consults the parent's store before it ever looks at the
child's own membership, so a parent-store outage denies every non-owner check
in every nested container beneath it — even a subject whose own membership
would otherwise have sufficed. That is the correct trade-off (failing closed
beats guessing), but it is worth knowing before it surprises you in an
incident.

Parent chains must be acyclic. Two `*Service` values can't form one by
construction — a parent has to already exist before it can be named as one —
but `ParentScope` is an exported single-method interface, so a custom
implementation with a field wired up after construction (a late-bound parent)
can still build a cycle. Either way the engine does not detect it: configuring
one recurses until the goroutine's stack overflows, a fail-stop crash in your
own wiring rather than anything a request can trigger. Each level a check
climbs — resolving the parent's own standing, and its parent's, and so on —
costs one more store round trip.

## Invitations

`invite` admits a person who has no standing in a scope yet, without a direct
[`AddMember`](#managing-members) call: a one-time emailed token, or a reusable
link. Both end the same way, at the newly exported
`scope.Service.GrantMembership` — admitting the named user at the named role
while performing **no actor check of its own**, not even `member:create`, let
alone the escalation guard. Every actor-facing rule already ran when the
credential was minted, and the person accepting it has no standing yet to
check in the first place. `GrantMembership` is therefore only as safe as
whatever decided to call it: it must never be reachable except by presenting a
credential minted for exactly that container and role, which is exactly what
`AcceptInvite`, `JoinViaLink`, and `ListLinks`'s redaction (below) exist to
guarantee.

```go
svc := org.New(org.NewAccess(nil), memory.New[org.Organization, org.Member]())
isvc := invite.New(svc.Service, memory.NewInviteStore()) // org.Service embeds *scope.Service as .Service

ctx := org.WithSubject(context.Background(), "alice")
acme, _ := svc.CreateOrganization(ctx, "Acme", "acme") // alice becomes owner

owner := org.WithOrg(ctx, acme.ID)
_, token, _ := isvc.InviteByEmail(owner, "bob@example.com", org.RoleMember)
// deliver `token` yourself — authlayer knows no base URL and owns no transport

bob := org.WithSubject(context.Background(), "bob")
_, _ = isvc.AcceptInvite(bob, token) // bob is now a member of acme, holding org.RoleMember
```

A link works the same way, minus the email step — continuing from the snippet
above, with the same `owner` context:

```go
_, code, _ := isvc.CreateLink(owner, org.RoleMember, 5, nil) // up to 5 uses, never expires

carol := org.WithSubject(context.Background(), "carol")
_, _ = isvc.JoinViaLink(carol, code) // carol is now a member of acme, holding org.RoleMember
```

`store/memory`'s `NewInviteStore` is the dev/test `invite.Store`, exactly like
`memory.New` for `scope.Store`; `store/drops` ships the production one as
`dropsstore.NewInviteStore(db)`, with its own `CreateSchema`.

**Two artifacts, one hashed, one not.** An email invite (`EmailInvite`) is
delivered once and never redisplayed to anyone, including the inviter, so only
its sha256 is stored (`TokenHash`) — a database leak cannot be replayed into
admission, because an attacker who steals the row still cannot produce a token
that hashes to it. A link (`Link`) is the opposite: its whole purpose is to be
shown again, on a "manage invite links" screen, so `Code` is stored in clear —
hashing it would make redisplay impossible. A link's security therefore comes
from `MaxUses`, `ExpiresAt` and revocation rather than secrecy of storage,
which is why `Store.ConsumeLink` must weigh all three atomically before
admitting anyone.

**Addresses are normalized.** `InviteByEmail` passes the address through
`invite.NormalizeEmail` (trim, lowercase) before either store call, and a
compliant backend applies it again on the write and on `DeleteEmailInvitesFor`'s
argument. So `(ContainerID, Email)` uniqueness — and with it "re-inviting an
address replaces rather than duplicates" — is a constraint on a *person*, not on
a spelling: `erin@example.com` and `Erin@Example.com` are one pending
invitation, and `EmailInvite.Email`, `Preview.Email` and `ListInvites` all hand
back the normalized form. It is the same rule `auth` applies, deliberately, so a
caller never has to remember which half of this library folds case. Through
v0.1.0 `invite` normalized nothing, and two casings of one address were two
live tokens where revoking the one an admin recognised left the other
redeemable.

**Delivery is your job.** `InviteByEmail` returns the plain token exactly
once, alongside the stored record; authlayer knows no base URL and owns no
transport, so turning that into an actual email — which link, which template,
which provider — is entirely the caller's own business. `WithNotifier` wires a
`Notifier` that `InviteByEmail` calls once the invite is persisted; it is
optional sugar over calling one yourself right after `InviteByEmail` returns,
and the default (nil) sends nothing at all.

**`ListLinks`'s redaction is the security core of this package.** `invite:read`
sits on the merged control-statement surface every `NewAccess` builds (see
[Statements & permissions](#statements--permissions)), so the built-in `admin`
role acquires it automatically — and `admin` is deliberately not `IsFull` (see
[Roles](#roles)), so it is normally subject to the privilege-escalation guard
everywhere else in this codebase. Without redaction that guard would be
worthless here: a non-elevated admin lists the links, reads the owner's `Code`
in clear, leaves the container, and rejoins at the owner role through
`JoinViaLink` — which admits via `GrantMembership`, a call that runs no
escalation check of its own, because the whole point of a link is to admit
someone who has no standing yet to check. Two calls, full escalation, and
every fine-grained check elsewhere in the codebase never touched. So a `Code`
survives in `ListLinks`' result only when **both** halves of the mint test hold
for the reader, because minting takes two things:

1. **The capability** — the reader must hold `invite:create`, the same
   permission `CreateLink` requires, resolved once for the whole list. A reader
   granted `invite:read` *without* `invite:create` could not have minted any
   link here, so they see no `Code` at all, whatever the roles involved.
   Splitting a resource's actions across roles is the entire product, and
   `CreateRole` will happily define an `auditor` granting only `invite:read`;
   without this half, such a read-only reader would silently acquire the power
   to admit arbitrary third parties, which is exactly what `invite:create`
   exists to gate.
2. **The standing** — the reader must be elevated, or the link's role must
   resolve to a permission set that is a `SubsetOf` their own current standing.
   That is the same test applied when the link was created, reapplied here
   because a role's grants (or the reader's own standing) can change
   afterwards.

The two are independent: the first bounds *whether* this principal mints at
all, the second bounds *how high*. Every other field stays populated, so a
management screen can still list a link and let its owner revoke it, even one
whose code it cannot show back.

**Claim first, admit second — in both flows.** Acceptance spans two stores
that may not share a database — the invite lives in `invite.Store`, the
membership in `scope.Store` — so there is no cross-store transaction. Both
`AcceptInvite` and `JoinViaLink` claim the credential atomically FIRST and
admit SECOND. `AcceptInvite` deletes the invite through the rows-affected-gated
`Store.DeleteEmailInvite`: of any two callers racing to delete the same id —
including the same token presented twice — at most one ever sees a nil error,
and only that caller proceeds to `GrantMembership`. `JoinViaLink` consumes a
use through the atomic `Store.ConsumeLink`, which folds the
revoked/expired/exhausted check and the increment into one step a concurrent
caller cannot split. In both, a failure AFTER the claim burns the credential
and admits no one — under-admission, the safe direction — at the cost that
accepting is not safe to retry with the same token: the invitee has to be
re-invited, or, for a link with uses left, try again. The reverse order — admit
first, claim second — was an earlier version of `AcceptInvite`, and it was a
Critical finding, not a style preference: while the invite row still existed,
the token stayed redeemable by *anyone* holding it, not merely by the original
caller retrying — two distinct subjects were demonstrably admitted from a
single invitation. A one-time credential must never pay out more than once; do
not "tidy" this ordering back during a later refactor. See `AcceptInvite`'s
and `JoinViaLink`'s own doc comments in `invite/service.go` for the full
argument, including the narrow, deliberately-accepted boundary imprecision
around `AcceptInvite`'s expiry check.

**On a nested scope, admit to the parent first.** The post-claim failure that
actually happens is not a store outage — it is `scope.ErrNotParentMember`.
Under the default `Policy.MembersFromParent`, `GrantMembership` refuses anyone
who does not *already* hold standing in the parent of a [nested](#nested-scopes)
scope, deterministically and every time. Since the credential is claimed first,
that burns it: a team invitation sent to someone who is not yet in the
organization fails, the token is spent, and re-presenting it gives
`ErrInviteNotFound`. Nothing in `invite` checks parent standing before the
claim. So add the invitee to the parent org — directly, or via a parent-scope
invitation they accept first — before they accept the child's, or clear
`MembersFromParent` for that scope if the child is meant to hold members the
parent has never heard of. It fails closed; nobody is over-admitted, the
invitation is simply gone.

**An email invite is a bearer credential.** `AcceptInvite` admits whoever
presents the token, at the invited role; it never compares the accepting
subject to `EmailInvite.Email`. "One-time" bounds how many times the token pays
out, not who it pays out to, so a forwarded or intercepted invitation email
admits whoever clicks it. That is not something `invite` can check for you: it
stores no users and takes no dependency on [`auth`](#authentication) — `scope`
carries a user id as an opaque value and nothing else — so `Email` is a
delivery hint and an audit record rather than an authorization test. If your
application needs the invitation bound to its recipient, enforce it yourself
before calling `AcceptInvite` — `PreviewInvite` reads the invited address out
of a token without consuming it, so compare that against the authenticated
user's own verified address (`auth.UserBase.EmailVerifiedAt`, if that is where
your accounts live). A plain `==` is the right comparison: `Preview.Email` and
`auth.UserBase.Email` are both the output of the same trim-and-lowercase rule
(`invite.NormalizeEmail` *is* `auth.NormalizeEmail`), so nobody is refused for
having been invited as `Bob@Example.com`. That was not true through v0.1.0,
when `invite` stored addresses verbatim and this advice, followed literally,
turned away legitimate recipients.

**An existing member is idempotent, but not symmetrically.** If the ctx
subject already has standing in the link's container, `JoinViaLink` returns
the container immediately and consumes nothing — no use taken, no redundant
membership write — checked before the escalation recheck or the use count, so
a member re-clicking an old invite link never costs it anything.
`AcceptInvite` instead folds a duplicate's `scope.ErrAlreadyMember` into
success after the token is already consumed: a member who already holds a
role *below* the one the invite grants gets no error and no promotion, and
nothing in the return value distinguishes "already had this role" from
"already had a lesser one". This never over-privileges — folding a duplicate
can only leave someone at or below what they already had — but it can
silently swallow an intended promotion. Check `scope.Service.Standing` first,
or route promotions through `ChangeMemberRole`, if your application needs to
tell the two apart.

**`RecheckInviterOnAccept`, on by default.** The privilege-escalation guard
already ran once, at mint time, against the inviter's standing as of that
moment — nothing about a stored token or link updates afterwards, so without a
recheck a credential keeps paying out at the power level its inviter held when
they minted it, even after that inviter is demoted or leaves the container
entirely. Enabled, the guard reruns against the inviter's CURRENT standing
before `AcceptInvite` or `JoinViaLink` admit anyone — before the claim, so a
refusal spends nothing: a demoted inviter's pending invitation now fails with
`scope.ErrPrivilegeEscalation`, and one from an inviter who has since left
fails with `scope.ErrNotMember`. The cost is durability: a pending invitation
now dies the moment its inviter's own standing can no longer support it,
including simply leaving the container. Turn it off with
`invite.WithRecheckInviterOnAccept(false)` if your application wants "who
invited me" to be provenance rather than an ongoing authorization the inviter
must keep backing.

**`PurgeExpired` is for a cron.** `Service.PurgeExpired(ctx, before)` deletes
every expired invite and link across every container the `Store` holds, and
returns how many rows were removed. It performs NO authorization check and
reads neither a subject nor a container from the context — there is no ctx
container to check against, since a single call spans every container the
store holds — so call it only from a trusted context, never from a
per-request handler wired to caller input: an unauthenticated caller who could
trigger it at will gets a cross-tenant denial-of-service knob even though it
cannot itself grant access.

**Two new `scope` primitives, exported to make this package possible.**
`RolePermissions(ctx, containerID, roleKey)` resolves a role key to its
permission set exactly the way every check in the engine does — a
code-defined role first, then a custom role loaded from the store — and is the
right way for another package to ask that question: `ListRoles` enumerates
only the three defaults plus a container's *stored* custom roles, so a
code-defined role registered directly with `access.Access.NewRole` (a
`viewer` role, say) resolves through `RolePermissions` but is invisible to
`ListRoles`, and approximating from the latter would silently treat such a
role as nonexistent. `Container(ctx, id)` loads a container by id, returning
the whole record — including any application-defined fields your container
type carries beyond `ContainerBase` — because `GrantMembership` returns only
the new membership, not the container the invitee was just admitted to, and
acceptance needs to hand one back. Like `Standing` and `HasPermission`, neither
reads anything from the context nor checks that the caller is entitled to
ask — do not expose either directly to end users.

## Service accounts & API keys

`apikey` gives a scope **non-human members**. A `ServiceAccount` is an
ordinary membership whose id the package mints rather than your users table;
a `Key` is a bearer credential that authenticates as it. From the moment the
account is admitted the engine treats it exactly like a person — the same
role resolution, the same [escalation guard](#the-privilege-escalation-guard),
the same [query guards](#query-level-filtering) — and nothing in `scope`
knows the difference.

```go
svc := org.New(org.NewAccess(map[string][]access.Action{"project": {"read", "deploy"}}),
    memory.New[org.Organization, org.Member]())
keys := apikey.New(svc.Service, memory.NewAPIKeyStore()) // .Service: the embedded *scope.Service

ctx := org.WithSubject(context.Background(), "alice")
acme, _ := svc.CreateOrganization(ctx, "Acme", "acme")
owner := org.WithOrg(ctx, acme.ID)
_, _ = svc.CreateRole(owner, "deployer", "Deployer", map[string][]access.Action{"project": {"read", "deploy"}})

sa, _ := keys.CreateServiceAccount(owner, "ci", "deploys main", "deployer") // a member now
key, plaintext, _ := keys.CreateKey(owner, sa.ID, "github",                 // plaintext returned ONCE
    apikey.WithPermissions(map[string][]access.Action{"project": {"read"}}))

p, _ := keys.Authenticate(context.Background(), plaintext) // no subject needed: the key IS the credential
asKey := apikey.WithPrincipal(context.Background(), p)     // subject + org + cap on one context
ok, _ := svc.Can(asKey, "project", "read")   // true  — in the role and in the cap
ok, _ = svc.Can(asKey, "project", "deploy")  // false — in the role, removed by the cap
_ = keys.RevokeKey(owner, key.ID)
```

`store/memory`'s `NewAPIKeyStore` is the dev/test `apikey.Store`;
`store/drops` ships `dropsstore.NewAPIKeyStore(db)` with its own
`CreateSchema` — two tables, `service_accounts` and `api_keys` (see
[`store/drops`](#storedrops)). `examples/apikey` is the runnable tour.

**Minting.** The plaintext is `sk_` followed by the url-safe base64 of 32
bytes from `crypto/rand` — 46 characters — and `CreateKey` returns it exactly
once. Only `token.HashOpaque(plaintext)` is stored, so a database leak cannot
be replayed into a working key; `Key.Prefix` keeps `sk_` plus eight characters
in clear so a management screen can show `sk_ab12cd34…`. `WithExpiry` makes a
key valid strictly before an instant (one not after now is
`ErrInvalidExpiry`); `WithKeyPrefix` on the service changes the prefix, which
is never checked on authentication — the hash is — so existing keys survive
it.

**Restricted permissions, and the cap.** `WithPermissions` restricts a key to
a set narrower than its account's role. It is a *cap*, never a grant: the
key's effective standing is `role ∩ cap`, enforced by
`scope.WithPermissionCap`, which the engine applies *after* owner bypass,
inherited standing and role lookup — so it can only ever remove, and a capped
owner is not elevated. Minting is guarded twice: the cap must be within the
account's role (a cap outside it would intersect to less than it claims and
mislead whoever reads it back) *and* within the actor's own capped standing,
both with `scope.ErrPrivilegeEscalation`. An *unrestricted* key is guarded the
same way — holding a key is holding the account's standing, so minting one is
treated like `AddMember`: an admin cannot mint a full key for an owner-role
account. A cap that compiles to nothing is `ErrEmptyPermissions`, because the
stored encoding cannot tell an empty cap from no cap and such a key would
authenticate as the whole role. The cap is intersected at every check, never
copied onto the key, so lowering the account's role lowers every key with it.
The paths that honour the cap are exactly the ones that resolve the *context
subject* — `Can`, `Authorize`, every escalation guard (scope's, invite's and
apikey's), `PermissionGuard`; the explicit-user-id methods `HasPermission`,
`Standing`, `RolePermissions` and `ContainersWith` read nothing from the
context by contract, the cap included, and say so.
`scope.Service.CapStanding(ctx, perms, elevated)` is the one exported
definition of the rule — role ∩ cap, elevated only if the cap is Full *in this
scope's space* — for a package that resolves an actor through `Standing` and
must apply what the engine applies.

**Authenticating.** `Authenticate(ctx, plaintext)` hashes, looks up by hash,
and refuses in this order: `ErrKeyNotFound`, `ErrKeyRevoked`, `ErrKeyExpired`
(valid strictly before `ExpiresAt`), `ErrServiceAccountNotFound` (a key that
outlived its account, which the store's cascade MUST prevents),
`ErrServiceAccountDisabled`. It reads no subject and no container: the
container comes from the key. On success it decodes the key's cap against the
scope's own statements into `Principal.Permissions`, stamps `LastUsedAt`
through `Store.TouchKey` — *best-effort*: a touch failure is reported on the
`KeyAuthenticated` event as `touch_failed` and the principal is returned all
the same, because a bookkeeping hiccup must not lock every automated client
out — and returns a `Principal{Kind, ID, ContainerID, KeyID, ClientID,
GrantID, Permissions, AuthenticatedAt}`. `WithPrincipal(ctx, p)` installs
`scope.WithSubject(p.ID)`, `scope.WithScope(p.ContainerID)`, the cap when
`p.Permissions` is set, and the principal itself (`PrincipalFrom`). `Kind` is
a string — `service_account` from this package; `user` and `delegated` are
declared for the oauth package to populate, as are `ClientID` and `GrantID`.
The refusal reason is disclosed on purpose: the caller already holds a
256-bit random plaintext that cannot be enumerated, so "revoked" rather than
"unknown" gives an attacker nothing and an operator the diagnosis.

**Revocation, expiry, disable.** `RevokeKey` stamps `RevokedAt` and is
idempotent; the row stays for audit until `PurgeExpired(ctx, before)` removes
keys expired *or* revoked strictly before the cutoff — a cron-only call that
spans every container and checks nothing, like invite's.
`DisableServiceAccount` refuses every key of the account and lets none be
minted while the membership and keys are untouched, so
`EnableServiceAccount` restores it exactly: the move for "something leaked
and we do not yet know which key". `DeleteServiceAccount` removes the
membership, then the record and every key together.

**What is NOT atomic.** An account spans two stores that may not share a
database — its record in `apikey.Store`, its membership in `scope.Store` —
and there is no cross-store transaction, exactly as
[invitation acceptance](#invitations) has none. Each two-store method orders
its halves so a failure between them leaves the *inert* shape behind.
`CreateServiceAccount` writes the record FIRST, then
`scope.Service.GrantMembership`: a record with no membership has no standing,
gets no key (`CreateKey` resolves its role and finds `ErrNotMember`) and
authenticates nothing, whereas a membership with no record would be a phantom
member with a role that every roster reports. If the grant fails the record
is deleted again, best-effort, and on a second failure both errors come back
joined. `DeleteServiceAccount` removes the membership FIRST — from that
instant the account has no standing anywhere — then the record and keys,
atomically in `apikey.Store`. On a [nested scope](#nested-scopes) under the
default `MembersFromParent`, `GrantMembership` refuses a subject with no
parent standing, which a freshly minted id never has: `CreateServiceAccount`
on a team fails with `scope.ErrNotParentMember` and cleans up, and this
package makes no attempt to admit the account to the parent for you.

**Authorization of the management calls.** Every call reads the subject and
container from the context and checks the `service_account` control resource
through `scope.Service.Authorize`: `create` for `CreateServiceAccount` (plus
the escalation guard on the role), `read` for `ListServiceAccounts` and
`ListKeys`, `update` for enable/disable, `ChangeServiceAccountRole`,
`CreateKey` and `RevokeKey`, `delete` for `DeleteServiceAccount`. Two calls
delegate the membership half to scope and so need scope's grants as well:
`ChangeServiceAccountRole` runs `ChangeMemberRole` (`member:update`, guard),
`DeleteServiceAccount` runs `RemoveMember` (`member:delete`, target-rank
guard). A cross-tenant id is reported as not-found, as `invite` does.

**Every `admin` gains `service_account:*` on adoption.** `ControlStatements`
now declares `service_account: create, read, update, delete`, and `admin` is
derived from the merged surface — the same widening `invite:*` caused in
0.1.0, landing on existing installations with no code change and no
migration to notice. Define a custom role if `admin` must not manage service
accounts. `member` still holds nothing.

**Hooks** mirror scope's exactly — `Hook`, `Event`, `HookFunc`, `WithHooks`,
fired after the change and before the return, a hook error returned to the
caller (for `Authenticate`, *instead of* the principal; on a refusal, joined
onto the sentinel so `errors.Is` still holds). `Event.Detail` is a fixed
vocabulary, never free text and never a plaintext. `scope` emits its own
`MemberAdded` for the membership half with `ActorID` equal to the *account*
id (see [Hooks & events](#hooks--events) on `GrantMembership`);
`ServiceAccountCreated` from this package carries the real actor.

**`scope` primitives exported for this package.** `WithPermissionCap` /
`PermissionCapFrom` on a private key of `scope`'s own;
`Service.CapStanding`; `Service.Access()`, so a sibling package compiles and
decodes permissions in the *same* statement space the engine decides in (a
cap built against any other intersects to nothing —
`access.Permission.Intersect` fails closed rather than reinterpret bits); and
`access.Permission.Intersect` itself, the meet of two permissions, with the
same same-Statements precondition as `Union` and `SubsetOf`.

## Authentication

`auth` owns identity: the user record, its password credential, revocable
server-side sessions, and the one-time tokens that confirm an address or reset
a password. It sits on two smaller packages — [`token`](token/), which mints
the opaque refresh tokens and the HS256 access tokens, and
[`password`](password/), the hashing port with a bcrypt default. Together they
replace the sign-up, login and refresh-rotation code an application would
otherwise write by hand.

**What authlayer does not own.** No transport: no HTTP handlers, no cookies,
no middleware, no base URL. No email delivery — `SignUp`,
`RequestPasswordReset` and `RequestEmailChange` each return a plaintext token
exactly once and putting it in a message is entirely yours, the same division
[`invite`](#invitations) already draws. And no user profile: the `Store`
persists `auth.UserBase` and nothing else, so a `Plan` or `DisplayName` field
of your own is yours to load and save, keyed by `UserBase.ID`
(`WithClaimsExtender`'s doc has the worked example).

[`examples/auth`](examples/auth/main.go) runs this whole section end to end
against `store/memory` — sign up, verify, log in, verify the access token,
create an org, invite a second user, accept, authorize, refresh, log out —
and prints a trace of each step:

```sh
go run ./examples/auth
```

It is also the one place the `auth` + `invite` seam is written down — see
[Wiring `auth`, `org` and `invite` together](#wiring-auth-org-and-invite-together)
at the end of this section.

[`examples/reset`](examples/reset/main.go) is the companion for the flows
`examples/auth` does not reach — `RequestPasswordReset`, `ResetPassword` and
`RequestEmailChange`, [the password lifecycle](#the-password-lifecycle) — and
prints the same kind of trace:

```sh
go run ./examples/reset
```

### Sign-up, verification, login

The snippets in this section are one program, each continuing the last, and it
opens with an `auth.Store`. `memory.NewAuthStore()` is the in-process one,
from [`store/memory`](store/memory/) — that is the whole of what "swap for
drops" below means: `dropsstore.NewAuthStore(db)` from
[`store/drops`](store/drops/), whose `db` the
[`store/drops` section](#storedrops) builds. The imports for the section:

```go
import (
    "context"
    "errors"
    "fmt"
    "time"

    "github.com/bernardoforcillo/authlayer/access"
    "github.com/bernardoforcillo/authlayer/auth"
    "github.com/bernardoforcillo/authlayer/invite"
    "github.com/bernardoforcillo/authlayer/org"
    "github.com/bernardoforcillo/authlayer/store/memory" // memory.NewAuthStore
    "github.com/bernardoforcillo/authlayer/token"
)
```

```go
key := []byte("32-bytes-or-more-from-your-vault") // the HS256 floor, RFC 7518 §3.2
svc := auth.New(memory.NewAuthStore(), // swap for drops
    auth.WithJWT([][]byte{key}, 15*time.Minute), // access-token TTL
    auth.WithRefreshTTL(30*24*time.Hour),        // session lifetime
    auth.WithRequireVerifiedEmail(true))

ctx := context.Background()
res, _ := svc.SignUp(ctx, "  Bob@Example.com ", "Correct-Horse-Battery-7")
fmt.Println(res.Created, res.User.Email) // true bob@example.com
// deliver res.VerifyToken yourself — authlayer owns no transport

_, err := svc.VerifyEmail(ctx, res.VerifyToken)
fmt.Println(err) // <nil>

login, err := svc.Login(ctx,
    "bob@example.com", "Correct-Horse-Battery-7", "203.0.113.9", "curl/8")
fmt.Println(login.User.ID != "", login.AccessToken != "", err) // true true <nil>
```

`Login` and `Refresh` both return a `LoginResult` — the user, an access token
and a refresh token — rather than one returning a named struct and the other a
positional tuple whose two same-typed token strings a caller can transpose
without the compiler noticing. The user is an `auth.UserBase`: **`auth` is not
generic over a user type of yours**, unlike `scope`, and the [package
doc](auth/) says why in full. Your profile fields go in your own tables, keyed
by `UserBase.ID`. Every address is passed through `auth.NormalizeEmail` (trim,
lowercase) on every read and write, which is why the trailing space and the
capitals above vanish and why `BOB@example.com` cannot become a second
account. `ip` must be non-empty — a blank one would put every caller that
omits it into a single shared rate-limit bucket, so it is `ErrMissingIP`
rather than a tolerated "unknown".

**Five lifetimes, one option each:**

| Token | Minted by | TTL | Option |
|---|---|---|---|
| access | `Login`, `Refresh` | 15 min default | `WithJWT` |
| refresh (session) | `Login`, `Refresh` | 30 days default | `WithRefreshTTL` |
| `signup`, `email_change` | `SignUp`, `RequestEmailChange` | 24 hours default | `WithVerificationTTL` |
| `password_reset` | `RequestPasswordReset` | 1 hour default | `WithPasswordResetTTL` |
| `magic_link` | `RequestMagicLink` | 15 min default | `WithMagicLinkTTL` |

The defaults differ on purpose, and they rank the tokens by what holding one
gets you. The signup window is generous because mail that arrives late must
not force a whole new sign-up. The reset window is short because a reset link
grants a full credential change rather than an "I own this address"
attestation. The [magic-link](#magic-links) window is the shortest of all
because that token is not a step towards a credential — it *is* one, exchanged
for a live session with nothing else asked. Every one of these ignores a
non-positive duration and keeps its default rather than minting a token that
has already expired. Shortening the verification TTL also shortens how long an
`email_change` token stays armed, which is the strongest of the address-change
tokens — see the password lifecycle below.

### Rotation, reuse detection, and family revocation

A login mints two credentials. The **access token** is a short-lived HS256 JWT
the server never stores. The **refresh token** is a 32-byte opaque bearer
token whose sha256 becomes a `Session` row — the plaintext is never persisted,
so a database leak cannot be replayed into a session, the same stance
`invite.EmailInvite.TokenHash` takes.

Refreshing rotates: the presented token is marked superseded and a successor
is minted in the same **family** (every session descending from one login
shares a `FamilyID`). Presenting a token that has already been rotated away is
a **replay**, and authlayer cannot tell an attacker replaying a stolen token
from a client retrying a raced request — so it treats every replay as
compromise and revokes the whole family. Continuing from above:

```go
next, err := svc.Refresh(ctx, login.RefreshToken)
fmt.Println(next.RefreshToken != login.RefreshToken, err) // true <nil>

_, err = svc.Refresh(ctx, login.RefreshToken) // the token we already rotated away
fmt.Println(errors.Is(err, auth.ErrTokenReuse)) // true

_, err = svc.Refresh(ctx, next.RefreshToken) // died with its family
fmt.Println(errors.Is(err, auth.ErrTokenInvalid)) // true

live, _ := svc.ListSessions(ctx, login.User.ID)
fmt.Println(len(live)) // 0
```

The successor is gone too: revocation takes the family, not merely the token
that was replayed, because a successor an attacker had already rotated into
would otherwise survive the alarm that detected them. That is a
security-first trade — a genuine race between a client and its own retry
signs that user out everywhere — and it is deliberate.

Two things make it hold under concurrency, and both live on the `Store` port
as atomicity obligations rather than as advice. `MarkRotated` is a
compare-and-set: of however many callers present the same refresh token at
once, exactly one sees `ok=true`, and only that result authorizes minting —
never a `RotatedAt` value read a moment earlier, which is stale the instant
the goroutine yields. `CreateSuccessorSession` then inserts the successor only
if the predecessor row still exists, so a family revoked in the window between
the two is not resurrected by a winner still in flight — `Refresh` returns
`ErrSessionRevoked` instead of minting. Both windows are closed only insofar
as the backend honours the atomicity the port demands of it; both shipped
stores do, and the requirement is written on the interface for anyone writing
a third. An expired refresh token is ordinary end-of-life, not evidence of
theft: it is `ErrTokenInvalid` and leaves the family intact.

Rotated-but-unexpired rows are kept on purpose — they are what makes replay
detectable at all — and `auth.Service.PurgeExpired(ctx, before)` is the cron
that sweeps expired sessions and verifications later, a pass-through to the
`Store` method of the same name. It is housekeeping, not a security boundary
(an expired row is already refused by `Refresh`, `VerifyEmail` and
`ResetPassword` without it) but this package does *require* it, since nothing
else removes a retained predecessor row. Like `invite`'s, it authorizes
nothing and spans every user the store holds, so call it from a cron job or a
superuser console, never a per-request handler. The cutoff is literal: a
`before` in the future signs out live sessions. Because those rows are kept,
**revocation is per-family, not per-row**, everywhere it can be:

- `Logout` is idempotent. Presented a *current* token it removes that one
  session and leaves the family's tripwire rows alone. Presented a
  *superseded* one it revokes the whole family and still returns `nil` — the
  same signal `Refresh` treats as a replay, so the two paths agree about what
  it means. Deleting that row instead was a complete bypass of reuse
  detection that needed no race: a thief who steals `R`, refreshes it into
  `S_a`, then calls `Logout(R)` removed the very row the victim's replay
  would have tripped over, so the victim got a benign `ErrTokenInvalid`, the
  family was never revoked, and `S_a` rotated on indefinitely.
- `LogoutAll` revokes every family a user has, and is the only session path
  that also invalidates the account's pending `password_reset` and
  `email_change` verifications — see [the password lifecycle](#the-password-lifecycle).
- `RevokeSession` takes a session id but revokes that session's **family**,
  and only if the id belongs to the named user — another user's session is
  still reported identically to a nonexistent one. A family is one login's
  rotation chain, which is what "sign this device out" has to revoke — but
  it is not a promise about *devices*: `Refresh` copies the predecessor's
  `UserAgent`/`IP` into every successor, so a thief who rotates a stolen
  token joins the victim's family wearing the victim's fingerprint and a
  listing grouped by `FamilyID` shows one device where two are in use.
  Revoking the family is still right — it signs the thief out too.
  `ListSessions` returns rotation *history*, not a device list — one device
  refreshing at the 15-minute default accumulates about 97 rows a day, 96
  superseded — so revoking the single row a user picked off such a listing
  used to delete a superseded entry, return `nil`, and leave the device
  signed in. Group by `FamilyID` to build the listing; any row of a family
  revokes it.

### Verifying an access token

`WithJWT` already holds the keys, so verification is a method rather than
something you re-wire with a second copy of the key material:

```go
claims, err := svc.VerifyAccessToken(next.AccessToken)
fmt.Println(err, claims.Subject == login.User.ID) // <nil> true

u, _ := svc.User(ctx, claims.Subject)
fmt.Println(u.Email, u.PasswordHash == "") // bob@example.com true
```

It tries every key in the list, not just the signing key, which is what makes
a rotation transparent to tokens already in flight. Failures are
[`token`](token/)'s own sentinels — `ErrMalformedToken`,
`ErrUnsupportedAlgorithm`, `ErrInvalidSignature`, `ErrExpiredToken`,
`ErrKeyTooShort` — unwrapped, so you can tell an expired token from a forged
one; a `Service` built without `WithJWT` returns `ErrKeyTooShort` here exactly
as `Login` fails closed on the same misconfiguration. `claims.SessionID` is
what `ChangePassword` wants for its `currentSessionID`, which is the pairing
most handlers need:

```go
err = svc.ChangePassword(ctx, claims.Subject, claims.SessionID,
    "Correct-Horse-Battery-7", "Another-Valid-Pass22!")
fmt.Println(err) // <nil>
```

`User(ctx, id)` is the read path that goes with it: a thin wrapper over
`Store.FindUserByID` that scrubs `PasswordHash` like every other `Service`
method, which the `Store`'s own method — the only exported way to read a user
before it existed — does not.

### What "revocable" actually means

**Revoking a session does not invalidate an access token already issued for
it.** Verification is signature and expiry and nothing else: neither
`VerifyAccessToken` nor the `token.Parse` beneath it looks anything up. A
device holding a token keeps working until it expires — up to 15 minutes with
the default TTL — no matter what `Refresh`, `Logout`, `LogoutAll`,
`RevokeSession`, `ChangePassword` or `ResetPassword` did to the session behind
it. The verification above ran *after* reuse detection had already revoked the
entire family:

```go
sessions, _ := svc.ListSessions(ctx, claims.Subject)
fmt.Println(claims.SessionID != "", len(sessions)) // true 0
```

Zero sessions, and a token that still parses. So "revocable sessions" means
the refresh side is revocable *instantly* and the access side is revocable
*within one TTL*. Read every "signs out every device" sentence in this section
and in the package docs with that bound attached; it applies to all of them
without exception.

The hook for closing the gap is the `sid` claim (`token.Claims.SessionID`),
stamped by `Login` and `Refresh` with the id of the session that minted the
token. An application that needs another device's access to stop being
honoured sooner than the TTL must look `sid` up in the `Store` on every
request — the same per-request read `Refresh` and `RevokeSession` already do —
rather than trusting a parsed, still-unexpired JWT on its own. That is a real
cost (a database round trip per request) for a real property, and authlayer
does not make the choice for you: it puts `sid` in the token so the choice
exists. Shortening the access TTL through `WithJWT` narrows the window without
closing it.

### Enumeration-safe sign-up

A library that returns a token cannot fake "we emailed the account already on
file", so `SignUp` does not try: a duplicate address is **not an error**. Both
outcomes return `(SignUpResult, nil)`.

```go
again, err := svc.SignUp(ctx, "BOB@example.com", "Some-Other-Password-9")
fmt.Println(again.Created, again.VerifyToken == "", err) // false true <nil>
fmt.Println(again.User == (auth.UserBase{}))             // true — nothing of the account

weak, err := svc.SignUp(ctx, "carol@example.com", "short")
fmt.Println(weak.Created, errors.Is(err, auth.ErrWeakPassword)) // false true
```

The property holds *by construction* rather than by argument: the password is
validated before the address is even looked up, and every `Store` call after
`CreateUser` — the read-back and the verification mint — runs on **both**
branches with its result discarded on the duplicate one, so there is no call,
and therefore no failure, that one branch can reach and the other cannot. A
probe never touches the real accountholder's pending verification either; the
duplicate branch's mint is purely additive, so nobody can destroy a victim's
emailed link by "signing up" as them. And the duplicate branch hands back the
**zero** `User`, never the account it found: that record's `ID`, `CreatedAt`
and `EmailVerifiedAt` would each answer "is this address registered?" on their
own, in one request, to someone who has proven nothing about the address.

**The caller's obligation.** A public sign-up handler must emit a **fixed
response regardless of outcome** — same status code, same body shape, same
rough latency. That is stronger than "don't branch on `Created`": `Created`,
whether `VerifyToken` is present, whether `User` is populated, and the wall
clock are all observable, and any one of them reaching the client answers the
question the method exists not to answer. Use `VerifyToken` — non-empty only
when `Created` is true — to decide whether to send mail, never to decide what
to tell the HTTP client. The property is enforced up to the boundary of the
function and no further.

Two `Store` obligations are load-bearing here and are documented as
requirements on the port: `CreateUser` must decide `ErrEmailTaken` from the
same attempt that performs the write (never from a cheaper read first), and
`FindUserByEmail` must read its own writes. `store/memory` and `store/drops`
both honour them; a third-party backend that does not reopens the oracle from
inside the store. This is a joint property, not one `SignUp` can guarantee
alone.

### The password lifecycle

Every claim in this section is demonstrated, in order, by
[`examples/reset`](examples/reset/main.go) — `go run ./examples/reset`. It is
the runnable form of what follows: the enumeration-safe request shape, the
one-time redemption, the session revocation, the `EmailVerifiedAt` stamp, the
current-password gate on `RequestEmailChange`, and the sweep that kills a
parked reset token.

`ChangePassword(ctx, userID, currentSessionID, current, next)` requires the
current password, then revokes every session **except** the caller's own
family — pass the `sid` from the access token that authenticated the request,
which is what [`VerifyAccessToken`](#verifying-an-access-token) hands you; an
empty or foreign id revokes everything, which is the fail-closed direction.
`RequestPasswordReset` returns `(token, ok, nil)` and never errors merely
because an address is unknown. `ResetPassword` claims the verification first
and applies second (a failure after the claim burns the token rather than
leaving it redeemable twice), then revokes every session the account has.

**A completed reset also verifies the address.** A reset token is only ever
deliverable to the address it was minted for, so redeeming one *is* proof of
control of that address — the same proof a signup token carries, arriving
through a different door. `ResetPassword` therefore stamps `EmailVerifiedAt`
when it is not already set. Without that, `WithRequireVerifiedEmail(true)` —
which the quick start above enables — had no way out, because authlayer
exposes no verification resend path: someone who signed up with an address
they did not own permanently denied the real owner that address (the owner
could prove control through a reset and *still* not log in), and a user whose
signup mail was lost was locked out for good. Two guards keep it honest: an
already-verified address keeps its original timestamp rather than having it
moved forward by every unrelated reset, and an account whose address changed
since the token was minted is not certified at all — the proof is about the
address the token was *delivered* to, and `Store.MarkEmailVerified` re-checks
that atomically rather than trusting whatever the row now holds.
`RequestEmailChange` mints an `email_change` token, and **requires the current
password** to do it — the same check `ChangePassword` makes, with the same
timing discipline (an account with no password credential spends a comparable
`Dummy` and gets the same `ErrInvalidCredentials`, and a caller who fails the
check is not even told whether the address they proposed was well-formed).
Arming a rotation of the account's login identifier is the same kind of act as
rotating its password, and `VerifyEmail` then redeems the result with no
authentication at all; without the check, a briefly-held session or a leaked
15-minute access token bought a 24-hour account takeover. The new address is
checked for uniqueness atomically at redemption, not before, because a
pre-check would be an unrate-limited "is this registered?" oracle for any
authenticated caller.

`ChangePassword`, `ResetPassword` and `LogoutAll` each invalidate every
outstanding `password_reset`, `email_change` **and** `magic_link` token for
the account, which closes three real side doors. The reset one: an attacker
who requested a reset link and waited would otherwise keep a working way in
for that token's whole hour, even after the victim changed their password —
the one thing a user does on suspecting compromise. The `email_change` one is
stronger: that token lives 24 hours rather than one by default (all of them
are options — see the lifetimes table above) and `VerifyEmail` redeems it with
no authentication at all — moving the account to the attacker's address, after
which the victim cannot recover, because `Login` and `RequestPasswordReset`
both look accounts up *by email*. The [`magic_link`](#magic-links) one is the
most direct of the three: it does not let its holder *set* a credential, it
**is** one. A credential rotation that leaves any of them armed has not
rotated the credential that matters, and neither has a sign-out-everywhere.

`LogoutAll` is in that list because "sign out of every device" is precisely
what a user clicks on spotting an intruder; sweeping only on the two
credential paths meant the takeover survived it. `Logout` and `RevokeSession`
sweep **nothing**, deliberately: they are per-device and routine, and sweeping
there would break a flow with no attacker in it — request an email change on a
desktop, sign that desktop out, click the link that arrives on a phone.

**The whole table lives in one place.** Which action destroys which credential
is documented as a single matrix — eleven paths against five credential kinds
(the three token purposes above, the external identity, and the session) — in
`ChangePassword`'s own doc comment, under *The sweep matrix*, and every cell
of it has a test, the deliberate non-sweeps included. It is one table rather
than a rule to be inferred method by method because the last time it lived only
as an assumption spread across five method docs, it got filled in for two of
its three columns and the third was a full account takeover — and the columns
have since grown to five while the features filling them were built on branches
that could not see each other.

The mirror holds too: **redeeming an `email_change` invalidates the account's
outstanding `password_reset` and `magic_link` tokens.** Either is deliverable
to exactly one address, so moving the account away from that address — often
precisely because the mailbox is no longer trustworthy — must not leave one
sitting in the abandoned mailbox able to act on the account at its new one.
The magic-link half matters more than it looks: `RedeemMagicLink` does *not*
refuse a link whose recorded address no longer matches the account's — it
merely declines to re-stamp `EmailVerifiedAt`, and signs the holder in anyway
— so this sweep is the only thing between the abandoned mailbox and a live
session. That redemption does *not* revoke sessions: `VerifyEmail` is
unauthenticated by construction, so giving it a sign-out-everywhere effect
would hand a denial-of-service lever to anyone who obtains the link, and
arming the token already cost the current password. `LogoutAll` is the
authenticated control for that, and an application wanting "changing your
address signs you out everywhere" composes the two.

**All of these sweeps are sequential-only.** Nothing orders them against a
`RequestPasswordReset`, `RequestEmailChange` or `RequestMagicLink` whose own
`CreateVerification` is genuinely concurrent: park such a mint, run a full
`ChangePassword` (the sweep finds nothing), release the mint, and the
resulting token survives and later redeems. Closing that window for real needs
a transaction spanning both, which the `Store` port does not offer. The
sequential case is closed; the concurrent one is not, and this is stated
rather than papered over.

`password.DefaultRules()` is the default policy — 12 characters, upper, lower,
digit, and one character that is neither a letter, a digit, nor whitespace, so
padding a short password with spaces cannot satisfy it. `password.Validate`
returns the names of the failed rules (`min_length`, `upper`, `lower`,
`digit`, `special`) so a handler can render a stable message. Swap the
algorithm with `WithHasher`; `password.Hasher` is a three-method port, and its
`Dummy` method exists solely to spend comparable bcrypt time on a
user-not-found path — deleting it because "the result is discarded" silently
reinstates a timing oracle.

### Magic links

Every claim in this section is demonstrated, in order, by
[`examples/magiclink`](examples/magiclink/main.go) — `go run
./examples/magiclink`.

```go
token, ok, err := svc.RequestMagicLink(ctx, "dana@example.com", ip)
// ... deliver the link to that address if ok; return a FIXED response either way
result, err := svc.RedeemMagicLink(ctx, token, ip, userAgent) // a live session
```

`RequestMagicLink` is **byte-identical in shape to `RequestPasswordReset`** —
same `(token, ok, nil)` on every branch, same call sequence, same error set —
and the caller's obligation is the same, word for word: **return a fixed
response, same status and body shape, regardless of `ok`.** `ok` decides
whether to send mail and nothing else. Surfacing it, or the token's presence,
to an unauthenticated requester re-opens the existence oracle the whole shape
exists to close, and it is the one thing authlayer cannot enforce from here.
An anonymized account takes that same branch, with that same
`("", false, nil)`, for exactly that reason.

**A magic link is a login credential sitting in a mailbox.** Its holder
exchanges it for a live session through `RedeemMagicLink` with nothing else
asked of them, which is why:

- its default lifetime is the **shortest of the four purposes**
  (`WithMagicLinkTTL`, 15 minutes, against the reset token's hour and the
  signup/email-change token's 24);
- redemption **burns the token before issuing anything** — mint-then-burn
  would let two people clicking one forwarded link both get a session;
- a `password_reset` token presented here is `ErrVerificationPurpose`, checked
  *before* the burn: without that, a token granting only the right to *set* a
  password would be exchangeable directly for a session;
- **every remediation path sweeps it** — `ChangePassword`, `ResetPassword`,
  `LogoutAll`, both deletion postures, and an `email_change` redemption. See
  *The sweep matrix* above. `Logout` and `RevokeSession` deliberately do not.

**Redeeming a link verifies the address**, and stamps `EmailVerifiedAt` when
it is unset — receiving the link at that address is proof of control of it,
the same argument that makes a completed reset stamp. So a magic link is also
the way into an account that never clicked its signup mail. The two guards
`ResetPassword` applies apply here too: an already-verified address keeps its
original timestamp, and an account whose address moved since the link was
minted is not certified at all.

**Re-issuing invalidates the previous link**, so at most one is live per
account — with the same griefing consequence `RequestPasswordReset` carries
(anyone who merely knows an address can kill a victim's unclicked link by
looping the call). `WithMagicLinkRateLimiter` is what bounds it, keyed by the
normalized address; a denial from *that* limiter returns `("", false, nil)`,
never `ErrRateLimited`, because a distinguishable rate-limit error is itself
an oracle once enough requests for that address have run.

**`WithMagicLinkProvisioning(true)` creates the account at request time**, and
it is off by default. Stated plainly: with it on, anyone who can receive mail
can create an account for any address they control — the exposure an open
`SignUp` endpoint already has, and the rate limiter is the control, not the
option's absence. It also *reverses* the timing residual below: the unknown
branch becomes the slower one, because it performs an extra `CreateUser`. The
sign of the difference flips; it does not disappear. An account provisioned
this way holds no password credential at all, and asking for a link proves
nothing about the address — only redeeming one does, so the row stays
unverified until somebody clicks.

### Enumeration safety is bounded, not absolute

`SignUp`, `RequestPasswordReset` and `RequestMagicLink` equalise the *sequence
of calls* and the *set of errors* each branch can produce. None of them
equalises the wall clock, and on `RequestPasswordReset` the residual is
measured rather than assumed — by a harness in the tree, so it can be
re-derived and re-checked after any change:

```
AUTHLAYER_TEST_DSN=... go test -tags integration ./store/drops/ -run TimingChannel -v
```

Against a live PostgreSQL store a known address answers **several times
slower** than an unknown one, because the known branch performs two extra
writes — invalidate the previous token, mint the new one — that the unknown
branch has no user row to perform. The durable finding is that the two
distributions are **disjoint at the known branch's 5th percentile against the
unknown branch's 95th**: on a quiet same-host network one sample already
separates them more often than not. Six runs on one machine (Windows host,
PostgreSQL in a container, loopback) put the known median at 3.3–8.7 ms
against an unknown median of 0.5–1.0 ms — Δ≈2.8–8.0 ms, roughly 5.5–12×. The
disjointness held on every run; the absolute numbers did not — the same
machine reported 9.5–16.7 ms on a different day — and yours will differ, which
is why the harness reports rather than asserting a threshold.

What still makes a deployment's channel *wider* than that is unreclaimed dead
tuples: the harness measures a freshly vacuumed table, and an unvacuumed
version of it watched its own churn take the known median from 6.3 ms to
31.8 ms. **Table size no longer does.** `store/drops` indexes `verifications
(user_id, purpose)`, so the invalidating `DELETE` reads your own rows rather
than scanning every pending token held for *all* users. That was measured, not
assumed: seeding 40,000 other users' pending tokens moved the known branch's
floor from 2.3–2.5 ms to 4.7–5.0 ms *without* the index and left it at
2.4–2.8 ms *with* it. A backend that omits that index — a third-party `Store`,
or your own migrations owning these tables — puts the growth term back.

Over WAN jitter this needs on the order of 10²–10³ samples against one address
to resolve: practical against a single suspected address, impractical for bulk
enumeration, and real either way.

`WithPasswordResetRateLimiter` is what bounds it, by capping how many samples
an attacker can collect against any one address. It earns its keep twice over,
because the re-issue behaviour it gates has a second cost: since each request
invalidates the account's previous reset token, anyone who merely knows an
address — no credential, no relationship to the account — can kill a victim's
genuine pending reset link by looping calls. That falls out of the re-issue
contract itself, and the address limiter is what bounds how often it can
happen. There is no default; the bucket size is an operator decision.
`WithMagicLinkRateLimiter` is its counterpart for
[magic links](#magic-links), and carries both costs identically. Neither
limiter's denial is distinguishable from an unknown address: both return
`("", false, nil)`.

None of the figures above were measured for the magic-link flow specifically,
and this does not quote the reset flow's numbers as though they had been. The
mechanism is the same — the known branch performs the same two extra writes —
so the same shape applies, with the reversal `WithMagicLinkProvisioning`
causes noted in that section.

A caller can also reopen the channel from outside: if your handler awaits
`RequestPasswordReset` and then does address-dependent work before responding
— a real mail send, say — the transport leaks what the function bounded.
Normalise your own response timing, or accept the documented channel.

### Rate limiting

`RateLimiter` is a one-method port. `WithRateLimiter` wires the IP-keyed
limiter `Login`, `RequestPasswordReset` and `RequestMagicLink` all consult;
`WithPasswordResetRateLimiter` and `WithMagicLinkRateLimiter` wire the
address-keyed ones that only their own method consults. Keying login on IP and
never on email is
deliberate: an email-keyed bucket lets an attacker lock a victim out of their
own account by exhausting the victim's bucket, never their own.

There is **no default limiter** — the zero configuration rate-limits nothing,
because authlayer has no idea what your traffic looks like, and a wrong
default here is an outage. Wiring one is your job. Once wired, it fails
**closed**: a limiter that returns an error has failed to make a decision, and
an authentication decision that cannot be made must deny, so the error
propagates and the call is refused rather than admitted. The one deliberate
exception is *shape*, not stance: a denial from either address-keyed limiter
— the reset one or the [magic-link](#magic-links) one — returns the same
`("", false, nil)` an unknown address gets instead of `ErrRateLimited`, because a distinguishable error reachable only once enough
requests for *that* address had run would itself be the existence oracle the
method exists to close.

### The JWT, and why hand-rolling it is defensible

The two classic JWT vulnerabilities — `alg: none`, and RS256/HS256 confusion
where a public key is fed to an HMAC verifier — both need the same enabling
mistake: a parser that takes its algorithm *from the token* and dispatches on
it. `token.Parse` does not. It supports exactly one algorithm and compares the
header's `alg` to the literal string `"HS256"` before it verifies a signature
or decodes a payload; every other value, a missing field and a lower-case
`hs256` included, is rejected through that one line with
`ErrUnsupportedAlgorithm`. There is no `none` branch to reach and no second
algorithm to confuse it with. That single check is the whole justification for
not taking a dependency — and it is why generalising this package to a second
algorithm would bring both vulnerabilities back.

The same reasoning covers the key. An empty or undersized HMAC key is `alg:
none` reached through the key parameter instead of the header — the realistic
failure being `[]byte(os.Getenv("JWT_SECRET"))` with the variable unset — so
`Issue` and `Parse` both refuse anything under 32 bytes, the floor RFC 7518
§3.2 sets for HS256. `Parse` refuses the whole call if *any* key in the list
is short, rather than quietly skipping it. Signature comparison is
`hmac.Equal`, and every segment is decoded with strict base64, so one token
has exactly one valid encoding and the raw string is usable as a denylist key.

`Parse` takes a list of keys and tries each; `Issue` always signs with the
first, which is how a signing key is rotated. `WithClaimsExtender` adds
application claims, and they nest under one `"ext"` object rather than merging
into the top level — structurally, not by denylist, so an extender cannot
shadow a reserved claim:

```go
_, err = token.Issue(token.Claims{Subject: "u1"}, []byte("too-short"), time.Minute)
fmt.Println(errors.Is(err, token.ErrKeyTooShort)) // true

ext := auth.New(memory.NewAuthStore(),
    auth.WithJWT([][]byte{key}, 15*time.Minute),
    auth.WithClaimsExtender(func(u auth.UserBase) map[string]any {
        return map[string]any{"plan": "pro", "sub": "victim"}
    }))
_, _ = ext.SignUp(ctx, "dana@example.com", "Correct-Horse-Battery-7")
dana, _ := ext.Login(ctx,
    "dana@example.com", "Correct-Horse-Battery-7", "203.0.113.9", "curl/8")

c, err := token.Parse(dana.AccessToken, key)
fmt.Println(err, c.Subject == dana.User.ID)  // <nil> true
fmt.Println(c.Extra["plan"], c.Extra["sub"]) // pro victim
```

The extender's `"sub"` lands at `ext.sub` and the real subject is untouched.

### Wiring `auth`, `org` and `invite` together

The three packages share no store and no types. The only thing that connects
them is the user id `auth` mints, which `org`/`scope` and `invite` treat as an
opaque subject.

One seam is worth writing down, because every `auth` + `invite` integration
hits it: `invite.New` takes the **generic `*scope.Service`**, not the
`org.Service` wrapper. `org.Service` embeds
`*scope.Service[Organization, Member, *Organization, *Member]`, so the field
is reached by the embedded type's own name — `orgSvc.Service`.

```go
orgSvc := org.New(
    org.NewAccess(map[string][]access.Action{"project": {"create"}}),
    memory.New[org.Organization, org.Member]())
inviteSvc := invite.New(orgSvc.Service, memory.NewInviteStore())

// login.User.ID, from the Login above, is what org and invite see as the
// subject. Nothing else crosses between the halves.
alice := org.WithSubject(ctx, login.User.ID)
acme, err := orgSvc.CreateOrganization(alice, "Acme", "acme")
fmt.Println(acme.OwnerID == login.User.ID, err) // true <nil>

inOrg := org.WithOrg(alice, acme.ID)
inv, inviteToken, err := inviteSvc.InviteByEmail(inOrg, "carol@example.com", org.RoleAdmin)
fmt.Println(inv.RoleKey, inviteToken != "", err) // admin true <nil>
```

Carol then signs up through `auth` like anyone else and calls
`AcceptInvite` with the id `auth` minted for her — the invitation was created
for an *address*, before she had an account at all.
[`examples/auth`](examples/auth/main.go) runs exactly this, end to end.

## OAuth

`auth` signs a user in from an external provider — "sign in with Google", with
GitHub, with a corporate IdP — and owns the `identities` table that ties that
external account to a local one. [`examples/oauth`](examples/oauth/main.go)
runs this whole section end to end against `store/memory`, with no database,
and prints a trace of each step:

```sh
go run ./examples/oauth
```

### The boundary, first

**authlayer stores no provider access token and no provider refresh token, and
it is not an API client.** It never redirects a browser, never exchanges an
authorization code, never calls a provider's API, and never refreshes a
provider grant. Your application runs the dance with whatever client library
it likes — `golang.org/x/oauth2`, a vendor SDK, hand-written HTTP — validates
the response, and hands the result here as an `auth.ExternalIdentity`. That is
the same division of labour [`invite`](#invitations) draws around email
delivery, and the reason no OAuth client appears in [`go.mod`](go.mod).

An identity row is seven columns and no more: `id`, `user_id`, `provider`,
`subject`, `email`, `created_at`, `last_used_at`. There is no token column, so
a dump of that table holds nothing to replay against a provider on a user's
behalf. If your product needs to call a provider's API for a user, those
tokens are yours to store, in your own table, under your own rotation policy —
authlayer will not do it for you, and will not get in the way.

`Identity.Email` is what the **provider** asserted, normalized, at the moment
the link was made. It is an audit and display field. It may legitimately
differ from `UserBase.Email` — someone changed their address at the provider —
and it is **never an authentication input once the link exists**. Nothing in
the package copies it onto the account, and nothing rewrites it from a later
assertion.

### Wiring

`auth.IdentityStore` is a **separate, optional port**, deliberately not part of
`auth.Store`. [Account deletion](#account-deletion) went the *other* way in the
same milestone — four methods added straight onto the released `auth.Store` —
so the rule at work is not "never grow a released port", and it is worth
stating which one it is: **identities are functionality; deletion is not.** A
deployment that never offers a social login never needs an identity row, and a
backend that cannot store one is still a complete backend for every deployment
that does not — so charging every existing backend for a feature most will
never enable buys nothing. Every deployment, by contrast, eventually has to
remove an account, so a `Store` that silently could not is not one anybody can
finish deploying, and putting deletion behind an optional port would have
asserted the opposite. An application that offers no external sign-in wires
nothing and creates no table, and all four identity methods answer
`ErrOAuthNotConfigured` rather than dereferencing nil.

```go
import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/bernardoforcillo/authlayer/auth"
	"github.com/bernardoforcillo/authlayer/store/memory"
)
```

```go
key := []byte("32-bytes-or-more-from-your-vault") // the HS256 floor, RFC 7518 §3.2

svc := auth.New(memory.NewAuthStore(),
	auth.WithIdentityStore(memory.NewIdentityStore()), // dropsstore.NewIdentityStore(db)
	auth.WithJWT([][]byte{key}, 15*time.Minute))
// No WithLinking call: LinkVerified is Linking's zero value, so the safe
// policy is the one you get by saying nothing.

ctx := context.Background()
res, err := svc.SignInWith(ctx, auth.SignInRequest{
	Identity: auth.ExternalIdentity{
		Provider:      "google",
		Subject:       "109371829301827364501", // the provider's `sub` — opaque
		Email:         "dana@example.com",
		EmailVerified: true,
	},
	IP:        "203.0.113.9",
	UserAgent: "Mozilla/5.0",
})
fmt.Println(err, res.Created, res.User.Email) // <nil> true dana@example.com
```

`SignInWith` takes a `SignInRequest` struct, not positional arguments, and
returns a `SignInResult`: `Created`, the `User`, and the same `AccessToken`
and `RefreshToken` a password `Login` mints. `Created` is what you branch on to
run first-run onboarding.

**It is not free of disclosure, and an earlier version of this readme said it
was.** Reaching it takes a *completed* dance at a configured provider, so it is
not the freely pollable oracle sign-up's would be — but on the `FallbackEmail`
path the address is the caller's, so the outcome answers a question about it:
unregistered provisions, registered is refused with
`ErrLinkRequiresVerification`. The signal is the error rather than the field,
and the cost to a prober is one throwaway provider account per probe (a reused
subject resolves on rung 1 and never consults an address) plus a junk local
account left behind on every miss. That is a real cost, not a wall. Rate-limit
your callback.

Two deliberate differences from `Login`, both pinned by test: `SignInWith`
consults **no rate limiter** (the IP-keyed `WithRateLimiter` gates `Login` and
`RequestPasswordReset`, and neither limiter is consulted here), and
it therefore accepts an **empty `IP`** instead of refusing it with
`ErrMissingIP` — `IP` and `UserAgent` are the audit fields the `Session` row
records and nothing more. Rate limiting external sign-in is yours to do at the
transport, where the dance already lives.

### The resolution ladder

Two rungs, tried strictly in this order.

1. **`(provider, subject)`.** A hit **is** the account: its user is signed in,
   `LastUsedAt` is stamped, `Created` is false. No address is consulted at all.
2. **On a miss, the address decides** — `Identity.Email`, or
   `SignInRequest.FallbackEmail` when the provider returned none (GitHub with
   a private address is the usual case), normalized either way. With neither
   present the call fails with `ErrEmailRequired` having written nothing:
   `users.email` is unique, so provisioning on an empty address would create
   the one row every later address-less sign-in then collides with.
   - **No local account at that address** → provision one, with an **empty
     `PasswordHash`** and `EmailVerifiedAt` stamped only if the provider
     asserted the address verified. `Created` is true.
   - **A local account exists** → link to it only if the address came from the
     **provider** and the `Linking` policy allows, otherwise
     `ErrLinkRequiresVerification`. `Created` is false.

A `FallbackEmail` is **never** credited with `EmailVerified`, whatever the
provider said. That flag is the provider's claim about the address *the
provider returned*; when it returned none the claim is about nothing, and
letting it certify an address your application supplied would let a
verification of some entirely different address stand in for this one.

**A `FallbackEmail` may provision a new account and may never link to an
existing one** — under `LinkVerified`, under `LinkNever`, and under
`LinkAlways` too. The provider vouched for no address on that path, so the one
being matched is a string your caller supplied: linking on it would attach an
external account to somebody else's local account on the strength of that
string, and anyone able to finish a dance at any configured provider with a
throwaway account could name a victim's address and be signed in as them. The
rule therefore sits **above** the policy switch rather than inside it.
Provisioning stays allowed because nobody holds the address — there is nobody
to take over from, and refusing would strand every user whose provider keeps
their address private, which is the case `FallbackEmail` exists for. The
consequence to design your callback around: such a user cannot reach an account
they already hold by typing its address; they sign in with their password (or a
reset) and connect the provider afterwards.

A blank — or whitespace-only — `Provider` or `Subject` is refused with
`ErrProviderSubjectRequired` before any store is touched, in **both**
`SignInWith` and `LinkIdentity`. A blank subject is not a harmless empty
string: it is a key every account at that provider would collide on.

#### Why the subject rung comes first

Reversing it is a vulnerability, and it costs the same number of queries either
way.

The subject is the provider's own stable, opaque identifier for the external
account. The email is a mutable *attribute* of that account. Resolving by
subject first means someone who changes their address at the provider still
lands on the same local account instead of being silently split into a second
one. That is the usability half.

The security half is the same fact from the other side. If the address were
consulted first, an established link would resolve to whichever local account
the provider's *current* email field happens to name — so an attacker who can
make a provider assert a victim's address would re-route an identity they
already control onto the victim's account. With the subject first, an
already-linked identity never consults the address at all: **nothing a provider
says about email can move an existing link.**

### The three linking modes

`Linking` governs the **implicit** link on rung 2 only — an unknown
`(provider, subject)` whose address already belongs to someone here. An email
match is not authentication: under a naive "the addresses match, so sign them
in", anyone who can make any configured provider assert `victim@example.com`
owns that account without ever learning the password.

| Mode | Links to an existing account when | Notes |
|---|---|---|
| `LinkVerified` *(default; `Linking`'s zero value)* | the provider asserted the address verified **and** the local account's own email is already verified | Both halves; each closes an attack the other does not. |
| `LinkNever` | never | Every link must then be made explicitly, by an application that authenticated the user some other way first. |
| `LinkAlways` | always, on a **provider-asserted** address match alone | **Unsafe for any provider you do not fully control** — see below. |

`LinkVerified` needs *both* halves because either one alone is forgeable by
exactly the route the other closes. Without the provider half, anyone who can
register a victim's address at a provider that does not verify addresses signs
in as the victim. Without the local half, an attacker signs up locally with an
address they do not own and waits; when the real owner arrives through a
provider that genuinely verified it, their identity is attached to the
*attacker's* account — one the attacker still holds the password to.

`LinkAlways` is exactly the "an email match is authentication" behaviour above.
Its only legitimate use is a single first-party identity provider that **you**
operate, whose verification semantics you know, and which no third party can
make assert an arbitrary address. A provider that does not report verification
status at all must be mapped to `EmailVerified: false`, never defaulted to
true. That justification is about a provider's *assertions*, and it is the
exact boundary of what the mode permits: it does not extend to a
`FallbackEmail`, which links under no policy at all.

`WithLinking` **panics** on a mode outside those three, at construction rather
than at the first sign-in: a linking mode is a security decision made once, by
a human reading the option's doc, and a `Service` holding a value no branch
handles is either an unexplainable denial or a fallback that links more freely
than anyone chose.

`WithRequireVerifiedEmail` is **not** applied by `SignInWith`, deliberately. In
a password login the address *is* the claim; here the account is identified by
`(provider, subject)`, which the provider actually authenticated, and the
address is corroborating detail. Both rungs it could apply to are already
covered and more strictly — on the link rung `LinkVerified` already demands the
local account be verified, and on the provisioning rung the address lookup
*missed*, so there is nobody to take over from. **The residual, stated
plainly:** an application that sets `WithRequireVerifiedEmail(true)` can still
end up with an active, unverified account, provisioned here when the provider
reports the address unverified. Such an account holds no password, so it can
never reach `Login`'s check at all. The remedy available today is to configure
only providers that report verification honestly.
`TestSignInWithIgnoresRequireVerifiedEmail` pins both halves so this cannot
drift into an accident.

### The refusal, and its remedy

```go
// A second, unknown subject asserts an address that already belongs to
// someone here — and its provider does not claim to have verified it.
_, err = svc.SignInWith(ctx, auth.SignInRequest{
	Identity: auth.ExternalIdentity{
		Provider: "github", Subject: "2002", Email: "dana@example.com",
	},
})
fmt.Println(errors.Is(err, auth.ErrLinkRequiresVerification)) // true

// The remedy: the application authenticates dana some other way — a password
// login, or a reset if she has none — and links deliberately.
id, err := svc.LinkIdentity(ctx, res.User.ID, auth.ExternalIdentity{
	Provider: "github", Subject: "2002", Email: "dana@example.com",
})
fmt.Println(err, id.Provider, id.LastUsedAt == nil) // <nil> github true
```

The refusal is total — no identity row is written and no session is issued —
and `ErrLinkRequiresVerification` is a "not like this", not a dead end.

**`LinkIdentity` is not gated by the `Linking` policy, on purpose.** The policy
governs the *implicit* link inside `SignInWith`, where it is the only thing
standing between a provider's assertion and somebody else's account. Here the
trust basis is different in kind: the application has already authenticated the
user, and is attaching an identity to the account that user just proved they
hold. So `LinkNever` does **not** disable this method, and `LinkVerified` does
not require either side to be verified here. If the policy that produced the
refusal also blocked the remedy, the error would have no answer — and under
`LinkNever`, which produces it most often, no identity could ever be linked at
all.

What `LinkIdentity` does refuse:

- the pair is already linked to a **different** user → `ErrIdentityLinked`, and
  nothing is written. An existing link is never re-pointed;
- `userID` names no account → `ErrUserNotFound`. The account is read *before*
  the pair is looked up, so `ErrUserNotFound` wins when both would apply, and
  no row is ever left pointing at a user that does not exist;
- a blank `Provider` or `Subject` → `ErrProviderSubjectRequired`, before even
  the account is read.

Already linked to **this** user is not a refusal: the stored `Identity` comes
back unchanged, so a retried request is a no-op.

`Identity.LastUsedAt` is `nil` above because no sign-in happened. The sign-in
paths stamp it at creation for exactly that reason, so `nil` genuinely means
"this link has never signed the user in" rather than recording which code path
wrote the row.

### Unlinking, and the last credential

```go
// The google identity survives this one, so the account stays reachable.
fmt.Println(svc.UnlinkIdentity(ctx, res.User.ID, "github")) // <nil>

// This one would leave no identity and no password. Nothing is deleted.
err = svc.UnlinkIdentity(ctx, res.User.ID, "google")
fmt.Println(errors.Is(err, auth.ErrLastCredential)) // true
```

`UnlinkIdentity` removes **every** row for `(userID, provider)` — nothing in
the data model forbids two identities at one provider, and "unlink this
provider" means all of them — but refuses when that would leave the account
with no way in at all. The refusal is not a formality: `Login` rejects an empty
`PasswordHash` and `SignInWith` would have no link to resolve, so the lockout
would be permanent and silent. `ErrIdentityNotFound` is the different answer
for "there was nothing to unlink here", which a connected-accounts screen acts
on differently.

The question asked of the account is **"can it authenticate"**, not "is a hash
stored". Under `WithRequireVerifiedEmail(true)` `Login` refuses an unverified
account outright, so a password hash on one opens nothing and unlinking its
last identity would remove the only door that does — the predicate reads the
same option `Login` reads, so the two cannot disagree. It errs strict, and a
refusal removes nothing.

A successful unlink also **revokes every session the account holds**, the same
sweep `LogoutAll` and `ResetPassword` perform. Removing a credential and
revoking nothing would leave a session minted *through the identity being
removed* rotating for its full refresh TTL — the opposite of what "disconnect
this account" means. It sweeps all of the user's families rather than only
those minted through this identity, because a `Session` records no identity
provenance and a rotated successor would not carry it anyway; and there is no
carve-out for the caller's own session, unlike `ChangePassword`, which is handed
a `currentSessionID` this method has no equivalent of. Say so on the screen
before you call it. The delete runs first, so either refusal reaches you having
changed nothing at all.

The check and the delete are **one atomic step inside the store**
(`DeleteIdentityIfNotLast`), not a read-then-write in the service. Two
concurrent unlinks of a password-less user's last two identities would
otherwise each see the other's row, each conclude the account stays reachable,
and each delete — the read-then-write race this project has closed four times
elsewhere. `store/memory` gets atomicity from a single mutex acquisition;
`store/drops` uses a transaction with a per-user advisory lock and
`SELECT … FOR UPDATE`, because a single conditional `DELETE` cannot do it — its
`EXISTS` subquery neither locks what it reads nor sees a concurrent
uncommitted delete, so both callers would decide against a sibling that is
already going away.

The store is *told* whether the user holds a password rather than reading it,
because an `IdentityStore` owns `identities` and not `users` — which may be an
entirely different backend. The service reads the account fresh on every call
and passes the answer down, and that value can only go stale in the harmless
direction: no `Service` method removes a password (both writers store a freshly
hashed, non-empty value, and this package offers no "remove my password" and no
account deletion), so a `true` cannot become a `false` under the delete. **The
limit:** an application that calls `Store.UpdateUserPassword` with an empty hash
itself, going around `Service`, has removed a credential this package cannot
see, and must not concurrently unlink identities.

`ListIdentities` is a scoped pass-through: that user's rows and nobody else's.
An unknown user id comes back **empty rather than `ErrUserNotFound`**, so it is
not an account-existence oracle — while a store failure *is* an error, never a
quietly empty list. Whether "none" arrives as an empty or a nil slice is
unspecified; use `len`.

### An account provisioned here has no password

Not a scrubbed one — an empty column, which is a supported state.

```go
// The empty string is not a password-less account's password.
_, err = svc.Login(ctx, "dana@example.com", "", "203.0.113.9", "web")
fmt.Println(errors.Is(err, auth.ErrInvalidCredentials)) // true
```

`ChangePassword` cannot help either: it requires the **current** password, and
there is none to present. The only route to a first password is
`RequestPasswordReset` → `ResetPassword`, which needs no current password and
whose redemption is itself proof of control of the address the link was
delivered to — see [the password lifecycle](#the-password-lifecycle). That
route is pinned by `TestOAuthProvisionedUserGetsAPasswordThroughTheResetFlow`,
because a regression there would strand every such account on its provider
forever. A dedicated "set your first password" method would be better API; it
is additive, and not shipped.

### A password reset disconnects every linked account

`ResetPassword` removes **every** external identity on the account, and
`ChangePassword` removes none. A reset is *unauthenticated* recovery: whoever
redeemed the token proved control of an address and nothing else — no password,
no session, no device — so it is the one path that must assume every other
credential on the account is hostile, exactly as it already assumes every
session is. An external identity is such a credential, and the only one nothing
else here can reach: without the sweep, an attacker who had provisioned an
account holding the victim's address kept signing in through their identity
after the victim reset the password, logged in and called `LogoutAll` — every
step these docs prescribe, with the account still not theirs at the end.
`ChangePassword` deliberately does not sweep, because its caller was already
authenticated and is doing something routine; that is the same split this
package draws between `Logout` and `LogoutAll`.

**The consequence, plainly: after a password reset, connected accounts must be
linked again.** Either the user presses "Sign in with Google" once more — rung
2 re-applies the policy, and a reset has just certified the address, so a
verified assertion links straight back — or your application calls
`LinkIdentity` once they are authenticated. The sweep removes links that
*exist*; it cannot stop a provider that will keep asserting the address as
verified from being linked again under `LinkVerified`, which is the trust your
configuration places in that provider.

The sweep runs **before** the session revocation, not after: an identity left
live while the revocation runs can mint a fresh session the revocation has
already passed. A `Service` built without `WithIdentityStore` sweeps nothing and
reports no error, so a deployment with no external sign-in is unaffected.

### The `identities` table

`dropsstore.NewIdentityStore(db)` is the PostgreSQL backend, with its own
`CreateSchema` and `Schema()` like the other three stores:

```
identities  id PK (uuid by default), user_id, provider, subject, email,
            created_at, last_used_at NULL,
            UNIQUE (provider, subject), INDEX (user_id)
```

`UNIQUE (provider, subject)` is the load-bearing one. Without it two rows can
name the same external account against two **different** local users, and a
sign-in resolving that subject lands on whichever row the server returns
first — one external account silently able to sign in as either of two people,
decided by row order. It is also what closes the race below.
`INDEX (user_id)` serves both `ListIdentitiesByUser` (every connected-accounts
screen) and the locking `SELECT` inside every unlink; a live `EXPLAIN` test
proves the planner picks it, with a control that drops it and requires the plan
to degrade.

`last_used_at` is the table's only nullable column. `WithIdentityNames` renames
the table, and `WithIdentityTextLibraryIDs()` retypes **both** its id columns as
`text` for a non-UUID [`auth.WithIDGenerator`](#ids) — it must be passed
alongside `WithAuthTextLibraryIDs()`, since `identities.user_id` references
`users.id`. No foreign key is declared, matching every other schema here, and
here it is also forced: the auth store may be a different backend.

### What is not atomic, stated rather than smoothed over

Rung 1's lookup and rung 2's write are two steps, and two sign-ins for the same
new external account can both pass the lookup. That window is closed where it
can be: by `UNIQUE (provider, subject)`, which fails the loser with
`ErrIdentityLinked`, and by `users.email`'s uniqueness, which fails a concurrent
provisioning with `ErrEmailTaken`. Both are propagated rather than retried into
a link — "it exists now, so link to it" would skip the policy for precisely the
caller who lost the race. A retry from your application re-enters the ladder at
the top, which is the right outcome either way.

**The link window, closed without a transaction.** The linking decision reads
the local account from `auth.Store` and then writes the identity to
`auth.IdentityStore`, and the two may be different backends with no transaction
spanning them — that is the point of the split port. A concurrent
`UpdateUserEmail` landing in between would otherwise leave the identity
attached to an account that no longer holds the asserted address **at all**,
and rung 1 would then resolve that subject to it forever, never consulting an
address again. Closing that needs no transaction and it is closed: after the
write the account is re-read, and the row is deleted when the address it was
matched on is no longer the account's, with `ErrLinkRequiresVerification`
returned. Re-reading the address covers the `EmailVerifiedAt` the decision
stood on too, because nothing in `Service` can clear that field without also
moving the address. What remains is a retraction whose own delete fails: the
row survives, and the error says so.

**One window is disclosed rather than closed.** On the *provisioning* branch
`Store.CreateUser` commits before `CreateIdentity` runs, so a transient
identity-backend failure leaves a user row holding the address with no password
and no identity. When the provider did not assert the address verified, every
retry of the identical assertion then finds that account and is refused with
`ErrLinkRequiresVerification`. It is not an address lost for good:
`RequestPasswordReset` → `ResetPassword` gives that account a password **and**
certifies the address, after which `Login` works and a later verified assertion
links normally — pinned by
`TestSignInWithLeavesTheProvisionedUserWhenTheIdentityWriteFails`, so the
disclosure is checked rather than asserted. Compensating would mean deleting
the just-created user, and `Store.DeleteUser` now exists to do it with — the
reason `SignInWith` still does not is no longer a missing primitive. The row is
**addressable the instant `CreateUser` commits**: a concurrent `SignInWith`,
`RequestPasswordReset` or `RequestMagicLink` at that same address can already
have found it and acted on it by the time the identity write fails, so deleting
it would destroy an account somebody else is legitimately using — strictly
worse than the failure being compensated for. The compensating delete can also
fail on its own, which turns one disclosed window into two.

## Account deletion

Every claim in this section is demonstrated, in order, by
[`examples/deletion`](examples/deletion/main.go) — `go run ./examples/deletion`.

```go
err := svc.DeleteAccount(ctx, userID, currentPassword)    // hard: the row is gone
err := svc.AnonymizeAccount(ctx, userID, currentPassword) // soft: the row is kept and scrubbed
```

**Two postures, one shape.** They share the re-authentication rule, the hook,
the fail-safe order and the non-atomicity disclosure, and differ in one step:
where `DeleteAccount` ends with `Store.DeleteUser`, `AnonymizeAccount` ends
with `Store.MarkUserDeleted`, which keeps the row and scrubs it — address
replaced with an undeliverable value derived from the user's own id
(`deleted-<id>@example.invalid`, so two of them can never collide against
`users.email`'s UNIQUE constraint), password hash cleared, `EmailVerifiedAt`
cleared, and a new nullable `DeletedAt` stamped.

Choose on **one question: does anything outside authlayer still hold the user
id?** An audit trail, an order history, a foreign key from your own tables. If
so, removing the row leaves those pointing at nothing, and anonymizing is the
posture that keeps the id resolvable while making the person unidentifiable
and the account unusable. If nothing does, the hard posture is what "delete my
account" ordinarily means. Either way the original address is free for a new
sign-up immediately afterwards, and the new account gets a **new id**.

**Re-authentication is required when the account has a password.** An account
with none — provisioned by [`SignInWith`](#oauth) or by
[magic-link provisioning](#magic-links) — cannot supply one, and proceeds on
the caller's authority. That asymmetry is stated rather than implied: not
every deletion these methods perform is re-authenticated, and the application
is what authenticated the caller in the first place.

**The hook is the boundary.** `WithAccountDeletionHook(func(ctx, userID)
error)` fires **first**, before any authlayer row is removed, and **an error
from it aborts the whole call.** Fail closed: a half-deleted account is worse
than an undeleted one. authlayer removes what it owns — the user row, every
session, every verification, and (with an `IdentityStore` wired) every linked
identity. Everything else is yours, and the hook is where it goes: your own
tables, and critically the `scope` memberships authlayer cannot reach from
here. It must tolerate running again, because a later step failing leaves a
call the caller should retry.

**The order is fail-safe and is not negotiable:**

1. re-authenticate (or take the no-password branch);
2. the hook — the only step that may refuse;
3. `DeleteSessionsByUser` — **access stops here**;
4. `DeleteVerificationsByUser` — by *user*, so `signup` goes too, which no
   other path in [the sweep matrix](#the-password-lifecycle) touches;
5. every linked identity — a social account is a way in that needs no password
   at all;
6. `DeleteUser` or `MarkUserDeleted`, **last**.

Sessions before the row means a failure part-way leaves an account that cannot
be logged into and cannot be refreshed into, and that is still there to retry
the whole call against. The reverse order would leave the data gone and the
sessions live.

**None of it is atomic, and it cannot be.** `Store` exposes no transaction,
the identities live behind a *different* port that may be a different backend
entirely, and the hook reaches tables authlayer has no connection to at all.
There is no scope in which one commit could cover them. What the order buys is
that every reachable partial state falls on the same side, and the returned
error is the signal to run the call again — steps 3 and 4 treat "matched no
rows" as success, the identity sweep treats an already-removed row as success,
and `MarkUserDeleted` is idempotent.

**A stamped account is refused by every authentication entry point**, and this
is the half of the feature that must not be got wrong, so it is enumerated
rather than described: `Login`, `Refresh`, `ChangePassword`,
`RequestEmailChange`, `ResetPassword`, `VerifyEmail`, `RequestPasswordReset`,
`RequestMagicLink`, `RedeemMagicLink`, `SignInWith` (on **both** rungs of its
ladder) and `LinkIdentity`. Each carries its own explicit check rather than
sharing a guard, so that removing any one of them fails exactly one test.
`LinkIdentity` is in that list because it *arms* a way in rather than using
one: the scrub removes the password, so an identity linked afterwards would be
the account's only credential.

`ErrUserNotFound` is the refusal, rather than a new sentinel — it is already
in each of those methods' documented error sets, and an application already
maps it to 404. The two exceptions are the enumeration-safe pair:
**`RequestPasswordReset` and `RequestMagicLink` keep their indistinguishable
`("", false, nil)`** and gain no new error, because a distinguishable refusal
there would tell an anonymous caller that a particular address had been
anonymized — precisely the oracle those methods' shape exists to close.

**What neither posture revokes: an access token already issued.** It is a
stateless signed JWT; this package never looks a presented one up in the
`Store`. A device holding one keeps working for the remainder of its own TTL
(`WithJWT`, 15 minutes by default) after either method returns. That is the
single hole in "nobody may authenticate as this account", it is bounded, and
the per-request `sid`-claim lookup that closes it is
[described above](#what-revocable-actually-means).

## Errors

Compare with `errors.Is`, never by string. `org` re-exports these as *aliases*,
so `org.ErrOrgNotFound` **is** `scope.ErrContainerNotFound` and either name
matches.

| Error (`org` name if different) | Meaning | Suggested status |
|---|---|---|
| `ErrContainerNotFound` (`ErrOrgNotFound`) | No such container | 404 |
| `ErrRoleNotFound` | No default or custom role with that key | 404 |
| `ErrForbidden` | Member, but the role does not grant it | 403 |
| `ErrNotMember` | No membership in this container | 403 |
| `ErrOwnerOnly` | Reserved to the owner; no grant substitutes | 403 |
| `ErrPrivilegeEscalation` | Cannot grant what you do not hold | 403 |
| `ErrAlreadyMember` | That user is already a member | 409 |
| `ErrRoleKeyTaken` | Key collides with a default or existing role | 409 |
| `ErrConflict` (`ErrSlugTaken`) | Unique constraint on one of your fields | 409 |
| `ErrRoleInUse` | Role still assigned to members | 422 |
| `ErrDefaultRole` | Default roles cannot be modified at runtime | 422 |
| `ErrLastOwner` | Would remove or demote the owner | 422 |
| `ErrNotParentMember` | [Nested scope](#nested-scopes): `AddMember` target has no standing in the parent | 422 |
| `ErrSubjectMissing` | No subject on the context — a wiring bug | 500 |
| `ErrScopeMissing` (`ErrOrgMissing`) | No container on the context — a wiring bug | 500 |

`Can` already folds `ErrForbidden` and `ErrNotMember` into a plain `false`.

`invite` adds seven sentinels of its own — not exported by `scope`, and not
aliased anywhere, since invitations are a separate package with its own
failure modes (`apikey`'s eight follow further down):

| Error | Meaning | Suggested status |
|---|---|---|
| `ErrInviteNotFound` | No email invite with that id or token hash | 404 |
| `ErrLinkNotFound` | No link with that id or code | 404 |
| `ErrInviteExpired` | The invite's `ExpiresAt` has passed | 410 |
| `ErrLinkRevoked` | The link's `RevokedAt` is set | 410 |
| `ErrLinkExpired` | The link's `ExpiresAt` has passed | 410 |
| `ErrLinkExhausted` | The link's `UseCount` has reached its `MaxUses` | 410 |
| `ErrInvalidMaxUses` | `CreateLink` was passed a negative `maxUses` | 400 |

The first two are raised by the `Store` itself, on any lookup or delete that
matches no row — and also by the service layer, deliberately: `RevokeInvite`
and `RevokeLink` report them for an id that exists in *another* container, so
a cross-tenant id is indistinguishable from a missing one. `ErrInvalidMaxUses`
is a plain argument error, raised before any store is touched. The middle four
describe *why a redemption did not happen*
rather than a lookup miss, and only the service layer raises them: a link's
`Store.ConsumeLink` folds all three of its own reasons into a single
`ok=false` — the check and the increment must be one atomic step, so asking
that step to also report which of three conditions applied would require a
second, separate read, which is exactly the race atomicity rules out — and
`JoinViaLink` re-reads the link afterwards to tell them apart.

[`apikey`](#service-accounts--api-keys) adds eight. Denials are not
re-declared: a management call the actor may not make is `scope.ErrForbidden`
(or `scope.ErrNotMember`), and minting above one's standing is
`scope.ErrPrivilegeEscalation`.

| Error | Meaning | Suggested status |
|---|---|---|
| `ErrServiceAccountNotFound` | No service account with that id — or one in *another* container than the one on the context | 404 |
| `ErrKeyNotFound` | No key with that id or token hash — or, from the management calls, one in another container | 404 |
| `ErrKeyRevoked` | The key's `RevokedAt` is set | 401 |
| `ErrKeyExpired` | The key's `ExpiresAt` is not in the future | 401 |
| `ErrServiceAccountDisabled` | The key is live but its account is disabled; also refused by `CreateKey` | 401 (403 from `CreateKey`) |
| `ErrIDTaken` | A `Create*` was given an id that already identifies a row of that kind | 409 |
| `ErrEmptyPermissions` | `WithPermissions` compiled to a set granting nothing — refused rather than stored as *no cap* | 400 |
| `ErrInvalidExpiry` | `WithExpiry` named an instant not after now | 400 |

The first two are raised by the `Store` on any lookup, update or delete that
matches no row — and by the service, deliberately, for a record in another
container. The middle three are raised only by `Authenticate`; a `Store`
returns the row and the service reads the timestamps. The last two are
argument errors raised before any store is touched.

[`auth`](#authentication) adds twenty-four, split the same way — some raised by
the `Store` on a lookup or a constraint, the rest by the service. Eighteen
belong to the password-and-session core:

| Error | Meaning | Suggested status |
|---|---|---|
| `ErrUserNotFound` | No user with that id or email | 404 |
| `ErrSessionNotFound` | No session with that id or token hash | 404 |
| `ErrVerificationNotFound` | No verification with that id or token hash | 404 |
| `ErrInvalidCredentials` | `Login` failed — unknown address, no password credential, or wrong password, deliberately indistinguishable | 401 |
| `ErrTokenInvalid` | The refresh token is unknown or its session has expired. The family is **not** revoked | 401 |
| `ErrTokenReuse` | A rotated-away refresh token was presented again. Returned **alone**, the whole family is already revoked; wrapped around a second error, a replay was detected and the family may still be live — see the note under this table | 401 |
| `ErrSessionRevoked` | `Refresh` won the rotation, but the family was revoked before the successor could be persisted | 401 |
| `ErrEmailNotVerified` | `WithRequireVerifiedEmail` is on and the address is unconfirmed — checked only after the password verifies | 403 |
| `ErrEmailTaken` | Another user already holds this normalized address | 409 |
| `ErrIDTaken` | A `Create*` was given an id that already identifies a row of that kind | 409 |
| `ErrEmailMismatch` | `MarkEmailVerified` was asked to certify an address that is not the user's current one | 409 |
| `ErrVerificationExpired` | The verification's `ExpiresAt` has passed — checked before the claim, so the token is not burned | 410 |
| `ErrWeakPassword` | Fails the configured `password.Rules`; wraps the failed rule names | 400 |
| `ErrVerificationPurpose` | Right token, wrong flow — a `password_reset` token at `VerifyEmail` or at `RedeemMagicLink`, say. Checked before the claim, so the token is not burned | 400 |
| `ErrEmailRequired` | An address that is empty once normalized — `RequestEmailChange`'s new address, or a `SignInWith` whose provider returned none and whose `FallbackEmail` is blank too | 400 |
| `ErrRateLimited` | The IP-keyed `RateLimiter` refused. Never returned for either address-keyed limiter, reset or magic-link — see [Rate limiting](#rate-limiting) | 429 |
| `ErrMissingIP` | `Login`, `RequestPasswordReset` or `RequestMagicLink` was called with an empty ip — a wiring bug, not caller input. `RedeemMagicLink` deliberately does not refuse one: it consults no limiter | 500 |
| `ErrStoreContract` | A `Store` returned a value its own contract forbids, where continuing would silently degrade a security control. Every trigger today is one condition — a `Session` handed back with no `FamilyID`, leaving nothing to revoke — reached from `Refresh` (on a reported replay), `Logout` (of a superseded token) and `RevokeSession` | 500 |

`SignUp` is the one method that reports a duplicate address without an error
at all; see [Enumeration-safe sign-up](#enumeration-safe-sign-up).
`ErrTokenReuse` must be checked *before* testing whether an error wraps
anything else. Returned alone it means the family is already revoked; it comes
wrapped around a second error in exactly two cases, and in both a replay was
detected while the family may still be live — the family revocation itself
failing, and `ErrStoreContract`. Either way the alarm is never lost to the
failure of the response to it.

The remaining six are the [external-identity](#oauth) surface's own, raised by
`SignInWith`, `LinkIdentity`, `UnlinkIdentity` and `ListIdentities` or by the
`IdentityStore` beneath them:

| Error | Meaning | Suggested status |
|---|---|---|
| `ErrIdentityNotFound` | No identity for that `(provider, subject)` pair, id, or `(user, provider)` pair. From `UnlinkIdentity`, it means there was nothing to unlink | 404 |
| `ErrIdentityLinked` | That `(provider, subject)` pair is already linked to a *different* user. An existing link is never re-pointed | 409 |
| `ErrLinkRequiresVerification` | The address matches an existing local account and the identity was not attached to it: the [`Linking`](#the-three-linking-modes) policy refused, or the address came from `FallbackEmail` (refused under every policy), or the account's address moved under the decision and the link was retracted. The remedy in all three is `LinkIdentity` after authenticating the user another way | 409 |
| `ErrLastCredential` | Unlinking would leave the account with no identity and no password this `Service` would accept — under `WithRequireVerifiedEmail(true)` a hash on an unverified account does not count. A permanent lockout, so nothing is removed | 422 |
| `ErrProviderSubjectRequired` | An `ExternalIdentity` arrived with a blank or whitespace-only `Provider` or `Subject`. Refused before any store is touched, by both entry points | 400 |
| `ErrOAuthNotConfigured` | An external-identity method was called on a `Service` built without `WithIdentityStore` — a wiring bug, not caller input | 500 |

[`token`](token/) adds six. The first four are what a caller gets from
`Parse` for a bad token. The last two report a bad *key or TTL* rather than a
bad token — but only `ErrInvalidTTL` is confined to `Issue`. `Parse` checks
every key's length before it looks at the token at all and refuses the whole
call with `ErrKeyTooShort` if any one of them is short, so a misconfigured
`Service` surfaces that on the request path, not only at startup:

| Error | Meaning | Suggested status |
|---|---|---|
| `ErrMalformedToken` | Not a valid JWS compact serialization — wrong segment count, non-canonical base64, or a segment that is not JSON | 401 |
| `ErrUnsupportedAlgorithm` | The header's `alg` is not exactly `"HS256"`. Returned before any signature is verified | 401 |
| `ErrInvalidSignature` | No key in the list produced a matching signature | 401 |
| `ErrExpiredToken` | The signature verified but `exp` is not in the future — checked after verification, so it cannot probe for a valid signature on forged claims | 401 |
| `ErrKeyTooShort` | An HMAC key under 32 bytes was passed to `Issue`, or appears anywhere in `Parse`'s key list | 500 |
| `ErrInvalidTTL` | `Issue` was given a zero or negative ttl | 500 |

`password` defines no sentinels: `Validate` returns the names of the failed
rules and `Verify` returns a bool, so there is nothing to compare with
`errors.Is`.

## Packages

| Package | What it is |
|---|---|
| [`access`](access/) | The pure access-control engine — statements, permissions, roles. Standard library only. |
| [`scope`](scope/) | The generic RBAC engine: `Service`, `Store` port, policy, hooks, context helpers, guard. |
| [`org`](org/) | Organization RBAC — `scope` with the type parameters fixed and the names spelled "organization". |
| [`team`](team/) | Team RBAC nested inside `org` via `scope.WithParent` — the worked example of [nesting](#nested-scopes). |
| [`invite`](invite/) | [Invitations](#invitations) — email tokens and reusable links admitting a user with no standing yet, via `scope.Service.GrantMembership`. |
| [`invite/invitetest`](invite/invitetest/) | `invite.Store`'s contract as an executable suite — [write your own backend](#writing-your-own-invitestore) and run it. Test-only; imports `testing`. |
| [`apikey`](apikey/) | [Service accounts & API keys](#service-accounts--api-keys) — non-human members and the keys that authenticate as them, capped with `scope.WithPermissionCap`. |
| [`apikey/apikeytest`](apikey/apikeytest/) | `apikey.Store`'s contract as an executable suite — [write your own backend](#writing-your-own-apikeystore) and run it. Test-only; imports `testing`. |
| [`auth`](auth/) | [Authentication](#authentication) — `Service`, its `Store` port, and the user/session/verification records. Sign-up, login, email verification, refresh rotation, and the password lifecycle. Also the optional `IdentityStore` port and the four [external-identity](#oauth) methods. |
| [`auth/authtest`](auth/authtest/) | `auth.Store`'s contract as an executable suite — [write your own backend](#writing-your-own-authstore) and run it. Test-only; imports `testing`. |
| [`token`](token/) | Opaque bearer tokens (32 random bytes, sha256 stored) and a hand-rolled, [single-algorithm](#the-jwt-and-why-hand-rolling-it-is-defensible) HS256 JWT. Standard library only. |
| [`password`](password/) | The `Hasher` port with a bcrypt default, plus `Rules`/`Validate` for a strength policy. The only package that pulls in `golang.org/x/crypto`. |
| [`store/memory`](store/memory/) | In-memory `scope.Store`, `invite.Store`, `apikey.Store`, `auth.Store` and `auth.IdentityStore` for dev, tests, and examples. |
| [`store/drops`](store/drops/) | PostgreSQL stores built on drops — RBAC (composite-key membership), invitations, service accounts and keys, the three auth tables, and the [`identities`](#the-identities-table) table. |
| [`examples/basic`](examples/basic/) | Runnable, database-free tour of the RBAC half. |
| [`examples/auth`](examples/auth/) | Runnable, database-free tour of `auth` + `org` + `invite` wired together. |
| [`examples/reset`](examples/reset/) | Runnable, database-free tour of [the password lifecycle](#the-password-lifecycle) — `RequestPasswordReset`, `ResetPassword`, `RequestEmailChange`. |
| [`examples/oauth`](examples/oauth/) | Runnable, database-free tour of [external identities](#oauth) — the ladder, the linking policy, the explicit link, and the last-credential guard. |
| [`examples/apikey`](examples/apikey/) | Runnable, database-free tour of [service accounts & API keys](#service-accounts--api-keys) — mint, cap, authenticate, revoke, disable, cascade delete. |

Every exported symbol carries a doc comment; `go doc ./scope` is the reference.

### Checks

```sh
gofmt -l .                      # must print nothing
go vet ./... && go vet -tags integration ./...
go test ./... -count=1          # database-free
golangci-lint run ./...         # v2 required; the config is .golangci.yml
go run ./examples/basic && go run ./examples/auth && go run ./examples/reset
go run ./examples/oauth && go run ./examples/magiclink && go run ./examples/deletion
go run ./examples/apikey
go run ./docs/_verify           # every Go sample under docs/, compiled and run
```

`.golangci.yml` is a v2 config and runs clean at zero issues. It lints the
`integration`-tagged files too (`run.build-tags`), which is otherwise about
3.5k lines of the suite no static check would see. Every exclusion in it
carries the reason it is there.

[`.github/workflows/ci.yml`](.github/workflows/ci.yml) runs every command in
that block on each push and pull request, plus two the hand gate does not: the
unit tests under `-race`, and the live PostgreSQL lane below against a
`postgres:17-alpine` service container with its own `authlayer_test` database.
The Go version comes from `go.mod`'s own directive, so it cannot drift from the
module.

`internal/uid` is not importable — it is the RFC 9562 UUIDv7 generator
authlayer uses for every id it mints (containers, roles, users, sessions,
verifications), written out rather than depended on so the module stays at
three requirements. `scope.WithIDGenerator` and `auth.WithIDGenerator` override
it — see [Ids](#ids) for what `store/drops` needs when you do.

### Ids

`scope.WithIDGenerator` and `auth.WithIDGenerator` replace the id source for
everything authlayer mints. Against a `Store` of your own, the only requirement
is that ids are unique and stable.

**Against `store/drops`, a non-UUID generator needs the matching
text-library-ids option.** Every id the library mints for itself — a
container's `id`, a role's `id`, `container_id`, `parent_id`, and
`users`/`sessions`/`verifications` `id` — is a PostgreSQL `uuid` column *by
default*, which is right for the UUIDv7 generator authlayer ships and wrong for
any other. Pass the option for each store you use:

```go
// ulid here is github.com/oklog/ulid/v2 — illustrative, and not a dependency
// of authlayer. Both options take a func() string, and ulid.Make returns a
// ulid.ULID, so the adapter is yours to write.
newID := func() string { return ulid.Make().String() }

scopeSt := dropsstore.New[org.Organization, org.Member](db,
    dropsstore.WithTextLibraryIDs(), dropsstore.WithTextUserIDs())
inviteSt := dropsstore.NewInviteStore(db,
    dropsstore.WithInviteTextLibraryIDs(), dropsstore.WithInviteTextUserIDs())
authSt := dropsstore.NewAuthStore(db, dropsstore.WithAuthTextLibraryIDs())

orgSvc := org.New(ac, scopeSt, org.WithIDGenerator(newID))
authSvc := auth.New(authSt, auth.WithIDGenerator(newID))
```

The `WithTextUserIDs` / `WithInviteTextUserIDs` calls are there because in this
configuration the user ids stamped into `owner_id`, `user_id`, `invited_by` and
`created_by` come from that same generator. They are a **separate** option
covering a separate question — pointing the RBAC half at an existing non-UUID
user table — and on their own they do nothing for `WithIDGenerator`:
`New[...](db, WithTextUserIDs())` with a ULID generator still fails on the
first write. The auth store has no text-*user*-id option at all;
`WithAuthTextLibraryIDs` moves its `user_id` columns along with `users.id`,
since it owns the table they reference. The identity store is the same shape
for the same reason: `WithIdentityTextLibraryIDs()` moves `identities.id` and
`identities.user_id` together, and must be passed **alongside**
`WithAuthTextLibraryIDs()`, since the second of those columns references
`users.id`.

Without the right option, the first `CreateOrganization` or `SignUp` fails with
`SQLSTATE 22P02` (`invalid_text_representation`) — at the store, on the first
write. `store/memory` accepts any string, so a service developed and tested
entirely against the memory store passes every test and breaks on deployment.
All three directions are pinned by test:
`TestNonUUIDIDGeneratorIsAcceptedByTheMemoryStore` in `auth`;
`TestNonUUIDIDGeneratorFailsAgainstDropsLive` and
`TestNonUUIDIDGeneratorFailsAgainstTheScopeStoreLive` in `store/drops`'
integration lane, which assert the `22P02` on each half; and
`TestTextLibraryIDsRoundTripANonUUIDGeneratorLive` in the same lane, which
drives a ULID generator through a full sign-up/verify/login/refresh arc and a
full organization/member/custom-role arc against live PostgreSQL with the
options on.

`CreateSchema` emits the right DDL either way and stays idempotent, but it
never alters a table that already exists — so pick before the tables are
created, or retype the columns in your own migration.

## Roadmap

Milestone 2 is complete: [invitations](#invitations),
[authentication](#authentication) and [external identities](#oauth) have all
shipped. Two things this library deliberately does not do, and has no plan to:
run an OAuth dance, and store a provider's tokens.

One known gap inside what did ship: an account provisioned by an external
sign-in has [no password](#an-account-provisioned-here-has-no-password), and
its only route to a first one is the reset flow. A dedicated "set your first
password" method would be better API; it is additive, and can land without
breaking anything.

Released versions are recorded in [changelog.md](changelog.md).

## License

MIT — see [license.md](license.md).
