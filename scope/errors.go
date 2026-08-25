package scope

import "errors"

// Sentinel errors returned by the engine and stores. Compare with [errors.Is],
// never by string — the messages are not part of the API.
//
// They fall into four groups, which is usually how an HTTP layer wants to map
// them:
//
//   - Not found — ErrContainerNotFound, ErrRoleNotFound (404).
//   - Denied — ErrForbidden, ErrNotMember, ErrOwnerOnly,
//     ErrPrivilegeEscalation (403). Note that [Service.Can] already folds the
//     first two into a plain false.
//   - Conflict / invariant — ErrAlreadyMember, ErrRoleKeyTaken, ErrConflict,
//     ErrRoleInUse, ErrDefaultRole, ErrLastOwner, ErrNotParentMember (409 or
//     422).
//   - Caller bug — ErrSubjectMissing, ErrScopeMissing (500; the context was
//     not populated, which is a wiring mistake rather than a user error).
//
// The org package re-exports these under organization-flavoured names, so
// org.ErrOrgNotFound and scope.ErrContainerNotFound are the same value and
// either matches.
var (
	// ErrContainerNotFound: no container with that id exists.
	ErrContainerNotFound = errors.New("authlayer/scope: container not found")
	// ErrNotMember: the user has no membership in this container. Returned for
	// the acting subject and for a named target alike.
	ErrNotMember = errors.New("authlayer/scope: not a member of this container")
	// ErrForbidden: the subject is a member but their role does not grant every
	// requested (resource, action) pair.
	ErrForbidden = errors.New("authlayer/scope: insufficient permissions")
	// ErrPrivilegeEscalation: the escalation guard refused — the actor tried to
	// grant, mint, or remove a role carrying powers they do not themselves hold.
	ErrPrivilegeEscalation = errors.New("authlayer/scope: cannot grant permissions you do not have")
	// ErrRoleNotFound: no default role and no custom role in this container
	// carries that key.
	ErrRoleNotFound = errors.New("authlayer/scope: role not found")
	// ErrRoleInUse: the role still has members, so it cannot be deleted.
	// Reassign them first.
	ErrRoleInUse = errors.New("authlayer/scope: role is assigned to members")
	// ErrDefaultRole: owner, admin and member are defined in code and cannot be
	// updated or deleted at runtime.
	ErrDefaultRole = errors.New("authlayer/scope: cannot modify a default role")
	// ErrLastOwner: LastOwnerLocked is in force and the operation would remove
	// or demote the owner. Use TransferOwnership instead.
	ErrLastOwner = errors.New("authlayer/scope: cannot remove or demote the owner")
	// ErrOwnerOnly: the operation is reserved to the container owner and no
	// permission grant substitutes for ownership.
	ErrOwnerOnly = errors.New("authlayer/scope: only the owner may do this")
	// ErrAlreadyMember: that user already has a membership in this container.
	ErrAlreadyMember = errors.New("authlayer/scope: user is already a member")
	// ErrRoleKeyTaken: the key collides with a default role or with an existing
	// custom role of this container.
	ErrRoleKeyTaken = errors.New("authlayer/scope: role key already exists")
	// ErrNotParentMember: Policy.MembersFromParent is in force and the user
	// being added holds no standing in the parent scope — you cannot be on a
	// team without being in the organization that owns it. Add them to the
	// parent first. It is distinct from ErrNotMember, which is about this
	// container.
	ErrNotParentMember = errors.New("authlayer/scope: user is not a member of the parent scope")
	// ErrConflict: a container violated a unique constraint on one of the
	// application's own fields — a duplicate slug, say. org re-exports it as
	// ErrSlugTaken.
	ErrConflict = errors.New("authlayer/scope: container violates a unique constraint")
	// ErrSubjectMissing: no acting user on the context. Wrap requests with
	// WithSubject.
	ErrSubjectMissing = errors.New("authlayer/scope: no subject on context")
	// ErrScopeMissing: no active container on the context. Wrap requests with
	// WithScope (org.WithOrg).
	ErrScopeMissing = errors.New("authlayer/scope: no container on context")
)
