package scope

// EscalationMode controls the privilege-escalation guard applied when a member
// grants or is assigned a role.
//
// The guard exists so delegated administration cannot be used to climb: an
// actor who can add members must not be able to add a member more powerful than
// themselves, mint a custom role with powers they lack, or remove someone who
// outranks them. It applies to AddMember, ChangeMemberRole, RemoveMember,
// CreateRole and UpdateRole.
//
// Actors with elevated standing (the owner under OwnerBypass, or anyone holding
// a full permission set) are never subject to the guard — for them every role
// is trivially a subset.
type EscalationMode int

const (
	// EscalationStrict rejects granting any role not a subset of the actor's
	// own permissions (the default, matching the original behaviour).
	EscalationStrict EscalationMode = iota
	// EscalationAllowEqual additionally permits granting a role equal to the
	// actor's own set (subset check already covers equal, so this is reserved
	// for future "strictly-less" semantics and currently behaves like Strict).
	EscalationAllowEqual
	// EscalationOff disables the guard entirely (elevated actors already bypass
	// it; this extends the bypass to everyone with the base management perm).
	EscalationOff
)

// Policy bundles the tunable authorization invariants.
//
// The zero Policy is the *most permissive* configuration reachable through
// these fields for two of the three (no owner protection, no owner bypass) and
// the strictest for the third, so it is not a meaningful default. Do not build
// a Policy by zero value and set one field; start from the defaults —
// EscalationStrict, LastOwnerLocked and OwnerBypass all on, which is what a
// Service uses when no [WithPolicy] option is given — and change what you mean
// to change:
//
//	svc := org.New(ac, store, org.WithPolicy(org.Policy{
//	    Escalation:      scope.EscalationStrict,
//	    LastOwnerLocked: true,
//	    OwnerBypass:     false, // the only deviation
//	}))
type Policy struct {
	// Escalation selects the privilege-escalation guard; see [EscalationMode].
	Escalation EscalationMode
	// LastOwnerLocked protects the owner's membership: while set, the owner
	// cannot be removed or have their role changed by anyone (ErrLastOwner),
	// and cannot leave the container. Ownership can still move via
	// TransferOwnership, which is the intended path. Clearing it allows a
	// container to be left with no owner-membership at all, so only do so if
	// the application enforces its own invariant.
	LastOwnerLocked bool
	// OwnerBypass grants the container owner the full permission set and
	// elevated standing regardless of the role key on their membership, so the
	// owner can always recover a container whose roles were mis-configured.
	// Clearing it makes the owner an ordinary member subject to their role —
	// note that this can lock the owner out of their own container.
	OwnerBypass bool
}

func defaultPolicy() Policy {
	return Policy{
		Escalation:      EscalationStrict,
		LastOwnerLocked: true,
		OwnerBypass:     true,
	}
}
