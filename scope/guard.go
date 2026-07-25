package scope

import "github.com/bernardoforcillo/drops/pg"

// MembershipGuard builds a drops query guard that restricts a resource table's
// rows to the containers the context subject belongs to. It reuses drops'
// pg.MembershipGuard and emits:
//
//	<resourceContainerCol> IN (
//	    SELECT <containerCol> FROM <junction> WHERE <subjectCol> = $subject
//	)
//
// junction is the members table; subjectCol and containerCol are its user-id
// and container-id columns; resourceContainerCol is the container-id column on
// the guarded table. Mount it with entity.AuthorizeWith(guard); the subject is
// read from the same context the Service uses (WithSubject), and a missing
// subject fails closed (pg.ErrSubjectMissing).
//
// This is coarse, membership-level filtering. Per-action row filtering is a
// planned follow-up.
func MembershipGuard(junction *pg.Table, subjectCol, containerCol, resourceContainerCol *pg.Column) pg.Guard {
	return pg.MembershipGuard{
		Junction:         junction,
		JunctionSubject:  subjectCol,
		JunctionResource: containerCol,
		ResourceOwner:    resourceContainerCol,
	}
}
