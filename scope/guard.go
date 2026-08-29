package scope

import (
	"context"
	"errors"

	"github.com/bernardoforcillo/drops"
	"github.com/bernardoforcillo/drops/pg"

	"github.com/bernardoforcillo/authlayer/access"
)

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
// This is coarse, membership-level filtering: it asks only whether the
// subject belongs to the container, not what they may do there. For
// per-action filtering, use [Service.PermissionGuard].
func MembershipGuard(junction *pg.Table, subjectCol, containerCol, resourceContainerCol *pg.Column) pg.Guard {
	return pg.MembershipGuard{
		Junction:         junction,
		JunctionSubject:  subjectCol,
		JunctionResource: containerCol,
		ResourceOwner:    resourceContainerCol,
	}
}

// PermissionGuard returns a drops query guard restricting a table's rows to the
// containers in which the context subject may perform every action on resource.
//
// Where [MembershipGuard] asks "is the subject a member?", this asks "may the
// subject do this?" — the difference between showing every project in the
// user's organizations and showing only those they may delete.
//
//	projects.AuthorizeWith(svc.PermissionGuard(
//	    projectsTbl.Col("organization_id"), "project", org.ActionDelete))
//	// WHERE "organization_id" IN ($1, $2)
//
// It is built on [Service.ContainersWith] and inherits that method's limits — in
// particular, in a nested scope ([WithParent]) it sees membership-based standing
// only, so a subject whose standing in a container comes purely from the parent
// gets no rows for it here even though [Service.Can] admits them there.
//
// col is the container-id column on the table being guarded; a nil one is an
// error from Predicate, not a panic in the builder. The subject comes
// from the same context the Service reads ([WithSubject]); a missing subject is
// pg.ErrSubjectMissing and no predicate is produced. A subject with no
// qualifying containers renders as a false predicate, so the query returns
// nothing rather than everything.
//
// The predicate is resolved per query, which costs one round trip for the
// subject's standings plus one role lookup per distinct (container, role key)
// pair that names a custom role — a custom role is per-container, so the same
// role key in two containers is two lookups. [Service.ContainersWith] is
// exported so a hot path can hoist the id set and reuse it. The rendered IN
// list binds one parameter per qualifying container, so a subject who belongs
// to very many containers is another reason to hoist. Compose with other
// guards using pg.AnyOf / pg.AllOf.
func (s *Service[C, M, PC, PM]) PermissionGuard(
	col *pg.Column, resource string, actions ...access.Action,
) pg.Guard {
	return pg.CustomGuard(func(ctx context.Context) (drops.Expression, error) {
		// Reported like drops' own guards report a missing column, rather
		// than nil-dereferencing inside the query builder.
		if col == nil {
			return nil, errors.New("authlayer/scope: PermissionGuard col is nil")
		}
		subject, ok := SubjectFrom(ctx)
		if !ok {
			return nil, pg.ErrSubjectMissing
		}
		ids, err := s.ContainersWith(ctx, subject, resource, actions...)
		if err != nil {
			return nil, err
		}
		// pg.In renders an empty list as a false predicate, so this fails
		// closed without a special case.
		return pg.In(col, ids), nil
	})
}
