package dropsstore

// IDOption retypes id columns from uuid to text, and is accepted by every
// store constructor in this package: [New], [NewAuthStore], [NewInviteStore],
// [NewAPIKeyStore], [NewIdentityStore], [NewCredentialStore], [NewMFAStore] and
// [NewOAuthStore], [NewAuditStore] and [NewAuditKeyStore], and the matching
// New*Schema functions. One list therefore
// configures a whole deployment:
//
//	rbac := dropsstore.New[org.Organization, org.Member](db,
//	    dropsstore.TextLibraryIDs(), dropsstore.TextUserIDs())
//	auth := dropsstore.NewAuthStore(db, dropsstore.TextLibraryIDs())
//
// The per-store options (WithAuthTextLibraryIDs, WithInviteTextUserIDs, ...)
// remain and are equivalent to these.
type IDOption struct {
	library, user bool
}

// TextLibraryIDs types the library-minted id columns — id, parent_id,
// container_id, and the ids that reference them — as text rather than uuid.
// Use it when a WithIDGenerator has replaced the default UUIDv7 with an id
// PostgreSQL's uuid parser does not accept.
//
// On the stores that own the users table — auth, identity, credential and MFA —
// the user ids are minted by the library too, so this also retypes user_id.
func TextLibraryIDs() IDOption { return IDOption{library: true} }

// TextUserIDs types the user-id columns the application supplies — user_id,
// owner_id, created_by, invited_by — as text rather than uuid. It applies where
// a store references users it does not own (the RBAC, invite, API-key and OAuth
// stores) and is ignored by the stores that own the users table, whose user ids
// follow [TextLibraryIDs].
func TextUserIDs() IDOption { return IDOption{user: true} }

// apply folds o into ids. ownsUsers is true for the stores whose user ids are
// library-minted.
func (o IDOption) apply(ids *idTypes, ownsUsers bool) {
	if o.library {
		ids.library = false
		if ownsUsers {
			ids.user = false
		}
	}
	if o.user && !ownsUsers {
		ids.user = false
	}
}
