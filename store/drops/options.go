package dropsstore

// Option customizes any store or schema constructor in this package. There is
// one option type, not one per store: each constructor reads only the settings
// that concern it and ignores the rest, so a single list can configure a whole
// deployment:
//
//	opts := []dropsstore.Option{dropsstore.TextLibraryIDs()}
//	auth := dropsstore.NewAuthStore(db, opts...)
//	rbac := dropsstore.New[org.Organization, org.Member](db, opts...)
//
// The per-store names (AuthOption, InviteOption, ...) are aliases of Option and
// remain only so existing signatures keep compiling.
type Option interface{ apply(*config) }

// optionFunc adapts a plain function to [Option].
type optionFunc func(*config)

func (f optionFunc) apply(c *config) { f(c) }

// config is everything an Option can set. The per-store table names live side
// by side, so one value carries a whole deployment's naming.
type config struct {
	scope      Names
	auth       AuthNames
	invite     InviteNames
	apikey     APIKeyNames
	identity   IdentityNames
	credential CredentialNames
	mfa        MFANames
	oauth      OAuthNames
	audit      AuditNames

	textLibrary, textUser bool
}

func newConfig(opts []Option) config {
	var c config
	for _, o := range opts {
		if o != nil {
			o.apply(&c)
		}
	}
	return c
}

// ids resolves the id column types for one store. ownsUsers is true for the
// stores whose user ids the library mints itself (auth, identity, credential,
// MFA); there [TextLibraryIDs] also retypes user_id and [TextUserIDs] is
// ignored.
func (c config) ids(ownsUsers bool) idTypes {
	ids := uuidIDs()
	if c.textLibrary {
		ids.library = false
		if ownsUsers {
			ids.user = false
		}
	}
	if c.textUser && !ownsUsers {
		ids.user = false
	}
	return ids
}

// defaulted sets *p to def when it is empty. It is what every Names type's
// withDefaults is built from.
func defaulted(p *string, def string) {
	if *p == "" {
		*p = def
	}
}

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

func (o IDOption) apply(c *config) {
	c.textLibrary = c.textLibrary || o.library
	c.textUser = c.textUser || o.user
}
