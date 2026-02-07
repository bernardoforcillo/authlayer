package repository

import (
	"context"

	"authz-go/internal/model"

	"github.com/google/uuid"
)

// Pagination holds cursor-based pagination parameters.
type Pagination struct {
	PageSize  int
	PageToken string
}

// UserFilter holds optional filters for user listing.
type UserFilter struct {
	Search *string
	Status *model.UserStatus
}

type UserRepository interface {
	Create(ctx context.Context, user *model.User) error
	GetByID(ctx context.Context, id uuid.UUID) (*model.User, error)
	GetByEmail(ctx context.Context, email string) (*model.User, error)
	Update(ctx context.Context, user *model.User) error
	Delete(ctx context.Context, id uuid.UUID) error
	List(ctx context.Context, filter UserFilter, pagination Pagination) ([]model.User, int64, error)
}

type AccountRepository interface {
	Create(ctx context.Context, account *model.Account) error
	GetByProviderAndID(ctx context.Context, provider, providerAccountID string) (*model.Account, error)
	GetByUserIDAndProvider(ctx context.Context, userID uuid.UUID, provider string) (*model.Account, error)
	DeleteByUserIDAndProvider(ctx context.Context, userID uuid.UUID, provider string) error
}

type SessionRepository interface {
	Create(ctx context.Context, session *model.Session) error
	GetByTokenHash(ctx context.Context, tokenHash string) (*model.Session, error)
	RevokeByTokenHash(ctx context.Context, tokenHash string) error
	RevokeAllByUserID(ctx context.Context, userID uuid.UUID) error
	RevokeByFamily(ctx context.Context, family string) error
	DeleteExpired(ctx context.Context) error
}

type APIKeyRepository interface {
	Create(ctx context.Context, apiKey *model.APIKey) error
	GetByKeyHash(ctx context.Context, keyHash string) (*model.APIKey, error)
	GetByID(ctx context.Context, id uuid.UUID) (*model.APIKey, error)
	ListByUserID(ctx context.Context, userID uuid.UUID, pagination Pagination) ([]model.APIKey, int64, error)
	Revoke(ctx context.Context, id uuid.UUID) error
	UpdateLastUsed(ctx context.Context, id uuid.UUID) error
}

type OrganizationRepository interface {
	Create(ctx context.Context, org *model.Organization) error
	GetByID(ctx context.Context, id uuid.UUID) (*model.Organization, error)
	GetBySlug(ctx context.Context, slug string) (*model.Organization, error)
	Update(ctx context.Context, org *model.Organization) error
	Delete(ctx context.Context, id uuid.UUID) error
	ListByUserID(ctx context.Context, userID uuid.UUID, pagination Pagination) ([]model.Organization, int64, error)
}

type OrganizationMemberRepository interface {
	Add(ctx context.Context, member *model.OrganizationMember) error
	Remove(ctx context.Context, orgID, userID uuid.UUID) error
	GetMembership(ctx context.Context, orgID, userID uuid.UUID) (*model.OrganizationMember, error)
	UpdateRole(ctx context.Context, orgID, userID, roleID uuid.UUID) error
	ListByOrgID(ctx context.Context, orgID uuid.UUID, pagination Pagination) ([]model.OrganizationMember, int64, error)
}

type TeamRepository interface {
	Create(ctx context.Context, team *model.Team) error
	GetByID(ctx context.Context, id uuid.UUID) (*model.Team, error)
	Update(ctx context.Context, team *model.Team) error
	Delete(ctx context.Context, id uuid.UUID) error
	ListByOrgID(ctx context.Context, orgID uuid.UUID, pagination Pagination) ([]model.Team, int64, error)
}

type TeamMemberRepository interface {
	Add(ctx context.Context, member *model.TeamMember) error
	Remove(ctx context.Context, teamID, userID uuid.UUID) error
	ListByTeamID(ctx context.Context, teamID uuid.UUID, pagination Pagination) ([]model.TeamMember, int64, error)
}

type RoleRepository interface {
	Create(ctx context.Context, role *model.Role) error
	GetByID(ctx context.Context, id uuid.UUID) (*model.Role, error)
	GetByNameAndOrg(ctx context.Context, name string, orgID *uuid.UUID) (*model.Role, error)
	Update(ctx context.Context, role *model.Role) error
	Delete(ctx context.Context, id uuid.UUID) error
	ListByOrgID(ctx context.Context, orgID *uuid.UUID, pagination Pagination) ([]model.Role, int64, error)
	GetAncestors(ctx context.Context, roleID uuid.UUID, maxDepth int) ([]model.Role, error)
}

type PermissionRepository interface {
	Create(ctx context.Context, perm *model.Permission) error
	GetByID(ctx context.Context, id uuid.UUID) (*model.Permission, error)
	GetByName(ctx context.Context, name string) (*model.Permission, error)
	List(ctx context.Context, pagination Pagination) ([]model.Permission, int64, error)
	GetByRoleID(ctx context.Context, roleID uuid.UUID) ([]model.Permission, error)
}

type RolePermissionRepository interface {
	Assign(ctx context.Context, roleID, permissionID uuid.UUID) error
	Revoke(ctx context.Context, roleID, permissionID uuid.UUID) error
	GetPermissionsByRoleIDs(ctx context.Context, roleIDs []uuid.UUID) ([]model.Permission, error)
}

type InvitationRepository interface {
	Create(ctx context.Context, invitation *model.Invitation) error
	GetByToken(ctx context.Context, token string) (*model.Invitation, error)
	UpdateStatus(ctx context.Context, id uuid.UUID, status model.InvitationStatus) error
	ListByOrgID(ctx context.Context, orgID uuid.UUID, pagination Pagination) ([]model.Invitation, int64, error)
}

type ServiceAccountRepository interface {
	Create(ctx context.Context, sa *model.ServiceAccount) error
	GetByID(ctx context.Context, id uuid.UUID) (*model.ServiceAccount, error)
	Update(ctx context.Context, sa *model.ServiceAccount) error
	Delete(ctx context.Context, id uuid.UUID) error
	ListByOrgID(ctx context.Context, orgID uuid.UUID, pagination Pagination) ([]model.ServiceAccount, int64, error)
}

type ServiceAccountKeyRepository interface {
	Create(ctx context.Context, key *model.ServiceAccountKey) error
	GetByKeyHash(ctx context.Context, keyHash string) (*model.ServiceAccountKey, error)
	Revoke(ctx context.Context, id uuid.UUID) error
	ListByServiceAccountID(ctx context.Context, saID uuid.UUID, pagination Pagination) ([]model.ServiceAccountKey, int64, error)
	UpdateLastUsed(ctx context.Context, id uuid.UUID) error
}

type ServiceAccountRoleRepository interface {
	Assign(ctx context.Context, sar *model.ServiceAccountRole) error
	Revoke(ctx context.Context, saID, roleID, orgID uuid.UUID) error
	ListByServiceAccountID(ctx context.Context, saID uuid.UUID) ([]model.ServiceAccountRole, error)
}
