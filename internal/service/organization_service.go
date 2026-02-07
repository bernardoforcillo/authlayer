package service

import (
	"context"
	"errors"
	"time"

	"github.com/bernardoforcillo/authlayer/internal/auth"
	"github.com/bernardoforcillo/authlayer/internal/middleware"
	"github.com/bernardoforcillo/authlayer/internal/model"
	"github.com/bernardoforcillo/authlayer/internal/repository"
	authlayerv1 "github.com/bernardoforcillo/authlayer/pkg/proto/authlayer/v1"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
	"gorm.io/gorm"
)

type OrganizationService struct {
	authlayerv1.UnimplementedOrganizationServiceServer

	orgRepo       repository.OrganizationRepository
	orgMemberRepo repository.OrganizationMemberRepository
	roleRepo      repository.RoleRepository
	inviteRepo    repository.InvitationRepository
	userRepo      repository.UserRepository
	logger        *zap.Logger
}

func NewOrganizationService(
	orgRepo repository.OrganizationRepository,
	orgMemberRepo repository.OrganizationMemberRepository,
	roleRepo repository.RoleRepository,
	inviteRepo repository.InvitationRepository,
	userRepo repository.UserRepository,
	logger *zap.Logger,
) *OrganizationService {
	return &OrganizationService{
		orgRepo:       orgRepo,
		orgMemberRepo: orgMemberRepo,
		roleRepo:      roleRepo,
		inviteRepo:    inviteRepo,
		userRepo:      userRepo,
		logger:        logger,
	}
}

func (s *OrganizationService) CreateOrganization(ctx context.Context, req *authlayerv1.CreateOrganizationRequest) (*authlayerv1.CreateOrganizationResponse, error) {
	callerID, err := middleware.UserIDFromContext(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "not authenticated")
	}

	if req.Name == "" || req.Slug == "" {
		return nil, status.Errorf(codes.InvalidArgument, "name and slug are required")
	}

	org := &model.Organization{
		Name:    req.Name,
		Slug:    req.Slug,
		OwnerID: callerID,
	}

	if err := s.orgRepo.Create(ctx, org); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create organization: %v", err)
	}

	// Find the "owner" system role
	ownerRole, err := s.roleRepo.GetByNameAndOrg(ctx, "owner", nil)
	if err != nil {
		s.logger.Warn("owner role not found, skipping auto-membership", zap.Error(err))
	} else {
		// Add creator as owner member
		member := &model.OrganizationMember{
			OrgID:  org.ID,
			UserID: callerID,
			RoleID: ownerRole.ID,
		}
		if err := s.orgMemberRepo.Add(ctx, member); err != nil {
			s.logger.Error("failed to add owner membership", zap.Error(err))
		}
	}

	return &authlayerv1.CreateOrganizationResponse{
		Organization: orgToProto(org),
	}, nil
}

func (s *OrganizationService) GetOrganization(ctx context.Context, req *authlayerv1.GetOrganizationRequest) (*authlayerv1.GetOrganizationResponse, error) {
	var org *model.Organization
	var err error

	if req.GetId() != "" {
		id, parseErr := uuid.Parse(req.GetId())
		if parseErr != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid id")
		}
		org, err = s.orgRepo.GetByID(ctx, id)
	} else if req.GetSlug() != "" {
		org, err = s.orgRepo.GetBySlug(ctx, req.GetSlug())
	} else {
		return nil, status.Errorf(codes.InvalidArgument, "id or slug is required")
	}

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Errorf(codes.NotFound, "organization not found")
		}
		return nil, status.Errorf(codes.Internal, "failed to get organization")
	}

	return &authlayerv1.GetOrganizationResponse{Organization: orgToProto(org)}, nil
}

func (s *OrganizationService) UpdateOrganization(ctx context.Context, req *authlayerv1.UpdateOrganizationRequest) (*authlayerv1.UpdateOrganizationResponse, error) {
	orgID, err := uuid.Parse(req.OrgId)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid org_id")
	}

	org, err := s.orgRepo.GetByID(ctx, orgID)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "organization not found")
	}

	if req.Name != nil {
		org.Name = *req.Name
	}
	if req.Slug != nil {
		org.Slug = *req.Slug
	}

	if err := s.orgRepo.Update(ctx, org); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to update organization")
	}

	return &authlayerv1.UpdateOrganizationResponse{Organization: orgToProto(org)}, nil
}

func (s *OrganizationService) DeleteOrganization(ctx context.Context, req *authlayerv1.DeleteOrganizationRequest) (*authlayerv1.DeleteOrganizationResponse, error) {
	orgID, err := uuid.Parse(req.OrgId)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid org_id")
	}

	if err := s.orgRepo.Delete(ctx, orgID); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to delete organization")
	}

	return &authlayerv1.DeleteOrganizationResponse{}, nil
}

func (s *OrganizationService) ListOrganizations(ctx context.Context, req *authlayerv1.ListOrganizationsRequest) (*authlayerv1.ListOrganizationsResponse, error) {
	callerID, err := middleware.UserIDFromContext(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "not authenticated")
	}

	pagination := repository.Pagination{PageSize: 20}
	if req.Pagination != nil {
		pagination.PageSize = int(req.Pagination.PageSize)
		pagination.PageToken = req.Pagination.PageToken
	}

	orgs, total, err := s.orgRepo.ListByUserID(ctx, callerID, pagination)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to list organizations")
	}

	protoOrgs := make([]*authlayerv1.OrganizationInfo, len(orgs))
	for i, o := range orgs {
		protoOrgs[i] = orgToProto(&o)
	}

	return &authlayerv1.ListOrganizationsResponse{
		Organizations: protoOrgs,
		Pagination: &authlayerv1.PaginationResponse{
			TotalCount: int32(total),
		},
	}, nil
}

func (s *OrganizationService) ListMembers(ctx context.Context, req *authlayerv1.ListOrgMembersRequest) (*authlayerv1.ListOrgMembersResponse, error) {
	orgID, err := uuid.Parse(req.OrgId)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid org_id")
	}

	pagination := repository.Pagination{PageSize: 20}
	if req.Pagination != nil {
		pagination.PageSize = int(req.Pagination.PageSize)
		pagination.PageToken = req.Pagination.PageToken
	}

	members, total, err := s.orgMemberRepo.ListByOrgID(ctx, orgID, pagination)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to list members")
	}

	protoMembers := make([]*authlayerv1.MemberInfo, len(members))
	for i, m := range members {
		protoMembers[i] = &authlayerv1.MemberInfo{
			UserId:   m.UserID.String(),
			Name:     m.User.Name,
			Email:    m.User.Email,
			RoleId:   m.RoleID.String(),
			RoleName: m.Role.Name,
			JoinedAt: timestamppb.New(m.CreatedAt),
		}
	}

	return &authlayerv1.ListOrgMembersResponse{
		Members: protoMembers,
		Pagination: &authlayerv1.PaginationResponse{
			TotalCount: int32(total),
		},
	}, nil
}

func (s *OrganizationService) InviteMember(ctx context.Context, req *authlayerv1.InviteMemberRequest) (*authlayerv1.InviteMemberResponse, error) {
	callerID, err := middleware.UserIDFromContext(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "not authenticated")
	}

	orgID, err := uuid.Parse(req.OrgId)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid org_id")
	}

	roleID, err := uuid.Parse(req.RoleId)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid role_id")
	}

	token, err := auth.GenerateRandomToken(32)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to generate invitation token")
	}

	invitation := &model.Invitation{
		OrgID:     orgID,
		Email:     req.Email,
		RoleID:    roleID,
		Token:     auth.HashToken(token),
		Status:    model.InvitationStatusPending,
		ExpiresAt: time.Now().Add(7 * 24 * time.Hour),
		InviterID: callerID,
	}

	if err := s.inviteRepo.Create(ctx, invitation); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create invitation")
	}

	return &authlayerv1.InviteMemberResponse{
		InvitationId: invitation.ID.String(),
	}, nil
}

func (s *OrganizationService) AcceptInvitation(ctx context.Context, req *authlayerv1.AcceptInvitationRequest) (*authlayerv1.AcceptInvitationResponse, error) {
	callerID, err := middleware.UserIDFromContext(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "not authenticated")
	}

	tokenHash := auth.HashToken(req.Token)
	invitation, err := s.inviteRepo.GetByToken(ctx, tokenHash)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "invitation not found")
	}

	if invitation.Status != model.InvitationStatusPending {
		return nil, status.Errorf(codes.FailedPrecondition, "invitation is no longer pending")
	}

	if time.Now().After(invitation.ExpiresAt) {
		_ = s.inviteRepo.UpdateStatus(ctx, invitation.ID, model.InvitationStatusExpired)
		return nil, status.Errorf(codes.FailedPrecondition, "invitation has expired")
	}

	// Add member
	member := &model.OrganizationMember{
		OrgID:  invitation.OrgID,
		UserID: callerID,
		RoleID: invitation.RoleID,
	}
	if err := s.orgMemberRepo.Add(ctx, member); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to add member")
	}

	_ = s.inviteRepo.UpdateStatus(ctx, invitation.ID, model.InvitationStatusAccepted)

	org, _ := s.orgRepo.GetByID(ctx, invitation.OrgID)

	return &authlayerv1.AcceptInvitationResponse{
		Organization: orgToProto(org),
	}, nil
}

func (s *OrganizationService) RemoveMember(ctx context.Context, req *authlayerv1.RemoveOrgMemberRequest) (*authlayerv1.RemoveOrgMemberResponse, error) {
	orgID, err := uuid.Parse(req.OrgId)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid org_id")
	}
	userID, err := uuid.Parse(req.UserId)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid user_id")
	}

	if err := s.orgMemberRepo.Remove(ctx, orgID, userID); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to remove member")
	}

	return &authlayerv1.RemoveOrgMemberResponse{}, nil
}

func (s *OrganizationService) UpdateMemberRole(ctx context.Context, req *authlayerv1.UpdateOrgMemberRoleRequest) (*authlayerv1.UpdateOrgMemberRoleResponse, error) {
	orgID, err := uuid.Parse(req.OrgId)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid org_id")
	}
	userID, err := uuid.Parse(req.UserId)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid user_id")
	}
	roleID, err := uuid.Parse(req.RoleId)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid role_id")
	}

	if err := s.orgMemberRepo.UpdateRole(ctx, orgID, userID, roleID); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to update member role")
	}

	return &authlayerv1.UpdateOrgMemberRoleResponse{}, nil
}

func orgToProto(o *model.Organization) *authlayerv1.OrganizationInfo {
	if o == nil {
		return nil
	}
	return &authlayerv1.OrganizationInfo{
		Id:        o.ID.String(),
		Name:      o.Name,
		Slug:      o.Slug,
		OwnerId:   o.OwnerID.String(),
		CreatedAt: timestamppb.New(o.CreatedAt),
	}
}
