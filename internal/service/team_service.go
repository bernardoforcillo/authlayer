package service

import (
	"context"
	"errors"

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

type TeamService struct {
	authlayerv1.UnimplementedTeamServiceServer

	teamRepo       repository.TeamRepository
	teamMemberRepo repository.TeamMemberRepository
	logger         *zap.Logger
}

func NewTeamService(
	teamRepo repository.TeamRepository,
	teamMemberRepo repository.TeamMemberRepository,
	logger *zap.Logger,
) *TeamService {
	return &TeamService{
		teamRepo:       teamRepo,
		teamMemberRepo: teamMemberRepo,
		logger:         logger,
	}
}

func (s *TeamService) CreateTeam(ctx context.Context, req *authlayerv1.CreateTeamRequest) (*authlayerv1.CreateTeamResponse, error) {
	if req.OrgId == "" || req.Name == "" {
		return nil, status.Errorf(codes.InvalidArgument, "org_id and name are required")
	}

	orgID, err := uuid.Parse(req.OrgId)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid org_id")
	}

	team := &model.Team{
		Name:  req.Name,
		OrgID: orgID,
	}

	if err := s.teamRepo.Create(ctx, team); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create team: %v", err)
	}

	return &authlayerv1.CreateTeamResponse{
		Team: teamToProto(team),
	}, nil
}

func (s *TeamService) GetTeam(ctx context.Context, req *authlayerv1.GetTeamRequest) (*authlayerv1.GetTeamResponse, error) {
	id, err := uuid.Parse(req.TeamId)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid team_id")
	}

	team, err := s.teamRepo.GetByID(ctx, id)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Errorf(codes.NotFound, "team not found")
		}
		return nil, status.Errorf(codes.Internal, "failed to get team")
	}

	return &authlayerv1.GetTeamResponse{Team: teamToProto(team)}, nil
}

func (s *TeamService) UpdateTeam(ctx context.Context, req *authlayerv1.UpdateTeamRequest) (*authlayerv1.UpdateTeamResponse, error) {
	id, err := uuid.Parse(req.TeamId)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid team_id")
	}

	team, err := s.teamRepo.GetByID(ctx, id)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "team not found")
	}

	if req.Name != nil {
		team.Name = *req.Name
	}

	if err := s.teamRepo.Update(ctx, team); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to update team")
	}

	return &authlayerv1.UpdateTeamResponse{Team: teamToProto(team)}, nil
}

func (s *TeamService) DeleteTeam(ctx context.Context, req *authlayerv1.DeleteTeamRequest) (*authlayerv1.DeleteTeamResponse, error) {
	id, err := uuid.Parse(req.TeamId)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid team_id")
	}

	if err := s.teamRepo.Delete(ctx, id); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to delete team")
	}

	return &authlayerv1.DeleteTeamResponse{}, nil
}

func (s *TeamService) ListTeams(ctx context.Context, req *authlayerv1.ListTeamsRequest) (*authlayerv1.ListTeamsResponse, error) {
	orgID, err := uuid.Parse(req.OrgId)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid org_id")
	}

	pagination := repository.Pagination{PageSize: 20}
	if req.Pagination != nil {
		pagination.PageSize = int(req.Pagination.PageSize)
		pagination.PageToken = req.Pagination.PageToken
	}

	teams, total, err := s.teamRepo.ListByOrgID(ctx, orgID, pagination)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to list teams")
	}

	protoTeams := make([]*authlayerv1.TeamInfo, len(teams))
	for i, t := range teams {
		protoTeams[i] = teamToProto(&t)
	}

	return &authlayerv1.ListTeamsResponse{
		Teams: protoTeams,
		Pagination: &authlayerv1.PaginationResponse{
			TotalCount: int32(total),
		},
	}, nil
}

func (s *TeamService) AddMember(ctx context.Context, req *authlayerv1.AddTeamMemberRequest) (*authlayerv1.AddTeamMemberResponse, error) {
	teamID, err := uuid.Parse(req.TeamId)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid team_id")
	}
	userID, err := uuid.Parse(req.UserId)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid user_id")
	}
	roleID, err := uuid.Parse(req.RoleId)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid role_id")
	}

	member := &model.TeamMember{
		TeamID: teamID,
		UserID: userID,
		RoleID: roleID,
	}

	if err := s.teamMemberRepo.Add(ctx, member); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to add team member")
	}

	return &authlayerv1.AddTeamMemberResponse{}, nil
}

func (s *TeamService) RemoveMember(ctx context.Context, req *authlayerv1.RemoveTeamMemberRequest) (*authlayerv1.RemoveTeamMemberResponse, error) {
	teamID, err := uuid.Parse(req.TeamId)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid team_id")
	}
	userID, err := uuid.Parse(req.UserId)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid user_id")
	}

	if err := s.teamMemberRepo.Remove(ctx, teamID, userID); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to remove team member")
	}

	return &authlayerv1.RemoveTeamMemberResponse{}, nil
}

func (s *TeamService) ListMembers(ctx context.Context, req *authlayerv1.ListTeamMembersRequest) (*authlayerv1.ListTeamMembersResponse, error) {
	teamID, err := uuid.Parse(req.TeamId)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid team_id")
	}

	pagination := repository.Pagination{PageSize: 20}
	if req.Pagination != nil {
		pagination.PageSize = int(req.Pagination.PageSize)
		pagination.PageToken = req.Pagination.PageToken
	}

	members, total, err := s.teamMemberRepo.ListByTeamID(ctx, teamID, pagination)
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

	return &authlayerv1.ListTeamMembersResponse{
		Members: protoMembers,
		Pagination: &authlayerv1.PaginationResponse{
			TotalCount: int32(total),
		},
	}, nil
}

func teamToProto(t *model.Team) *authlayerv1.TeamInfo {
	return &authlayerv1.TeamInfo{
		Id:    t.ID.String(),
		Name:  t.Name,
		OrgId: t.OrgID.String(),
	}
}

// Suppress unused import warning
var _ = middleware.AuthTypeUser
