package authzv1

import "google.golang.org/protobuf/types/known/timestamppb"

type CreateAPIKeyRequest struct {
	Name      string                 `json:"name,omitempty"`
	Scopes    []string               `json:"scopes,omitempty"`
	ExpiresAt *timestamppb.Timestamp `json:"expires_at,omitempty"`
}

type CreateAPIKeyResponse struct {
	ApiKey       *APIKeyInfo `json:"api_key,omitempty"`
	PlainTextKey string      `json:"plain_text_key,omitempty"`
}

type RevokeAPIKeyRequest struct {
	ApiKeyId string `json:"api_key_id,omitempty"`
}

type RevokeAPIKeyResponse struct{}

type ListAPIKeysRequest struct {
	Pagination *PaginationRequest `json:"pagination,omitempty"`
}

type ListAPIKeysResponse struct {
	ApiKeys    []*APIKeyInfo       `json:"api_keys,omitempty"`
	Pagination *PaginationResponse `json:"pagination,omitempty"`
}

type ValidateAPIKeyRequest struct {
	Key string `json:"key,omitempty"`
}

type ValidateAPIKeyResponse struct {
	Valid  bool     `json:"valid,omitempty"`
	UserId *string  `json:"user_id,omitempty"`
	Scopes []string `json:"scopes,omitempty"`
}
