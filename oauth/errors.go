package oauth

import (
	"errors"
	"net/http"
)

// The RFC 6749 §5.2, RFC 8628 §3.5, RFC 6750 §3.1 and RFC 7591 §3.2.2 error
// codes [ErrorCode] maps this package's sentinels to. They are the strings
// an application writes into the "error" member of an error response.
const (
	CodeInvalidRequest        = "invalid_request"
	CodeInvalidClient         = "invalid_client"
	CodeInvalidGrant          = "invalid_grant"
	CodeUnauthorizedClient    = "unauthorized_client"
	CodeInvalidScope          = "invalid_scope"
	CodeAccessDenied          = "access_denied"
	CodeAuthorizationPending  = "authorization_pending"
	CodeSlowDown              = "slow_down"
	CodeExpiredToken          = "expired_token"
	CodeInvalidToken          = "invalid_token"
	CodeInvalidClientMetadata = "invalid_client_metadata"
	CodeInvalidRedirectURI    = "invalid_redirect_uri"
	CodeServerError           = "server_error"
)

// errorCodes is the mapping [ErrorCode] walks, in precedence order: the
// most specific sentinel an error wraps wins, so an ErrInvalidGrant
// wrapping ErrCodeNotFound answers invalid_grant, and an ErrInvalidToken
// wrapping ErrGrantRevoked answers invalid_token.
var errorCodes = []struct {
	err    error
	code   string
	status int
}{
	{ErrInvalidToken, CodeInvalidToken, http.StatusUnauthorized},
	{ErrInvalidClient, CodeInvalidClient, http.StatusUnauthorized},
	{ErrClientDisabled, CodeInvalidClient, http.StatusUnauthorized},
	{ErrAuthorizationPending, CodeAuthorizationPending, http.StatusBadRequest},
	{ErrSlowDown, CodeSlowDown, http.StatusBadRequest},
	{ErrAccessDenied, CodeAccessDenied, http.StatusBadRequest},
	{ErrExpiredToken, CodeExpiredToken, http.StatusBadRequest},
	{ErrCodeReused, CodeInvalidGrant, http.StatusBadRequest},
	{ErrTokenReuse, CodeInvalidGrant, http.StatusBadRequest},
	{ErrPKCEMismatch, CodeInvalidGrant, http.StatusBadRequest},
	{ErrGrantRevoked, CodeInvalidGrant, http.StatusBadRequest},
	{ErrGrantExpired, CodeInvalidGrant, http.StatusBadRequest},
	{ErrInvalidGrant, CodeInvalidGrant, http.StatusBadRequest},
	{ErrInvalidScope, CodeInvalidScope, http.StatusBadRequest},
	{ErrUnauthorizedClient, CodeUnauthorizedClient, http.StatusBadRequest},
	{ErrInvalidRedirectURI, CodeInvalidRedirectURI, http.StatusBadRequest},
	{ErrPKCERequired, CodeInvalidRequest, http.StatusBadRequest},
	{ErrInvalidClientMetadata, CodeInvalidClientMetadata, http.StatusBadRequest},
	{ErrEmptyPermissions, CodeInvalidScope, http.StatusBadRequest},
	{ErrRegistrationDisabled, CodeInvalidRequest, http.StatusForbidden},
	{ErrDeviceNotPending, CodeInvalidRequest, http.StatusConflict},
	{ErrIDTaken, CodeServerError, http.StatusConflict},
	{ErrClientNotFound, CodeInvalidRequest, http.StatusNotFound},
	{ErrGrantNotFound, CodeInvalidRequest, http.StatusNotFound},
	{ErrDeviceNotFound, CodeInvalidRequest, http.StatusNotFound},
	{ErrCodeNotFound, CodeInvalidGrant, http.StatusNotFound},
	{ErrRefreshNotFound, CodeInvalidGrant, http.StatusNotFound},
	{ErrIssuerRequired, CodeServerError, http.StatusInternalServerError},
}

// ErrorCode maps an error from this package to the "error" code an OAuth
// error response carries and a suggested HTTP status, so an application
// writes the JSON body and this package never has to. The table, which the
// readme reproduces:
//
//	ErrInvalidToken            invalid_token            401   (RFC 6750; the WWW-Authenticate challenge)
//	ErrInvalidClient           invalid_client           401
//	ErrClientDisabled          invalid_client           401
//	ErrAuthorizationPending    authorization_pending    400   (RFC 8628)
//	ErrSlowDown                slow_down                400   (RFC 8628)
//	ErrAccessDenied            access_denied            400   (RFC 8628)
//	ErrExpiredToken            expired_token            400   (RFC 8628)
//	ErrCodeReused              invalid_grant            400
//	ErrTokenReuse              invalid_grant            400
//	ErrPKCEMismatch            invalid_grant            400   (RFC 7636 §4.6)
//	ErrGrantRevoked            invalid_grant            400
//	ErrGrantExpired            invalid_grant            400
//	ErrInvalidGrant            invalid_grant            400
//	ErrInvalidScope            invalid_scope            400
//	ErrUnauthorizedClient      unauthorized_client      400
//	ErrInvalidRedirectURI      invalid_redirect_uri     400   (RFC 7591; invalid_request at the authorization endpoint)
//	ErrPKCERequired            invalid_request          400
//	ErrInvalidClientMetadata   invalid_client_metadata  400   (RFC 7591)
//	ErrEmptyPermissions        invalid_scope            400
//	ErrRegistrationDisabled    invalid_request          403
//	ErrDeviceNotPending        invalid_request          409
//	ErrIDTaken                 server_error             409
//	ErrClientNotFound          invalid_request          404
//	ErrGrantNotFound           invalid_request          404
//	ErrDeviceNotFound          invalid_request          404
//	ErrCodeNotFound            invalid_grant            404
//	ErrRefreshNotFound         invalid_grant            404
//	ErrIssuerRequired          server_error             500
//	anything else              server_error             500
//
// The walk is in precedence order, so a wrapped chain answers for its most
// specific member: the token endpoints wrap ErrCodeNotFound,
// ErrRefreshNotFound and ErrDeviceNotFound in ErrInvalidGrant, which is
// what a client is told, and Authenticate wraps every cause in
// ErrInvalidToken. scope's own denials — ErrForbidden, ErrNotMember,
// ErrPrivilegeEscalation — reach an application from the management and
// consent calls, not the token endpoints, and are its own to map (403).
// Two statuses are suggestions the RFCs leave open: a not-found from a
// management call is 404 here as everywhere in this module, and
// ErrRegistrationDisabled is 403 because the endpoint exists and is
// refusing, not missing.
func ErrorCode(err error) (code string, status int) {
	for _, e := range errorCodes {
		if errors.Is(err, e.err) {
			return e.code, e.status
		}
	}
	return CodeServerError, http.StatusInternalServerError
}
