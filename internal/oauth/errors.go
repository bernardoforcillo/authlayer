package oauth

import "errors"

var (
	ErrNoIDToken       = errors.New("oauth: no id_token in token response")
	ErrProviderNotFound = errors.New("oauth: provider not found")
)
