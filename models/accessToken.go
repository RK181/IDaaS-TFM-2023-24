package models

import "time"

// AccessToken is a token that can be used to access resources
type AccessToken struct {
	ID             string // access token id
	Token          string // access token
	ClientID       string // client id
	RefreshTokenID string // refresh token id
	Subject        string // user id

	Audience   []string  // audience
	Expiration time.Time // expiration time
	Scopes     []string  // scopes
}
