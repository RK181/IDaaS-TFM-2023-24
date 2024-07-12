package models

import "time"

// RefreshToken is a token that can be used to obtain a new access token
type RefreshToken struct {
	ID       string // refresh token id
	Token    string // refresh token
	UserID   string // user id
	ClientID string // client id

	AuthTime   time.Time // auth time
	AMR        []string  // auth method references
	Audience   []string  // audience
	Expiration time.Time // expiration time
	Scopes     []string  // scopes
}
