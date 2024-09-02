package models

import (
	"module/utils"
	"time"
)

// AccessToken is a token that can be used to access resources
type AccessToken struct {
	ID             int    `storm:"id,increment"` // access token id
	TokenID        string `storm:"unique"`       // alternative id
	ClientID       string // client id
	RefreshTokenID int    // refresh token id
	Subject        int    // user id

	Audience   []string  // audience
	Expiration time.Time // expiration time
	Scopes     []string  // scopes
}

// SaveAccessToken creates an access token
func (a *AccessToken) SaveAccessToken() error {
	// Generate a unique token id
	a.TokenID = utils.GenUniqueIDv7()

	return saveAccessToken(a)
}

// GetAccessToken
func (a *AccessToken) GetAccessToken() error {
	return getAccessToken(a)
}

// DeleteAccessToken deletes an access token
func (a *AccessToken) DeleteAccessToken() error {
	return deleteAccessToken(a)
}
