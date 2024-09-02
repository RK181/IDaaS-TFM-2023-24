package models

import (
	"module/utils"
	"time"
)

// RefreshToken is a token that can be used to obtain a new access token
type RefreshToken struct {
	id       int    // refresh token id
	token    string // refresh token
	userID   int    // user id
	clientID string // client id

	authTime   time.Time // auth time
	amr        []string  // auth method references
	audience   []string  // audience
	expiration time.Time // expiration time
	scopes     []string  // scopes
}

func NewRefreshToken(userID int, clientID string, expiration time.Time, amr, audience, scopes []string) *RefreshToken {
	return &RefreshToken{
		token:      utils.GenUniqueID(), // uutd v4
		userID:     userID,
		clientID:   clientID,
		authTime:   time.Now().UTC(), // time of token creation
		expiration: expiration,
		amr:        amr,
		audience:   audience,
		scopes:     scopes,
	}
}

func (r *RefreshToken) SaveRefreshToken() error {
	return saveRefreshToken(r)
}

func (r *RefreshToken) GetRefreshToken() error {
	return getRefreshToken(r)
}

func (r *RefreshToken) DeleteRefreshToken() error {
	return deleteRefreshToken(r)
}
