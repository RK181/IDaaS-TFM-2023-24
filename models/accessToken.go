package models

import (
	"module/utils"
	"time"

	"github.com/asdine/storm/v3/q"
)

// AccessToken is a token that can be used to access resources
type AccessToken struct {
	ID             int    // access token id
	TokenID        string // alternative id
	ClientID       string // client id
	RefreshTokenID string // refresh token id
	Subject        string // user id

	Audience   []string  // audience
	Expiration time.Time // expiration time
	Scopes     []string  // scopes
}

func NewAccessToken(clientID, refreshTokenID, subject string, audience, scopes []string) *AccessToken {

	return &AccessToken{
		ClientID:       clientID,
		RefreshTokenID: refreshTokenID,
		Subject:        subject,
		Audience:       audience,
		Expiration:     time.Now().Add(5 * time.Minute),
		Scopes:         scopes,
	}
}

// SaveAccessToken creates an access token
func (a *AccessToken) SaveAccessToken() error {
	var client Client
	client.SetID(a.ClientID)
	err := client.GetClient()
	if err != nil {
		return err
	}

	// Generate a unique token id
	a.TokenID = utils.GenUniqueIDv7()
	a.Expiration = time.Now().Add(time.Duration(client.GetAccessTokenExpTime()) * time.Minute)

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

func (a *AccessToken) DeleteAccessTokenByRefreshToken() error {
	db, err := dbConnect()
	if err != nil {
		return err
	}
	defer db.Close()

	query := db.Select(q.Eq("RefreshTokenID", a.RefreshTokenID)).Bucket("AccessToken")
	return query.Delete(new(AccessToken))
}
