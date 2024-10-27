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
		Expiration:     time.Now().Add(5 * time.Minute), // default expiration time is 5 minutes
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

	db, err := dbConnect()
	if err != nil {
		return err
	}
	defer db.Close()

	accessTokenDB := accessTokenSerialize(a)
	return db.Save(accessTokenDB)
}

// GetAccessToken
func (a *AccessToken) GetAccessToken() error {
	db, err := dbConnect()
	if err != nil {
		return err
	}
	defer db.Close()

	var accessTokenDB accessTokenDB

	if a.ID != 0 {
		err = db.One("ID", a.ID, &accessTokenDB)
	} else {
		err = db.One("Token", a.TokenID, &accessTokenDB)
	}

	if err == nil {
		*a = *accessTokenDeserialize(&accessTokenDB)
	}
	return err
}

// DeleteAccessToken deletes an access token
func (a *AccessToken) DeleteAccessToken() error {
	db, err := dbConnect()
	if err != nil {
		return err
	}
	defer db.Close()

	accessTokenDB := &AccessToken{
		ID:      a.ID,
		TokenID: a.TokenID,
	}

	if accessTokenDB.ID != 0 {
		return db.DeleteStruct(accessTokenDB)
	}
	// Delete by token
	err = db.One("Token", accessTokenDB.TokenID, &accessTokenDB)
	if err != nil {
		return err
	}
	return db.DeleteStruct(accessTokenDB)
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
