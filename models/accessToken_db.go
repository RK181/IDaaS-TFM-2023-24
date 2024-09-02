package models

import (
	"module/utils"
	"time"
)

type accessTokenDB struct {
	ID             int    `storm:"id,increment"` // access token id
	TokenID        string `storm:"unique"`       // access token
	ClientID       string // client id
	RefreshTokenID int    // refresh token id
	Subject        int    // user id

	Data []byte // accessTokenData
}

type accessTokenData struct {
	Audience   []string  // audience
	Expiration time.Time // expiration time
	Scopes     []string  // scopes
}

// saveAccessToken creates an access token
func saveAccessToken(accessToken *AccessToken) error {
	db, err := dbConnect()
	if err != nil {
		return err
	}
	defer db.Close()

	accessTokenDB := accessTokenSerialize(accessToken)
	return db.Save(accessTokenDB)
}

// getAccessToken
func getAccessToken(accessToken *AccessToken) error {
	db, err := dbConnect()
	if err != nil {
		return err
	}
	defer db.Close()

	var accessTokenDB accessTokenDB

	if accessToken.ID != 0 {
		err = db.One("ID", accessToken.ID, &accessTokenDB)
	} else {
		err = db.One("Token", accessToken.TokenID, &accessTokenDB)
	}

	if err == nil {
		accessToken = accessTokenDeserialize(&accessTokenDB)
	}
	return err
}

// deleteAccessToken deletes an access token
func deleteAccessToken(accessToken *AccessToken) error {
	db, err := dbConnect()
	if err != nil {
		return err
	}
	defer db.Close()

	accessTokenDB := &AccessToken{
		ID:      accessToken.ID,
		TokenID: accessToken.TokenID,
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

func accessTokenSerialize(accessToken *AccessToken) *accessTokenDB {
	var data = utils.EncodeGob(accessTokenData{
		Audience:   accessToken.Audience,
		Expiration: accessToken.Expiration,
		Scopes:     accessToken.Scopes,
	})

	return &accessTokenDB{
		ID:             accessToken.ID,
		TokenID:        accessToken.TokenID,
		ClientID:       accessToken.ClientID,
		RefreshTokenID: accessToken.RefreshTokenID,
		Subject:        accessToken.Subject,
		Data:           data,
	}
}

func accessTokenDeserialize(accessTokenDB *accessTokenDB) *AccessToken {
	var data accessTokenData
	utils.DecodeGob(accessTokenDB.Data, &data)

	return &AccessToken{
		ID:             accessTokenDB.ID,
		TokenID:        accessTokenDB.TokenID,
		ClientID:       accessTokenDB.ClientID,
		RefreshTokenID: accessTokenDB.RefreshTokenID,
		Subject:        accessTokenDB.Subject,
		Audience:       data.Audience,
		Expiration:     data.Expiration,
		Scopes:         data.Scopes,
	}
}
