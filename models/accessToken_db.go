package models

import (
	"module/utils"
	"time"
)

type accessTokenDB struct {
	ID             int    `storm:"id,increment"` // access token id
	TokenID        string `storm:"unique"`       // access token
	ClientID       string // client id
	RefreshTokenID string // refresh token id
	Subject        string // user id

	Data []byte // accessTokenData
}

type accessTokenData struct {
	Audience   []string  // audience
	Expiration time.Time // expiration time
	Scopes     []string  // scopes
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
