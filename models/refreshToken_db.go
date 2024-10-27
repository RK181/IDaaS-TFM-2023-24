package models

import (
	"module/utils"
	"time"
)

type refreshTokenDB struct {
	ID       int    `storm:"id,increment"` // refresh token id
	Token    string `storm:"unique"`       // refresh token
	UserID   string // user id
	ClientID string // client id

	Data []byte // refreshTokenData
}

type refreshTokenDataDB struct {
	AuthTime   time.Time // auth time
	AMR        []string  // auth method references
	Audience   []string  // audience
	Expiration time.Time // expiration time
	Scopes     []string  // scopes
}

func refreshTokenSerialize(refreshToken *RefreshToken) *refreshTokenDB {
	data := utils.EncodeGob(refreshTokenDataDB{
		AuthTime:   refreshToken.AuthTime,
		AMR:        refreshToken.AMR,
		Audience:   refreshToken.Audience,
		Expiration: refreshToken.Expiration,
		Scopes:     refreshToken.Scopes,
	})
	return &refreshTokenDB{
		ID:       refreshToken.ID,
		Token:    refreshToken.Token,
		UserID:   refreshToken.UserID,
		ClientID: refreshToken.ClientID,
		Data:     data,
	}
}

func refreshTokenDeserialize(refreshTokenDB *refreshTokenDB) *RefreshToken {
	var data refreshTokenDataDB
	utils.DecodeGob(refreshTokenDB.Data, &data)
	return &RefreshToken{
		ID:         refreshTokenDB.ID,
		Token:      refreshTokenDB.Token,
		UserID:     refreshTokenDB.UserID,
		ClientID:   refreshTokenDB.ClientID,
		AuthTime:   data.AuthTime,
		AMR:        data.AMR,
		Audience:   data.Audience,
		Expiration: data.Expiration,
		Scopes:     data.Scopes,
	}
}
