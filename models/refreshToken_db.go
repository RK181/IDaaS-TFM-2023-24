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

func saveRefreshToken(refreshToken *RefreshToken) error {
	db, err := dbConnect()
	if err != nil {
		return err
	}
	defer db.Close()

	refreshTokenDB := refreshTokenSerialize(refreshToken)
	return db.Save(refreshTokenDB)
}

func getRefreshToken(refreshToken *RefreshToken) error {
	db, err := dbConnect()
	if err != nil {
		return err
	}
	defer db.Close()

	var refreshTokenDB refreshTokenDB

	if refreshToken.ID != 0 {
		err = db.One("ID", refreshToken.ID, &refreshTokenDB)
	} else {
		err = db.One("Token", refreshToken.Token, &refreshTokenDB)
	}

	if err == nil {
		refreshToken = refreshTokenDeserialize(&refreshTokenDB)
	}
	return err
}

func deleteRefreshToken(refreshToken *RefreshToken) error {
	db, err := dbConnect()
	if err != nil {
		return err
	}
	defer db.Close()

	refreshTokenDB := &refreshTokenDB{
		ID:    refreshToken.ID,
		Token: refreshToken.Token,
	}

	if refreshTokenDB.ID != 0 {
		return db.DeleteStruct(refreshTokenDB)
	}

	err = db.One("Token", refreshTokenDB.Token, refreshTokenDB)
	if err != nil {
		return err
	}
	return db.DeleteStruct(refreshTokenDB)
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
