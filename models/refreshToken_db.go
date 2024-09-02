package models

import (
	"module/utils"
	"time"
)

type refreshTokenDB struct {
	ID       int    `storm:"id,increment"` // refresh token id
	Token    string `storm:"unique"`       // refresh token
	UserID   int    // user id
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

	if refreshToken.id != 0 {
		err = db.One("ID", refreshToken.id, &refreshTokenDB)
	} else {
		err = db.One("Token", refreshToken.token, &refreshTokenDB)
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
		ID:    refreshToken.id,
		Token: refreshToken.token,
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
		AuthTime:   refreshToken.authTime,
		AMR:        refreshToken.amr,
		Audience:   refreshToken.audience,
		Expiration: refreshToken.expiration,
		Scopes:     refreshToken.scopes,
	})
	return &refreshTokenDB{
		ID:       refreshToken.id,
		Token:    refreshToken.token,
		UserID:   refreshToken.userID,
		ClientID: refreshToken.clientID,
		Data:     data,
	}
}

func refreshTokenDeserialize(refreshTokenDB *refreshTokenDB) *RefreshToken {
	var data refreshTokenDataDB
	utils.DecodeGob(refreshTokenDB.Data, &data)
	return &RefreshToken{
		id:         refreshTokenDB.ID,
		token:      refreshTokenDB.Token,
		userID:     refreshTokenDB.UserID,
		clientID:   refreshTokenDB.ClientID,
		authTime:   data.AuthTime,
		amr:        data.AMR,
		audience:   data.Audience,
		expiration: data.Expiration,
		scopes:     data.Scopes,
	}
}
