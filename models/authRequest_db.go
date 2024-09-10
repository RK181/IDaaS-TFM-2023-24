package models

import (
	"module/utils"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"
)

type authRequestDB struct {
	ID        int    `storm:"id,increment"` // auth request id
	RequestID string `storm:"unique"`       // auth request
	ClientID  string
	UserID    string
	Data      []byte
}

type authRequestData struct {
	CreationDate  time.Time
	CallbackURI   string
	TransferState string
	Prompt        []string
	MaxAuthAge    *time.Duration
	Scopes        []string
	ResponseType  oidc.ResponseType
	ResponseMode  oidc.ResponseMode
	Nonce         string
	CodeChallenge *OIDCCodeChallenge
	Step          int
	AuthDone      bool
	AuthTime      time.Time
}

// saveAuthRequest creates an auth request
func saveAuthRequest(authRequest *AuthRequest) error {
	db, err := dbConnect()
	if err != nil {
		return err
	}
	defer db.Close()

	authRequestDB := authRequestSerialize(authRequest)
	return db.Save(authRequestDB)
}

// getAuthRequest
func getAuthRequest(authRequest *AuthRequest) error {
	db, err := dbConnect()
	if err != nil {
		return err
	}
	defer db.Close()

	var authRequestDB authRequestDB

	if authRequest.ID != 0 {
		err = db.One("ID", authRequest.ID, &authRequestDB)
	} else {
		err = db.One("RequestID", authRequest.RequestID, &authRequestDB)
	}

	if err == nil {
		authRequest = authRequestDeserialize(&authRequestDB)
	}
	return err
}

// deleteAuthRequest deletes an auth request
func deleteAuthRequest(authRequest *AuthRequest) error {
	db, err := dbConnect()
	if err != nil {
		return err
	}
	defer db.Close()

	authRequestDB := &authRequestDB{
		ID:        authRequest.ID,
		RequestID: authRequest.RequestID,
	}

	if authRequestDB.ID != 0 {
		return db.DeleteStruct(authRequestDB)
	}
	// Delete by request id
	err = db.One("RequestID", authRequestDB.RequestID, &authRequestDB)
	if err != nil {
		return err
	}

	return db.DeleteStruct(authRequestDB)
}

func authRequestSerialize(authRequest *AuthRequest) *authRequestDB {
	var data = utils.EncodeGob(authRequestData{
		CreationDate:  authRequest.CreationDate,
		CallbackURI:   authRequest.CallbackURI,
		TransferState: authRequest.TransferState,
		Prompt:        authRequest.Prompt,
		MaxAuthAge:    authRequest.MaxAuthAge,
		Scopes:        authRequest.Scopes,
		ResponseType:  authRequest.ResponseType,
		ResponseMode:  authRequest.ResponseMode,
		Nonce:         authRequest.Nonce,
		CodeChallenge: authRequest.CodeChallenge,
		Step:          authRequest.Step,
		AuthDone:      authRequest.AuthDone,
		AuthTime:      authRequest.AuthTime,
	})

	return &authRequestDB{
		ID:        authRequest.ID,
		RequestID: authRequest.RequestID,
		ClientID:  authRequest.ClientID,
		UserID:    authRequest.UserID,
		Data:      data,
	}
}

func authRequestDeserialize(authRequestDB *authRequestDB) *AuthRequest {
	var data authRequestData
	utils.DecodeGob(authRequestDB.Data, &data)

	return &AuthRequest{
		ID:            authRequestDB.ID,
		RequestID:     authRequestDB.RequestID,
		ClientID:      authRequestDB.ClientID,
		UserID:        authRequestDB.UserID,
		CreationDate:  data.CreationDate,
		CallbackURI:   data.CallbackURI,
		TransferState: data.TransferState,
		Prompt:        data.Prompt,
		MaxAuthAge:    data.MaxAuthAge,
		Scopes:        data.Scopes,
		ResponseType:  data.ResponseType,
		ResponseMode:  data.ResponseMode,
		Nonce:         data.Nonce,
		CodeChallenge: data.CodeChallenge,
		Step:          data.Step,
		AuthDone:      data.AuthDone,
		AuthTime:      data.AuthTime,
	}
}
