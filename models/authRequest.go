package models

import (
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

// Explicitly declare that AuthRequest implements op.AuthRequest.
var (
	_ op.AuthRequest = &AuthRequest{}
)

type AuthRequest struct {
	ID            int
	RequestID     string
	CreationDate  time.Time
	ClientID      string
	UserID        string
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

func NewAuthRequest(authReq *oidc.AuthRequest, userID string) *AuthRequest {

	return &AuthRequest{
		CreationDate:  time.Now(),
		ClientID:      authReq.ClientID,
		CallbackURI:   authReq.RedirectURI,
		TransferState: authReq.State,
		Prompt:        PromptToInternal(authReq.Prompt),
		MaxAuthAge:    MaxAgeToInternal(authReq.MaxAge),
		UserID:        userID,
		Scopes:        authReq.Scopes,
		ResponseType:  authReq.ResponseType,
		ResponseMode:  authReq.ResponseMode,
		Nonce:         authReq.Nonce,
		CodeChallenge: &OIDCCodeChallenge{
			Challenge: authReq.CodeChallenge,
			Method:    string(authReq.CodeChallengeMethod),
		},
		AuthDone: false,
	}
}

func (a *AuthRequest) SaveAuthRequest() error {
	db, err := dbConnect()
	if err != nil {
		return err
	}
	defer db.Close()

	authRequestDB := authRequestSerialize(a)
	return db.Save(authRequestDB)
}

func (a *AuthRequest) GetAuthRequest() error {
	db, err := dbConnect()
	if err != nil {
		return err
	}
	defer db.Close()

	var authRequestDB authRequestDB

	if a.ID != 0 {
		err = db.One("ID", a.ID, &authRequestDB)
	} else {
		err = db.One("RequestID", a.RequestID, &authRequestDB)
	}

	if err == nil {
		*a = *authRequestDeserialize(&authRequestDB)
	}
	return err
}

func (a AuthRequest) DeleteAuthRequest() error {
	db, err := dbConnect()
	if err != nil {
		return err
	}
	defer db.Close()

	authRequestDB := &authRequestDB{
		ID:        a.ID,
		RequestID: a.RequestID,
	}

	if authRequestDB.ID != 0 {
		return db.DeleteStruct(authRequestDB)
	}
	// Delete by request id
	err = db.One("RequestID", authRequestDB.RequestID, authRequestDB)
	if err != nil {
		return err
	}

	return db.DeleteStruct(authRequestDB)
}

func (a *AuthRequest) DeleteAuthRequestByRequestID(requestID string) error {
	db, err := dbConnect()
	if err != nil {
		return err
	}
	defer db.Close()

	var authRequestDB *authRequestDB

	// Delete by request id
	err = db.One("RequestID", requestID, authRequestDB)
	if err != nil {
		return err
	}

	return db.DeleteStruct(authRequestDB)
}

// Done implements op.AuthRequest.
func (a AuthRequest) Done() bool {
	return a.AuthDone
}

// GetACR implements op.AuthRequest.
func (a AuthRequest) GetACR() string {
	return ""
}

// GetAMR implements op.AuthRequest.
func (a AuthRequest) GetAMR() []string {
	if a.AuthDone {
		return []string{"pwd"}
	}
	return nil
}

// GetAudience implements op.AuthRequest.
func (a AuthRequest) GetAudience() []string {
	return []string{a.ClientID}
}

// GetAuthTime implements op.AuthRequest.
func (a AuthRequest) GetAuthTime() time.Time {
	return a.AuthTime
}

// GetClientID implements op.AuthRequest.
func (a AuthRequest) GetClientID() string {
	return a.ClientID
}

// GetCodeChallenge implements op.AuthRequest.
func (a AuthRequest) GetCodeChallenge() *oidc.CodeChallenge {
	return CodeChallengeToOIDC(a.CodeChallenge)
}

// GetID implements op.AuthRequest.
func (a AuthRequest) GetID() string {
	return a.RequestID
}

// GetNonce implements op.AuthRequest.
func (a AuthRequest) GetNonce() string {
	return a.Nonce
}

// GetRedirectURI implements op.AuthRequest.
func (a AuthRequest) GetRedirectURI() string {
	return a.CallbackURI
}

// GetResponseMode implements op.AuthRequest.
func (a AuthRequest) GetResponseMode() oidc.ResponseMode {
	return a.ResponseMode
}

// GetResponseType implements op.AuthRequest.
func (a AuthRequest) GetResponseType() oidc.ResponseType {
	return a.ResponseType
}

// GetScopes implements op.AuthRequest.
func (a AuthRequest) GetScopes() []string {
	return a.Scopes
}

// GetState implements op.AuthRequest.
func (a AuthRequest) GetState() string {
	return a.TransferState
}

// GetSubject implements op.AuthRequest.
func (a AuthRequest) GetSubject() string {
	return a.UserID
}

type OIDCCodeChallenge struct {
	Challenge string
	Method    string
}

func CodeChallengeToOIDC(challenge *OIDCCodeChallenge) *oidc.CodeChallenge {
	if challenge == nil {
		return nil
	}
	challengeMethod := oidc.CodeChallengeMethodPlain
	if challenge.Method == "S256" {
		challengeMethod = oidc.CodeChallengeMethodS256
	}
	return &oidc.CodeChallenge{
		Challenge: challenge.Challenge,
		Method:    challengeMethod,
	}
}

func PromptToInternal(oidcPrompt oidc.SpaceDelimitedArray) []string {
	prompts := make([]string, len(oidcPrompt))
	for _, oidcPrompt := range oidcPrompt {
		switch oidcPrompt {
		case oidc.PromptNone,
			oidc.PromptLogin,
			oidc.PromptConsent,
			oidc.PromptSelectAccount:
			prompts = append(prompts, oidcPrompt)
		}
	}
	return prompts
}

func MaxAgeToInternal(maxAge *uint) *time.Duration {
	if maxAge == nil {
		return nil
	}
	dur := time.Duration(*maxAge) * time.Second
	return &dur
}
