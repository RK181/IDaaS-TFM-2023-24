package models

import (
	"module/utils"
	"time"

	"github.com/zitadel/oidc/v3/pkg/op"
)

// RefreshToken is a token that can be used to obtain a new access token
type RefreshToken struct {
	ID       int    // refresh token id
	Token    string // refresh token
	UserID   string // user id
	ClientID string // client id

	AuthTime   time.Time // auth time
	AMR        []string  // auth method references
	Audience   []string  // audience
	Expiration time.Time // expiration time
	Scopes     []string  // scopes
}

func NewRefreshToken(userID string, clientID string, amr, audience, scopes []string) *RefreshToken {
	return &RefreshToken{
		Token:      utils.GenUniqueID(), // uutd v4
		UserID:     userID,
		ClientID:   clientID,
		AuthTime:   time.Now().UTC(), // time of token creation
		Expiration: time.Now().Add(5 * time.Hour),
		AMR:        amr,
		Audience:   audience,
		Scopes:     scopes,
	}
}

func (r *RefreshToken) SaveRefreshToken() error {
	var client Client
	client.SetID(r.ClientID)
	err := client.GetClient()
	if err != nil {
		return err
	}

	r.Expiration = time.Now().Add(time.Duration(client.GetRefreshTokenExpTime()) * time.Minute)
	return saveRefreshToken(r)
}

func (r *RefreshToken) GetRefreshToken() error {
	return getRefreshToken(r)
}

func (r *RefreshToken) DeleteRefreshToken() error {

	return deleteRefreshToken(r)
}

func RefreshTokenRequestFromBusiness(token *RefreshToken) op.RefreshTokenRequest {
	return &RefreshTokenRequest{token}
}

type RefreshTokenRequest struct {
	*RefreshToken
}

func (r *RefreshTokenRequest) GetAMR() []string {
	return r.AMR
}

func (r *RefreshTokenRequest) GetAudience() []string {
	return r.Audience
}

func (r *RefreshTokenRequest) GetAuthTime() time.Time {
	return r.AuthTime
}

func (r *RefreshTokenRequest) GetClientID() string {
	return r.ClientID
}

func (r *RefreshTokenRequest) GetScopes() []string {
	return r.Scopes
}

func (r *RefreshTokenRequest) GetSubject() string {
	return r.UserID
}

func (r *RefreshTokenRequest) SetCurrentScopes(scopes []string) {
	r.Scopes = scopes
}
