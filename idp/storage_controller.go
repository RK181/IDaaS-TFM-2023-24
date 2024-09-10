package idp

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"log"
	"module/models"
	"module/utils"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

var (
	_ StorageOP = &Storage{}
	//_ authenticate = &Storage{}
)

// storage implements the op.Storage interface
// typically you would implement this as a layer on top of your database
// for simplicity this example keeps everything in-memory
type Storage struct {
	signingKey signingKey
}

type signingKey struct {
	id        string
	algorithm jose.SignatureAlgorithm
	key       *rsa.PrivateKey
}

func (s *signingKey) SignatureAlgorithm() jose.SignatureAlgorithm {
	return s.algorithm
}

func (s *signingKey) Key() any {
	return s.key
}

func (s *signingKey) ID() string {
	return s.id
}

type publicKey struct {
	signingKey
}

func (s *publicKey) ID() string {
	return s.id
}

func (s *publicKey) Algorithm() jose.SignatureAlgorithm {
	return s.algorithm
}

func (s *publicKey) Use() string {
	return "sig"
}

func (s *publicKey) Key() any {
	return &s.key.PublicKey
}

func (s *Storage) GetScopes(id string) []string {
	authRequest := models.AuthRequest{
		RequestID: id,
	}
	err := authRequest.GetAuthRequest()
	if err != nil {
		panic(err)
	}
	return authRequest.GetScopes()
}

func NewStorage() *Storage {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	return &Storage{
		signingKey: signingKey{
			id:        uuid.NewString(),
			algorithm: jose.RS256,
			key:       key,
		},
	}
}

// CheckUsernamePassword implements the `authenticate` interface of the login
func (s *Storage) CheckUsernamePassword(username, password, id string) error {

	request := models.AuthRequest{
		RequestID: id,
	}
	err := request.GetAuthRequest()
	if err != nil {
		return fmt.Errorf("request not found")
	}

	var user models.User
	err = user.GetUserByName(username)
	if err != nil {
		return fmt.Errorf("user not found")
	}

	if utils.CheckArgon2Salt(utils.Hash512([]byte(password)), user.Salt, user.Password) {
		request.UserID = user.AltID
		request.AuthDone = true
		return nil
	}
	return fmt.Errorf("username or password wrong")
}

// CreateAuthRequest implements the op.Storage interface
// it will be called after parsing and validation of the authentication request
func (s *Storage) CreateAuthRequest(ctx context.Context, authReq *oidc.AuthRequest, userID string) (op.AuthRequest, error) {

	if len(authReq.Prompt) == 1 && authReq.Prompt[0] == "none" {
		return nil, oidc.ErrLoginRequired()
	}

	request := models.NewAuthRequest(authReq, userID)

	request.RequestID = uuid.NewString()

	err := request.SaveAuthRequest()
	if err != nil {
		return nil, err
	}

	log.Panicln("\n\n\n\n", request.ClientID, "\n\n\n\n")
	// finally, return the request (which implements the AuthRequest interface of the OP
	return request, nil
}

// AuthRequestByID implements the op.Storage interface
// it will be called after the Login UI redirects back to the OIDC endpoint
func (s *Storage) AuthRequestByID(ctx context.Context, id string) (op.AuthRequest, error) {
	request := models.AuthRequest{
		RequestID: id,
	}
	err := request.GetAuthRequest()
	if err != nil {
		return nil, fmt.Errorf("request not found")
	}

	return request, nil
}

// AuthRequestByCode implements the op.Storage interface
// it will be called after parsing and validation of the token request (in an authorization code flow)
func (s *Storage) AuthRequestByCode(ctx context.Context, code string) (op.AuthRequest, error) {
	// for this example we read the id by code and then get the request by id
	aurthCode := models.AuthCode{
		Code: code,
	}
	err := aurthCode.GetAuthCode()
	if err != nil {
		return nil, fmt.Errorf("code invalid or expired")
	}

	return s.AuthRequestByID(ctx, aurthCode.AuthRequestID)
}

// SaveAuthCode implements the op.Storage interface
// it will be called after the authentication has been successful and before redirecting the user agent to the redirect_uri
// (in an authorization code flow)
func (s *Storage) SaveAuthCode(ctx context.Context, id string, code string) error {
	// for this example we'll just save the authRequestID to the code
	authCode := models.AuthCode{
		Code:          code,
		AuthRequestID: id,
	}

	return authCode.SaveAuthCode()
}

// DeleteAuthRequest implements the op.Storage interface
// it will be called after creating the token response (id and access tokens) for a valid
// - authentication request (in an implicit flow)
// - token request (in an authorization code flow)
func (s *Storage) DeleteAuthRequest(ctx context.Context, id string) error {
	// you can simply delete all reference to the auth request
	authRequest := models.AuthRequest{
		RequestID: id,
	}
	err := authRequest.DeleteAuthRequest()
	if err != nil {
		return err
	}

	authCode := models.AuthCode{
		AuthRequestID: id,
	}
	return authCode.DeleteAuthCodeByAuthRequestID()
}

// CreateAccessToken implements the op.Storage interface
// it will be called for all requests able to return an access token (Authorization Code Flow, Implicit Flow, JWT Profile, ...)
func (s *Storage) CreateAccessToken(ctx context.Context, request op.TokenRequest) (string, time.Time, error) {
	var applicationID string
	switch req := request.(type) {
	case *models.AuthRequest:
		// if authenticated for an app (auth code / implicit flow) we must save the client_id to the token
		applicationID = req.GetClientID()
	case op.TokenExchangeRequest:
		applicationID = req.GetClientID()
	}

	accesToken, err := s.accessToken(applicationID, "", request.GetSubject(), request.GetAudience(), request.GetScopes())
	if err != nil {
		return "", time.Time{}, err
	}
	return accesToken.TokenID, accesToken.Expiration, nil
}

// CreateAccessAndRefreshTokens implements the op.Storage interface
// it will be called for all requests able to return an access and refresh token (Authorization Code Flow, Refresh Token Request)
func (s *Storage) CreateAccessAndRefreshTokens(ctx context.Context, request op.TokenRequest, currentRefreshToken string) (accessTokenID string, newRefreshToken string, expiration time.Time, err error) {
	// generate tokens via token exchange flow if request is relevant
	if teReq, ok := request.(op.TokenExchangeRequest); ok {
		return s.exchangeRefreshToken(ctx, teReq)
	}

	// get the information depending on the request type / implementation
	applicationID, authTime, amr := getInfoFromRequest(request)

	// if currentRefreshToken is empty (Code Flow) we will have to create a new refresh token
	if currentRefreshToken == "" {
		refreshTokenID := uuid.NewString()
		accessToken, err := s.accessToken(applicationID, refreshTokenID, request.GetSubject(), request.GetAudience(), request.GetScopes())
		if err != nil {
			return "", "", time.Time{}, err
		}
		refreshToken, err := s.createRefreshToken(accessToken, amr, authTime)
		if err != nil {
			return "", "", time.Time{}, err
		}
		return accessToken.TokenID, refreshToken, accessToken.Expiration, nil
	}

	// if we get here, the currentRefreshToken was not empty, so the call is a refresh token request
	// we therefore will have to check the currentRefreshToken and renew the refresh token
	refreshToken, refreshTokenID, err := s.renewRefreshToken(currentRefreshToken)
	if err != nil {
		return "", "", time.Time{}, err
	}
	accessToken, err := s.accessToken(applicationID, refreshTokenID, request.GetSubject(), request.GetAudience(), request.GetScopes())
	if err != nil {
		return "", "", time.Time{}, err
	}
	return accessToken.TokenID, refreshToken, accessToken.Expiration, nil
}

func (s *Storage) exchangeRefreshToken(ctx context.Context, request op.TokenExchangeRequest) (accessTokenID string, newRefreshToken string, expiration time.Time, err error) {
	applicationID := request.GetClientID()
	authTime := request.GetAuthTime()

	refreshTokenID := uuid.NewString()
	accessToken, err := s.accessToken(applicationID, refreshTokenID, request.GetSubject(), request.GetAudience(), request.GetScopes())
	if err != nil {
		return "", "", time.Time{}, err
	}

	refreshToken, err := s.createRefreshToken(accessToken, nil, authTime)
	if err != nil {
		return "", "", time.Time{}, err
	}

	return accessToken.TokenID, refreshToken, accessToken.Expiration, nil
}

// TokenRequestByRefreshToken implements the op.Storage interface
// it will be called after parsing and validation of the refresh token request
func (s *Storage) TokenRequestByRefreshToken(ctx context.Context, refreshToken string) (op.RefreshTokenRequest, error) {

	token := models.RefreshToken{
		Token: refreshToken,
	}

	err := token.GetRefreshToken()
	if err != nil {
		return nil, fmt.Errorf("invalid refresh_token")
	}

	return models.RefreshTokenRequestFromBusiness(&token), nil
}

// TerminateSession implements the op.Storage interface
// it will be called after the user signed out, therefore the access and refresh token of the user of this client must be removed
func (s *Storage) TerminateSession(ctx context.Context, userID string, clientID string) error {

	panic("No implemented")
}

// GetRefreshTokenInfo looks up a refresh token and returns the token id and user id.
// If given something that is not a refresh token, it must return error.
func (s *Storage) GetRefreshTokenInfo(ctx context.Context, clientID string, token string) (userID string, tokenID string, err error) {
	refreshToken := models.RefreshToken{
		Token: token,
	}
	err = refreshToken.GetRefreshToken()
	if err != nil {
		return "", "", op.ErrInvalidRefreshToken
	}
	return refreshToken.UserID, refreshToken.Token, nil
}

// RevokeToken implements the op.Storage interface
// it will be called after parsing and validation of the token revocation request
func (s *Storage) RevokeToken(ctx context.Context, tokenIDOrToken string, userID string, clientID string) *oidc.Error {
	// a single token was requested to be removed
	accessToken := models.AccessToken{
		TokenID: tokenIDOrToken,
	}
	err := accessToken.GetAccessToken()
	if err == nil {
		if accessToken.ClientID != clientID {
			return oidc.ErrInvalidClient().WithDescription("token was not issued for this client")
		}
		// if it is an access token, just remove it
		// you could also remove the corresponding refresh token if really necessary
		err = accessToken.DeleteAccessToken()
		if err != nil {
			return oidc.ErrServerError().WithDescription("could not delete access token")
		}
		return nil
	}
	refreshToken := models.RefreshToken{
		Token: tokenIDOrToken,
	}
	err = refreshToken.GetRefreshToken()
	if err != nil {
		// if the token is neither an access nor a refresh token, just ignore it, the expected behaviour of
		// being not valid (anymore) is achieved
		return nil
	}
	if refreshToken.ClientID != clientID {
		return oidc.ErrInvalidClient().WithDescription("token was not issued for this client")
	}
	err = refreshToken.DeleteRefreshToken()
	if err != nil {
		return oidc.ErrServerError().WithDescription("could not delete refresh token")
	}

	accessToken.RefreshTokenID = refreshToken.Token
	err = accessToken.DeleteAccessTokenByRefreshToken()
	if err != nil {
		return oidc.ErrServerError().WithDescription("could not delete access token")
	}
	return nil
}

// SigningKey implements the op.Storage interface
// it will be called when creating the OpenID Provider
func (s *Storage) SigningKey(ctx context.Context) (op.SigningKey, error) {
	// in this example the signing key is a static rsa.PrivateKey and the algorithm used is RS256
	// you would obviously have a more complex implementation and store / retrieve the key from your database as well
	return &s.signingKey, nil
}

// SignatureAlgorithms implements the op.Storage interface
// it will be called to get the sign
func (s *Storage) SignatureAlgorithms(context.Context) ([]jose.SignatureAlgorithm, error) {
	return []jose.SignatureAlgorithm{s.signingKey.algorithm}, nil
}

// KeySet implements the op.Storage interface
// it will be called to get the current (public) keys, among others for the keys_endpoint or for validating access_tokens on the userinfo_endpoint, ...
func (s *Storage) KeySet(ctx context.Context) ([]op.Key, error) {
	// as mentioned above, this example only has a single signing key without key rotation,
	// so it will directly use its public key
	//
	// when using key rotation you typically would store the public keys alongside the private keys in your database
	// and give both of them an expiration date, with the public key having a longer lifetime
	return []op.Key{&publicKey{s.signingKey}}, nil
}

// GetClientByClientID implements the op.Storage interface
// it will be called whenever information (type, redirect_uris, ...) about the client behind the client_id is needed
func (s *Storage) GetClientByClientID(ctx context.Context, clientID string) (op.Client, error) {

	var client models.Client
	client.SetID(clientID)
	err := client.GetClient()
	if err != nil {
		return nil, fmt.Errorf("client not found")
	}
	return client, nil
}

// AuthorizeClientIDSecret implements the op.Storage interface
// it will be called for validating the client_id, client_secret on token or introspection requests
func (s *Storage) AuthorizeClientIDSecret(ctx context.Context, clientID, clientSecret string) error {

	/*
		var client models.Client
		client.SetID(clientID)
		err := client.GetClient()
		if err != nil {
			return fmt.Errorf("client not found")
		}
		// for this example we directly check the secret
		// obviously you would not have the secret in plain text, but rather hashed and salted (e.g. using bcrypt)
		if client.secret != clientSecret {
			return fmt.Errorf("invalid secret")
		}
		return nil
	*/
	panic("No implemented")
}

// SetUserinfoFromScopes implements the op.Storage interface.
// Provide an empty implementation and use SetUserinfoFromRequest instead.
func (s *Storage) SetUserinfoFromScopes(ctx context.Context, userinfo *oidc.UserInfo, userID, clientID string, scopes []string) error {
	return nil
}

// SetUserinfoFromRequests implements the op.CanSetUserinfoFromRequest interface.  In the
// next major release, it will be required for op.Storage.
// It will be called for the creation of an id_token, so we'll just pass it to the private function without any further check
func (s *Storage) SetUserinfoFromRequest(ctx context.Context, userinfo *oidc.UserInfo, token op.IDTokenRequest, scopes []string) error {
	return s.setUserinfo(ctx, userinfo, token.GetSubject(), token.GetClientID(), scopes)
}

// SetUserinfoFromToken implements the op.Storage interface
// it will be called for the userinfo endpoint, so we read the token and pass the information from that to the private function
func (s *Storage) SetUserinfoFromToken(ctx context.Context, userinfo *oidc.UserInfo, tokenID, subject, origin string) error {

	accesToken := models.AccessToken{
		TokenID: tokenID,
	}
	err := accesToken.GetAccessToken()
	if err != nil {
		return fmt.Errorf("token is invalid or has expired")
	}
	// the userinfo endpoint should support CORS. If it's not possible to specify a specific origin in the CORS handler,
	// and you have to specify a wildcard (*) origin, then you could also check here if the origin which called the userinfo endpoint here directly
	// note that the origin can be empty (if called by a web client)
	//
	if origin != "" {
		log.Println("\n\n\n origin", origin, "\n\n\n")
		/*client, ok := s.clients[token.ApplicationID]
		if !ok {
			return fmt.Errorf("client not found")
		}
		if err := checkAllowedOrigins(client.allowedOrigins, origin); err != nil {
			return err
		}*/
	}
	log.Println("\n\n\n origin", origin, "\n\n\n")
	return s.setUserinfo(ctx, userinfo, accesToken.Subject, accesToken.ClientID, accesToken.Scopes)
}

// SetIntrospectionFromToken implements the op.Storage interface
// it will be called for the introspection endpoint, so we read the token and pass the information from that to the private function
func (s *Storage) SetIntrospectionFromToken(ctx context.Context, introspection *oidc.IntrospectionResponse, tokenID, subject, clientID string) error {
	accesToken := models.AccessToken{
		TokenID: tokenID,
	}
	err := accesToken.GetAccessToken()
	if err != nil {
		return fmt.Errorf("token is invalid or has expired")
	}
	// check if the client is part of the requested audience
	for _, aud := range accesToken.Audience {
		if aud == clientID {
			// the introspection response only has to return a boolean (active) if the token is active
			// this will automatically be done by the library if you don't return an error
			// you can also return further information about the user / associated token
			// e.g. the userinfo (equivalent to userinfo endpoint)

			userInfo := new(oidc.UserInfo)
			err := s.setUserinfo(ctx, userInfo, subject, clientID, accesToken.Scopes)
			if err != nil {
				return err
			}
			introspection.SetUserInfo(userInfo)
			//...and also the requested scopes...
			introspection.Scope = accesToken.Scopes
			//...and the client the token was issued to
			introspection.ClientID = accesToken.ClientID
			return nil
		}
	}
	return fmt.Errorf("token is not valid for this client")
}

// GetPrivateClaimsFromScopes implements the op.Storage interface
// it will be called for the creation of a JWT access token to assert claims for custom scopes
func (s *Storage) GetPrivateClaimsFromScopes(ctx context.Context, userID, clientID string, scopes []string) (claims map[string]any, err error) {
	return s.getPrivateClaimsFromScopes(ctx, userID, clientID, scopes)
}

func (s *Storage) getPrivateClaimsFromScopes(ctx context.Context, userID, clientID string, scopes []string) (claims map[string]any, err error) {
	for _, scope := range scopes {
		switch scope {
		case models.CustomScope:
			claims = appendClaim(claims, models.CustomClaim, customClaim(clientID))
			claims = appendClaim(claims, "asd", customClaim(clientID))
		}
	}
	return claims, nil
}

// GetKeyByIDAndClientID implements the op.Storage interface
// it will be called to validate the signatures of a JWT (JWT Profile Grant and Authentication)
func (s *Storage) GetKeyByIDAndClientID(ctx context.Context, keyID, clientID string) (*jose.JSONWebKey, error) {
	panic("No implemented")
}

// ValidateJWTProfileScopes implements the op.Storage interface
// it will be called to validate the scopes of a JWT Profile Authorization Grant request
func (s *Storage) ValidateJWTProfileScopes(ctx context.Context, userID string, scopes []string) ([]string, error) {
	allowedScopes := make([]string, 0)
	for _, scope := range scopes {
		if scope == oidc.ScopeOpenID {
			allowedScopes = append(allowedScopes, scope)
		}
	}
	return allowedScopes, nil
}

// Health implements the op.Storage interface
func (s *Storage) Health(ctx context.Context) error {
	return nil
}

// createRefreshToken will store a refresh_token in-memory based on the provided information
func (s *Storage) createRefreshToken(accessToken *models.AccessToken, amr []string, authTime time.Time) (string, error) {

	refreshToken := &models.RefreshToken{
		Token:      accessToken.RefreshTokenID,
		AuthTime:   authTime,
		AMR:        amr,
		ClientID:   accessToken.ClientID,
		UserID:     accessToken.Subject,
		Audience:   accessToken.Audience,
		Expiration: time.Now().Add(5 * time.Hour),
		Scopes:     accessToken.Scopes,
	}
	err := refreshToken.SaveRefreshToken()
	if err != nil {
		return "", err
	}
	return refreshToken.Token, nil
}

// renewRefreshToken checks the provided refresh_token and creates a new one based on the current
func (s *Storage) renewRefreshToken(currentRefreshToken string) (string, string, error) {

	refreshToken := models.RefreshToken{
		Token: currentRefreshToken,
	}
	err := refreshToken.GetRefreshToken()
	if err != nil {
		return "", "", fmt.Errorf("invalid refresh token")
	}
	newRefreshToken := refreshToken

	err = refreshToken.DeleteRefreshToken()
	if err != nil {
		return "", "", err
	}

	accesToken := models.AccessToken{
		RefreshTokenID: currentRefreshToken,
	}
	err = accesToken.DeleteAccessTokenByRefreshToken()
	if err != nil {
		return "", "", err
	}

	// creates a new refresh token based on the current one
	token := uuid.NewString()

	newRefreshToken.Token = token
	newRefreshToken.SaveRefreshToken()

	return token, refreshToken.Token, nil
}

// accessToken will store an access_token in-memory based on the provided information
func (s *Storage) accessToken(applicationID, refreshTokenID, subject string, audience, scopes []string) (*models.AccessToken, error) {

	accesToken := models.NewAccessToken(applicationID, refreshTokenID, subject, audience, scopes)
	err := accesToken.SaveAccessToken()
	if err != nil {
		return nil, err
	}

	return accesToken, nil
}

// setUserinfo sets the info based on the user, scopes and if necessary the clientID
func (s *Storage) setUserinfo(ctx context.Context, userInfo *oidc.UserInfo, userID, clientID string, scopes []string) (err error) {

	user := models.User{
		AltID: userID,
	}
	err = user.GetUserByAltID(userID)
	if err != nil {
		return fmt.Errorf("user not found")
	}

	var info oidc.UserInfo
	/*info.Subject = user.AltID
	info.PreferredUsername = user.Username
	info.Name = user.FirstName + " " + user.LastName
	info.FamilyName = user.LastName
	info.GivenName = user.FirstName
	info.Email = user.Email
	info.EmailVerified = oidc.Bool(user.EmailVerified)*/
	for i := 0; i < len(scopes); i++ {
		switch scopes[i] {
		case oidc.ScopeOpenID:
			info.Subject = user.AltID
		case oidc.ScopeEmail:
			info.Email = user.Email
			info.EmailVerified = oidc.Bool(user.EmailVerified)
		case oidc.ScopeProfile:
			info.PreferredUsername = user.Username
			info.Name = user.FirstName + " " + user.LastName
			info.FamilyName = user.LastName
			info.GivenName = user.FirstName
		case models.CustomScope:
			// you can also have a custom scope and assert public or custom claims based on that
			info.AppendClaims(models.CustomClaim, customClaim(clientID))
			info.Email = user.Email
			info.FamilyName = scopes[0]
			info.AppendClaims("email", user.Email)
		}
	}
	*userInfo = info

	return nil
}

// getInfoFromRequest returns the clientID, authTime and amr depending on the op.TokenRequest type / implementation
func getInfoFromRequest(req op.TokenRequest) (clientID string, authTime time.Time, amr []string) {
	authReq, ok := req.(*models.AuthRequest) // Code Flow (with scope offline_access)
	if ok {
		return authReq.ClientID, authReq.AuthTime, authReq.GetAMR()
	}
	refreshReq, ok := req.(*models.RefreshTokenRequest) // Refresh Token Request
	if ok {
		return refreshReq.ClientID, refreshReq.AuthTime, refreshReq.AMR
	}
	return "", time.Time{}, nil
}

// customClaim demonstrates how to return custom claims based on provided information
func customClaim(clientID string) string {
	return "ess"
	/*map[string]any{
		"client": clientID,
		"other":  "stuff",
	}*/
}

func appendClaim(claims map[string]any, claim string, value any) map[string]any {
	if claims == nil {
		claims = make(map[string]any)
	}
	claims[claim] = value
	return claims
}
