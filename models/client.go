package models

import (
	"errors"
	"module/utils"
	"time"

	"github.com/asdine/storm/v3/q"
	"github.com/google/uuid"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

const (
	// CustomScope is an example for how to use custom scopes in this library
	//(in this scenario, when requested, it will return a custom claim)
	CustomScope = "custom_scope"

	// CustomClaim is an example for how to return custom claims with this library
	CustomClaim = "custom_claim"
)

const (
	// we use the default login UI and pass the (auth request) id
	defaultLoginURL = "/login"
)

var _ op.Client = &Client{}

// Client represents the storage model of an OAuth/OIDC client
// it implements the op.Client interface
type Client struct {
	//id              int
	clientID        string
	userID          int
	clientName      string
	secret          []byte
	salt            []byte
	redirectURIs    []string // callback URLs
	applicationType op.ApplicationType
	authMethod      oidc.AuthMethod
	loginURL        string
	responseTypes   []oidc.ResponseType
	grantTypes      []oidc.GrantType
	accessTokenType op.AccessTokenType
}

type clientDB struct {
	//ID         int    `storm:"id,increment"`
	ClientID   string `storm:"id"`
	UserID     int
	ClientName string
	Secret     []byte
	Salt       []byte
	Data       []byte
}

type clientDate struct {
	RedirectURIs    []string
	ApplicationType op.ApplicationType
	AuthMethod      oidc.AuthMethod
	LoginURL        string
	ResponseTypes   []oidc.ResponseType
	GrantTypes      []oidc.GrantType
	AccessTokenType op.AccessTokenType
}

// CreateNativeClient will create a client of type native, which will always use PKCE and allow the use of refresh tokens
// user-defined redirectURIs may include:
//   - http://localhost without port specification (e.g. http://localhost/auth/callback)
//   - custom protocol (e.g. custom://auth/callback)
func CreateNativeClient(userID int, clientName, secret string, redirectURIs []string) (*Client, error) {
	if len(redirectURIs) == 0 {
		/*redirectURIs = []string{
			"http://localhost/auth/callback",
			"custom://auth/callback",
		}*/
		panic("redirectURIs must be provided")
	}

	db, err := dbConnect()
	if err != nil {
		return nil, err
	}
	defer db.Close()

	/*err = db.Select(q.And(q.Eq("UserID", userID), q.Eq("ClientName", clientName))).First(&clientDB{})
	if err == nil {
		return nil, errors.New("client name already exists")
	}*/

	// generate new salt
	salt := utils.GenRandByteSlice(16)

	client := &Client{
		clientID: uuid.NewString(),                            // generate a new clientID
		salt:     salt,                                        // store the salt
		secret:   utils.ApplyArgon2Salt([]byte(secret), salt), // salt and hash the secret

		userID:          userID,
		clientName:      clientName,
		redirectURIs:    redirectURIs,
		applicationType: op.ApplicationTypeNative,
		authMethod:      oidc.AuthMethodNone,
		loginURL:        defaultLoginURL,
		responseTypes:   []oidc.ResponseType{oidc.ResponseTypeCode},
		grantTypes:      []oidc.GrantType{oidc.GrantTypeCode, oidc.GrantTypeRefreshToken},
		accessTokenType: op.AccessTokenTypeBearer,
	}
	// serialize the client data
	clientDB := clientSerialize(client)

	err = db.Save(clientDB)
	if err != nil {
		return nil, err
	}

	return clientDeserialize(clientDB), err
}

// CreateWebClient will create a client of type web, which will always use Basic Auth and allow the use of refresh tokens
// user-defined redirectURIs may include:
//   - http://localhost with port specification (e.g. http://localhost:9999/auth/callback)
func CreateWebClient(userID int, clientName, secret string, redirectURIs []string) (*Client, error) {
	if len(redirectURIs) == 0 {
		/*redirectURIs = []string{
			"http://localhost:9999/auth/callback",
		}*/
		panic("redirectURIs must be provided")
	}
	db, err := dbConnect()
	if err != nil {
		return nil, err
	}
	defer db.Close()

	/*err = db.Select(q.And(q.Eq("UserID", userID), q.Eq("ClientName", clientName))).First(&clientDB{})
	if err == nil {
		return nil, errors.New("client name already exists")
	}*/

	// generate new salt
	salt := utils.GenRandByteSlice(16)

	client := &Client{
		clientID: uuid.NewString(),                            // generate a new clientID
		salt:     salt,                                        // store the salt
		secret:   utils.ApplyArgon2Salt([]byte(secret), salt), // salt and hash the secret

		userID:          userID,
		clientName:      clientName,
		redirectURIs:    redirectURIs,
		applicationType: op.ApplicationTypeWeb,
		authMethod:      oidc.AuthMethodBasic,
		loginURL:        defaultLoginURL,
		responseTypes:   []oidc.ResponseType{oidc.ResponseTypeCode, oidc.ResponseTypeIDTokenOnly, oidc.ResponseTypeIDToken},
		grantTypes:      []oidc.GrantType{oidc.GrantTypeCode, oidc.GrantTypeRefreshToken, oidc.GrantTypeTokenExchange},
		accessTokenType: op.AccessTokenTypeBearer,
	}

	// serialize the client data
	clientDB := clientSerialize(client)

	err = db.Save(clientDB)
	if err != nil {
		return nil, err
	}

	return clientDeserialize(clientDB), err
}

// GetID must return the client_id
func (c *Client) GetID() string {
	return c.clientID
}

// RedirectURIs must return the registered redirect_uris for Code and Implicit Flow
func (c *Client) RedirectURIs() []string {
	return c.redirectURIs
}

// PostLogoutRedirectURIs must return the registered post_logout_redirect_uris for sign-outs
func (c *Client) PostLogoutRedirectURIs() []string {
	return []string{}
}

// ApplicationType must return the type of the client (app, native, user agent)
func (c *Client) ApplicationType() op.ApplicationType {
	return c.applicationType
}

// AuthMethod must return the authentication method (client_secret_basic, client_secret_post, none, private_key_jwt)
func (c *Client) AuthMethod() oidc.AuthMethod {
	return c.authMethod
}

// ResponseTypes must return all allowed response types (code, id_token token, id_token)
// these must match with the allowed grant types
func (c *Client) ResponseTypes() []oidc.ResponseType {
	return c.responseTypes
}

// GrantTypes must return all allowed grant types (authorization_code, refresh_token, urn:ietf:params:oauth:grant-type:jwt-bearer)
func (c *Client) GrantTypes() []oidc.GrantType {
	return c.grantTypes
}

// LoginURL will be called to redirect the user (agent) to the login UI
// you could implement some logic here to redirect the users to different login UIs depending on the client
func (c *Client) LoginURL(id string) string {
	return c.loginURL + "?authRequestID=" + id
}

// AccessTokenType must return the type of access token the client uses (Bearer (opaque) or JWT)
func (c *Client) AccessTokenType() op.AccessTokenType {
	return c.accessTokenType
}

// IDTokenLifetime must return the lifetime of the client's id_tokens
func (c *Client) IDTokenLifetime() time.Duration {
	return 1 * time.Hour
}

// DevMode enables the use of non-compliant configs such as redirect_uris (e.g. http schema for user agent client)
func (c *Client) DevMode() bool {
	return false
}

// RestrictAdditionalIdTokenScopes allows specifying which custom scopes shall be asserted into the id_token
func (c *Client) RestrictAdditionalIdTokenScopes() func(scopes []string) []string {
	return func(scopes []string) []string {
		return scopes
	}
}

// RestrictAdditionalAccessTokenScopes allows specifying which custom scopes shall be asserted into the JWT access_token
func (c *Client) RestrictAdditionalAccessTokenScopes() func(scopes []string) []string {
	return func(scopes []string) []string {
		return scopes
	}
}

// IsScopeAllowed enables Client specific custom scopes validation
// in this example we allow the CustomScope for all clients
func (c *Client) IsScopeAllowed(scope string) bool {
	return scope == CustomScope
}

// IDTokenUserinfoClaimsAssertion allows specifying if claims of scope profile, email, phone and address are asserted into the id_token
// even if an access token if issued which violates the OIDC Core spec
// (5.4. Requesting Claims using Scope Values: https://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims)
// some clients though require that e.g. email is always in the id_token when requested even if an access_token is issued
func (c *Client) IDTokenUserinfoClaimsAssertion() bool {
	return false
}

// ClockSkew enables clients to instruct the OP to apply a clock skew on the various times and expirations
// (subtract from issued_at, add to expiration, ...)
func (c *Client) ClockSkew() time.Duration {
	return 0
}

/*
// GetClientByID retrieves a client from the storage by its ID
func GetClientByID(id string) (*Client, error) {
	db, err := dbConnect()
	if err != nil {
		return nil, err
	}
	defer db.Close()

	var clientDB clientDB
	err = db.One("ID", id, &clientDB)
	if err != nil {
		return nil, err
	}

	return clientDeserialize(&clientDB), nil
}
*/

func GetClientByClientID(clientID string) (*Client, error) {
	db, err := dbConnect()
	if err != nil {
		return nil, err
	}
	defer db.Close()

	var clientDB clientDB
	err = db.One("ClientID", clientID, &clientDB)
	if err != nil {
		return nil, err
	}

	return clientDeserialize(&clientDB), nil
}

// GetClientByClientName retrieves a client from the storage by its client name
func GetClientsByUserID(userID int) ([]Client, error) {
	db, err := dbConnect()
	if err != nil {
		return nil, err
	}
	defer db.Close()

	var clientsDB []clientDB
	err = db.Select(q.Eq("UserID", userID)).Find(&clientsDB)
	if err != nil {
		return nil, err
	}

	return clientDeserializeSlice(clientsDB), nil
}

// GetClientByClientIDAndSecret retrieves a client from the storage by its client name and secret
//
//   - if the client name exists but the secret is incorrect, return an error
func GetClientByClientIDAndSecret(clientID, secret string) (*Client, error) {
	db, err := dbConnect()
	if err != nil {
		return nil, err
	}
	defer db.Close()

	var clientDB clientDB
	err = db.One("ClientID", clientID, &clientDB)
	if err != nil {
		return nil, err
	}

	if !utils.CheckArgon2Salt(clientDB.Secret, clientDB.Salt, utils.Decode64(secret)) {
		return nil, errors.New("invalid secret")
	}

	client := clientDeserialize(&clientDB)

	return client, nil
}

// UpdateClient updates an existing client in the storage
func UpdateClient(client *Client) error {
	db, err := dbConnect()
	if err != nil {
		return err
	}
	defer db.Close()

	// serialize the client data
	clientDB := clientSerialize(client)

	return db.Update(clientDB)
}

// DeleteClient deletes a client from the storage
func DeleteClient(client *Client) error {
	db, err := dbConnect()
	if err != nil {
		return err
	}
	defer db.Close()

	clientDB := &clientDB{
		ClientID: client.clientID,
	}

	/*if clientDB.ID == 0 {
		err = db.One("ClientID", client.clientID, clientDB)
		if err != nil {
			return err
		}
		return db.DeleteStruct(clientDB)
	}*/

	return db.DeleteStruct(clientDB)
}

// clientSerialize serializes the client data for the database
//
//	returns a clientDB object
func clientSerialize(client *Client) *clientDB {
	var data = utils.EncodeGob(clientDate{
		RedirectURIs:    client.redirectURIs,
		ApplicationType: client.applicationType,
		AuthMethod:      client.authMethod,
		LoginURL:        client.loginURL,
		ResponseTypes:   client.responseTypes,
		GrantTypes:      client.grantTypes,
		AccessTokenType: client.accessTokenType,
	})

	return &clientDB{
		ClientID:   client.clientID,
		ClientName: client.clientName,
		UserID:     client.userID,
		Secret:     client.secret,
		Salt:       client.salt,
		Data:       data,
	}
}

// clientDeserialize deserializes the client data from the database
//
//	returns a Client object
func clientDeserialize(clientDB *clientDB) *Client {
	var data clientDate
	utils.DecodeGob(clientDB.Data, &data)

	return &Client{
		//id:              clientDB.ID,
		clientID:        clientDB.ClientID,
		clientName:      clientDB.ClientName,
		secret:          clientDB.Secret,
		salt:            clientDB.Salt,
		redirectURIs:    data.RedirectURIs,
		applicationType: data.ApplicationType,
		authMethod:      data.AuthMethod,
		loginURL:        data.LoginURL,
		responseTypes:   data.ResponseTypes,
		grantTypes:      data.GrantTypes,
		accessTokenType: data.AccessTokenType,
	}
}

func clientDeserializeSlice(clientsDB []clientDB) []Client {
	var clients []Client
	var data clientDate

	for _, clientDB := range clientsDB {
		utils.DecodeGob(clientDB.Data, &data)
		client := Client{
			//id:              clientDB.ID,
			clientID:        clientDB.ClientID,
			clientName:      clientDB.ClientName,
			secret:          clientDB.Secret,
			salt:            clientDB.Salt,
			redirectURIs:    data.RedirectURIs,
			applicationType: data.ApplicationType,
			authMethod:      data.AuthMethod,
			loginURL:        data.LoginURL,
			responseTypes:   data.ResponseTypes,
			grantTypes:      data.GrantTypes,
			accessTokenType: data.AccessTokenType,
		}
		clients = append(clients, client)
	}

	return clients
}
