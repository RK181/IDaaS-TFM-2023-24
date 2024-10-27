package models

import (
	"module/utils"

	"github.com/asdine/storm/v3/q"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

type clientDB struct {
	ID       int    `storm:"id,increment"`
	ClientID string `storm:"unique"`
	UserID   int
	Data     []byte // clientDate
}

type clientData struct {
	ClientName          string
	RedirectURIs        []string
	ApplicationType     op.ApplicationType // int
	AuthMethod          oidc.AuthMethod    // string
	LoginURL            string
	ResponseTypes       []oidc.ResponseType // string
	GrantTypes          []oidc.GrantType    // string
	AccessTokenType     op.AccessTokenType  // int
	AccessTokenExpTime  int
	RefreshTokenExpTime int
}

func getClientsByUser(user *User) ([]Client, error) {
	db, err := dbConnect()
	if err != nil {
		return nil, err
	}
	defer db.Close()
	var clientsDB []clientDB

	if user.ID != 0 {
		err = db.Select(q.Eq("UserID", user.ID)).Find(&clientsDB)
	} else {
		err = db.Select(q.Eq("AltID", user.AltID)).Find(&clientsDB)
	}

	return clientDeserializeSlice(clientsDB), err
}

// UpdateClient updates an existing client in the storage
func updateClient(client *Client) error {
	db, err := dbConnect()
	if err != nil {
		return err
	}
	defer db.Close()

	// serialize the client data
	clientDB := clientSerialize(client)

	return db.Update(clientDB)
}

// clientSerialize serializes the client data for the database
//
//	returns a clientDB object
func clientSerialize(client *Client) *clientDB {
	var data = utils.EncodeGob(clientData{
		ClientName:          client.clientName,
		RedirectURIs:        client.redirectURIs,
		ApplicationType:     client.applicationType,
		AuthMethod:          client.authMethod,
		LoginURL:            client.loginURL,
		ResponseTypes:       client.responseTypes,
		GrantTypes:          client.grantTypes,
		AccessTokenType:     client.accessTokenType,
		AccessTokenExpTime:  client.accessTokenExpTime,
		RefreshTokenExpTime: client.refreshTokenExpTime,
	})

	return &clientDB{
		ClientID: client.clientID,
		UserID:   client.userID,
		Data:     data,
	}
}

// clientDeserialize deserializes the client data from the database
//
//	returns a Client object
func clientDeserialize(clientDB *clientDB) *Client {
	var data clientData
	utils.DecodeGob(clientDB.Data, &data)

	return &Client{
		id:                  clientDB.ID,
		clientID:            clientDB.ClientID,
		clientName:          data.ClientName,
		redirectURIs:        data.RedirectURIs,
		applicationType:     data.ApplicationType,
		authMethod:          data.AuthMethod,
		loginURL:            data.LoginURL,
		responseTypes:       data.ResponseTypes,
		grantTypes:          data.GrantTypes,
		accessTokenType:     data.AccessTokenType,
		accessTokenExpTime:  data.AccessTokenExpTime,
		refreshTokenExpTime: data.RefreshTokenExpTime,
	}
}

func clientDeserializeSlice(clientsDB []clientDB) []Client {
	var clients []Client
	var data clientData

	for _, clientDB := range clientsDB {
		utils.DecodeGob(clientDB.Data, &data)
		client := Client{
			id:                  clientDB.ID,
			clientID:            clientDB.ClientID,
			clientName:          data.ClientName,
			redirectURIs:        data.RedirectURIs,
			applicationType:     data.ApplicationType,
			authMethod:          data.AuthMethod,
			loginURL:            data.LoginURL,
			responseTypes:       data.ResponseTypes,
			grantTypes:          data.GrantTypes,
			accessTokenType:     data.AccessTokenType,
			accessTokenExpTime:  data.AccessTokenExpTime,
			refreshTokenExpTime: data.RefreshTokenExpTime,
		}
		clients = append(clients, client)
	}

	return clients
}
