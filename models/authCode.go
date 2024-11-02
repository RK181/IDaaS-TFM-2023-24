package models

import "github.com/asdine/storm/v3/q"

type AuthCode struct {
	ID            int    `storm:"id,increment"` // auth code id
	Code          string `storm:"unique"`       // auth code
	AuthRequestID string // Auth Request ID
}

// saveAuthCode creates an auth code
func (a *AuthCode) SaveAuthCode() error {
	db, err := dbConnect()
	if err != nil {
		return err
	}
	defer db.Close()

	return db.Save(a)
}

// getAuthCode
func (a *AuthCode) GetAuthCode() error {
	db, err := dbConnect()
	if err != nil {
		return err
	}
	defer db.Close()

	return db.One("Code", a.Code, a)
}

// deleteAuthCode deletes an auth code
func (a *AuthCode) DeleteAuthCode() error {
	db, err := dbConnect()
	if err != nil {
		return err
	}
	defer db.Close()

	return db.DeleteStruct(a)
}

// deleteAuthCode deletes an auth code
func (a *AuthCode) DeleteAuthCodeByAuthRequestID() error {
	db, err := dbConnect()
	if err != nil {
		return err
	}
	defer db.Close()

	query := db.Select(q.Eq("AuthRequestID", a.AuthRequestID)).Bucket("AuthCode")
	return query.Delete(new(AuthCode))
}
