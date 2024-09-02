package models

import (
	"errors"
	"module/utils"
	"time"
)

type User struct {
	ID            int    `storm:"id,increment"`
	AltID         string `storm:"unique"`
	Username      string `storm:"unique"`
	Password      []byte
	Salt          []byte
	FirstName     string
	LastName      string
	TotpSecret    string
	HaveTotp      bool
	Email         string `storm:"unique"`
	EmailVerified bool
	CreatedAt     int64
}

func NewUser(username, firstName, lastName, password, email string) *User {
	salt := utils.GenRandByteSlice(16)

	return &User{
		Username:      username,
		FirstName:     firstName,
		LastName:      lastName,
		Password:      utils.ApplyArgon2Salt(utils.Hash512([]byte(password)), salt),
		Salt:          salt,
		TotpSecret:    "",
		HaveTotp:      false,
		Email:         email,
		EmailVerified: false,
		CreatedAt:     time.Now().UTC().Unix(),
	}
}

func (u *User) SaveUser() error {
	db, err := dbConnect()
	if err != nil {
		return err
	}
	defer db.Close()

	u.AltID = utils.GenUniqueIDv7()

	return db.Save(u)
}

func (u *User) GetUserByEmail(email string) error {
	db, err := dbConnect()
	if err != nil {
		return err
	}
	defer db.Close()

	return db.One("Email", email, u)
}

func (u *User) GetUserByID(id int) error {
	db, err := dbConnect()
	if err != nil {
		return err
	}
	defer db.Close()

	return db.One("ID", id, u)
}

func (u *User) GetUserByAltID(id string) error {
	db, err := dbConnect()
	if err != nil {
		return err
	}
	defer db.Close()

	return db.One("AltID", id, u)
}

func (u *User) GetUserByName(username string) error {
	db, err := dbConnect()
	if err != nil {
		return err
	}
	defer db.Close()

	return db.One("Username", username, u)
}

func (u *User) UpdateTOTP(totpSecret string) error {
	if totpSecret == "" {
		return errors.New("TOTP secret is empty")
	}

	db, err := dbConnect()
	if err != nil {
		return err
	}
	defer db.Close()

	u.TotpSecret = totpSecret
	u.HaveTotp = true

	if u.ID != 0 {
		return db.Update(u)
	}

	// Delete by altID (alternative key)
	err = db.One("AltID", u.AltID, u)
	if err != nil {
		return err
	}

	return db.Update(u)
}

func (u *User) UpdateEmailVerified(verified bool) error {
	db, err := dbConnect()
	if err != nil {
		return err
	}
	defer db.Close()

	u.EmailVerified = true

	if u.ID != 0 {
		return db.UpdateField(u, "EmailVerified", u.EmailVerified)
	}

	// Delete by altID (alternative key)
	err = db.One("AltID", u.AltID, u)
	if err != nil {
		return err
	}

	return db.UpdateField(u, "EmailVerified", u.EmailVerified)
}

func (u *User) UpdateUserInfo(username, firstName, lastName string) error {
	if username == "" || firstName == "" || lastName == "" {
		return errors.New("username, first name, or last name is empty")
	}

	db, err := dbConnect()
	if err != nil {
		return err
	}
	defer db.Close()

	u.Username = username
	u.FirstName = firstName
	u.LastName = lastName

	if u.ID != 0 {
		return db.Update(u)
	}

	// Delete by altID (alternative key)
	err = db.One("AltID", u.AltID, u)
	if err != nil {
		return err
	}

	return db.Update(u)
}

func (u *User) DeleteUser() error {
	db, err := dbConnect()
	if err != nil {
		return err
	}
	defer db.Close()

	if u.ID != 0 {
		return db.DeleteStruct(u)
	}

	err = db.One("AltID", u.AltID, u)
	if err != nil {
		return err
	}
	return db.DeleteStruct(u)
}

func (u *User) GetSalt() []byte {
	return u.Salt
}
