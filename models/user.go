package models

import "module/utils"

type User struct {
	ID            int    `storm:"id,increment"`
	Username      string `storm:"unique"`
	Password      []byte
	Salt          []byte
	FirstName     string
	LastName      string
	Email         string `storm:"unique"`
	EmailVerified bool
}

func CreateUser(user *User) error {
	db, err := dbConnect()
	if err != nil {
		return err
	}
	defer db.Close()

	salt := utils.GenRandByteSlice(16)
	user.Salt = salt
	user.Password = utils.ApplyArgon2Salt(user.Password, salt)

	return db.Save(user)
}

func GetUserByEmail(email string) (*User, error) {
	db, err := dbConnect()
	if err != nil {
		return nil, err
	}
	defer db.Close()

	var user User
	err = db.One("Email", email, &user)
	if err != nil {
		return nil, err
	}

	return &user, nil
}

func GetUserByID(id int) (*User, error) {
	db, err := dbConnect()
	if err != nil {
		return nil, err
	}
	defer db.Close()

	var user User
	err = db.One("ID", id, &user)
	if err != nil {
		return nil, err
	}

	return &user, nil
}

func GetUserByName(username string) (*User, error) {
	db, err := dbConnect()
	if err != nil {
		return nil, err
	}
	defer db.Close()

	var user User
	err = db.One("Username", username, &user)
	if err != nil {
		return nil, err
	}

	return &user, nil
}

func UpdateUser(user *User) error {
	db, err := dbConnect()
	if err != nil {
		return err
	}
	defer db.Close()

	return db.Update(user)
}

func DeleteUser(user *User) error {
	db, err := dbConnect()
	if err != nil {
		return err
	}
	defer db.Close()

	return db.DeleteStruct(user)
}
