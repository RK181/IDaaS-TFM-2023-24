package models

import (
	"module/utils"
	"testing"
	"time"
)

func userEqual(user, want *User) bool {
	return user.Username == want.Username &&
		user.FirstName == want.FirstName &&
		user.LastName == want.LastName &&
		user.TotpSecret == want.TotpSecret &&
		user.HaveTotp == want.HaveTotp &&
		user.Email == want.Email &&
		user.EmailVerified == want.EmailVerified &&
		user.CreatedAt == want.CreatedAt &&
		user.Password != nil &&
		user.Salt != nil
}

func TestNewUser(t *testing.T) {
	type args struct {
		username  string
		firstName string
		lastName  string
		password  string
		email     string
	}
	tests := []struct {
		name string
		args args
		want *User
	}{
		// TODO: Add test cases.
		{
			name: "TestNewUser",
			args: args{
				username:  "username",
				firstName: "firstName",
				lastName:  "lastName",
				password:  "password",
				email:     "test@email.com",
			},
			want: &User{
				Username:      "username",
				FirstName:     "firstName",
				LastName:      "lastName",
				TotpSecret:    "",
				HaveTotp:      false,
				Email:         "test@email.com",
				EmailVerified: false,
				CreatedAt:     time.Now().UTC().Unix(),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewUser(tt.args.username, tt.args.firstName, tt.args.lastName, tt.args.password, tt.args.email); !userEqual(got, tt.want) {
				t.Errorf("NewUser() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestUser_SaveUser(t *testing.T) {
	u := NewUser("username", "firstName", "lastName", "password", "test@email.com")
	err := u.SaveUser()
	if err != nil {
		t.Errorf("SaveUser() error = %v", err)
	}

	if u.Username != "username" || u.FirstName != "firstName" || u.LastName != "lastName" {
		t.Errorf("SaveUser() failed")
	}

	if !utils.CheckArgon2Salt(utils.Hash512([]byte("password")), u.Salt, u.Password) {
		t.Errorf("SaveUser() failed, expected password and salt")
	}
}

func TestUser_GetUserByEmail(t *testing.T) {
	u := &User{}
	err := u.GetUserByEmail("test@email.com")
	if err != nil {
		t.Errorf("GetUserByEmail() error = %v", err)
	}
	if u.Username != "username" || u.FirstName != "firstName" || u.LastName != "lastName" {
		t.Errorf("GetUserByEmail() failed")
	}

	if !utils.CheckArgon2Salt(utils.Hash512([]byte("password")), u.Salt, u.Password) {
		t.Errorf("GetUserByEmail() failed, expected password and salt")
	}
}

func TestUser_UpdateUserInfo(t *testing.T) {
	u := &User{}

	err := u.GetUserByEmail("test@email.com")
	if err != nil {
		t.Errorf("GetUserByEmail() error = %v", err)
	}

	err = u.UpdateUserInfo("newUsername", "newFirstName", "newLastName")
	if err != nil {
		t.Errorf("UpdateUserInfo() error = %v", err)
	}

	if u.Username != "newUsername" || u.FirstName != "newFirstName" || u.LastName != "newLastName" {
		t.Errorf("UpdateUserInfo() failed, expected updated user info")
	}
}
func TestUser_GetUserByName(t *testing.T) {
	u := &User{}
	err := u.GetUserByName("newUsername")
	if err != nil {
		t.Errorf("GetUserByName() error = %v", err)
	}
	if u.Username != "newUsername" || u.FirstName != "newFirstName" || u.LastName != "newLastName" {
		t.Errorf("GetUserByName() failed")
	}

	if !utils.CheckArgon2Salt(utils.Hash512([]byte("password")), u.Salt, u.Password) {
		t.Errorf("GetUserByName() failed, expected password and salt")
	}
}
func TestUser_UpdateTOTP(t *testing.T) {
	u := &User{}
	u.GetUserByName("newUsername")

	totpSecret := "testTOTPSecret"

	err := u.UpdateTOTP(totpSecret)
	if err != nil {
		t.Errorf("UpdateTOTP() error = %v", err)
	}

	if u.TotpSecret != totpSecret {
		t.Errorf("UpdateTOTP() failed, expected TotpSecret = %s, got TotpSecret = %s", totpSecret, u.TotpSecret)
	}

	if !u.HaveTotp {
		t.Errorf("UpdateTOTP() failed, expected HaveTotp = true, got HaveTotp = false")
	}
}
func TestUser_UpdateEmailVerified(t *testing.T) {
	u := &User{}
	u.GetUserByName("newUsername")

	err := u.UpdateEmailVerified(true)
	if err != nil {
		t.Errorf("UpdateEmailVerified() error = %v", err)
	}

	if !u.EmailVerified {
		t.Errorf("UpdateEmailVerified() failed, expected EmailVerified = true, got EmailVerified = false")
	}
}
func TestUser_DeleteUser(t *testing.T) {
	u := &User{}
	u.GetUserByName("newUsername")

	err := u.DeleteUser()
	if err != nil {
		t.Errorf("DeleteUser() error = %v", err)
	}

	err = u.GetUserByID(1)
	if err == nil {
		t.Errorf("DeleteUser() error = %v", err)
	}
}
