package models

import (
	"testing"

	"module/utils"
)

func TestCreateUser(t *testing.T) {
	user := User{
		Username:  "testuser",
		Password:  []byte("password123"),
		FirstName: "John",
		LastName:  "Doe",
		Email:     "test@example.com",
	}

	err := CreateUser(&user)
	if err != nil {
		t.Errorf("Failed to create user: %v", err)
	}

	// Verify that the user is saved in the database
	createdUser, err := GetUserByID(user.ID)
	if err != nil {
		t.Errorf("Failed to retrieve created user: %v", err)
	}

	// Verify the user's properties
	if createdUser.Username != user.Username {
		t.Errorf("Expected username %q, but got %q", user.Username, createdUser.Username)
	}
	if !utils.CheckArgon2Salt([]byte("password123"), createdUser.Salt, createdUser.Password) {
		t.Errorf("Password verification failed")
	}
	if createdUser.FirstName != user.FirstName {
		t.Errorf("Expected first name %q, but got %q", user.FirstName, createdUser.FirstName)
	}
	if createdUser.LastName != user.LastName {
		t.Errorf("Expected last name %q, but got %q", user.LastName, createdUser.LastName)
	}
	if createdUser.Email != user.Email {
		t.Errorf("Expected email %q, but got %q", user.Email, createdUser.Email)
	}
}

func TestGetUserByEmail(t *testing.T) {
	email := "test@example.com"

	user, err := GetUserByEmail(email)
	if err != nil {
		t.Errorf("Failed to retrieve user by email: %v", err)
	}

	// Verify the user's email
	if user.Email != email {
		t.Errorf("Expected email %q, but got %q", email, user.Email)
	}
}

func TestGetUserByID(t *testing.T) {
	email := "test@example.com"

	user, err := GetUserByEmail(email)
	if err != nil {
		t.Errorf("Failed to retrieve user by Email: %v", err)
	}

	// Verify the user's ID
	if user.Email != email {
		t.Errorf("Expected Email %s, but got %s", email, user.Email)
	}
}

func TestGetUserByName(t *testing.T) {
	username := "testuser"

	user, err := GetUserByName(username)
	if err != nil {
		t.Errorf("Failed to retrieve user by username: %v", err)
	}

	// Verify the user's username
	if user.Username != username {
		t.Errorf("Expected username %q, but got %q", username, user.Username)
	}
}

func TestUpdateUser(t *testing.T) {
	user := &User{
		Username:  "testuser",
		FirstName: "Updated",
		LastName:  "User",
	}

	// Retrieve the user by email
	user, err := GetUserByName(user.Username)
	if err != nil {
		t.Errorf("Failed to retrieve updated user: %v", err)
	}

	err = UpdateUser(user)
	if err != nil {
		t.Errorf("Failed to update user: %v", err)
	}

	// Verify that the user is updated in the database
	updatedUser, err := GetUserByEmail(user.Email)
	if err != nil {
		t.Errorf("Failed to retrieve updated user: %v", err)
	}

	// Verify the user's updated properties
	if updatedUser.FirstName != user.FirstName {
		t.Errorf("Expected first name %q, but got %q", user.FirstName, updatedUser.FirstName)
	}
	if updatedUser.LastName != user.LastName {
		t.Errorf("Expected last name %q, but got %q", user.LastName, updatedUser.LastName)
	}
}

func TestDeleteUser(t *testing.T) {
	user, err := GetUserByEmail("test@example.com")
	if err != nil {
		t.Errorf("Failed to retrieve user by Email: %v", err)
	}

	err = DeleteUser(user)
	if err != nil {
		t.Errorf("Failed to delete user: %v", err)
	}

	// Verify that the user is deleted from the database
	deletedUser, err := GetUserByID(user.ID)
	if err == nil {
		t.Errorf("Expected error when retrieving deleted user, but got nil")
	}
	if deletedUser != nil {
		t.Errorf("Expected deleted user to be nil, but got %v", deletedUser)
	}
}
