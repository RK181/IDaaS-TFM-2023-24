package models

type AuthCode struct {
	ID        string `storm:"id,increment"` // auth code id
	Code      string `storm:"unique"`       // auth code
	RequestID string // Auth Request ID
}
