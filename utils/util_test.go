package utils

import (
	"testing"
)

func TestHelloWorld(t *testing.T) {
	expected := "hello world"
	result := HelloWorld()

	if result != expected {
		t.Errorf("Expected %q, but got %q", expected, result)
	}
}

func TestCompressAndDecompress(t *testing.T) {
	data := []byte("compressed data")

	compressed := Compress(data)
	decompressed := Decompress(compressed)

	if string(decompressed) != string(data) {
		t.Errorf("Decompression failed. Expected %q, but got %q", string(data), string(decompressed))
	}
}

func TestEncodeAndDecode64(t *testing.T) {
	data := []byte("encoded data")

	encoded := Encode64(data)
	decoded := Decode64(encoded)

	if string(decoded) != string(data) {
		t.Errorf("Decoding failed. Expected %q, but got %q", string(data), string(decoded))
	}
}

func TestCheckArgon2Salt(t *testing.T) {
	password := []byte("password")
	salt := GenRandByteSlice(16)
	passwordArgon2Salt := ApplyArgon2Salt(password, salt)

	result := CheckArgon2Salt(password, salt, passwordArgon2Salt)

	if !result {
		t.Errorf("Argon2 salt check failed. Expected true, but got false")
	}
}

func TestHash256(t *testing.T) {
	data := []byte("hash data")

	hash := Hash256(data)

	if len(hash) != 32 {
		t.Errorf("Hashing failed. Expected hash length of 32, but got %d", len(hash))
	}
}

func TestHash512(t *testing.T) {
	data := []byte("hash data")

	hash := Hash512(data)

	if len(hash) != 64 {
		t.Errorf("Hashing failed. Expected hash length of 64, but got %d", len(hash))
	}
}

func TestEncryptAesCtrAndDecryptAesCtr(t *testing.T) {
	data := []byte("secret message")
	key := GenRandByteSlice(32)

	encrypted := EncryptAesCtr(data, key)
	decrypted := DecryptAesCtr(encrypted, key)

	if string(decrypted) != string(data) {
		t.Errorf("Decryption failed. Expected %q, but got %q", string(data), string(decrypted))
	}
}

func TestEncryptAesGcmAndDecryptAesGcm(t *testing.T) {
	data := []byte("secret message")
	key := GenRandByteSlice(32)

	encrypted := EncryptAesGcm(data, key)
	decrypted := DecryptAesGcm(encrypted, key)

	if string(decrypted) != string(data) {
		t.Errorf("Decryption failed. Expected %q, but got %q", string(data), string(decrypted))
	}
}

func TestEncryptChaCha20AndDecryptChaCha20(t *testing.T) {
	data := []byte("secret message")
	key := GenRandByteSlice(32)

	encrypted := EncryptChaCha20(data, key)
	decrypted := DecryptChaCha20(encrypted, key)

	if string(decrypted) != string(data) {
		t.Errorf("Decryption failed. Expected %q, but got %q", string(data), string(decrypted))
	}
}
