package utils

import (
	"bytes"
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"io"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/sha3"
)

// chk comprueba y sale si hay errores (ahorra escritura en programas sencillos)
func chk(e error) {
	if e != nil {
		panic(e)
	}
}

func HelloWorld() string {
	return "hello world"
}

/*
// función para cifrar (AES-CTR 256), adjunta el IV al principio
func Encrypt(data, key []byte) (out []byte) {
	out = make([]byte, len(data)+16)    // reservamos espacio para el IV al principio
	rand.Read(out[:16])                 // generamos el IV
	blk, err := aes.NewCipher(key)      // cifrador en bloque (AES), usa key
	chk(err)                            // comprobamos el error
	ctr := cipher.NewCTR(blk, out[:16]) // cifrador en flujo: modo CTR, usa IV
	ctr.XORKeyStream(out[16:], data)    // ciframos los datos
	return
}

// función para descifrar (AES-CTR 256)
func Decrypt(data, key []byte) (out []byte) {
	out = make([]byte, len(data)-16)     // la salida no va a tener el IV
	blk, err := aes.NewCipher(key)       // cifrador en bloque (AES), usa key
	chk(err)                             // comprobamos el error
	ctr := cipher.NewCTR(blk, data[:16]) // cifrador en flujo: modo CTR, usa IV
	ctr.XORKeyStream(out, data[16:])     // desciframos (doble cifrado) los datos
	return
}*/

// función para comprimir
func Compress(data []byte) []byte {
	var b bytes.Buffer      // b contendrá los datos comprimidos (tamaño variable)
	w := zlib.NewWriter(&b) // escritor que comprime sobre b
	_, err := w.Write(data) // escribimos los datos
	chk(err)                // comprobamos el error
	w.Close()               // cerramos el escritor (buffering)
	return b.Bytes()        // devolvemos los datos comprimidos
}

// función para descomprimir
func Decompress(data []byte) []byte {
	var b bytes.Buffer                              // b contendrá los datos descomprimidos
	r, err := zlib.NewReader(bytes.NewReader(data)) // lector descomprime al leer
	chk(err)                                        // comprobamos el error
	_, err = io.Copy(&b, r)                         // copiamos del descompresor (r) al buffer (b)
	chk(err)                                        // comprobamos el error
	r.Close()                                       // cerramos el lector (buffering)
	return b.Bytes()                                // devolvemos los datos descomprimidos
}

// función para codificar de []bytes a string (Base64)
func Encode64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data) // sólo utiliza caracteres "imprimibles"
}

// función para decodificar de string a []bytes (Base64)
func Decode64(s string) []byte {
	b, err := base64.StdEncoding.DecodeString(s) // recupera el formato original
	chk(err)                                     // comprobamos el error
	return b                                     // devolvemos los datos originales
}

// Tamaño recomendado, 16 byte == 128 bits, 32 byte == 256 bits, 64 byte == 562 bits para Sal y Token
func GenRandByteSlice(size int) []byte {
	var byteSlice = make([]byte, size)

	_, err := rand.Read(byteSlice[:])
	if err != nil {
		panic(err)
	}

	return byteSlice
}

// Se pasa la LoginKey(Hash para login derivado de la contraseña) en claro, la Sal y aplica Argon2+Sal
func CheckArgon2Salt(password, salt, passwordArgon2Salt []byte) bool {

	key := argon2.IDKey(password, salt, 1, 64*1024, 4, 32)

	return bytes.Equal(key, passwordArgon2Salt)
}

// Se pasa la LoginKey(Hash para login derivado de la contraseña) en claro, la Sal y aplica Argon2+Sal
func ApplyArgon2Salt(password, salt []byte) []byte {
	// Argon2 con parametros recomendados por defecto
	key := argon2.IDKey(password, salt, 1, 64*1024, 4, 32)

	return key
}

// Hash con SHA-3 SHAKE-128 con salida de 32 bytes y resistencia a colisiones de 128-bit
func Hash256(data []byte) []byte {

	//data := []byte(str)
	// A hash needs to be 32 bytes long to have 128-bit collision resistance.
	hash := make([]byte, 32)
	// Compute a 32-byte hash of data and put it in 'hash'.
	sha3.ShakeSum128(hash, data)

	return hash
}

// Hash con SHA-3 SHAKE-256 con salida de 64 bytes y resistencia a colisiones de 256-bit
func Hash512(data []byte) []byte {

	// A hash needs to be 64 bytes long to have 256-bit collision resistance.
	hash := make([]byte, 64)
	// Compute a 64-byte hash of data and put it in 'hash'.
	sha3.ShakeSum256(hash, data)

	return hash
}

// Hash con SHA-3 SHAKE-256 con entrada adicional para la funcion esponja y salida de 64 bytes y resistencia a colisiones de 256-bit
func Hash512_esponja(data []byte, function, passphrase []byte) []byte {

	// A hash needs to be 64 bytes long to have 256-bit collision resistance.
	hash := make([]byte, 64)
	// Compute a 64-byte hash of data and put it in 'hash'.
	sha3.ShakeSum256(hash, data)
	c1 := sha3.NewCShake256(function, passphrase)
	_, err := c1.Write(data)
	chk(err)
	_, err = c1.Read(hash)
	chk(err)

	return hash
}

// #########################
// # CIFRADORES
// #########################

// función para cifrar (AES-CTR 256), adjunta el IV al principio
func EncryptAesCtr(data, key []byte) (out []byte) {
	out = make([]byte, len(data)+16)    // reservamos espacio para el IV al principio
	_, err := rand.Read(out[:16])       // generamos el IV
	chk(err)                            // comprobamos el error
	blk, err := aes.NewCipher(key)      // cifrador en bloque (AES), usa key
	chk(err)                            // comprobamos el error
	ctr := cipher.NewCTR(blk, out[:16]) // cifrador en flujo: modo CTR, usa IV
	ctr.XORKeyStream(out[16:], data)    // ciframos los datos
	return
}

// función para descifrar (AES-CTR 256)
func DecryptAesCtr(data, key []byte) (out []byte) {
	out = make([]byte, len(data)-16)     // la salida no va a tener el IV
	blk, err := aes.NewCipher(key)       // cifrador en bloque (AES), usa key
	chk(err)                             // comprobamos el error
	ctr := cipher.NewCTR(blk, data[:16]) // cifrador en flujo: modo CTR, usa IV
	ctr.XORKeyStream(out, data[16:])     // desciframos (doble cifrado) los datos
	return
}

// Cifrado autentificado AES en modo GCM
func EncryptAesGcm(data, key []byte) (out []byte) {
	// cifrador en bloque (AES), usa key
	blk, err := aes.NewCipher(key)
	chk(err)

	// cifrador en bloque (AES), en modo GCM
	aead, err := cipher.NewGCM(blk)
	chk(err)

	// Select a random nonce, and leave capacity for the ciphertext.
	nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+len(data)+aead.Overhead())
	if _, err := rand.Read(nonce); err != nil {
		panic(err)
	}

	// Encrypt the message and append the ciphertext to the nonce.
	out = aead.Seal(nonce, nonce, data, nil)
	return
}

// Descifrado autentificado AES en modo GCM
func DecryptAesGcm(data, key []byte) (out []byte) {
	// cifrador en bloque (AES), usa key
	blk, err := aes.NewCipher(key)
	chk(err)

	// cifrador en bloque (AES), en modo GCM
	aead, err := cipher.NewGCM(blk)
	chk(err)

	if len(data) < aead.NonceSize() {
		panic("ciphertext too short")
	}

	// Split nonce and ciphertext.
	nonce, ciphertext := data[:aead.NonceSize()], data[aead.NonceSize():]

	// Decrypt the message and check it wasn't tampered with.
	out, err = aead.Open(nil, nonce, ciphertext, nil)
	chk(err)

	return
}

// Cifrado autentificado ChaCha20_Poly1305
func EncryptChaCha20(data, key []byte) (out []byte) {
	aead, err := chacha20poly1305.NewX(key)
	chk(err)

	// Select a random nonce, and leave capacity for the ciphertext.
	nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+len(data)+aead.Overhead())
	if _, err := rand.Read(nonce); err != nil {
		panic(err)
	}

	// Encrypt the message and append the ciphertext to the nonce.
	out = aead.Seal(nonce, nonce, data, nil)
	return
}

// Descifrado autentificado ChaCha20_Poly1305
func DecryptChaCha20(data, key []byte) (out []byte) {
	aead, err := chacha20poly1305.NewX(key)
	chk(err)

	if len(data) < aead.NonceSize() {
		panic("ciphertext too short")
	}

	// Split nonce and ciphertext.
	nonce, ciphertext := data[:aead.NonceSize()], data[aead.NonceSize():]

	// Decrypt the message and check it wasn't tampered with.
	out, err = aead.Open(nil, nonce, ciphertext, nil)
	chk(err)

	return
}
