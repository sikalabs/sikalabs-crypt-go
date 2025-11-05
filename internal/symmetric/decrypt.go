package symmetric

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/pbkdf2"
)

func SikaLabsSymmetricDecryptV1(password, encryptedBase64 string) (string, error) {
	encryptedData, err := base64.StdEncoding.DecodeString(encryptedBase64)
	if err != nil {
		return "", err
	}

	// Extract salt (first 16 bytes)
	saltSize := 16
	if len(encryptedData) < saltSize {
		return "", fmt.Errorf("encrypted data too short")
	}
	salt := encryptedData[:saltSize]
	remaining := encryptedData[saltSize:]

	// Derive key using salt
	key := pbkdf2.Key([]byte(password), salt, 100000, 32, sha256.New)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := aesGCM.NonceSize()
	if len(remaining) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := remaining[:nonceSize], remaining[nonceSize:]

	text, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(text), nil
}
