package sikalabs_crypt

import "github.com/sikalabs/sikalabs-crypt-go/internal/symmetric"

func SikaLabsSymmetricDecryptV1(password, encryptedBase64 string) (string, error) {
	return symmetric.SikaLabsSymmetricDecryptV1(
		password,
		encryptedBase64,
	)
}
