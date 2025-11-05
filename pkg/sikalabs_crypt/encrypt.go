package sikalabs_crypt

import "github.com/sikalabs/sikalabs-crypt-go/internal/symmetric"

func SikaLabsSymmetricEncryptV1(password, text string) (string, error) {
	return symmetric.SikaLabsSymmetricEncryptV1(
		password,
		text,
	)
}
