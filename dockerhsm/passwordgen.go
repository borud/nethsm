package dockerhsm

import (
	"crypto/rand"
	"math/big"
)

func generatePassword(n int) (string, error) {
	const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^*()-_=+"
	charRunes := []rune(chars) // Convert to runes to ensure valid characters

	password := make([]rune, n)
	for i := range password {
		index, err := rand.Int(rand.Reader, big.NewInt(int64(len(charRunes))))
		if err != nil {
			return "", err
		}
		password[i] = charRunes[index.Int64()]
	}
	return string(password), nil
}
