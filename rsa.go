package rsa

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
)

var ErrWrongFormatKey = errors.New("the key has a wrong format")

// PrivateEncrypt encrypts a payload with private key and return encrypted bytes or error.
func PrivateEncrypt(payload []byte, privateKey *rsa.PrivateKey) ([]byte, error) {
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.Hash(0), payload) // Note: crypto.Hash(0), unhashed payload
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt: %w", err)
	}

	return signature, nil
}

// PublicDecrypt decrypts a payload with public key and then return decrypted bytes.
func PublicDecrypt(payload []byte, pubKey *rsa.PublicKey) ([]byte, error) {
	m := new(big.Int).SetBytes(payload)
	e := big.NewInt(int64(pubKey.E))
	c := new(big.Int).Exp(m, e, pubKey.N)

	result := c.Bytes()

	// Skip unnecessary padding from the resulted slice of bytes.
	skip := 0
	for i := 2; i < len(result); i++ {
		if i+1 >= len(result) {
			break
		}
		if result[i] == 0xff && result[i+1] == 0 {
			skip = i + 2

			break
		}
	}

	return result[skip:], nil
}

// ParsePublic parses *rsa.PublicKey from the raw bytes data.
func ParsePublic(publicKey []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(publicKey)

	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	puk, ok := parsed.(*rsa.PublicKey)
	if !ok {
		return nil, ErrWrongFormatKey
	}

	return puk, nil
}

// ParsePrivate parses *rsa.PrivateKey from the raw bytes data.
func ParsePrivate(privateKey []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(privateKey)

	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	pk, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, ErrWrongFormatKey
	}

	return pk, nil
}
