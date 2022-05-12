package rsa

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
)

var (
	ErrWrongFormatKey          = errors.New("the key has a wrong format")
	ErrUnexpectedBytesPayload  = errors.New("unexpected bytes payload")
	ErrUnexpectedPayloadLength = errors.New("unexpected payload length")

	paddingBytesSequence = []byte{0xff, 0}
)

// PrivateEncrypt encrypts a payload with private key and return encrypted bytes or error.
func PrivateEncrypt(payload []byte, privateKey *rsa.PrivateKey) ([]byte, error) {
	if len(payload) < 1 {
		return nil, ErrUnexpectedPayloadLength
	}

	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.Hash(0), payload) // Note: crypto.Hash(0), unhashed payload
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt: %w", err)
	}

	return signature, nil
}

// PublicDecrypt decrypts a payload with public key and then return decrypted bytes.
func PublicDecrypt(payload []byte, pubKey *rsa.PublicKey) ([]byte, error) {
	if len(payload) < 1 {
		return nil, ErrUnexpectedPayloadLength
	}

	m := new(big.Int).SetBytes(payload)
	e := big.NewInt(int64(pubKey.E))
	c := new(big.Int).Exp(m, e, pubKey.N)

	bbytes := bytes.Split(c.Bytes(), paddingBytesSequence)
	if len(bbytes) != 2 {
		return nil, ErrUnexpectedBytesPayload
	}

	return bbytes[1], nil
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
