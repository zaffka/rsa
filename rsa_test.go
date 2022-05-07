package rsa_test

import (
	_ "embed"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/zaffka/rsa"
)

var (
	//go:embed testkeys/public.key
	testPublicKey []byte

	//go:embed testkeys/pkcs8.key
	testPrivateKey []byte
)

func TestEncryptDecrypt(t *testing.T) {
	testSessionKey := []byte("e!Ym1D6n,N7JcdQMV04hh2B71bqaKMZq")

	prk, err := rsa.ParsePrivate(testPrivateKey)
	assert.NoError(t, err)

	pbk, err := rsa.ParsePublic(testPublicKey)
	assert.NoError(t, err)

	encrypted, err := rsa.PrivateEncrypt(testSessionKey, prk)
	assert.NoError(t, err)

	decrypted, err := rsa.PublicDecrypt(encrypted, pbk)
	assert.NoError(t, err)

	assert.Equal(t, testSessionKey, decrypted)
}
