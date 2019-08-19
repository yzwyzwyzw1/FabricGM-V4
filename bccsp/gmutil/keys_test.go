package gmutil

import (
	"crypto/rand"
	"fmt"
	"github.com/chinaso/fabricGM/cryptopkg/golangGM/sm2"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestPrivateKeyToPEM(t *testing.T) {
	_, err := PrivateKeyToPEM(nil, nil)
	assert.Error(t, err)
    //priv,err:=sm2..RawBytesToPrivateKey([]byte("hello world"))
	priv,err:=sm2.ParsePKCS8PrivateKey([]byte("hello world"),nil)

	_, err = PrivateKeyToPEM(priv, nil)
	assert.Error(t, err)

	key, err := sm2.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	pem, err := PrivateKeyToPEM(key, nil)
	fmt.Println("key",key)
	fmt.Println("pem",pem)


	assert.NoError(t, err)
	assert.NotNil(t, pem)
	key2, err := PEMtoPrivateKey(pem, nil)
	fmt.Println("key2",key2)
	assert.NoError(t, err)
	assert.NotNil(t, key2)
	assert.Equal(t, key.D, key2.D)

	pem, err = PublicKeyToPEM(&key.PublicKey, nil)
	assert.NoError(t, err)
	assert.NotNil(t, pem)
	key3, err := PEMtoPublicKey(pem, nil)
	assert.NoError(t, err)
	assert.NotNil(t, key2)
	assert.Equal(t, key.PublicKey.Y, key3.Y)
	assert.Equal(t, key.PublicKey.X, key3.X)
}

