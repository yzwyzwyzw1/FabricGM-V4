package gmsw

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestInvalidStore(t *testing.T) {
	t.Parallel()

	ks := NewInMemoryGMKeyStore()

	err := ks.StoreKey(nil)
	assert.EqualError(t, err, "key is nil")
}

func TestInvalidLoad(t *testing.T) {
	t.Parallel()

	ks := NewInMemoryGMKeyStore()

	_, err := ks.GetKey(nil)
	assert.EqualError(t, err, "ski is nil or empty")
}

func TestNoKeyFound(t *testing.T) {
	t.Parallel()

	ks := NewInMemoryGMKeyStore()

	ski := []byte("foo")
	_, err := ks.GetKey(ski)
	assert.EqualError(t, err, fmt.Sprintf("no key found for ski %x", ski))
}

//func TestStoreLoad(t *testing.T) {
//	t.Parallel()
//
//	ks := NewInMemoryGMKeyStore()
//
//	// generate a key for the keystore to find
//	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
//	assert.NoError(t, err)
//	cspKey := &ecdsaPrivateKey{privKey}
//
//	// store key
//	err = ks.StoreKey(cspKey)
//	assert.NoError(t, err)
//
//	// load key
//	key, err := ks.GetKey(cspKey.SKI())
//	assert.NoError(t, err)
//
//	assert.Equal(t, cspKey, key)
//}

func TestReadOnly(t *testing.T) {
	t.Parallel()
	ks := NewInMemoryGMKeyStore()
	readonly := ks.ReadOnly()
	assert.Equal(t, false, readonly)
}


//func TestStoreExisting(t *testing.T) {
//	t.Parallel()
//
//	ks := NewInMemoryGMKeyStore()
//
//	// generate a key for the keystore to find
//	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
//	assert.NoError(t, err)
//	cspKey := &ecdsaPrivateKey{privKey}
//
//	// store key
//	err = ks.StoreKey(cspKey)
//	assert.NoError(t, err)
//
//	// store key a second time
//	err = ks.StoreKey(cspKey)
//	assert.EqualError(t, err, fmt.Sprintf("ski %x already exists in the keystore", cspKey.SKI()))
//}

