package gmsw

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"github.com/chinaso/fabricGM/bccsp/gmutil"
	"github.com/chinaso/fabricGM/cryptopkg/golangGM/sm2"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
)

func TestInvalidStoreKey(t *testing.T) {
	t.Parallel()

	tempDir, err := ioutil.TempDir("", "bccspks")
	assert.NoError(t, err)
	defer os.RemoveAll(tempDir)

	ks, err := NewFileBasedGMKeyStore(nil, filepath.Join(tempDir, "bccspks"), false)
	if err != nil {
		fmt.Printf("Failed initiliazing KeyStore [%s]", err)
		os.Exit(-1)
	}

	err = ks.StoreKey(nil)
	if err == nil {
		t.Fatal("Error should be different from nil in this case")
	}

	err = ks.StoreKey(&sm2PrivateKey{nil})
	if err == nil {
		t.Fatal("Error should be different from nil in this case")
	}

	err = ks.StoreKey(&sm2PublicKey{nil})
	if err == nil {
		t.Fatal("Error should be different from nil in this case")
	}

	err = ks.StoreKey(&sm4PrivateKey{nil, false})
	if err == nil {
		t.Fatal("Error should be different from nil in this case")
	}

	err = ks.StoreKey(&sm4PrivateKey{nil, true})
	if err == nil {
		t.Fatal("Error should be different from nil in this case")
	}
}

func TestReadPemFromFile(t *testing.T){

	privKey, err := sm2.GenerateKey(rand.Reader)
	assert.NoError(t, err)

	fmt.Println("privKey",privKey)
	rawKey, err := gmutil.PrivateKeyToPEM(privKey, nil)
	assert.NoError(t, err)

	fmt.Println("rawKey",rawKey)

	priv ,err := gmutil.PEMtoPrivateKey(rawKey,nil)
	assert.NoError(t, err)
	fmt.Println("priv",priv)
}

func TestBigKeyFile(t *testing.T) {
	ksPath, err := ioutil.TempDir("", "bccspks")
	assert.NoError(t, err)
	defer os.RemoveAll(ksPath)

	ks, err := NewFileBasedGMKeyStore(nil, ksPath, false)
	assert.NoError(t, err)

	// Generate a key for keystore to find
	privKey, err := sm2.GenerateKey(rand.Reader)
	assert.NoError(t, err)

	cspKey := &sm2PrivateKey{privKey}
	ski := cspKey.SKI()

	//
//	rawKey, err := utils.PrivateKeyToPEM(privKey, nil)
	rawKey, err := gmutil.PrivateKeyToPEM(privKey, nil)
	assert.NoError(t, err)

	fmt.Println("rawKey",rawKey)
	// Large padding array, of some values PEM parser will NOOP
	bigBuff := make([]byte, (1 << 17))
	for i := range bigBuff {
		bigBuff[i] = '\n'
	}
	copy(bigBuff, rawKey)

	//>64k, so that total file size will be too big
	ioutil.WriteFile(filepath.Join(ksPath, "bigfile.pem"), bigBuff, 0666)

	_, err = ks.GetKey(ski)
	assert.Error(t, err)
	expected := fmt.Sprintf("Key with SKI %s not found in %s", hex.EncodeToString(ski), ksPath)
	assert.EqualError(t, err, expected)

	// 1k, so that the key would be found
	//ioutil.WriteFile(filepath.Join(ksPath, "smallerfile.pem"), bigBuff[0:1<<10], 0666)
	//
	//_, err = ks.GetKey(ski) // 存储报错
	//assert.NoError(t, err)
}

func TestReInitKeyStore(t *testing.T) {
	ksPath, err := ioutil.TempDir("", "bccspks")
	assert.NoError(t, err)
	defer os.RemoveAll(ksPath)

	ks, err := NewFileBasedGMKeyStore(nil, ksPath, false)
	assert.NoError(t, err)
	fbKs, isFileBased := ks.(*fileBasedGMKeyStore)
	assert.True(t, isFileBased)
	err = fbKs.Init(nil, ksPath, false)
	assert.EqualError(t, err, "KeyStore already initilized.")
}

