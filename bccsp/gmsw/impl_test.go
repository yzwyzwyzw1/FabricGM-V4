package gmsw

import (
	"crypto/rand"
	"fmt"
	"github.com/chinaso/fabricGM/bccsp"
	"github.com/chinaso/fabricGM/cryptopkg/golangGM/sm2"

	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"os"
	"testing"
)




var (
	currentTestConfig testConfig
	tempDir           string
)

type testConfig struct {
	securityLevel int
	hashFamily    string
}

func (tc testConfig) Provider(t *testing.T) (bccsp.BCCSP, bccsp.KeyStore, func()) {
	td, err := ioutil.TempDir(tempDir, "test")
	assert.NoError(t, err)
	ks, err := NewFileBasedGMKeyStore(nil, td, false)
	assert.NoError(t, err)
	p, err := NewWithParams(tc.securityLevel, tc.hashFamily, ks)
	assert.NoError(t, err)
	return p, ks, func() { os.RemoveAll(td) }
}

func TestMain(m *testing.M) {
	tests := []testConfig{
		{256, "SM3"},

	}

	var err error
	tempDir, err = ioutil.TempDir("", "bccsp-sw")
	if err != nil {
		fmt.Printf("Failed to create temporary directory: %s\n\n", err)
		os.Exit(-1)
	}
	defer os.RemoveAll(tempDir)

	for _, config := range tests {
		currentTestConfig = config
		ret := m.Run()
		if ret != 0 {
			fmt.Printf("Failed testing at [%d, %s]", config.securityLevel, config.hashFamily)
			os.Exit(-1)
		}
	}
	os.Exit(0)
}
func TestSM2Sign(t *testing.T) {
	t.Parallel()
	provider, _, cleanup := currentTestConfig.Provider(t)
	defer cleanup()

	k, err := provider.KeyGen(&bccsp.SM2KeyGenOpts{Temporary: false})
	if err != nil {
		t.Fatalf("Failed generating SM2 key [%s]", err)
	}
	fmt.Println(k)

	msg := []byte("Hello World")

	digest, err := provider.Hash(msg, &bccsp.SM3Opts{})
	if err != nil {
		t.Fatalf("Failed computing HASH [%s]", err)
	}

	signature, err := provider.Sign(k, digest, nil)
	if err != nil {
		t.Fatalf("Failed generating SM2 signature [%s]", err)
	}
	if len(signature) == 0 {
		t.Fatal("Failed generating SM2 key. Signature must be different from nil")
	}
}


func TestSM2Verify(t *testing.T) {
	t.Parallel()
	provider, ks, cleanup := currentTestConfig.Provider(t)
	defer cleanup()

	k, err := provider.KeyGen(&bccsp.SM2KeyGenOpts{Temporary: false})
	if err != nil {
		t.Fatalf("Failed generating SM2 key [%s]", err)
	}

	msg := []byte("Hello World")

	digest, err := provider.Hash(msg, &bccsp.SM3Opts{})
	if err != nil {
		t.Fatalf("Failed computing HASH [%s]", err)
	}

	signature, err := provider.Sign(k, digest, nil)
	if err != nil {
		t.Fatalf("Failed generating SM2 signature [%s]", err)
	}

	valid, err := provider.Verify(k, signature, digest, nil)
	if err != nil {
		t.Fatalf("Failed verifying SM2 signature [%s]", err)
	}
	if !valid {
		t.Fatal("Failed verifying SM2 signature. Signature not valid.")
	}

	pk, err := k.PublicKey()
	if err != nil {
		t.Fatalf("Failed getting corresponding public key [%s]", err)
	}

	valid, err = provider.Verify(pk, signature, digest, nil)
	if err != nil {
		t.Fatalf("Failed verifying SM2 signature [%s]", err)
	}
	if !valid {
		t.Fatal("Failed verifying SM2 signature. Signature not valid.")
	}



	//Store public key
	err = ks.StoreKey(pk)
	if err != nil {
		t.Fatalf("Failed storing corresponding public key [%s]", err)
	}



	pk2, err := ks.GetKey(pk.SKI())
	if err != nil {
		t.Fatalf("Failed retrieving corresponding public key [%s]", err)
	}
	fmt.Println(pk2)

	valid, err = provider.Verify(pk2, signature, digest, nil)
	if err != nil {
		t.Fatalf("Failed verifying SM2 signature [%s]", err)
	}
	if !valid {
		t.Fatal("Failed verifying SM2 signature. Signature not valid.")
	}
}


func TestSM2KeyDeriv(t *testing.T) {
	t.Parallel()
	provider, _, cleanup := currentTestConfig.Provider(t)
	defer cleanup()

	k, err := provider.KeyGen(&bccsp.SM2KeyGenOpts{Temporary: false})
	if err != nil {
		t.Fatalf("Failed generating SM2 key [%s]", err)
	}

	fmt.Println("k",k)
	reRandomizedKey, err := provider.KeyDeriv(k, &bccsp.SM2ReRandKeyOpts{Temporary: false, Expansion: []byte{1}})
	if err != nil {
		t.Fatalf("Failed re-randomizing SM2 key [%s]", err)
	}
	//
	//fmt.Println(k)
	fmt.Println(reRandomizedKey)
	//msg := []byte("Hello World")

	//digest, err := provider.Hash(msg, &bccsp.SM3Opts{})
	//if err != nil {
	//	t.Fatalf("Failed computing HASH [%s]", err)
	//}

	//signature, err := provider.Sign(reRandomizedKey, digest, nil)
	//if err != nil {
	//	t.Fatalf("Failed generating SM2 signature [%s]", err)
	//}
	//fmt.Println("signature",signature)

	//valid, err := provider.Verify(reRandomizedKey, signature, digest, nil)
	//if err != nil {
	//	t.Fatalf("Failed verifying SM2 signature [%s]", err)
	//}
	//if !valid {
	//	t.Fatal("Failed verifying SM2 signature. Signature not valid.")
	//}
}
func TestSM2KeyGenEphemeral(t *testing.T) {
	t.Parallel()
	provider, _, cleanup := currentTestConfig.Provider(t)
	defer cleanup()

	k, err := provider.KeyGen(&bccsp.SM2KeyGenOpts{Temporary: true})
	if err != nil {
		t.Fatalf("Failed generating SM2 key [%s]", err)
	}
	if k == nil {
		t.Fatal("Failed generating SM2 key. Key must be different from nil")
	}
	if !k.Private() {
		t.Fatal("Failed generating SM2 key. Key should be private")
	}
	if k.Symmetric() {
		t.Fatal("Failed generating SM2 key. Key should be asymmetric")
	}
	raw, err := k.Bytes()
	if err == nil {
		t.Fatal("Failed marshalling to bytes. Marshalling must fail.")
	}
	if len(raw) != 0 {
		t.Fatal("Failed marshalling to bytes. Output should be 0 bytes")
	}
	pk, err := k.PublicKey()
	if err != nil {
		t.Fatalf("Failed getting corresponding public key [%s]", err)
	}
	if pk == nil {
		t.Fatal("Public key must be different from nil.")
	}
}

func TestSM2KeyGenNonEphemeral(t *testing.T) {
	t.Parallel()
	provider, _, cleanup := currentTestConfig.Provider(t)
	defer cleanup()

	k, err := provider.KeyGen(&bccsp.SM2KeyGenOpts{Temporary: false})
	if err != nil {
		t.Fatalf("Failed generating SM2 key [%s]", err)
	}
	if k == nil {
		t.Fatal("Failed generating SM2 key. Key must be different from nil")
	}
	if !k.Private() {
		t.Fatal("Failed generating SM2 key. Key should be private")
	}
	if k.Symmetric() {
		t.Fatal("Failed generating SM2 key. Key should be asymmetric")
	}
}


func TestSM2KeyReRand(t *testing.T) {
	t.Parallel()
	provider, _, cleanup := currentTestConfig.Provider(t)
	defer cleanup()

	k, err := provider.KeyGen(&bccsp.SM2KeyGenOpts{Temporary: false})
	if err != nil {
		t.Fatalf("Failed generating SM2 key [%s]", err)
	}
	if k == nil {
		t.Fatal("Failed re-randomizing SM2 key. Re-randomized Key must be different from nil")
	}

	reRandomizedKey, err := provider.KeyDeriv(k, &bccsp.SM2ReRandKeyOpts{Temporary: false, Expansion: []byte{1}})
	fmt.Println("reRandomizeKey",reRandomizedKey)
	//if err != nil {
	//	t.Fatalf("Failed re-randomizing SM2 key [%s]", err)
	//}
	fmt.Println("reRandomizeKey",reRandomizedKey)
	//if !reRandomizedKey.Private() {
	//	t.Fatal("Failed re-randomizing SM2 key. Re-randomized Key should be private")
	//}
	//if reRandomizedKey.Symmetric() {
	//	t.Fatal("Failed re-randomizing SM2 key. Re-randomized Key should be asymmetric")
	//}
	//
	//k2, err := k.PublicKey()
	//if err != nil {
	//	t.Fatalf("Failed getting public SM2 key from private [%s]", err)
	//}
	//if k2 == nil {
	//	t.Fatal("Failed re-randomizing SM2 key. Re-randomized Key must be different from nil")
	//}
	//
	//reRandomizedKey2, err := provider.KeyDeriv(k2, &bccsp.ECDSAReRandKeyOpts{Temporary: false, Expansion: []byte{1}})
	//if err != nil {
	//	t.Fatalf("Failed re-randomizing SM2 key [%s]", err)
	//}
	//
	//if reRandomizedKey2.Private() {
	//	t.Fatal("Re-randomized public Key must remain public")
	//}
	//if reRandomizedKey2.Symmetric() {
	//	t.Fatal("Re-randomized SM2 asymmetric key must remain asymmetric")
	//}
	//
	//if false == bytes.Equal(reRandomizedKey.SKI(), reRandomizedKey2.SKI()) {
	//	t.Fatal("Re-randomized ECDSA Private- or Public-Keys must end up having the same SKI")
	//}
}

func TestSM2KeyImportFromExportedKey(t *testing.T) {
	t.Parallel()
	provider, _, cleanup := currentTestConfig.Provider(t)
	defer cleanup()

	// Generate an SM2 key
	k, err := provider.KeyGen(&bccsp.SM2KeyGenOpts{Temporary: false})
	if err != nil {
		t.Fatalf("Failed generating SM2 key [%s]", err)
	}
	fmt.Println(k)

	//Export the public key
	pk, err := k.PublicKey()
	if err != nil {
		t.Fatalf("Failed getting SM2 public key [%s]", err)
	}

	pkRaw, err := pk.Bytes()
	if err != nil {
		t.Fatalf("Failed getting SM2 raw public key [%s]", err)
	}
	fmt.Println(pkRaw)
	fmt.Println("pkRaw:",pkRaw)

	//Import the exported public key
	pk2, err := provider.KeyImport(pkRaw, &bccsp.SM2PKIXPublicKeyImportOpts{Temporary: false})
	if err != nil {
		t.Fatalf("Failed importing SM2 public key [%s]", err)
	}

	fmt.Println("pk2:",pk2)
	if pk2 == nil {
		t.Fatal("Failed importing SM2 public key. Return BCCSP key cannot be nil.")
	}

	// Sign and verify with the imported public key
	msg := []byte("Hello World")

	digest, err := provider.Hash(msg, &bccsp.SM3Opts{})
	if err != nil {
		t.Fatalf("Failed computing HASH [%s]", err)
	}
	fmt.Println(digest)
	//
	signature, err := provider.Sign(k, digest, nil)
	if err != nil {
		t.Fatalf("Failed generating SM2 signature [%s]", err)
	}
	fmt.Println(signature)
	//
	valid, err := provider.Verify(pk2, signature, digest, nil)
	if err != nil {
		t.Fatalf("Failed verifying SM2 signature [%s]", err)
	}
	if !valid {
		t.Fatal("Failed verifying SM2 signature. Signature not valid.")
	}
}

func TestSM2KeyImportFromSM2PublicKey(t *testing.T) {
	t.Parallel()
	provider, _, cleanup := currentTestConfig.Provider(t)
	defer cleanup()

	// Generate an ECDSA key
	k, err := provider.KeyGen(&bccsp.SM2KeyGenOpts{Temporary: false})
	if err != nil {
		t.Fatalf("Failed generating SM2 key [%s]", err)
	}

	// Export the public key
	pk, err := k.PublicKey()
	if err != nil {
		t.Fatalf("Failed getting SM2 public key [%s]", err)
	}

	pkRaw, err := pk.Bytes()
	if err != nil {
		t.Fatalf("Failed getting SM2 raw public key [%s]", err)
	}

	//pub, err := utils.DERToPublicKey(pkRaw)

	pub, err := sm2.ParseSM2PublicKey(pkRaw)
	if err != nil {
		t.Fatalf("Failed converting raw to sm2.PublicKey [%s]", err)
	}
	//fmt.Println(pub)


	// Import the ecdsa.PublicKey
	pk2, err := provider.KeyImport(pub, &bccsp.SM2GoPublicKeyImportOpts{Temporary: false})
	if err != nil {
		t.Fatalf("Failed importing SM2 public key [%s]", err)
	}
	if pk2 == nil {
		t.Fatal("Failed importing SM2 public key. Return BCCSP key cannot be nil.")
	}
	fmt.Println("pk2",pk2)
	//
	// Sign and verify with the imported public key
	msg := []byte("Hello World")

	digest, err := provider.Hash(msg, &bccsp.SM3Opts{})
	if err != nil {
		t.Fatalf("Failed computing HASH [%s]", err)
	}
	fmt.Println("digest",digest)
	////
	signature, err := provider.Sign(k, digest, nil)
	if err != nil {
		t.Fatalf("Failed generating SM2 signature [%s]", err)
	}
	fmt.Println(signature)

	valid, err := provider.Verify(pk2, signature, digest, nil)
	if err != nil {
		t.Fatalf("Failed verifying SM2 signature [%s]", err)
	}
	if !valid {
		t.Fatal("Failed verifying SM2 signature. Signature not valid.")
	}
}

func TestSM2KeyImportFromSM2PrivateKey(t *testing.T) {
	t.Parallel()
	provider, _, cleanup := currentTestConfig.Provider(t)
	defer cleanup()

	// Generate an SM2 key, default is P256
	key, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed generating SM2 key [%s]", err)
	}

	// Import the ecdsa.PrivateKey
	//priv, err := utils.PrivateKeyToDER(key)
	priv,err := sm2.MarshalSM2UnecryptedPrivateKey(key)

	//fmt.Println("priv",priv)

	if err != nil {
		t.Fatalf("Failed converting raw to ecdsa.PrivateKey [%s]", err)
	}

	sk, err := provider.KeyImport(priv, &bccsp.SM2PrivateKeyImportOpts{Temporary: false})
	if err != nil {
		t.Fatalf("Failed importing SM2 private key [%s]", err)
	}
	if sk == nil {
		t.Fatal("Failed importing SM2 private key. Return BCCSP key cannot be nil.")
	}

	// Import the ecdsa.PublicKey

	//pub, err := utils.PublicKeyToDER(&key.PublicKey)
	pub, err := sm2.MarshalSM2PublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("Failed converting raw to sm2.PublicKey [%s]", err)
	}

	pk, err := provider.KeyImport(pub, &bccsp.SM2PKIXPublicKeyImportOpts{Temporary: false})

	if err != nil {
		t.Fatalf("Failed importing SM2 public key [%s]", err)
	}
	if pk == nil {
		t.Fatal("Failed importing SM2 public key. Return BCCSP key cannot be nil.")
	}

	// Sign and verify with the imported public key
	msg := []byte("Hello World")

	digest, err := provider.Hash(msg, &bccsp.SM3Opts{})
	if err != nil {
		t.Fatalf("Failed computing HASH [%s]", err)
	}

	signature, err := provider.Sign(sk, digest, nil)
	if err != nil {
		t.Fatalf("Failed generating SM2 signature [%s]", err)
	}
	fmt.Println("signature",signature)
	//
	valid, err := provider.Verify(pk, signature, digest, nil)
	if err != nil {
		t.Fatalf("Failed verifying SM2 signature [%s]", err)
	}
	if !valid {
		t.Fatal("Failed verifying SM2 signature. Signature not valid.")
	}
}
