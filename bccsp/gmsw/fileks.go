/*
Copyright IBM Corp. 2016 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

		 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package gmsw

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/chinaso/fabricGM/bccsp/gmutil"
	"github.com/chinaso/fabricGM/cryptopkg/golangGM/sm2"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/chinaso/fabricGM/bccsp"
	"github.com/chinaso/fabricGM/bccsp/utils"
)

// NewFileBasedGMKeyStore instantiated a file-based key store at a given position.
// The key store can be encrypted if a non-empty password is specified.
// It can be also be set as read only. In this case, any store operation
// will be forbidden
func NewFileBasedGMKeyStore(pwd []byte, path string, readOnly bool) (bccsp.KeyStore, error) {
	ksgm := &fileBasedGMKeyStore{}
	return ksgm, ksgm.Init(pwd, path, readOnly)
}

// fileBasedGMKeyStore is a folder-based KeyStore.
// Each key is stored in a separated file whose name contains the key's SKI
// and flags to identity the key's type. All the keys are stored in
// a folder whose path is provided at initialization time.
// The KeyStore can be initialized with a password, this password
// is used to encrypt and decrypt the files storing the keys.
// A KeyStore can be read only to avoid the overwriting of keys.
type fileBasedGMKeyStore struct {
	path string

	readOnly bool
	isOpen   bool

	pwd []byte

	// Sync
	m sync.Mutex
}

// Init initializes this KeyStore with a password, a path to a folder
// where the keys are stored and a read only flag.
// Each key is stored in a separated file whose name contains the key's SKI
// and flags to identity the key's type.
// If the KeyStore is initialized with a password, this password
// is used to encrypt and decrypt the files storing the keys.
// The pwd can be nil for non-encrypted KeyStores. If an encrypted
// key-store is initialized without a password, then retrieving keys from the
// KeyStore will fail.
// A KeyStore can be read only to avoid the overwriting of keys.
func (ksgm *fileBasedGMKeyStore) Init(pwd []byte, path string, readOnly bool) error {
	// Validate inputs
	// pwd can be nil

	if len(path) == 0 {
		return errors.New("An invalid KeyStore path provided. Path cannot be an empty string.")
	}

	ksgm.m.Lock()
	defer ksgm.m.Unlock()

	if ksgm.isOpen {
		return errors.New("KeyStore already initilized.")
	}

	ksgm.path = path
	ksgm.pwd = utils.Clone(pwd)

	err := ksgm.createKeyStoreIfNotExists()
	if err != nil {
		return err
	}

	err = ksgm.openKeyStore()
	if err != nil {
		return err
	}

	ksgm.readOnly = readOnly

	return nil
}

// ReadOnly returns true if this KeyStore is read only, false otherwise.
// If ReadOnly is true then StoreKey will fail.
func (ksgm *fileBasedGMKeyStore) ReadOnly() bool {
	return ksgm.readOnly
}

// GetKey returns a key object whose SKI is the one passed.
func (ksgm *fileBasedGMKeyStore) GetKey(ski []byte) (bccsp.Key, error) {
	// Validate arguments
	if len(ski) == 0 {
		return nil, errors.New("Invalid SKI. Cannot be of zero length.")
	}

	suffix := ksgm.getSuffix(hex.EncodeToString(ski))

	switch suffix {
	case "key":
		// Load the key
		key, err := ksgm.loadKey(hex.EncodeToString(ski))
		if err != nil {
			return nil, fmt.Errorf("Failed loading key [%x] [%s]", ski, err)
		}

		return &sm4PrivateKey{key, false}, nil
	case "sk":
		// Load the private key
		key, err := ksgm.loadPrivateKey(hex.EncodeToString(ski))
		if err != nil {
			return nil, fmt.Errorf("Failed loading secret key [%x] [%s]", ski, err)
		}

		switch key.(type) {
		case *sm2.PrivateKey:
			
			return &sm2PrivateKey{key.(*sm2.PrivateKey)},nil
		default:
			return nil, errors.New("Secret key type not recognized")
		}
	case "pk":
		// Load the public key
		key, err := ksgm.loadPublicKey(hex.EncodeToString(ski))
		if err != nil {
			return nil, fmt.Errorf("Failed loading public key [%x] [%s]", ski, err)
		}

		switch key.(type) {
		case *sm2.PublicKey:
			
			return &sm2PublicKey{key.(*sm2.PublicKey)},nil
		default:
			return nil, errors.New("Public key type not recognized")
		}
	default:
		return ksgm.searchKeystoreForSKI(ski)
	}
}

// StoreKey stores the key k in this KeyStore.
// If this KeyStore is read only then the method will fail.
func (ksgm *fileBasedGMKeyStore) StoreKey(k bccsp.Key) (err error) {
	if ksgm.readOnly {
		return errors.New("Read only KeyStore.")
	}

	//fmt.Println("yzw")
	if k == nil {
		return errors.New("Invalid key. It must be different from nil.")
	}
	switch k.(type) {
	case *sm2PrivateKey:
		kk := k.(*sm2PrivateKey)

		fmt.Println("执行了此句话")
	//	fmt.Println("kk.privKey",kk.privKey)
		err = ksgm.storePrivateKey(hex.EncodeToString(k.SKI()), kk.privKey)
		if err != nil {
			return fmt.Errorf("Failed storing GMSM2 private key [%s]", err)
		}

	case *sm2PublicKey:
		kk := k.(*sm2PublicKey)

		err = ksgm.storePublicKey(hex.EncodeToString(k.SKI()), kk.pubKey)
		if err != nil {
			return fmt.Errorf("Failed storing GMSM2 public key [%s]", err)
		}
	case *sm4PrivateKey:
		kk := k.(*sm4PrivateKey)

		err = ksgm.storeKey(hex.EncodeToString(k.SKI()), kk.privKey)
		if err != nil {
			return fmt.Errorf("Failed storing GMSM4 key [%s]", err)
		}
	default:
		return fmt.Errorf("Key type not reconigned [%s]", k)
	}

	return
}

func (ksgm *fileBasedGMKeyStore) searchKeystoreForSKI(ski []byte) (k bccsp.Key, err error) {

	files, _ := ioutil.ReadDir(ksgm.path)
	for _, f := range files {
		if f.IsDir() {
			continue
		}

		if f.Size() > (1 << 16) { //64k, somewhat arbitrary limit, considering even large RSA keys
			continue
		}

		raw, err := ioutil.ReadFile(filepath.Join(ksgm.path, f.Name()))
		if err != nil {
			continue
		}

		key, err := gmutil.PEMtoPrivateKey(raw, ksgm.pwd)
		if err != nil {
			continue
		}
		k = &sm2PrivateKey{key}


		if !bytes.Equal(k.SKI(), ski) {
			continue
		}

		return k, nil
	}
	return nil, fmt.Errorf("Key with SKI %s not found in %s", hex.EncodeToString(ski), ksgm.path)
}

func (ksgm *fileBasedGMKeyStore) getSuffix(alias string) string {
	files, _ := ioutil.ReadDir(ksgm.path)
	for _, f := range files {
		if strings.HasPrefix(f.Name(), alias) {
			if strings.HasSuffix(f.Name(), "sk") {
				return "sk"
			}
			if strings.HasSuffix(f.Name(), "pk") {
				return "pk"
			}
			if strings.HasSuffix(f.Name(), "key") {
				return "key"
			}
			break
		}
	}
	return ""
}

func (ksgm *fileBasedGMKeyStore) storePrivateKey(alias string, privateKey *sm2.PrivateKey) error {


	//fmt.Println("ksgm.pwd",ksgm.pwd)
	//rawKey, err := gmutil.PrivateKeyToPEM(privateKey, ksgm.pwd)
	rawKey, err := gmutil.PrivateKeyToPEM(privateKey, nil)
	//fmt.Println("privateKey",privateKey)

	if err != nil {
		logger.Errorf("Failed converting private key to PEM [%s]: [%s]", alias, err)
		return err
	}

	fmt.Println("执行了storePrivateKey")
	err = ioutil.WriteFile(ksgm.getPathForAlias(alias, "sk"), rawKey, 0600)
	if err != nil {
		logger.Errorf("Failed storing private key [%s]: [%s]", alias, err)
		return err
	}

	return nil
}

func (ksgm *fileBasedGMKeyStore) storePublicKey(alias string, publicKey *sm2.PublicKey) error {
	rawKey, err := gmutil.PublicKeyToPEM(publicKey, ksgm.pwd)
	if err != nil {
		logger.Errorf("Failed converting public key to PEM [%s]: [%s]", alias, err)
		return err
	}

	err = ioutil.WriteFile(ksgm.getPathForAlias(alias, "pk"), rawKey, 0600)
	if err != nil {
		logger.Errorf("Failed storing private key [%s]: [%s]", alias, err)
		return err
	}

	return nil
}



func (ksgm *fileBasedGMKeyStore) loadPrivateKey(alias string) (interface{}, error) {
	path := ksgm.getPathForAlias(alias, "sk")
	logger.Debugf("Loading private key [%s] at [%s]...", alias, path)

	raw, err := ioutil.ReadFile(path)
	if err != nil {
		logger.Errorf("Failed loading private key [%s]: [%s].", alias, err.Error())

		return nil, err
	}

	privateKey, err := gmutil.PEMtoPrivateKey(raw, ksgm.pwd)
	if err != nil {
		logger.Errorf("Failed parsing private key [%s]: [%s].", alias, err.Error())

		return nil, err
	}

	return privateKey, nil
}

func (ksgm *fileBasedGMKeyStore) loadPublicKey(alias string) (interface{}, error) {
	path := ksgm.getPathForAlias(alias, "pk")
	logger.Debugf("Loading public key [%s] at [%s]...", alias, path)

	raw, err := ioutil.ReadFile(path)
	if err != nil {
		logger.Errorf("Failed loading public key [%s]: [%s].", alias, err.Error())

		return nil, err
	}

	privateKey, err := gmutil.PEMtoPublicKey(raw, ksgm.pwd)
	if err != nil {
		logger.Errorf("Failed parsing private key [%s]: [%s].", alias, err.Error())

		return nil, err
	}

	return privateKey, nil
}


func (ksgm *fileBasedGMKeyStore) storeKey(alias string, key []byte) error {
	pem, err := gmutil.SM4toEncryptedPEM(key, ksgm.pwd)
	if err != nil {
		logger.Errorf("Failed converting key to PEM [%s]: [%s]", alias, err)
		return err
	}

	err = ioutil.WriteFile(ksgm.getPathForAlias(alias, "key"), pem, 0600)
	if err != nil {
		logger.Errorf("Failed storing key [%s]: [%s]", alias, err)
		return err
	}

	return nil
}

func (ksgm *fileBasedGMKeyStore) loadKey(alias string) ([]byte, error) {
	path := ksgm.getPathForAlias(alias, "key")
	logger.Debugf("Loading key [%s] at [%s]...", alias, path)

	pem, err := ioutil.ReadFile(path)
	if err != nil {
		logger.Errorf("Failed loading key [%s]: [%s].", alias, err.Error())

		return nil, err
	}

	key, err := gmutil.PEMtoSM4(pem, ksgm.pwd)
	if err != nil {
		logger.Errorf("Failed parsing key [%s]: [%s]", alias, err)

		return nil, err
	}

	return key, nil
}

func (ksgm *fileBasedGMKeyStore) createKeyStoreIfNotExists() error {
	// Check keystore directory
	ksPath := ksgm.path
	missing, err := gmutil.DirMissingOrEmpty(ksPath)

	if missing {
		logger.Debugf("KeyStore path [%s] missing [%t]: [%s]", ksPath, missing, utils.ErrToString(err))

		err := ksgm.createKeyStore()
		if err != nil {
			logger.Errorf("Failed creating KeyStore At [%s]: [%s]", ksPath, err.Error())
			return nil
		}
	}

	return nil
}

func (ksgm *fileBasedGMKeyStore) createKeyStore() error {
	// Create keystore directory root if it doesn't exist yet
	ksPath := ksgm.path
	logger.Debugf("Creating KeyStore at [%s]...", ksPath)

	os.MkdirAll(ksPath, 0755)

	logger.Debugf("KeyStore created at [%s].", ksPath)
	return nil
}

func (ksgm *fileBasedGMKeyStore) openKeyStore() error {
	if ksgm.isOpen {
		return nil
	}
	ksgm.isOpen = true
	logger.Debugf("KeyStore opened at [%s]...done", ksgm.path)

	return nil
}

func (ksgm *fileBasedGMKeyStore) getPathForAlias(alias, suffix string) string {
	return filepath.Join(ksgm.path, alias+"_"+suffix)
}


