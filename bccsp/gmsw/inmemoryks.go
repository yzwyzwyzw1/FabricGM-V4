package gmsw

import (
	"encoding/hex"
	"github.com/chinaso/fabricGM/bccsp"
	"github.com/pkg/errors"
	"sync"
)

// NewInMemoryGMKeyStore instantiates an ephemeral in-memory keystore
func NewInMemoryGMKeyStore() bccsp.KeyStore {
	eks := &inmemoryGMKeyStore{}
	eks.keys = make(map[string]bccsp.Key)
	return eks
}

type inmemoryGMKeyStore struct {
	// keys maps the hex-encoded SKI to keys
	keys map[string]bccsp.Key
	m    sync.RWMutex
}

// ReadOnly returns false - the key store is not read-only
func (ksgm *inmemoryGMKeyStore) ReadOnly() bool {
	return false
}

// GetKey returns a key object whose SKI is the one passed.
func (ksgm *inmemoryGMKeyStore) GetKey(ski []byte) (bccsp.Key, error) {
	if len(ski) == 0 {
		return nil, errors.New("ski is nil or empty")
	}

	skiStr := hex.EncodeToString(ski)

	ksgm.m.RLock()
	defer ksgm.m.RUnlock()
	if key, found := ksgm.keys[skiStr]; found {
		return key, nil
	}
	return nil, errors.Errorf("no key found for ski %x", ski)
}

// StoreKey stores the key k in this KeyStore.
func (ksgm *inmemoryGMKeyStore) StoreKey(k bccsp.Key) error {
	if k == nil {
		return errors.New("key is nil")
	}

	ski := hex.EncodeToString(k.SKI())

	ksgm.m.Lock()
	defer ksgm.m.Unlock()

	if _, found := ksgm.keys[ski]; found {
		return errors.Errorf("ski %x already exists in the keystore", k.SKI())
	}
	ksgm.keys[ski] = k

	return nil
}
