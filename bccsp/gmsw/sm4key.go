package gmsw

import (
	"github.com/chinaso/fabricGM/cryptopkg/golangGM/sm3"
	"github.com/chinaso/fabricGM/bccsp"
	"github.com/pkg/errors"
)

type sm4PrivateKey struct {
	privKey []byte
	exportable bool
}


/******************************/
//实现BCCSP的Key接口

func (k *sm4PrivateKey) Bytes() (raw []byte,err error) {
	if k.exportable {
		return k.privKey,nil
	}
	return nil,errors.New("Not supported.")
}

func (k *sm4PrivateKey) SKI() (ski []byte) {
	hash := sm3.New()
	hash.Write([]byte{0x01})
	hash.Write(k.privKey)
	return hash.Sum(nil)
}

func (k *sm4PrivateKey) Symmetric() bool {
	return true
}

func (k *sm4PrivateKey) Private() bool {
	return true
}

func (k *sm4PrivateKey) PublicKey() (bccsp.Key,error) {
	return nil,errors.New("Cannot call this method on a sysmetric key.")
}

