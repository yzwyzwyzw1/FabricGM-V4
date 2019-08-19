package gmsw

import (
	"fmt"
	"github.com/chinaso/fabricGM/bccsp"
	"github.com/chinaso/fabricGM/cryptopkg/golangGM/sm2"
	"github.com/chinaso/fabricGM/cryptopkg/golangGM/sm3"

	"github.com/pkg/errors"
)


//type SM2PrivateKey struct {
//	SM2PrivateKey  sm2PrivateKey
//}

type sm2PrivateKey struct {
	privKey *sm2.PrivateKey
}


//type sm2P256V1 struct {
//	sm2P256v1 sm2.P256V1Curve
//}
//
//func (k *sm2P256V1) Bytes() ([]byte, error) {
//	k.sm2P256v1
//	return nil,errors.New()
//}


// Bytes converts this key to its byte representation,
// if this operation is allowed.
func (k *sm2PrivateKey) Bytes() ([]byte,error) {
	return nil,errors.New("Not supported")
}


// SKI returns the subject key identifier of this key.
func (k *sm2PrivateKey) SKI() []byte {
	if k.privKey == nil {
		return nil
	}

	// Marshall the public key
	//raw := elliptic.Marshal(k.privKey.Curve,k.privKey.PublicKey.X, k.privKey.PublicKey.Y)
    //raw := k.privKey.GetRawBytes()
	raw,_ := sm2.MarshalSM2PrivateKey(k.privKey,nil)
	// Hash it
	hash := sm3.New()
	hash.Write(raw)
	return hash.Sum(nil)
}


func (k *sm2PrivateKey) Symmetric() bool {
	return false
}

func (k *sm2PrivateKey) Private() bool {
	return true
}

func (k *sm2PrivateKey) PublicKey() (bccsp.Key,error) {
	return &sm2PublicKey{&k.privKey.PublicKey},nil
}




type sm2PublicKey struct {
	pubKey *sm2.PublicKey
}


func (k *sm2PublicKey) Bytes() (raw []byte,err error) {
	//
	// raw,err = x509.MarshalPKIXPublicKey(k.pubKey)
	raw,err = sm2.MarshalSM2PublicKey(k.pubKey)
	if err != nil {
		return nil,fmt.Errorf("Failed marshalling key [%s]",err)
	}
	return
}

func (k *sm2PublicKey) SKI() []byte {
	if k.pubKey == nil {
		return nil
	}
	//raw := elliptic.Marshal(k.pubKey.Curve,k.pubKey.X,k.pubKey.Y)
	raw,_ := sm2.MarshalSM2PublicKey(k.pubKey)
	//raw := k.pubKey.GetRawBytes()
	hash := sm3.New()
	hash.Write(raw)
	return hash.Sum(nil)
}



func (k *sm2PublicKey) Symmetric() bool {
	return false
}

func (k *sm2PublicKey) Private() bool {
	return false
}

func (k *sm2PublicKey) PublicKey() (bccsp.Key,error) {
	return k,nil
}