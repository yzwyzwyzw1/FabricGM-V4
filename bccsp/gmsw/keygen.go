package gmsw

import (
	"crypto/elliptic"
	"crypto/rand"
	"github.com/chinaso/fabricGM/cryptopkg/golangGM/sm2"
	"fmt"
	"github.com/chinaso/fabricGM/bccsp"
)

type sm2KeyGenerator struct {
	curve elliptic.Curve
}

func (kg *sm2KeyGenerator) KeyGen(opts bccsp.KeyGenOpts) (bccsp.Key, error) {
	privKey, err := sm2.GenerateKey(rand.Reader)

//	fmt.Println("trace1")
	if err != nil {
		return nil, fmt.Errorf("Failed generating SM2 key for [%v]: [%s]", kg.curve, err)
	}

	return &sm2PrivateKey{privKey}, nil
}





type sm4KeyGenerator struct {
	length int
}

func (kg *sm4KeyGenerator) KeyGen(opts bccsp.KeyGenOpts) (bccsp.Key, error) {
	lowLevelKey, err := GetRandomBytes(int(kg.length))
	if err != nil {
		return nil, fmt.Errorf("Failed generating SM4 %d key [%s]", kg.length, err)
	}

	return &sm4PrivateKey{lowLevelKey, false}, nil
}




