package gmsw

import (
	"crypto/elliptic"
	"fmt"
	"github.com/chinaso/fabricGM/cryptopkg/golangGM/sm2"
	"github.com/chinaso/fabricGM/cryptopkg/golangGM/sm3"
	"hash"
)

type config struct {
	ellipticCurve elliptic.Curve
	hashFunction  func() hash.Hash
	aesBitLength  int
	rsaBitLength  int
}

func (conf *config) setSecurityLevel(securityLevel int, hashFamily string) (err error) {

	if hashFamily =="SM3" {
		err = conf.setSecurityLevelSM3(securityLevel)
	}else{
		err = fmt.Errorf("Hash Family not supported [%s]", hashFamily)
	}
	return

}

func (conf *config) setSecurityLevelSM3(level int) (err error) {

	if level== 256 {

		conf.ellipticCurve = sm2.SM2P256()
		conf.hashFunction = sm3.New
		conf.rsaBitLength = 2048
		conf.aesBitLength = 16
	}

	return
}

