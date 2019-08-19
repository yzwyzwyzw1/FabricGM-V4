/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package bridge

import (
	"crypto/ecdsa"
	"github.com/chinaso/fabricGM/cryptopkg/golangGM/sm2"
	"strings"

	"github.com/chinaso/fabricGM/bccsp"
	cryptolib "github.com/chinaso/fabricGM/idemix"
	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric-amcl/amcl/FP256BN"
	"github.com/pkg/errors"
)

// Revocation encapsulates the idemix algorithms for revocation
type Revocation struct {
}

// NewKey generate a new revocation key-pair.
//func (*Revocation) NewKey(keyType string) (*ecdsa.PrivateKey, error) {
func (*Revocation) NewKey(keyType string) (interface{}, error) {
	if strings.Compare(keyType,"ecdsaPriv")==0 {
		return cryptolib.GenerateLongTermRevocationKey("ecdsaPriv")
	}else if strings.Compare(keyType,"sm2Priv")==0 {
		return cryptolib.GenerateLongTermRevocationKey("sm2Priv")
	}else {
		return nil ,errors.Errorf("Error Private Type")
	}

}

// Sign generates a new CRI with the respect to the passed unrevoked handles, epoch, and revocation algorithm.
//func (*Revocation) Sign(key *ecdsa.PrivateKey, unrevokedHandles [][]byte, epoch int, alg bccsp.RevocationAlgorithm) (res []byte, err error) {
func (*Revocation) Sign(keyType interface{}, unrevokedHandles [][]byte, epoch int, alg bccsp.RevocationAlgorithm) (res []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			res = nil
			err = errors.Errorf("failure [%s]", r)
		}
	}()


	handles := make([]*FP256BN.BIG, len(unrevokedHandles))
	for i := 0; i < len(unrevokedHandles); i++ {
		handles[i] = FP256BN.FromBytes(unrevokedHandles[i])
	}

	switch keyType.(type) {
	case *ecdsa.PrivateKey:
		key :=keyType.(*ecdsa.PrivateKey)
		cri, err := cryptolib.CreateCRI(key, handles, epoch, cryptolib.RevocationAlgorithm(alg), NewRandOrPanic())
		//fmt.Println("111yzw222")
		//cri, err := cryptolib.CreateCRI(keyType, handles, epoch, cryptolib.RevocationAlgorithm(alg), NewRandOrPanic())

		if err != nil {
			return nil, errors.WithMessage(err, "failed creating CRI")
		}
		return proto.Marshal(cri)
	case *sm2.PrivateKey:

		key :=keyType.(*sm2.PrivateKey)
		cri, err := cryptolib.CreateCRI(key, handles, epoch, cryptolib.RevocationAlgorithm(alg), NewRandOrPanic())
		if err != nil {
			return nil, errors.WithMessage(err, "failed creating CRI")
		}

		return proto.Marshal(cri)
	default:
	//	key :=keyType.(*ecdsa.PrivateKey)
		//fmt.Println("111yzw222")

		//cri, err := cryptolib.CreateCRI(key, handles, epoch, cryptolib.RevocationAlgorithm(alg), NewRandOrPanic())
		cri, err := cryptolib.CreateCRI(keyType, handles, epoch, cryptolib.RevocationAlgorithm(alg), NewRandOrPanic())

		if err != nil {
			return nil, errors.WithMessage(err, "failed creating CRI")
		}

		return proto.Marshal(cri)
	}

}

// Verify checks that the passed serialised CRI (criRaw) is valid with the respect to the passed revocation public key,
// epoch, and revocation algorithm.
//func (*Revocation) Verify(pk *ecdsa.PublicKey, criRaw []byte, epoch int, alg bccsp.RevocationAlgorithm) (err error) {
func (*Revocation) Verify(pkType interface{}, criRaw []byte, epoch int, alg bccsp.RevocationAlgorithm) (err error) {


	defer func() {
		if r := recover(); r != nil {
			err = errors.Errorf("failure [%s]", r)
		}
	}()


	cri := &cryptolib.CredentialRevocationInformation{}
	err = proto.Unmarshal(criRaw, cri)
	if err != nil {
		return err
	}

	switch pkType.(type) {
	case *sm2.PrivateKey:
		pk:=pkType.(*sm2.PublicKey)
		return cryptolib.VerifyEpochPK(
			pk,
			cri.EpochPk,
			cri.EpochPkSig,
			int(cri.Epoch),
			cryptolib.RevocationAlgorithm(cri.RevocationAlg),
		)
	case *ecdsa.PublicKey:

		pk:=pkType.(*ecdsa.PublicKey)
		return cryptolib.VerifyEpochPK(
			pk,
			cri.EpochPk,
			cri.EpochPkSig,
			int(cri.Epoch),
			cryptolib.RevocationAlgorithm(cri.RevocationAlg),
		)
	default:
		return cryptolib.VerifyEpochPK(
			pkType,
			cri.EpochPk,
			cri.EpochPkSig,
			int(cri.Epoch),
			cryptolib.RevocationAlgorithm(cri.RevocationAlg),
		)

	}
}
