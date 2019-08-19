/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package idemix

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"github.com/chinaso/fabricGM/bccsp/gmutil"
	"github.com/chinaso/fabricGM/cryptopkg/golangGM/sm2"
	"github.com/chinaso/fabricGM/cryptopkg/golangGM/sm3"

	"strings"

	"github.com/chinaso/fabricGM/bccsp/utils"
	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric-amcl/amcl"
	"github.com/hyperledger/fabric-amcl/amcl/FP256BN"
	"github.com/pkg/errors"
)

type RevocationAlgorithm int32

const (
	ALG_NO_REVOCATION RevocationAlgorithm = iota
)

var ProofBytes = map[RevocationAlgorithm]int{
	ALG_NO_REVOCATION: 0,
}

// GenerateLongTermRevocationKey generates a long term signing key that will be used for revocation
//func GenerateLongTermRevocationKey() (*ecdsa.PrivateKey, error) {
func GenerateLongTermRevocationKey(keyType string) (interface{}, error) {

	if strings.Compare(keyType,"ecdsaPriv")==0{
		return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	}else if strings.Compare(keyType,"sm2Priv")==0{
		return  sm2.GenerateKey(rand.Reader)
	}else {
		return nil,errors.Errorf("The Name of the Private Key Type")
	}


}

// CreateCRI creates the Credential Revocation Information for a certain time period (epoch).
// Users can use the CRI to prove that they are not revoked.
// Note that when not using revocation (i.e., alg = ALG_NO_REVOCATION), the entered unrevokedHandles are not used,
// and the resulting CRI can be used by any signer.
//func CreateCRI(key *ecdsa.PrivateKey, unrevokedHandles []*FP256BN.BIG, epoch int, alg RevocationAlgorithm, rng *amcl.RAND) (*CredentialRevocationInformation, error) {
func CreateCRI(keyType interface{} , unrevokedHandles []*FP256BN.BIG, epoch int, alg RevocationAlgorithm, rng *amcl.RAND) (*CredentialRevocationInformation, error) {
	if keyType == nil || rng == nil {
		return nil, errors.Errorf("CreateCRI received nil input")
	}
	switch keyType.(type) {
	case *ecdsa.PrivateKey:

		key:=keyType.(*ecdsa.PrivateKey)
		fmt.Println("key",key)
		//if key == nil || rng == nil {
		//	return nil, errors.Errorf("CreateCRI received nil input")
		//}
		cri := &CredentialRevocationInformation{}
		cri.RevocationAlg = int32(alg)
		cri.Epoch = int64(epoch)

		if alg == ALG_NO_REVOCATION {
			// put a dummy PK in the proto
			cri.EpochPk = Ecp2ToProto(GenG2)
		} else {
			// create epoch key
			_, epochPk := WBBKeyGen(rng)
			cri.EpochPk = Ecp2ToProto(epochPk)
		}

		// sign epoch + epoch key with long term key
		bytesToSign, err := proto.Marshal(cri)
		if err != nil {
			return nil, errors.Wrap(err, "failed to marshal CRI")
		}

		digest := sha256.Sum256(bytesToSign)

		cri.EpochPkSig, err = key.Sign(rand.Reader, digest[:], nil)
		if err != nil {
			return nil, err
		}

		if alg == ALG_NO_REVOCATION {
			return cri, nil
		} else {
			return nil, errors.Errorf("the specified revocation algorithm is not supported.")
		}
	case *sm2.PrivateKey:
		key := keyType.(*sm2.PrivateKey)
		//if key == nil || rng == nil {
		//	return nil, errors.Errorf("CreateCRI received nil input")
		//}
		cri := &CredentialRevocationInformation{}
		cri.RevocationAlg = int32(alg)
		cri.Epoch = int64(epoch)

		if alg == ALG_NO_REVOCATION {
			// put a dummy PK in the proto
			cri.EpochPk = Ecp2ToProto(GenG2)
		} else {
			// create epoch key
			_, epochPk := WBBKeyGen(rng)
			cri.EpochPk = Ecp2ToProto(epochPk)
		}

		// sign epoch + epoch key with long term key
		bytesToSign, err := proto.Marshal(cri)
		if err != nil {
			return nil, errors.Wrap(err, "failed to marshal CRI")
		}

		digest := sm3.Sum(bytesToSign)

		cri.EpochPkSig, err = key.Sign(rand.Reader, digest[:], nil)
		if err != nil {
			return nil, err
		}

		if alg == ALG_NO_REVOCATION {
			return cri, nil
		} else {
			return nil, errors.Errorf("the specified revocation algorithm is not supported.")
		}
	default:
		key:=keyType.(*ecdsa.PrivateKey)
		fmt.Println("key",key)
		return nil,errors.Errorf("The Type of Private Key is error!")
	}

}

// VerifyEpochPK verifies that the revocation PK for a certain epoch is valid,
// by checking that it was signed with the long term revocation key.
// Note that even if we use no revocation (i.e., alg = ALG_NO_REVOCATION), we need
// to verify the signature to make sure the issuer indeed signed that no revocation
// is used in this epoch.
//func VerifyEpochPK(pk *ecdsa.PublicKey, epochPK *ECP2, epochPkSig []byte, epoch int, alg RevocationAlgorithm) error {
func VerifyEpochPK(pkType interface{}, epochPK *ECP2, epochPkSig []byte, epoch int, alg RevocationAlgorithm) error {

	if pkType == nil || epochPK == nil {
		return errors.Errorf("EpochPK invalid: received nil input")
	}
	switch pkType.(type) {
	case *ecdsa.PublicKey:
		pk:=pkType.(*ecdsa.PublicKey)
		//if pk == nil || epochPK == nil {
		//	return errors.Errorf("EpochPK invalid: received nil input")
		//}
		cri := &CredentialRevocationInformation{}
		cri.RevocationAlg = int32(alg)
		cri.EpochPk = epochPK
		cri.Epoch = int64(epoch)
		bytesToSign, err := proto.Marshal(cri)
		if err != nil {
			return err
		}
		digest := sha256.Sum256(bytesToSign)

		r, s, err := utils.UnmarshalECDSASignature(epochPkSig)
		if err != nil {
			return errors.Wrap(err, "failed to unmarshal ECDSA signature")
		}

		if !ecdsa.Verify(pk, digest[:], r, s) {
			return errors.Errorf("EpochPKSig invalid")
		}

		return nil
	case *sm2.PublicKey:
		pk:=pkType.(*sm2.PublicKey)
		//if pk == nil || epochPK == nil {
		//	return errors.Errorf("EpochPK invalid: received nil input")
		//}
		cri := &CredentialRevocationInformation{}
		cri.RevocationAlg = int32(alg)
		cri.EpochPk = epochPK
		cri.Epoch = int64(epoch)
		bytesToSign, err := proto.Marshal(cri)
		if err != nil {
			return err
		}
		digest := sm3.Sum(bytesToSign)

		r, s, err := gmutil.UnmarshalSM2Signature(epochPkSig)
		if err != nil {
			return errors.Wrap(err, "failed to unmarshal ECDSA signature")
		}

		if !sm2.SM2Verify(pk, digest[:],nil, r, s) {
			return errors.Errorf("EpochPKSig invalid")
		}
	default:
		return errors.Errorf("Error Public Key Type!")

	}

    return errors.Errorf("Error Public Key Type!")

}
