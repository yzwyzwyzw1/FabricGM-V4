/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package handlers

import (
	"crypto/elliptic"
	"encoding/pem"
	"fmt"
	"github.com/chinaso/fabricGM/bccsp"
	"github.com/chinaso/fabricGM/cryptopkg/golangGM/sm2"
	"github.com/chinaso/fabricGM/cryptopkg/golangGM/sm3"
	"github.com/pkg/errors"
)

// gmrevocationSecretKey contains the revocation secret key
// and implements the bccsp.Key interface
type gmrevocationSecretKey struct {
	// sk is the idemix reference to the revocation key
	privKey *sm2.PrivateKey
	// exportable if true, sk can be exported via the Bytes function
	exportable bool
}


// Bytes converts this key to its byte representation,
// if this operation is allowed.
func (k *gmrevocationSecretKey) Bytes() ([]byte, error) {
	if k.exportable {
		return k.privKey.D.Bytes(), nil
	}

	return nil, errors.New("not exportable")
}

// SKI returns the subject key identifier of this key.
func (k *gmrevocationSecretKey) SKI() []byte {
	// Marshall the public key
	raw := elliptic.Marshal(k.privKey.Curve, k.privKey.PublicKey.X, k.privKey.PublicKey.Y)

	// Hash it
	hash := sm3.New()
	hash.Write(raw)
	return hash.Sum(nil)
}

// Symmetric returns true if this key is a symmetric key,
// false if this key is asymmetric
func (k *gmrevocationSecretKey) Symmetric() bool {
	return false
}

// Private returns true if this key is a private key,
// false otherwise.
func (k *gmrevocationSecretKey) Private() bool {
	return true
}

// PublicKey returns the corresponding public key part of an asymmetric public/private key pair.
// This method returns an error in symmetric key schemes.
func (k *gmrevocationSecretKey) PublicKey() (bccsp.Key, error) {
	return &gmrevocationPublicKey{&k.privKey.PublicKey}, nil
}

type gmrevocationPublicKey struct {
	pubKey *sm2.PublicKey
}


// Bytes converts this key to its byte representation,
// if this operation is allowed.
func (k *gmrevocationPublicKey) Bytes() (raw []byte, err error) {

	raw, err = sm2.MarshalSM2PublicKey(k.pubKey)
	if err != nil {
		return nil, fmt.Errorf("Failed marshalling key [%s]", err)
	}
	return
}

// SKI returns the subject key identifier of this key.
func (k *gmrevocationPublicKey) SKI() []byte {
	// Marshall the public key


	raw := elliptic.Marshal(k.pubKey.Curve, k.pubKey.X, k.pubKey.Y)

	// Hash it
	hash := sm3.New()
	hash.Write(raw)
	return hash.Sum(nil)
}

// Symmetric returns true if this key is a symmetric key,
// false if this key is asymmetric
func (k *gmrevocationPublicKey) Symmetric() bool {
	return false
}

// Private returns true if this key is a private key,
// false otherwise.
func (k *gmrevocationPublicKey) Private() bool {
	return false
}

// PublicKey returns the corresponding public key part of an asymmetric public/private key pair.
// This method returns an error in symmetric key schemes.
func (k *gmrevocationPublicKey) PublicKey() (bccsp.Key, error) {
	return k, nil
}

//// GMRevocationKeyGen generates revocation secret keys.
//type GMRevocationKeyGen struct {
//	// exportable is a flag to allow an revocation secret key to be marked as exportable.
//	// If a secret key is marked as exportable, its Bytes method will return the key's byte representation.
//	Exportable bool
//	// Revocation implements the underlying cryptographic algorithms
//	Revocation Revocation
//}
//
//func (g *GMRevocationKeyGen) KeyGen(opts bccsp.KeyGenOpts) (bccsp.Key, error) {
//	// Create a new key pair
//
//	hashType := "sm3"
//	key, err := g.Revocation.NewKey(hashType)
//	if err != nil {
//		return nil, err
//	}
//
//	return &gmrevocationSecretKey{exportable: g.Exportable, privKey: key}, nil
//}

// GMRevocationPublicKeyImporter imports revocation public keys
type GMRevocationPublicKeyImporter struct {
}

func (i *GMRevocationPublicKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (k bccsp.Key, err error) {
	der, ok := raw.([]byte)
	if !ok {
		return nil, errors.New("invalid raw, expected byte array")
	}

	if len(der) == 0 {
		return nil, errors.New("invalid raw, it must not be nil")
	}

	blockPub, _ := pem.Decode(raw.([]byte))
	if blockPub == nil {
		return nil, errors.New("Failed to decode revocation SM2 public key")
	}

	revocationPk, err := sm2.ParseSM2PublicKey(blockPub.Bytes)
	sm2PublicKey := revocationPk
	//revocationPk, err := x509.ParsePKIXPublicKey(blockPub.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to parse revocation SM2 public key bytes")
	}
	return &gmrevocationPublicKey{sm2PublicKey}, nil
}
	//ecdsaPublicKey, isECDSA := revocationPk
	//if !isECDSA {
	//	return nil, errors.Errorf("key is of type %v, not of type SM2", reflect.TypeOf(revocationPk))
	//}
	//return &gmrevocationPublicKey{ecdsaPublicKey}, nil
//}

//type GMCriSigner struct {
//	Revocation Revocation  // !!!
//}
//
//func (s *GMCriSigner) Sign(k bccsp.Key, digest []byte, opts bccsp.SignerOpts) ([]byte, error) {
//	gmrevocationSecretKey, ok := k.(*gmrevocationSecretKey)
//	if !ok {
//		return nil, errors.New("invalid key, expected *gmrevocationSecretKey")
//	}
//	criOpts, ok := opts.(*bccsp.IdemixCRISignerOpts)
//	if !ok {
//		return nil, errors.New("invalid options, expected *IdemixCRISignerOpts")
//	}
//
//	return s.Revocation.Sign(
//		gmrevocationSecretKey.privKey,
//		criOpts.UnrevokedHandles,
//		criOpts.Epoch,
//		criOpts.RevocationAlgorithm,
//	)
//}
//
//type GMCriVerifier struct {
//	Revocation Revocation
//}
//
//func (v *GMCriVerifier) Verify(k bccsp.Key, signature, digest []byte, opts bccsp.SignerOpts) (bool, error) {
//	gmrevocationPublicKey, ok := k.(*gmrevocationPublicKey)
//	if !ok {
//		return false, errors.New("invalid key, expected *gmrevocationPublicKey")
//	}
//	criOpts, ok := opts.(*bccsp.IdemixCRISignerOpts)
//	if !ok {
//		return false, errors.New("invalid options, expected *IdemixCRISignerOpts")
//	}
//	if len(signature) == 0 {
//		return false, errors.New("invalid signature, it must not be empty")
//	}
//
//	err := v.Revocation.Verify(
//		gmrevocationPublicKey.pubKey,
//		signature,
//		criOpts.Epoch,
//		criOpts.RevocationAlgorithm,
//	)
//	if err != nil {
//		return false, err
//	}
//
//	return true, nil
//}
