/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package csp

import (
	"crypto"
	"encoding/pem"
	//"fmt"
	//"github.com/chinaso/fabricGM/bccsp/gmsw"
	"github.com/chinaso/fabricGM/cryptopkg/golangGM/sm2"

	//"github.com/chinaso/fabricGM/cryptopkg/golangGM/sm2"
	"github.com/pkg/errors"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/chinaso/fabricGM/bccsp"
	"github.com/chinaso/fabricGM/bccsp/factory"
	"github.com/chinaso/fabricGM/bccsp/gmsigner"
)

// LoadPrivateKey loads a private key from file in keystorePath
func LoadPrivateKey(keystorePath string) (bccsp.Key, crypto.Signer, error) {
	var err error
	var priv bccsp.Key
	var s crypto.Signer

	opts := &factory.FactoryOpts{
		ProviderName: "GMSW",
		SwOpts: &factory.SwOpts{
			HashFamily: "SM3",
			SecLevel:   256,

			FileKeystore: &factory.FileKeystoreOpts{
				KeyStorePath: keystorePath,
			},
		},
	}

	csp, err := factory.GetBCCSPFromOpts(opts)
	if err != nil {
		return nil, nil, err
	}


	walkFunc := func(path string, info os.FileInfo, err error) error {
		if strings.HasSuffix(path, "_sk") {

			rawKey, err := ioutil.ReadFile(path)
			if err != nil {
				return err
			}
			//fmt.Println("rawKey",rawKey)

			block, _ := pem.Decode(rawKey)
			if block == nil {
				return errors.Errorf("%s: wrong PEM encoding", path)
			}

			//fmt.Println("block",block.Bytes)
			priv, err = csp.KeyImport(block.Bytes, &bccsp.SM2PrivateKeyImportOpts{Temporary: true})
			if err != nil {
				return err
			}
			//fmt.Println("priv123",priv)
			s, err = gmsigner.New(csp, priv)
			if err != nil {
				return err
			}

			return nil
		}
		return nil
	}

	err = filepath.Walk(keystorePath, walkFunc)
	if err != nil {
		return nil, nil, err
	}

	return priv, s, err
}

// GeneratePrivateKey creates a private key and stores it in keystorePath
func GeneratePrivateKey(keystorePath string) (bccsp.Key,
	crypto.Signer, error) {

	var err error
	var priv bccsp.Key
	var s crypto.Signer

	opts := &factory.FactoryOpts{
		ProviderName: "GMSW",
		SwOpts: &factory.SwOpts{
			HashFamily: "SM3",
			SecLevel:   256,

			FileKeystore: &factory.FileKeystoreOpts{
				KeyStorePath: keystorePath,
			},
		},
	}
	csp, err := factory.GetBCCSPFromOpts(opts)

    //这个CSP也可能存在问题

	if err == nil {
		// generate a key
		priv, err = csp.KeyGen(&bccsp.SM2KeyGenOpts{Temporary: false})


		//privsk:= gmsw.GetSM2PrivKey(priv)
		//fmt.Println("privsk11",privsk)

		if err == nil {
			// create a crypto.Signer
			s, err = gmsigner.New(csp, priv)
		}
	}

	//return sm2sk, s, err
	return priv, s, err
}

func GetSM2PublicKey(priv bccsp.Key) (*sm2.PublicKey, error) {

	// get the public key
	pubKey, err := priv.PublicKey()
	if err != nil {
		return nil, err
	}
	// marshal to bytes
	pubKeyBytes, err := pubKey.Bytes()
	if err != nil {
		return nil, err
	}

	// unmarshal using pkix
	//sm2PubKey, err := x509.ParsePKIXPublicKey(pubKeyBytes)
	sm2PubKey,err :=sm2.ParseSM2PublicKey(pubKeyBytes)
	if err != nil {
		return nil, err
	}
	return sm2PubKey, nil
}
