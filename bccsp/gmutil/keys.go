package gmutil

import (
	"encoding/pem"
	"errors"
	"github.com/chinaso/fabricGM/cryptopkg/golangGM/sm2"
	"github.com/chinaso/fabricGM/cryptopkg/golangGM/sm4"
)

// PublicKeyToDER marshals a public key to the der format
func PublicKeyToDER(publicKey *sm2.PublicKey) ([]byte, error) {

	PubASN1, err := sm2.MarshalSM2PublicKey(publicKey)
	if err != nil {
		return nil, err
	}

	return PubASN1, nil
}

// DERToPublicKey unmarshals a der to public key
func DERToPublicKey(raw []byte) (pub *sm2.PublicKey, err error) {
	if len(raw) == 0 {
		return nil, errors.New("Invalid DER. It must be different from nil.")
	}

	key, err := sm2.ParseSM2PublicKey(raw)

	return key, err
}

// DERToPrivateKey unmarshals a der to private key
func DERToPrivateKey(der []byte) (key *sm2.PrivateKey, err error) {



	if key, err =  sm2.ParsePKCS8PrivateKey(der,nil);err == nil {
		//fmt.Println("123eqq")
		return
	}
	if key, err = sm2.ParsePKCS8EcryptedSM2PrivateKey(der,nil); err == nil {
		//fmt.Println("123")
		return
	}

	return nil, errors.New("Invalid key type. The DER must contain an rsa.PrivateKey or ecdsa.PrivateKey")
}





func PrivateKeyToPEM(privateKey *sm2.PrivateKey, pwd []byte) ([]byte, error) {


	if privateKey == nil {
		return nil, errors.New("Invalid key. It must be different from nil.")
	}

	return sm2.WritePrivateKeytoMem(privateKey, pwd)

}

func PEMtoPrivateKey(raw []byte, pwd []byte) (*sm2.PrivateKey, error) {

	priv,err :=sm2.ReadPrivateKeyFromMem(raw,pwd)
	if err !=nil {
		return nil, errors.New("error pem,can not read private key from pem")
	}
	return priv,nil
}

func PublicKeyToPEM(publicKey *sm2.PublicKey, pwd []byte) ([]byte, error) {
	if publicKey == nil {
		return nil, errors.New("Invalid key. It must be different from nil.")
	}
	return sm2.WritePublicKeytoMem(publicKey,pwd)
}

func PEMtoPublicKey(raw []byte, pwd []byte) (*sm2.PublicKey, error) {

	pub,err := sm2.ReadPublicKeyFromMem(raw,pwd)
	if err !=nil {
		return nil, errors.New("error pem,can not read private key from pem")
	}
	return pub,nil

}



// ------------------------------------------- //
func SM4toPEM(raw []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "SM4 PRIVATE KEY", Bytes: raw})
}

// PEMtoAES extracts from the PEM an SM4 key
func PEMtoSM4(raw []byte, pwd []byte) ([]byte, error) {

	sm4key,err := sm4.ReadKeyFromMem(raw,pwd)
	if err != nil {
		return nil, errors.New("Invalid key. It must be different from nil.")
	}
	return sm4key,nil
}


// SM4toEncryptedPEM encapsulates an SM4 key in the encrypted PEM format
func SM4toEncryptedPEM(raw []byte, pwd []byte) ([]byte, error) {
	if len(raw) == 0 {
		return nil, errors.New("Invalid aes key. It must be different from nil")
	}

	return sm4.WriteKeytoMem(raw,pwd)

}