package x509

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/chinaso/fabricGM/cryptopkg/golangGM/sm2"
	"io/ioutil"
	"os"
)

func CreateCertificateToPem(FileName string, template, parent *Certificate,  privKey *sm2.PrivateKey) (bool, error) {
	der, err := CreateCertificate(rand.Reader, template, parent, &privKey.PublicKey,privKey)

	fmt.Println("der",hex.EncodeToString(der))
	if err != nil {
		return false, err
	}
	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: der,
	}
	file, err := os.Create(FileName)
	if err != nil {
		return false, err
	}
	defer file.Close()
	err = pem.Encode(file, block)
	if err != nil {
		return false, err
	}
	return true, nil
}


func ReadCertificateRequestFromMem(data []byte) (*CertificateRequest, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("failed to decode certificate request")
	}
	return ParseCertificateRequest(block.Bytes)
}

func ReadCertificateRequestFromPem(FileName string) (*CertificateRequest, error) {
	data, err := ioutil.ReadFile(FileName)
	if err != nil {
		return nil, err
	}
	return ReadCertificateRequestFromMem(data)
}

func CreateCertificateRequestToMem(template *CertificateRequest, privKey *sm2.PrivateKey) ([]byte, error) {
	der, err := CreateCertificateRequest(rand.Reader, template, privKey)
	if err != nil {
		return nil, err
	}
	block := &pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: der,
	}
	return pem.EncodeToMemory(block), nil
}

func CreateCertificateRequestToPem(FileName string, template *CertificateRequest,
	privKey *sm2.PrivateKey) (bool, error) {
	der, err := CreateCertificateRequest(rand.Reader, template, privKey)

	fmt.Println("der",hex.EncodeToString(der))
	if err != nil {
		return false, err
	}
	block := &pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: der,
	}
	file, err := os.Create(FileName)
	if err != nil {
		return false, err
	}
	defer file.Close()
	err = pem.Encode(file, block)
	if err != nil {
		return false, err
	}
	return true, nil
}

func ReadCertificateFromMem(data []byte) (*Certificate, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("failed to decode certificate request")
	}
	return ParseCertificate(block.Bytes)
}

func ReadCertificateFromPem(FileName string) (*Certificate, error) {
	data, err := ioutil.ReadFile(FileName)
	if err != nil {
		return nil, err
	}
	return ReadCertificateFromMem(data)
}

func CreateCertificateToMem(template, parent *Certificate, pubKey *sm2.PublicKey, privKey *sm2.PrivateKey) ([]byte, error) {
	der, err := CreateCertificate(rand.Reader, template, parent, pubKey,privKey)
	if err != nil {
		return nil, err
	}
	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: der,
	}
	return pem.EncodeToMemory(block), nil
}
