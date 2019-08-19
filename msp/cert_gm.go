package msp

import (
	"bytes"
	"encoding/asn1"
	"github.com/chinaso/fabricGM/bccsp/gmutil"
	"github.com/chinaso/fabricGM/cryptopkg/golangGM/sm2"
	"github.com/chinaso/fabricGM/cryptopkg/golangGM/x509"
	"github.com/pkg/errors"

)



func isSM2SignedCert(cert *x509.Certificate) bool {
	return cert.SignatureAlgorithm == x509.SM2WithSM3
}

// sanitizeSM2SignedCert checks that the signatures signing a cert
// is in low-S. This is checked against the public key of parentCert.
// If the signature is not in low-S, then a new certificate is generated
// that is equals to cert but the signature that is in low-S.
func sanitizeSM2SignedCert(cert *x509.Certificate, parentCert *x509.Certificate) (*x509.Certificate, error) {
	if cert == nil {
		return nil, errors.New("certificate must be different from nil")
	}
	if parentCert == nil {
		return nil, errors.New("parent certificate must be different from nil")
	}

	//expectedSig, err := utils.SM2SignatureToLowS(parentCert.PublicKey.(*sm2.PublicKey), cert.Signature)
	expectedSig, err := gmutil.SM2SignatureToLowS(parentCert.PublicKey.(*sm2.PublicKey),cert.Signature)

	if err != nil {
		return nil, err
	}

	// if sig == cert.Signature, nothing needs to be done
	if bytes.Equal(cert.Signature, expectedSig) {
		return cert, nil
	}
	// otherwise create a new certificate with the new signature

	// 1. Unmarshal cert.Raw to get an instance of certificate,
	//    the lower level interface that represent an x509 certificate
	//    encoding
	var newCert certificate
	newCert, err = certFromgmX509Cert(cert)
	if err != nil {
		return nil, err
	}

	// 2. Change the signature
	newCert.SignatureValue = asn1.BitString{Bytes: expectedSig, BitLength: len(expectedSig) * 8}

	// 3. marshal again newCert. Raw must be nil
	newCert.Raw = nil
	newRaw, err := asn1.Marshal(newCert)
	if err != nil {
		return nil, errors.Wrap(err, "marshalling of the certificate failed")
	}

	// 4. parse newRaw to get an x509 certificate
	return x509.ParseCertificate(newRaw)
}

func certFromgmX509Cert(cert *x509.Certificate) (certificate, error) {
	var newCert certificate
	_, err := asn1.Unmarshal(cert.Raw, &newCert)
	if err != nil {
		return certificate{}, errors.Wrap(err, "unmarshalling of the certificate failed")
	}
	return newCert, nil
}



// certToPEM converts the given x509.Certificate to a PEM
// encoded string
func certTogmPEM(certificate *x509.Certificate) string {
	cert, err := certFromgmX509Cert(certificate)
	if err != nil {
		mspIdentityLogger.Warning("Failed converting certificate to asn1", err)
		return ""
	}
	return cert.String()
}

