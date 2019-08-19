package tls

import (
	"crypto"
	"fmt"
	"github.com/chinaso/fabricGM/cryptopkg/golangGM/x509"
	"testing"
)

func TestSignatureSelectiongm(t *testing.T) {

	sigsPKCS1WithSHA := []SignatureScheme{PKCS1WithSHA256, PKCS1WithSHA1}
	// ------------------------------------------------------ //
	sm2Cert :=&testSM2PrivateKey.PublicKey
	sigsSM2WithSM3 := []SignatureScheme{SM2WithSM3}


	tests := []struct {
		pubkey      crypto.PublicKey
		peerSigAlgs []SignatureScheme
		ourSigAlgs  []SignatureScheme
		tlsVersion  uint16

		expectedSigAlg  SignatureScheme // or 0 if ignored
		expectedSigType uint8
		expectedHash    x509.Hash
	}{

		{sm2Cert, sigsSM2WithSM3, sigsSM2WithSM3, VersionTLS12, 0, signatureSM2, x509.SM3},


	}
	fmt.Println("test",tests)

	for testNo, test := range tests {
		sigAlg, sigType, hashFunc, err := pickSignatureAlgorithm(test.pubkey, test.peerSigAlgs, test.ourSigAlgs, test.tlsVersion)
		if err != nil {
			t.Errorf("test[%d]: unexpected error: %v", testNo, err)
		}
		if test.expectedSigAlg != 0 && test.expectedSigAlg != sigAlg {
			t.Errorf("test[%d]: expected signature scheme %#x, got %#x", testNo, test.expectedSigAlg, sigAlg)
		}
		if test.expectedSigType != sigType {
			t.Errorf("test[%d]: expected signature algorithm %#x, got %#x", testNo, test.expectedSigType, sigType)
		}

		msg := []byte("test")
		hw := x509.Hash(hashFunc).New()  //只能这么测试
		hw.Write(msg)
		hash := hw.Sum(nil)
		fmt.Println("hash test",hash)
		fmt.Println(hashFunc)
	}

	badTests := []struct {
		pubkey      crypto.PublicKey
		peerSigAlgs []SignatureScheme
		ourSigAlgs  []SignatureScheme
		tlsVersion  uint16
	}{


		// ECDSA is unspecified for SSL 3.0 in RFC 4492.
		// TODO a SSL 3.0 client cannot advertise signature_algorithms,
		// but if an application feeds an ECDSA certificate anyway, it
		// will be accepted rather than trigger a handshake failure. Ok?
		//{ecdsaCert, nil, nil, VersionSSL30},

		{sm2Cert, sigsSM2WithSM3, sigsPKCS1WithSHA, VersionTLS12},
	}

	for testNo, test := range badTests {
		sigAlg, sigType, hashFunc, err := pickSignatureAlgorithm(test.pubkey, test.peerSigAlgs, test.ourSigAlgs, test.tlsVersion)
		if err == nil {
			t.Errorf("test[%d]: unexpected success, got %#x %#x %#x", testNo, sigAlg, sigType, hashFunc)
		}
	}
}


