package tls

import (
	"crypto"
	"crypto/elliptic"
	"errors"
	"fmt"
	"github.com/chinaso/fabricGM/cryptopkg/golangGM/sm2"
	"github.com/chinaso/fabricGM/cryptopkg/golangGM/x509"
	"golang.org/x/crypto/curve25519"
	"io"
	"math/big"
)

// SM2heKeyAgreement implements a TLS key agreement where the server
// generates an ephemeral EC public/private key pair and signs it. The
// pre-master secret is then calculated using SM2.


type ecdheSM2KeyAgreement struct {
	version    uint16

	privateKey []byte
	curveid    CurveID
	isRSA      bool
	// publicKey is used to store the peer's public value when X25519 is
	// being used.
	publicKey []byte
	// x and y are used to store the peer's public value when one of the
	// NIST curves is being used.
	x, y *big.Int
}


func (ka *ecdheSM2KeyAgreement) generateServerKeyExchange(config *Config, cert *Certificate, clientHello *clientHelloMsg, hello *serverHelloMsg) (*serverKeyExchangeMsg, error) {
	preferredCurves := config.curvePreferences()

NextCandidate:
	for _, candidate := range preferredCurves {
		for _, c := range clientHello.supportedCurves {
			if candidate == c {
				ka.curveid = c
				break NextCandidate
			}
		}
	}

	if ka.curveid == 0 {
		return nil, errors.New("tls: no supported elliptic curves offered")
	}

	var sm2hePublic []byte

	if ka.curveid == X25519 {
		var scalar, public [32]byte
		if _, err := io.ReadFull(config.rand(), scalar[:]); err != nil {
			return nil, err
		}

		curve25519.ScalarBaseMult(&public, &scalar)
		ka.privateKey = scalar[:]
		sm2hePublic = public[:]
	} else {//我可以选择不传入X25519的曲线ID而是传入 CureP256SM2
		curve, ok := curveForCurveID(ka.curveid)
		if !ok {
			return nil, errors.New("tls: preferredCurves includes unsupported curve")
		}
		fmt.Println("curve",curve)

	//	var x, y *big.Int
		var err error
		//生成密钥
		sm2privkey, err := sm2.GenerateKey(config.rand())
		if err != nil {
			return nil, err
		}
		ka.privateKey,err =sm2.MarshalSM2PrivateKey(sm2privkey,nil)
		if err != nil {
			return nil, err
		}
		sm2hePublic,err = sm2.MarshalSM2PublicKey(&sm2privkey.PublicKey)
		//ecdhePublic = elliptic.Marshal(curve, x, y)

		//ka.privateKey, x, y, err = elliptic.GenerateKey(curve, config.rand())
		//if err != nil {
		//	return nil, err
		//}
		//ecdhePublic = elliptic.Marshal(curve, x, y)
	}

	// https://tools.ietf.org/html/rfc4492#section-5.4
	serverECDHParams := make([]byte, 1+2+1+len(sm2hePublic))
	serverECDHParams[0] = 3 // named curve
	serverECDHParams[1] = byte(ka.curveid >> 8)
	serverECDHParams[2] = byte(ka.curveid)
	serverECDHParams[3] = byte(len(sm2hePublic))
	copy(serverECDHParams[4:], sm2hePublic)

	priv, ok := cert.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, errors.New("tls: certificate private key does not implement crypto.Signer")
	}

	signatureAlgorithm, sigType, hashFunc, err := pickSignatureAlgorithm(priv.Public(), clientHello.supportedSignatureAlgorithms, supportedSignatureAlgorithms, ka.version)
	if err != nil {
		return nil, err
	}
	//if (sigType == signaturePKCS1v15 || sigType == signatureRSAPSS) != ka.isRSA {
	//	return nil, errors.New("tls: certificate cannot be used with the selected cipher suite")
	//}

	digest, err := hashForServerKeyExchange(sigType, hashFunc, ka.version, clientHello.random, hello.random, serverECDHParams)
	if err != nil {
		return nil, err
	}

	signOpts := crypto.SignerOpts(hashFunc)
	//if sigType == signatureRSAPSS {
	//	signOpts = &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: hashFunc}
	//}

	sig, err := priv.Sign(config.rand(), digest, signOpts)   //待測試
	if err != nil {
		return nil, errors.New("tls: failed to sign SM2 parameters: " + err.Error())
	}

	skx := new(serverKeyExchangeMsg)
	sigAndHashLen := 0
	if ka.version >= VersionTLS12 {
		sigAndHashLen = 2
	}
	skx.key = make([]byte, len(serverECDHParams)+sigAndHashLen+2+len(sig))
	copy(skx.key, serverECDHParams)
	k := skx.key[len(serverECDHParams):]
	if ka.version >= VersionTLS12 {
		k[0] = byte(signatureAlgorithm >> 8)
		k[1] = byte(signatureAlgorithm)
		k = k[2:]
	}
	k[0] = byte(len(sig) >> 8)
	k[1] = byte(len(sig))
	copy(k[2:], sig)

	return skx, nil
}

func (ka *ecdheSM2KeyAgreement) processClientKeyExchange(config *Config, cert *Certificate, ckx *clientKeyExchangeMsg, version uint16) ([]byte, error) {
	if len(ckx.ciphertext) == 0 || int(ckx.ciphertext[0]) != len(ckx.ciphertext)-1 {
		return nil, errClientKeyExchange
	}

	if ka.curveid == X25519 {
		if len(ckx.ciphertext) != 1+32 {
			return nil, errClientKeyExchange
		}

		var theirPublic, sharedKey, scalar [32]byte
		copy(theirPublic[:], ckx.ciphertext[1:])
		copy(scalar[:], ka.privateKey)
		curve25519.ScalarMult(&sharedKey, &scalar, &theirPublic)
		return sharedKey[:], nil
	}

	curve, ok := curveForCurveID(ka.curveid)
	if !ok {
		panic("internal error")
	}



	x, y := elliptic.Unmarshal(curve, ckx.ciphertext[1:]) // Unmarshal also checks whether the given point is on the curve  !!!
	if x == nil {
		return nil, errClientKeyExchange
	}
	x, _ = curve.ScalarMult(x, y, ka.privateKey)
	preMasterSecret := make([]byte, (curve.Params().BitSize+7)>>3)
	xBytes := x.Bytes()
	copy(preMasterSecret[len(preMasterSecret)-len(xBytes):], xBytes)

	return preMasterSecret, nil
}

func (ka *ecdheSM2KeyAgreement) processServerKeyExchange(config *Config, clientHello *clientHelloMsg, serverHello *serverHelloMsg, cert *x509.Certificate, skx *serverKeyExchangeMsg) error {
	if len(skx.key) < 4 {
		return errServerKeyExchange
	}
	if skx.key[0] != 3 { // named curve
		return errors.New("tls: server selected unsupported curve")
	}
	ka.curveid = CurveID(skx.key[1])<<8 | CurveID(skx.key[2])

	publicLen := int(skx.key[3])
	if publicLen+4 > len(skx.key) {
		return errServerKeyExchange
	}
	serverECDHParams := skx.key[:4+publicLen]
	publicKey := serverECDHParams[4:]

	sig := skx.key[4+publicLen:]
	if len(sig) < 2 {
		return errServerKeyExchange
	}

	if ka.curveid == X25519 {
		if len(publicKey) != 32 {
			return errors.New("tls: bad X25519 public value")
		}
		ka.publicKey = publicKey
	} else {
		curve, ok := curveForCurveID(ka.curveid)
		if !ok {
			return errors.New("tls: server selected unsupported curve")
		}
		ka.x, ka.y = elliptic.Unmarshal(curve, publicKey) // Unmarshal also checks whether the given point is on the curve
		if ka.x == nil {
			return errServerKeyExchange
		}
	}

	var signatureAlgorithm SignatureScheme
	if ka.version >= VersionTLS12 {
		// handle SignatureAndHashAlgorithm
		signatureAlgorithm = SignatureScheme(sig[0])<<8 | SignatureScheme(sig[1])
		sig = sig[2:]
		if len(sig) < 2 {
			return errServerKeyExchange
		}
	}
	_, sigType, hashFunc, err := pickSignatureAlgorithm(cert.PublicKey, []SignatureScheme{signatureAlgorithm}, clientHello.supportedSignatureAlgorithms, ka.version)
	if err != nil {
		return err
	}
	//if (sigType == signaturePKCS1v15 || sigType == signatureRSAPSS) != ka.isRSA {
	//	return errServerKeyExchange
	//}

	sigLen := int(sig[0])<<8 | int(sig[1])
	if sigLen+2 != len(sig) {
		return errServerKeyExchange
	}
	sig = sig[2:]

	digest, err := hashForServerKeyExchange(sigType, hashFunc, ka.version, clientHello.random, serverHello.random, serverECDHParams)
	if err != nil {
		return err
	}
	return verifyHandshakeSignature(sigType, cert.PublicKey, hashFunc, digest, sig)
}

func (ka *ecdheSM2KeyAgreement) generateClientKeyExchange(config *Config, clientHello *clientHelloMsg, cert *x509.Certificate) ([]byte, *clientKeyExchangeMsg, error) {
	if ka.curveid == 0 {
		return nil, nil, errors.New("tls: missing ServerKeyExchange message")
	}

	var serialized, preMasterSecret []byte

	if ka.curveid == X25519 {
		var ourPublic, theirPublic, sharedKey, scalar [32]byte

		if _, err := io.ReadFull(config.rand(), scalar[:]); err != nil {
			return nil, nil, err
		}

		copy(theirPublic[:], ka.publicKey)
		curve25519.ScalarBaseMult(&ourPublic, &scalar)
		curve25519.ScalarMult(&sharedKey, &scalar, &theirPublic)
		serialized = ourPublic[:]
		preMasterSecret = sharedKey[:]
	} else {
		curve, ok := curveForCurveID(ka.curveid)
		if !ok {
			panic("internal error")
		}

		privkey,err := sm2.GenerateKey(config.rand())
		//priv, mx, my, err := elliptic.GenerateKey(curve, config.rand())
		priv ,err := sm2.MarshalSM2PrivateKey(privkey,nil)
		if err != nil {
			return nil, nil, err
		}

		x, _ := curve.ScalarMult(ka.x, ka.y, priv)//会执行sm2.SM2P256().ScalarMult()
		preMasterSecret = make([]byte, (curve.Params().BitSize+7)>>3)
		xBytes := x.Bytes()
		copy(preMasterSecret[len(preMasterSecret)-len(xBytes):], xBytes)

		serialized,_ = sm2.MarshalSM2PublicKey(&privkey.PublicKey)
		//serialized = elliptic.Marshal(curve, mx, my)
	}

	// ---------------------------------------- //
	ckx := new(clientKeyExchangeMsg)
	ckx.ciphertext = make([]byte, 1+len(serialized))
	ckx.ciphertext[0] = byte(len(serialized))
	copy(ckx.ciphertext[1:], serialized)

	return preMasterSecret, ckx, nil
}
