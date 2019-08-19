package msp

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/pem"
	"github.com/chinaso/fabricGM/bccsp"
	"github.com/chinaso/fabricGM/cryptopkg/golangGM/sm2"
	"github.com/chinaso/fabricGM/cryptopkg/golangGM/x509"
	"github.com/chinaso/fabricGM/protos/msp"
	"github.com/golang/protobuf/proto"
	"github.com/pkg/errors"
	"go.uber.org/zap/zapcore"
	"time"
)

type gmidentity struct {
	// id contains the identifier (MSPID and gmidentity identifier) for this instance
	id *IdentityIdentifier

	// cert contains the x.509 certificate that signs the public key of this instance
	cert *x509.Certificate

	// this is the public key of this instance
	pk bccsp.Key

	// reference to the MSP that "owns" this gmidentity
	msp *bccspgmmsp
}


func newgmIdentity(cert *x509.Certificate, pk bccsp.Key, msp *bccspgmmsp) (Identity, error) {
	if mspIdentityLogger.IsEnabledFor(zapcore.DebugLevel) {
		mspIdentityLogger.Debugf("Creating gmidentity instance for cert %s", certTogmPEM(cert))
	}

	// Sanitize first the certificate
	cert, err := msp.sanitizeCert(cert)
	if err != nil {
		return nil, err
	}

	// Compute gmidentity identifier

	// Use the hash of the gmidentity's certificate as id in the IdentityIdentifier
	hashOpt, err := bccsp.GetHashOpt(msp.cryptoConfig.IdentityIdentifierHashFunction)
	if err != nil {
		return nil, errors.WithMessage(err, "failed getting hash function options")
	}

	digest, err := msp.bccsp.Hash(cert.Raw, hashOpt)
	if err != nil {
		return nil, errors.WithMessage(err, "failed hashing raw certificate to compute the id of the IdentityIdentifier")
	}

	id := &IdentityIdentifier{
		Mspid: msp.name,
		Id:    hex.EncodeToString(digest)}

	return &gmidentity{id: id, cert: cert, pk: pk, msp: msp}, nil
}



// ExpiresAt returns the time at which the Identity expires.
func (id *gmidentity) ExpiresAt() time.Time {
	return id.cert.NotAfter
}

// SatisfiesPrincipal returns null if this instance matches the supplied principal or an error otherwise
func (id *gmidentity) SatisfiesPrincipal(principal *msp.MSPPrincipal) error {
	return id.msp.SatisfiesPrincipal(id, principal)
}

// GetIdentifier returns the identifier (MSPID/IDID) for this instance
func (id *gmidentity) GetIdentifier() *IdentityIdentifier {
	return id.id
}

// GetMSPIdentifier returns the MSP identifier for this instance
func (id *gmidentity) GetMSPIdentifier() string {
	return id.id.Mspid
}

// Validate returns nil if this instance is a valid gmidentity or an error otherwise
func (id *gmidentity) Validate() error {
	return id.msp.Validate(id)
}

// GetOrganizationalUnits returns the OU for this instance
func (id *gmidentity) GetOrganizationalUnits() []*OUIdentifier {
	if id.cert == nil {
		return nil
	}

	cid, err := id.msp.getCertificationChainIdentifier(id)
	if err != nil {
		mspIdentityLogger.Errorf("Failed getting certification chain identifier for [%v]: [%+v]", id, err)

		return nil
	}

	res := []*OUIdentifier{}
	for _, unit := range id.cert.Subject.OrganizationalUnit {
		res = append(res, &OUIdentifier{
			OrganizationalUnitIdentifier: unit,
			CertifiersIdentifier:         cid,
		})
	}

	return res
}

// Anonymous returns true if this gmidentity provides anonymity
func (id *gmidentity) Anonymous() bool {
	return false
}

// NewSerializedGMIdentity returns a serialized gmidentity
// having as content the passed mspID and x509 certificate in PEM format.
// This method does not check the validity of certificate nor
// any consistency of the mspID with it.
func NewSerializedGMIdentity(mspID string, certPEM []byte) ([]byte, error) {
	// We serialize identities by prepending the MSPID
	// and appending the x509 cert in PEM format
	sId := &msp.SerializedIdentity{Mspid: mspID, IdBytes: certPEM}
	raw, err := proto.Marshal(sId)
	if err != nil {
		return nil, errors.Wrapf(err, "failed serializing gmidentity [%s][%X]", mspID, certPEM)
	}
	return raw, nil
}

// Verify checks against a signature and a message
// to determine whether this gmidentity produced the
// signature; it returns nil if so or an error otherwise
func (id *gmidentity) Verify(msg []byte, sig []byte) error {
	// mspIdentityLogger.Infof("Verifying signature")

	// Compute Hash
	hashOpt, err := id.getHashOpt(id.msp.cryptoConfig.SignatureHashFamily)
	if err != nil {
		return errors.WithMessage(err, "failed getting hash function options")
	}

	digest, err := id.msp.bccsp.Hash(msg, hashOpt)
	if err != nil {
		return errors.WithMessage(err, "failed computing digest")
	}

	if mspIdentityLogger.IsEnabledFor(zapcore.DebugLevel) {
		mspIdentityLogger.Debugf("Verify: digest = %s", hex.Dump(digest))
		mspIdentityLogger.Debugf("Verify: sig = %s", hex.Dump(sig))
	}

	valid, err := id.msp.bccsp.Verify(id.pk, sig, digest, nil)
	if err != nil {
		return errors.WithMessage(err, "could not determine the validity of the signature")
	} else if !valid {
		return errors.New("The signature is invalid")
	}

	return nil
}

// Serialize returns a byte array representation of this gmidentity
func (id *gmidentity) Serialize() ([]byte, error) {
	// mspIdentityLogger.Infof("Serializing gmidentity %s", id.id)

	pb := &pem.Block{Bytes: id.cert.Raw, Type: "CERTIFICATE"}
	pemBytes := pem.EncodeToMemory(pb)
	if pemBytes == nil {
		return nil, errors.New("encoding of gmidentity failed")
	}

	// We serialize identities by prepending the MSPID and appending the ASN.1 DER content of the cert
	sId := &msp.SerializedIdentity{Mspid: id.id.Mspid, IdBytes: pemBytes}
	idBytes, err := proto.Marshal(sId)
	if err != nil {
		return nil, errors.Wrapf(err, "could not marshal a SerializedIdentity structure for gmidentity %s", id.id)
	}

	return idBytes, nil
}

func (id *gmidentity) getHashOpt(hashFamily string) (bccsp.HashOpts, error) {
	switch hashFamily {
	case bccsp.SM3:
		return bccsp.GetHashOpt(bccsp.SM3)
	}
	return nil, errors.Errorf("hash familiy not recognized [%s]", hashFamily)
}

type signinggmidentity struct {
	// we embed everything from a base gmidentity
	gmidentity

	// signer corresponds to the object that can produce signatures from this gmidentity
	///signer crypto.Signer
	signer *sm2.PrivateKey
}

func newSigningGMIdentity(cert *x509.Certificate, pk bccsp.Key, signer *sm2.PrivateKey, msp *bccspgmmsp) (SigningIdentity, error) {
	//mspIdentityLogger.Infof("Creating signing gmidentity instance for ID %s", id)
	mspId, err := newgmIdentity(cert, pk, msp)
	if err != nil {
		return nil, err
	}
	return &signinggmidentity{gmidentity: *mspId.(*gmidentity), signer: signer}, nil
}

// Sign produces a signature over msg, signed by this instance
func (id *signinggmidentity) Sign(msg []byte) ([]byte, error) {
	//mspIdentityLogger.Infof("Signing message")

	// Compute Hash
	hashOpt, err := id.getHashOpt(id.msp.cryptoConfig.SignatureHashFamily)
	if err != nil {
		return nil, errors.WithMessage(err, "failed getting hash function options")
	}

	digest, err := id.msp.bccsp.Hash(msg, hashOpt)
	if err != nil {
		return nil, errors.WithMessage(err, "failed computing digest")
	}

	if len(msg) < 32 {
		mspIdentityLogger.Debugf("Sign: plaintext: %X \n", msg)
	} else {
		mspIdentityLogger.Debugf("Sign: plaintext: %X...%X \n", msg[0:16], msg[len(msg)-16:])
	}
	mspIdentityLogger.Debugf("Sign: digest: %X \n", digest)

	// Sign
	return id.signer.Sign(rand.Reader, digest, nil)
}

// GetPublicVersion returns the public version of this gmidentity,
// namely, the one that is only able to verify messages and not sign them
func (id *signinggmidentity) GetPublicVersion() Identity {
	return &id.gmidentity
}

