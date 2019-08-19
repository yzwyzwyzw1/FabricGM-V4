package accesscontrol

import (
	"errors"
	"fmt"
	"github.com/chinaso/fabricGM/common/crypto/tlsgen"
	pb "github.com/chinaso/fabricGM/protos/peer"
	"google.golang.org/grpc"

	"github.com/golang/protobuf/proto"
)

type GMAuthenticator struct {
	mapper *gmcertMapper
}

func (auth *GMAuthenticator) Wrap(srv pb.ChaincodeSupportServer) pb.ChaincodeSupportServer {
	return newInterceptor(srv, auth.authenticate)
}

// NewAuthenticator returns a new authenticator that can wrap a chaincode service
func GMNewAuthenticator(ca tlsgen.CA) *GMAuthenticator {
	return &GMAuthenticator{
		mapper: gmnewCertMapper(ca.NewClientCertKeyPair),
	}
}

// Generate returns a pair of certificate and private key,
// and associates the hash of the certificate with the given
// chaincode name
func (ac *GMAuthenticator) Generate(ccName string) (*CertAndPrivKeyPair, error) {
	cert, err := ac.mapper.genCert(ccName)
	if err != nil {
		return nil, err
	}
	return &CertAndPrivKeyPair{
		Key:  cert.PrivKeyString(),
		Cert: cert.PubKeyString(),
	}, nil
}

func (ac *GMAuthenticator) authenticate(msg *pb.ChaincodeMessage, stream grpc.ServerStream) error {
	if msg.Type != pb.ChaincodeMessage_REGISTER {
		logger.Warning("Got message", msg, "but expected a ChaincodeMessage_REGISTER message")
		return errors.New("First message needs to be a register")
	}

	chaincodeID := &pb.ChaincodeID{}
	err := proto.Unmarshal(msg.Payload, chaincodeID)
	if err != nil {
		logger.Warning("Failed unmarshaling message:", err)
		return err
	}
	ccName := chaincodeID.Name
	// Obtain certificate from stream
	hash := extractCertificateHashFromContext(stream.Context())
	if len(hash) == 0 {
		errMsg := fmt.Sprintf("TLS is active but chaincode %s didn't send certificate", ccName)
		logger.Warning(errMsg)
		return errors.New(errMsg)
	}
	// Look it up in the mapper
	registeredName := ac.mapper.lookup(certHash(hash))
	if registeredName == "" {
		errMsg := fmt.Sprintf("Chaincode %s with given certificate hash %v not found in registry", ccName, hash)
		logger.Warning(errMsg)
		return errors.New(errMsg)
	}
	if registeredName != ccName {
		errMsg := fmt.Sprintf("Chaincode %s with given certificate hash %v belongs to a different chaincode", ccName, hash)
		logger.Warning(errMsg)
		return fmt.Errorf(errMsg)
	}

	logger.Debug("Chaincode", ccName, "'s authentication is authorized")
	return nil
}
