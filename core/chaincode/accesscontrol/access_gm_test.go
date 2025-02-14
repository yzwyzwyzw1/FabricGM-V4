package accesscontrol

import (
	"encoding/base64"
	"github.com/chinaso/fabricGM/cryptopkg/golangGM/tls"
	"testing"
	"time"

	"github.com/chinaso/fabricGM/common/crypto/tlsgen"
	"github.com/chinaso/fabricGM/common/flogging/floggingtest"
	pb "github.com/chinaso/fabricGM/protos/peer"
	"github.com/golang/protobuf/proto"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap/zapcore"
)



func TestGMAccessControl(t *testing.T) {
	backupTTL := ttl
	defer func() {
		ttl = backupTTL
	}()
	ttl = time.Second * 3

	oldLogger := logger
	l, recorder := floggingtest.NewTestLogger(t, floggingtest.AtLevel(zapcore.InfoLevel))
	logger = l
	defer func() { logger = oldLogger }()

	chaincodeID := &pb.ChaincodeID{Name: "example02"}
	payload, err := proto.Marshal(chaincodeID)
	registerMsg := &pb.ChaincodeMessage{
		Type:    pb.ChaincodeMessage_REGISTER,
		Payload: payload,
	}
	putStateMsg := &pb.ChaincodeMessage{
		Type: pb.ChaincodeMessage_PUT_STATE,
	}

	ca, _ := tlsgen.NewCA()
	srv := newCCServer(t, 7052, "example02", true, ca)

	// ------------------------------------------------------------------ //
	auth := GMNewAuthenticator(ca)
	pb.RegisterChaincodeSupportServer(srv.grpcSrv, auth.Wrap(srv))
	go srv.grpcSrv.Serve(srv.l)
	defer srv.stop()

	// Create an attacker without a TLS certificate
	_, err = newClient(t, 7052, nil, ca.CertBytes())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "context deadline exceeded")

	// Create an attacker with its own TLS certificate
	maliciousCA, _ := tlsgen.NewCA()
	keyPair, err := maliciousCA.NewClientCertKeyPair()
	cert, err := tls.X509KeyPair(keyPair.Cert, keyPair.Key)
	assert.NoError(t, err)
	_, err = newClient(t, 7052, &cert, ca.CertBytes())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "context deadline exceeded")

	// Create a chaincode for example01 that tries to impersonate example02
	kp, err := auth.Generate("example01")
	assert.NoError(t, err)
	keyBytes, err := base64.StdEncoding.DecodeString(kp.Key)
	assert.NoError(t, err)
	certBytes, err := base64.StdEncoding.DecodeString(kp.Cert)
	assert.NoError(t, err)
	cert, err = tls.X509KeyPair(certBytes, keyBytes)
	assert.NoError(t, err)
	mismatchedShim, err := newClient(t, 7052, &cert, ca.CertBytes())
	assert.NoError(t, err)
	defer mismatchedShim.close()
	mismatchedShim.sendMsg(registerMsg)
	mismatchedShim.sendMsg(putStateMsg)
	// Mismatched chaincode didn't get back anything
	assert.Nil(t, mismatchedShim.recv())
	assertLogContains(t, recorder, "with given certificate hash", "belongs to a different chaincode")

	// Create the real chaincode that its cert is generated by us that should pass the security checks
	kp, err = auth.Generate("example02")
	assert.NoError(t, err)
	keyBytes, err = base64.StdEncoding.DecodeString(kp.Key)
	assert.NoError(t, err)
	certBytes, err = base64.StdEncoding.DecodeString(kp.Cert)
	assert.NoError(t, err)
	cert, err = tls.X509KeyPair(certBytes, keyBytes)
	assert.NoError(t, err)
	realCC, err := newClient(t, 7052, &cert, ca.CertBytes())
	assert.NoError(t, err)
	defer realCC.close()
	realCC.sendMsg(registerMsg)
	realCC.sendMsg(putStateMsg)
	echoMsg := realCC.recv()
	// The real chaincode should be echoed back its message
	assert.NotNil(t, echoMsg)
	assert.Equal(t, pb.ChaincodeMessage_PUT_STATE, echoMsg.Type)
	// Log should not complain about anything
	assert.Empty(t, recorder.Messages())

	// Create the real chaincode that its cert is generated by us
	// but one that the first message sent by it isn't a register message.
	// The second message that is sent is a register message but it's "too late"
	// and the stream is already denied.
	kp, err = auth.Generate("example02")
	assert.NoError(t, err)
	keyBytes, err = base64.StdEncoding.DecodeString(kp.Key)
	assert.NoError(t, err)
	certBytes, err = base64.StdEncoding.DecodeString(kp.Cert)
	assert.NoError(t, err)
	cert, err = tls.X509KeyPair(certBytes, keyBytes)
	assert.NoError(t, err)
	confusedCC, err := newClient(t, 7052, &cert, ca.CertBytes())
	assert.NoError(t, err)
	defer confusedCC.close()
	confusedCC.sendMsg(putStateMsg)
	confusedCC.sendMsg(registerMsg)
	confusedCC.sendMsg(putStateMsg)
	assert.Nil(t, confusedCC.recv())
	assertLogContains(t, recorder, "expected a ChaincodeMessage_REGISTER message")

	// Create a real chaincode, that its cert was generated by us
	// but it sends a malformed first message
	kp, err = auth.Generate("example02")
	assert.NoError(t, err)
	keyBytes, err = base64.StdEncoding.DecodeString(kp.Key)
	assert.NoError(t, err)
	certBytes, err = base64.StdEncoding.DecodeString(kp.Cert)
	assert.NoError(t, err)
	cert, err = tls.X509KeyPair(certBytes, keyBytes)
	assert.NoError(t, err)
	malformedMessageCC, err := newClient(t, 7052, &cert, ca.CertBytes())
	assert.NoError(t, err)
	defer malformedMessageCC.close()
	// Save old payload
	originalPayload := registerMsg.Payload
	registerMsg.Payload = append(registerMsg.Payload, 0)
	malformedMessageCC.sendMsg(registerMsg)
	malformedMessageCC.sendMsg(putStateMsg)
	assert.Nil(t, malformedMessageCC.recv())
	assertLogContains(t, recorder, "Failed unmarshaling message")
	// Recover old payload
	registerMsg.Payload = originalPayload

	// Create a real chaincode, that its cert was generated by us
	// but have it reconnect only after too much time.
	// This tests a use case where the CC's cert has been expired
	// and the CC has been compromised. We don't want it to be able
	// to reconnect to us.
	kp, err = auth.Generate("example02")
	assert.NoError(t, err)
	keyBytes, err = base64.StdEncoding.DecodeString(kp.Key)
	assert.NoError(t, err)
	certBytes, err = base64.StdEncoding.DecodeString(kp.Cert)
	assert.NoError(t, err)
	cert, err = tls.X509KeyPair(certBytes, keyBytes)
	assert.NoError(t, err)
	lateCC, err := newClient(t, 7052, &cert, ca.CertBytes())
	assert.NoError(t, err)
	defer lateCC.close()
	time.Sleep(ttl + time.Second*2)
	lateCC.sendMsg(registerMsg)
	lateCC.sendMsg(putStateMsg)
	echoMsg = lateCC.recv()
	assert.Nil(t, echoMsg)
	assertLogContains(t, recorder, "with given certificate hash", "not found in registry")
}


