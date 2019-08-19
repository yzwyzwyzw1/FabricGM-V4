package comm

import (
	"bytes"
	"crypto/hmac"

	"github.com/chinaso/fabricGM/cryptopkg/golangGM/sm3"
	"github.com/chinaso/fabricGM/gossip/identity"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
	"testing"

	"fmt"
	"github.com/chinaso/fabricGM/gossip/api"
	"github.com/chinaso/fabricGM/gossip/common"
	"github.com/chinaso/fabricGM/gossip/mocks"
	"time"



	proto "github.com/chinaso/fabricGM/protos/gossip"




)

type gmnaiveSecProvider struct {
	mocks.SecurityAdvisor
}

func (nsp *gmnaiveSecProvider) OrgByPeerIdentity(identity api.PeerIdentityType) api.OrgIdentityType {
	return nsp.SecurityAdvisor.Called(identity).Get(0).(api.OrgIdentityType)
}

func (*gmnaiveSecProvider) Expiration(peerIdentity api.PeerIdentityType) (time.Time, error) {
	return time.Now().Add(time.Hour), nil
}

func (*gmnaiveSecProvider) ValidateIdentity(peerIdentity api.PeerIdentityType) error {
	return nil
}

// GetPKIidOfCert returns the PKI-ID of a peer's identity
func (*gmnaiveSecProvider) GetPKIidOfCert(peerIdentity api.PeerIdentityType) common.PKIidType {
	return common.PKIidType(peerIdentity)
}

// VerifyBlock returns nil if the block is properly signed,
// else returns error
func (*gmnaiveSecProvider) VerifyBlock(chainID common.ChainID, seqNum uint64, signedBlock []byte) error {
	return nil
}

// Sign signs msg with this peer's signing key and outputs
// the signature if no error occurred.
func (*gmnaiveSecProvider) Sign(msg []byte) ([]byte, error) {
	mac := hmac.New(sm3.New, hmacKey)
	mac.Write(msg)
	return mac.Sum(nil), nil
}

// Verify checks that signature is a valid signature of message under a peer's verification key.
// If the verification succeeded, Verify returns nil meaning no error occurred.
// If peerCert is nil, then the signature is verified against this peer's verification key.
func (*gmnaiveSecProvider) Verify(peerIdentity api.PeerIdentityType, signature, message []byte) error {
	mac := hmac.New(sm3.New, hmacKey)
	mac.Write(message)
	expected := mac.Sum(nil)
	if !bytes.Equal(signature, expected) {
		return fmt.Errorf("Wrong certificate:%v, %v", signature, message)
	}
	return nil
}

// VerifyByChannel verifies a peer's signature on a message in the context
// of a specific channel
func (*gmnaiveSecProvider) VerifyByChannel(_ common.ChainID, _ api.PeerIdentityType, _, _ []byte) error {
	return nil
}



func TestHandshakeGM(t *testing.T) {
	t.Parallel()
	signer := func(msg []byte) ([]byte, error) {
		mac := hmac.New(sm3.New, hmacKey)
		mac.Write(msg)
		return mac.Sum(nil), nil
	}
	mutator := func(msg *proto.SignedGossipMessage) *proto.SignedGossipMessage {
		return msg
	}
	assertPositivePath := func(msg proto.ReceivedMessage, endpoint string) {
		expectedPKIID := common.PKIidType(endpoint)
		assert.Equal(t, expectedPKIID, msg.GetConnectionInfo().ID)
		assert.Equal(t, api.PeerIdentityType(endpoint), msg.GetConnectionInfo().Identity)
		assert.NotNil(t, msg.GetConnectionInfo().Auth)
		sig, _ := (&gmnaiveSecProvider{}).Sign(msg.GetConnectionInfo().Auth.SignedData)
		assert.Equal(t, sig, msg.GetConnectionInfo().Auth.Signature)
	}

	// Positive path 1 - check authentication without TLS
	port, endpoint, ll := getAvailablePort(t)
	s := grpc.NewServer()
	id := []byte(endpoint)
	idMapper := identity.NewIdentityMapper(naiveSec, id, noopPurgeIdentity, naiveSec)
	inst, err := NewCommInstance(s, nil, idMapper, api.PeerIdentityType(endpoint), func() []grpc.DialOption {
		return []grpc.DialOption{grpc.WithInsecure()}
	}, naiveSec, disabledMetrics, testCommConfig)
	go s.Serve(ll)
	assert.NoError(t, err)
	var msg proto.ReceivedMessage

	_, tempEndpoint, tempL := getAvailablePort(t)
	acceptChan := handshaker(port, tempEndpoint, inst, t, mutator, none)
	select {
	case <-time.After(time.Duration(time.Second * 4)):
		assert.FailNow(t, "Didn't receive a message, seems like handshake failed")
	case msg = <-acceptChan:
	}
	assert.Equal(t, common.PKIidType(tempEndpoint), msg.GetConnectionInfo().ID)
	assert.Equal(t, api.PeerIdentityType(tempEndpoint), msg.GetConnectionInfo().Identity)
	sig, _ := (&gmnaiveSecProvider{}).Sign(msg.GetConnectionInfo().Auth.SignedData)
	assert.Equal(t, sig, msg.GetConnectionInfo().Auth.Signature)

	inst.Stop()
	s.Stop()
	ll.Close()
	tempL.Close()
	time.Sleep(time.Second)

	comm, port := newCommInstance(t, naiveSec)
	defer comm.Stop()
	// Positive path 2: initiating peer sends its own certificate
	_, tempEndpoint, tempL = getAvailablePort(t)
	acceptChan = handshaker(port, tempEndpoint, comm, t, mutator, mutualTLS)

	select {
	case <-time.After(time.Second * 2):
		assert.FailNow(t, "Didn't receive a message, seems like handshake failed")
	case msg = <-acceptChan:
	}
	assertPositivePath(msg, tempEndpoint)
	tempL.Close()

	// Negative path: initiating peer doesn't send its own certificate
	_, tempEndpoint, tempL = getAvailablePort(t)
	acceptChan = handshaker(port, tempEndpoint, comm, t, mutator, oneWayTLS)
	time.Sleep(time.Second)
	assert.Equal(t, 0, len(acceptChan))
	tempL.Close()

	// Negative path, signature is wrong
	_, tempEndpoint, tempL = getAvailablePort(t)
	mutator = func(msg *proto.SignedGossipMessage) *proto.SignedGossipMessage {
		msg.Signature = append(msg.Signature, 0)
		return msg
	}
	acceptChan = handshaker(port, tempEndpoint, comm, t, mutator, mutualTLS)
	time.Sleep(time.Second)
	assert.Equal(t, 0, len(acceptChan))
	tempL.Close()

	// Negative path, the PKIid doesn't match the identity
	_, tempEndpoint, tempL = getAvailablePort(t)
	mutator = func(msg *proto.SignedGossipMessage) *proto.SignedGossipMessage {
		msg.GetConn().PkiId = []byte(tempEndpoint)
		// Sign the message again
		msg.Sign(signer)
		return msg
	}
	_, tempEndpoint2, tempL2 := getAvailablePort(t)
	acceptChan = handshaker(port, tempEndpoint2, comm, t, mutator, mutualTLS)
	time.Sleep(time.Second)
	assert.Equal(t, 0, len(acceptChan))
	tempL.Close()
	tempL2.Close()

	// Negative path, the cert hash isn't what is expected
	_, tempEndpoint, tempL = getAvailablePort(t)
	mutator = func(msg *proto.SignedGossipMessage) *proto.SignedGossipMessage {
		msg.GetConn().TlsCertHash = append(msg.GetConn().TlsCertHash, 0)
		msg.Sign(signer)
		return msg
	}
	acceptChan = handshaker(port, tempEndpoint, comm, t, mutator, mutualTLS)
	time.Sleep(time.Second)
	assert.Equal(t, 0, len(acceptChan))
	tempL.Close()

	// Negative path, no PKI-ID was sent
	_, tempEndpoint, tempL = getAvailablePort(t)
	mutator = func(msg *proto.SignedGossipMessage) *proto.SignedGossipMessage {
		msg.GetConn().PkiId = nil
		msg.Sign(signer)
		return msg
	}
	acceptChan = handshaker(port, tempEndpoint, comm, t, mutator, mutualTLS)
	time.Sleep(time.Second)
	assert.Equal(t, 0, len(acceptChan))
	tempL.Close()

	// Negative path, connection message is of a different type
	_, tempEndpoint, tempL = getAvailablePort(t)
	mutator = func(msg *proto.SignedGossipMessage) *proto.SignedGossipMessage {
		msg.Content = &proto.GossipMessage_Empty{
			Empty: &proto.Empty{},
		}
		msg.Sign(signer)
		return msg
	}
	acceptChan = handshaker(port, tempEndpoint, comm, t, mutator, mutualTLS)
	time.Sleep(time.Second)
	assert.Equal(t, 0, len(acceptChan))
	tempL.Close()

	// Negative path, the peer didn't respond to the handshake in due time
	_, tempEndpoint, tempL = getAvailablePort(t)
	mutator = func(msg *proto.SignedGossipMessage) *proto.SignedGossipMessage {
		time.Sleep(time.Second * 5)
		return msg
	}
	acceptChan = handshaker(port, tempEndpoint, comm, t, mutator, mutualTLS)
	time.Sleep(time.Second)
	assert.Equal(t, 0, len(acceptChan))
	tempL.Close()
}
