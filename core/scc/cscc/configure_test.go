/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cscc

import (
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/chinaso/fabricGM/common/config"
	"github.com/chinaso/fabricGM/common/configtx"
	configtxtest "github.com/chinaso/fabricGM/common/configtx/test"
	"github.com/chinaso/fabricGM/common/crypto/tlsgen"
	"github.com/chinaso/fabricGM/common/genesis"
	"github.com/chinaso/fabricGM/common/localmsp"
	"github.com/chinaso/fabricGM/common/metrics/disabled"
	"github.com/chinaso/fabricGM/common/mocks/scc"
	"github.com/chinaso/fabricGM/common/policies"
	"github.com/chinaso/fabricGM/common/tools/configtxgen/configtxgentest"
	"github.com/chinaso/fabricGM/common/tools/configtxgen/encoder"
	genesisconfig "github.com/chinaso/fabricGM/common/tools/configtxgen/localconfig"
	"github.com/chinaso/fabricGM/core/aclmgmt"
	aclmocks "github.com/chinaso/fabricGM/core/aclmgmt/mocks"
	"github.com/chinaso/fabricGM/core/aclmgmt/resources"
	"github.com/chinaso/fabricGM/core/chaincode"
	"github.com/chinaso/fabricGM/core/chaincode/accesscontrol"
	"github.com/chinaso/fabricGM/core/chaincode/platforms"
	"github.com/chinaso/fabricGM/core/chaincode/platforms/golang"
	"github.com/chinaso/fabricGM/core/chaincode/shim"
	"github.com/chinaso/fabricGM/core/common/ccprovider"
	"github.com/chinaso/fabricGM/core/container"
	"github.com/chinaso/fabricGM/core/container/inproccontroller"
	deliverclient "github.com/chinaso/fabricGM/core/deliverservice"
	"github.com/chinaso/fabricGM/core/deliverservice/blocksprovider"
	"github.com/chinaso/fabricGM/core/ledger/ledgermgmt"
	ccprovidermocks "github.com/chinaso/fabricGM/core/mocks/ccprovider"
	"github.com/chinaso/fabricGM/core/peer"
	"github.com/chinaso/fabricGM/core/policy"
	policymocks "github.com/chinaso/fabricGM/core/policy/mocks"
	"github.com/chinaso/fabricGM/core/scc/cscc/mock"
	"github.com/chinaso/fabricGM/gossip/api"
	"github.com/chinaso/fabricGM/gossip/service"
	"github.com/chinaso/fabricGM/msp/mgmt"
	msptesttools "github.com/chinaso/fabricGM/msp/mgmt/testtools"
	peergossip "github.com/chinaso/fabricGM/peer/gossip"
	"github.com/chinaso/fabricGM/peer/gossip/mocks"
	cb "github.com/chinaso/fabricGM/protos/common"
	pb "github.com/chinaso/fabricGM/protos/peer"
	"github.com/chinaso/fabricGM/protos/utils"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

//go:generate counterfeiter -o mock/config_manager.go --fake-name ConfigManager . configManager
type configManager interface {
	config.Manager
}

//go:generate counterfeiter -o mock/acl_provider.go --fake-name ACLProvider . aclProvider
type aclProvider interface {
	aclmgmt.ACLProvider
}

//go:generate counterfeiter -o mock/configtx_validator.go --fake-name ConfigtxValidator . configtxValidator
type configtxValidator interface {
	configtx.Validator
}

type mockDeliveryClient struct {
}

func (ds *mockDeliveryClient) UpdateEndpoints(chainID string, _ deliverclient.ConnectionCriteria) error {
	return nil
}

// StartDeliverForChannel dynamically starts delivery of new blocks from ordering service
// to channel peers.
func (ds *mockDeliveryClient) StartDeliverForChannel(chainID string, ledgerInfo blocksprovider.LedgerInfo, f func()) error {
	return nil
}

// StopDeliverForChannel dynamically stops delivery of new blocks from ordering service
// to channel peers.
func (ds *mockDeliveryClient) StopDeliverForChannel(chainID string) error {
	return nil
}

// Stop terminates delivery service and closes the connection
func (*mockDeliveryClient) Stop() {

}

type mockDeliveryClientFactory struct {
}

func (*mockDeliveryClientFactory) Service(g service.GossipService, _ service.OrdererAddressConfig, mcs api.MessageCryptoService) (deliverclient.DeliverService, error) {
	return &mockDeliveryClient{}, nil
}

var mockAclProvider *aclmocks.MockACLProvider

func TestMain(m *testing.M) {
	msptesttools.LoadMSPSetupForTesting()

	mockAclProvider = &aclmocks.MockACLProvider{}
	mockAclProvider.Reset()

	os.Exit(m.Run())
}

func TestConfigerInit(t *testing.T) {
	e := New(nil, nil, mockAclProvider)
	stub := shim.NewMockStub("PeerConfiger", e)

	if res := stub.MockInit("1", nil); res.Status != shim.OK {
		fmt.Println("Init failed", string(res.Message))
		t.FailNow()
	}
}

func TestConfigerInvokeInvalidParameters(t *testing.T) {
	e := New(nil, nil, mockAclProvider)
	stub := shim.NewMockStub("PeerConfiger", e)

	res := stub.MockInit("1", nil)
	assert.Equal(t, res.Status, int32(shim.OK), "Init failed")

	res = stub.MockInvoke("2", nil)
	assert.Equal(t, res.Status, int32(shim.ERROR), "CSCC invoke expected to fail having zero arguments")
	assert.Equal(t, res.Message, "Incorrect number of arguments, 0")

	args := [][]byte{[]byte("GetChannels")}
	res = stub.MockInvokeWithSignedProposal("3", args, nil)
	assert.Equal(t, res.Status, int32(shim.ERROR), "CSCC invoke expected to fail no signed proposal provided")
	assert.Contains(t, res.Message, "access denied for [GetChannels]")

	args = [][]byte{[]byte("fooFunction"), []byte("testChainID")}
	res = stub.MockInvoke("5", args)
	assert.Equal(t, res.Status, int32(shim.ERROR), "CSCC invoke expected wrong function name provided")
	assert.Equal(t, res.Message, "Requested function fooFunction not found.")

	mockAclProvider.Reset()
	mockAclProvider.On("CheckACL", resources.Cscc_GetConfigBlock, "testChainID", (*pb.SignedProposal)(nil)).Return(errors.New("Nil SignedProposal"))
	args = [][]byte{[]byte("GetConfigBlock"), []byte("testChainID")}
	res = stub.MockInvokeWithSignedProposal("4", args, nil)
	assert.Equal(t, res.Status, int32(shim.ERROR), "CSCC invoke expected to fail no signed proposal provided")
	assert.Contains(t, res.Message, "Nil SignedProposal")
	mockAclProvider.AssertExpectations(t)
}

func TestConfigerInvokeJoinChainMissingParams(t *testing.T) {
	viper.Set("peer.fileSystemPath", "/tmp/hyperledgertest/")
	os.Mkdir("/tmp/hyperledgertest", 0755)
	defer os.RemoveAll("/tmp/hyperledgertest/")

	e := New(nil, nil, mockAclProvider)
	stub := shim.NewMockStub("PeerConfiger", e)

	if res := stub.MockInit("1", nil); res.Status != shim.OK {
		fmt.Println("Init failed", string(res.Message))
		t.FailNow()
	}

	// Failed path: expected to have at least one argument
	args := [][]byte{[]byte("JoinChain")}
	if res := stub.MockInvoke("2", args); res.Status == shim.OK {
		t.Fatalf("cscc invoke JoinChain should have failed with invalid number of args: %v", args)
	}
}

func TestConfigerInvokeJoinChainWrongParams(t *testing.T) {

	viper.Set("peer.fileSystemPath", "/tmp/hyperledgertest/")
	os.Mkdir("/tmp/hyperledgertest", 0755)
	defer os.RemoveAll("/tmp/hyperledgertest/")

	e := New(nil, nil, mockAclProvider)
	stub := shim.NewMockStub("PeerConfiger", e)

	if res := stub.MockInit("1", nil); res.Status != shim.OK {
		fmt.Println("Init failed", string(res.Message))
		t.FailNow()
	}

	// Failed path: wrong parameter type
	args := [][]byte{[]byte("JoinChain"), []byte("action")}
	if res := stub.MockInvoke("2", args); res.Status == shim.OK {
		t.Fatalf("cscc invoke JoinChain should have failed with null genesis block.  args: %v", args)
	}
}

func TestConfigerInvokeJoinChainCorrectParams(t *testing.T) {
	mp := (&scc.MocksccProviderFactory{}).NewSystemChaincodeProvider()
	ccp := &ccprovidermocks.MockCcProviderImpl{}

	viper.Set("peer.fileSystemPath", "/tmp/hyperledgertest/")
	viper.Set("chaincode.executetimeout", "3s")
	os.Mkdir("/tmp/hyperledgertest", 0755)

	peer.MockInitialize()
	ledgermgmt.InitializeTestEnv()
	defer ledgermgmt.CleanupTestEnv()
	defer os.RemoveAll("/tmp/hyperledgertest/")

	e := New(ccp, mp, mockAclProvider)
	stub := shim.NewMockStub("PeerConfiger", e)

	peerEndpoint := "127.0.0.1:13611"

	ca, _ := tlsgen.NewCA()
	certGenerator := accesscontrol.NewAuthenticator(ca)
	config := chaincode.GlobalConfig()
	config.StartupTimeout = 30 * time.Second
	chaincode.NewChaincodeSupport(
		config,
		peerEndpoint,
		false,
		ca.CertBytes(),
		certGenerator,
		&ccprovider.CCInfoFSImpl{},
		nil,
		mockAclProvider,
		container.NewVMController(
			map[string]container.VMProvider{
				inproccontroller.ContainerType: inproccontroller.NewRegistry(),
			},
		),
		mp,
		platforms.NewRegistry(&golang.Platform{}),
		peer.DefaultSupport,
		&disabled.Provider{},
	)

	// Init the policy checker
	policyManagerGetter := &policymocks.MockChannelPolicyManagerGetter{
		Managers: map[string]policies.Manager{
			"mytestchainid": &policymocks.MockChannelPolicyManager{
				MockPolicy: &policymocks.MockPolicy{
					Deserializer: &policymocks.MockIdentityDeserializer{
						Identity: []byte("Alice"),
						Msg:      []byte("msg1"),
					},
				},
			},
		},
	}

	identityDeserializer := &policymocks.MockIdentityDeserializer{
		Identity: []byte("Alice"),
		Msg:      []byte("msg1"),
	}

	e.policyChecker = policy.NewPolicyChecker(
		policyManagerGetter,
		identityDeserializer,
		&policymocks.MockMSPPrincipalGetter{Principal: []byte("Alice")},
	)

	grpcServer := grpc.NewServer()
	socket, err := net.Listen("tcp", peerEndpoint)
	require.NoError(t, err)

	identity, _ := mgmt.GetLocalSigningIdentityOrPanic().Serialize()
	messageCryptoService := peergossip.NewMCS(&mocks.ChannelPolicyManagerGetter{}, localmsp.NewSigner(), mgmt.NewDeserializersManager())
	secAdv := peergossip.NewSecurityAdvisor(mgmt.NewDeserializersManager())
	var defaultSecureDialOpts = func() []grpc.DialOption {
		var dialOpts []grpc.DialOption
		dialOpts = append(dialOpts, grpc.WithInsecure())
		return dialOpts
	}
	err = service.InitGossipServiceCustomDeliveryFactory(identity, &disabled.Provider{}, peerEndpoint, grpcServer, nil,
		&mockDeliveryClientFactory{}, messageCryptoService, secAdv, defaultSecureDialOpts)
	assert.NoError(t, err)

	go grpcServer.Serve(socket)
	defer grpcServer.Stop()

	// Successful path for JoinChain
	blockBytes := mockConfigBlock()
	if blockBytes == nil {
		t.Fatalf("cscc invoke JoinChain failed because invalid block")
	}
	args := [][]byte{[]byte("JoinChain"), blockBytes}
	sProp, _ := utils.MockSignedEndorserProposalOrPanic("", &pb.ChaincodeSpec{}, []byte("Alice"), []byte("msg1"))
	identityDeserializer.Msg = sProp.ProposalBytes
	sProp.Signature = sProp.ProposalBytes

	// Try fail path with nil block
	res := stub.MockInvokeWithSignedProposal("2", [][]byte{[]byte("JoinChain"), nil}, sProp)
	assert.Equal(t, res.Status, int32(shim.ERROR))

	// Try fail path with block and nil payload header
	payload, _ := proto.Marshal(&cb.Payload{})
	env, _ := proto.Marshal(&cb.Envelope{
		Payload: payload,
	})
	badBlock := &cb.Block{
		Data: &cb.BlockData{
			Data: [][]byte{env},
		},
	}
	badBlockBytes := utils.MarshalOrPanic(badBlock)
	res = stub.MockInvokeWithSignedProposal("2", [][]byte{[]byte("JoinChain"), badBlockBytes}, sProp)
	assert.Equal(t, res.Status, int32(shim.ERROR))

	// Now, continue with valid execution path
	if res := stub.MockInvokeWithSignedProposal("2", args, sProp); res.Status != shim.OK {
		t.Fatalf("cscc invoke JoinChain failed with: %v", res.Message)
	}

	// This call must fail
	sProp.Signature = nil
	res = stub.MockInvokeWithSignedProposal("3", args, sProp)
	if res.Status == shim.OK {
		t.Fatalf("cscc invoke JoinChain must fail : %v", res.Message)
	}
	assert.Contains(t, res.Message, "access denied for [JoinChain][mytestchainid]")
	sProp.Signature = sProp.ProposalBytes

	// Query the configuration block
	//chainID := []byte{143, 222, 22, 192, 73, 145, 76, 110, 167, 154, 118, 66, 132, 204, 113, 168}
	chainID, err := utils.GetChainIDFromBlockBytes(blockBytes)
	if err != nil {
		t.Fatalf("cscc invoke JoinChain failed with: %v", err)
	}

	// Test an ACL failure on GetConfigBlock
	mockAclProvider.Reset()
	mockAclProvider.On("CheckACL", resources.Cscc_GetConfigBlock, "mytestchainid", sProp).Return(errors.New("Failed authorization"))
	args = [][]byte{[]byte("GetConfigBlock"), []byte(chainID)}
	res = stub.MockInvokeWithSignedProposal("2", args, sProp)
	if res.Status == shim.OK {
		t.Fatalf("cscc invoke GetConfigBlock should have failed: %v", res.Message)
	}
	assert.Contains(t, res.Message, "Failed authorization")
	mockAclProvider.AssertExpectations(t)

	// Test with ACL okay
	mockAclProvider.Reset()
	mockAclProvider.On("CheckACL", resources.Cscc_GetConfigBlock, "mytestchainid", sProp).Return(nil)
	if res := stub.MockInvokeWithSignedProposal("2", args, sProp); res.Status != shim.OK {
		t.Fatalf("cscc invoke GetConfigBlock failed with: %v", res.Message)
	}

	// get channels for the peer
	args = [][]byte{[]byte(GetChannels)}
	res = stub.MockInvokeWithSignedProposal("2", args, sProp)
	if res.Status != shim.OK {
		t.FailNow()
	}

	cqr := &pb.ChannelQueryResponse{}
	err = proto.Unmarshal(res.Payload, cqr)
	if err != nil {
		t.FailNow()
	}

	// peer joined one channel so query should return an array with one channel
	if len(cqr.GetChannels()) != 1 {
		t.FailNow()
	}
}

func TestGetConfigTree(t *testing.T) {
	aclProvider := &mock.ACLProvider{}
	configMgr := &mock.ConfigManager{}
	pc := &PeerConfiger{
		aclProvider: aclProvider,
		configMgr:   configMgr,
	}

	args := [][]byte{[]byte("GetConfigTree"), []byte("testchan")}

	t.Run("Success", func(t *testing.T) {
		ctxv := &mock.ConfigtxValidator{}
		configMgr.GetChannelConfigReturns(ctxv)
		testConfig := &cb.Config{
			ChannelGroup: &cb.ConfigGroup{
				Values: map[string]*cb.ConfigValue{
					"foo": {
						Value: []byte("bar"),
					},
				},
			},
		}
		ctxv.ConfigProtoReturns(testConfig)
		res := pc.InvokeNoShim(args, nil)
		assert.Equal(t, int32(shim.OK), res.Status)
		checkConfig := &pb.ConfigTree{}
		err := proto.Unmarshal(res.Payload, checkConfig)
		assert.NoError(t, err)
		assert.True(t, proto.Equal(testConfig, checkConfig.ChannelConfig))
	})

	t.Run("MissingConfig", func(t *testing.T) {
		ctxv := &mock.ConfigtxValidator{}
		configMgr.GetChannelConfigReturns(ctxv)
		res := pc.InvokeNoShim(args, nil)
		assert.NotEqual(t, int32(shim.OK), res.Status)
		assert.Equal(t, "Unknown chain ID, testchan", res.Message)
	})

	t.Run("NilChannel", func(t *testing.T) {
		ctxv := &mock.ConfigtxValidator{}
		configMgr.GetChannelConfigReturns(ctxv)
		res := pc.InvokeNoShim([][]byte{[]byte("GetConfigTree"), nil}, nil)
		assert.NotEqual(t, int32(shim.OK), res.Status)
		assert.Equal(t, "Chain ID must not be nil", res.Message)
	})

	t.Run("BadACL", func(t *testing.T) {
		aclProvider.CheckACLReturns(fmt.Errorf("fake-error"))
		res := pc.InvokeNoShim(args, nil)
		assert.NotEqual(t, int32(shim.OK), res.Status)
		assert.Equal(t, "access denied for [GetConfigTree][testchan]: fake-error", res.Message)
	})
}

func TestSimulateConfigTreeUpdate(t *testing.T) {
	aclProvider := &mock.ACLProvider{}
	configMgr := &mock.ConfigManager{}
	pc := &PeerConfiger{
		aclProvider: aclProvider,
		configMgr:   configMgr,
	}

	testUpdate := &cb.Envelope{
		Payload: utils.MarshalOrPanic(&cb.Payload{
			Header: &cb.Header{
				ChannelHeader: utils.MarshalOrPanic(&cb.ChannelHeader{
					Type: int32(cb.HeaderType_CONFIG_UPDATE),
				}),
			},
		}),
	}

	args := [][]byte{[]byte("SimulateConfigTreeUpdate"), []byte("testchan"), utils.MarshalOrPanic(testUpdate)}

	t.Run("Success", func(t *testing.T) {
		ctxv := &mock.ConfigtxValidator{}
		configMgr.GetChannelConfigReturns(ctxv)
		res := pc.InvokeNoShim(args, nil)
		assert.Equal(t, int32(shim.OK), res.Status, res.Message)
	})

	t.Run("BadUpdate", func(t *testing.T) {
		ctxv := &mock.ConfigtxValidator{}
		configMgr.GetChannelConfigReturns(ctxv)
		ctxv.ProposeConfigUpdateReturns(nil, fmt.Errorf("fake-error"))
		res := pc.InvokeNoShim(args, nil)
		assert.NotEqual(t, int32(shim.OK), res.Status)
		assert.Equal(t, "fake-error", res.Message)
	})

	t.Run("BadType", func(t *testing.T) {
		res := pc.InvokeNoShim([][]byte{
			args[0],
			args[1],
			utils.MarshalOrPanic(&cb.Envelope{
				Payload: utils.MarshalOrPanic(&cb.Payload{
					Header: &cb.Header{
						ChannelHeader: utils.MarshalOrPanic(&cb.ChannelHeader{
							Type: int32(cb.HeaderType_ENDORSER_TRANSACTION),
						}),
					},
				}),
			}),
		}, nil)
		assert.NotEqual(t, int32(shim.OK), res.Status)
		assert.Equal(t, "invalid payload header type: 3", res.Message)
	})

	t.Run("BadEnvelope", func(t *testing.T) {
		res := pc.InvokeNoShim([][]byte{
			args[0],
			args[1],
			[]byte("garbage"),
		}, nil)
		assert.NotEqual(t, int32(shim.OK), res.Status)
		assert.Contains(t, res.Message, "proto:")
	})

	t.Run("NilChainID", func(t *testing.T) {
		res := pc.InvokeNoShim([][]byte{
			args[0],
			nil,
			args[2],
		}, nil)
		assert.NotEqual(t, int32(shim.OK), res.Status)
		assert.Equal(t, "Chain ID must not be nil", res.Message)
	})

	t.Run("BadACL", func(t *testing.T) {
		aclProvider.CheckACLReturns(fmt.Errorf("fake-error"))
		res := pc.InvokeNoShim(args, nil)
		assert.NotEqual(t, int32(shim.OK), res.Status)
		assert.Equal(t, "access denied for [SimulateConfigTreeUpdate][testchan]: fake-error", res.Message)
	})
}

func TestPeerConfiger_SubmittingOrdererGenesis(t *testing.T) {
	viper.Set("peer.fileSystemPath", "/tmp/hyperledgertest/")
	os.Mkdir("/tmp/hyperledgertest", 0755)
	defer os.RemoveAll("/tmp/hyperledgertest/")

	e := New(nil, nil, nil)
	stub := shim.NewMockStub("PeerConfiger", e)

	if res := stub.MockInit("1", nil); res.Status != shim.OK {
		fmt.Println("Init failed", string(res.Message))
		t.FailNow()
	}
	conf := configtxgentest.Load(genesisconfig.SampleSingleMSPSoloProfile)
	conf.Application = nil
	cg, err := encoder.NewChannelGroup(conf)
	assert.NoError(t, err)
	block := genesis.NewFactoryImpl(cg).Block("mytestchainid")
	blockBytes := utils.MarshalOrPanic(block)

	// Failed path: wrong parameter type
	args := [][]byte{[]byte("JoinChain"), []byte(blockBytes)}
	if res := stub.MockInvoke("2", args); res.Status == shim.OK {
		t.Fatalf("cscc invoke JoinChain should have failed with wrong genesis block.  args: %v", args)
	} else {
		assert.Contains(t, res.Message, "missing Application configuration group")
	}
}

func mockConfigBlock() []byte {
	var blockBytes []byte = nil
	block, err := configtxtest.MakeGenesisBlock("mytestchainid")
	if err == nil {
		blockBytes = utils.MarshalOrPanic(block)
	}
	return blockBytes
}
