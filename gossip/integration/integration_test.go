/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package integration

import (
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/chinaso/fabricGM/common/metrics/disabled"
	"github.com/chinaso/fabricGM/core/config/configtest"
	"github.com/chinaso/fabricGM/gossip/api"
	"github.com/chinaso/fabricGM/gossip/common"
	"github.com/chinaso/fabricGM/gossip/metrics"
	"github.com/chinaso/fabricGM/gossip/util"
	"github.com/chinaso/fabricGM/msp/mgmt"
	"github.com/chinaso/fabricGM/msp/mgmt/testtools"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
)

func init() {
	util.SetupTestLogging()
}

var (
	cryptSvc = &cryptoService{}
	secAdv   = &secAdviser{}
)
var defaultSecureDialOpts = func() []grpc.DialOption {
	var dialOpts []grpc.DialOption
	dialOpts = append(dialOpts, grpc.WithInsecure())
	return dialOpts
}

// This is just a test that shows how to instantiate a gossip component
func TestNewGossipCryptoService(t *testing.T) {
	setupTestEnv()
	s1 := grpc.NewServer()
	s2 := grpc.NewServer()
	s3 := grpc.NewServer()
	ll1, _ := net.Listen("tcp", "127.0.0.1:0")
	ll2, _ := net.Listen("tcp", "127.0.0.1:0")
	ll3, _ := net.Listen("tcp", "127.0.0.1:0")
	endpoint1 := ll1.Addr().String()
	endpoint2 := ll2.Addr().String()
	endpoint3 := ll3.Addr().String()
	msptesttools.LoadMSPSetupForTesting()
	peerIdentity, _ := mgmt.GetLocalSigningIdentityOrPanic().Serialize()
	gossipMetrics := metrics.NewGossipMetrics(&disabled.Provider{})
	g1, err := NewGossipComponent(peerIdentity, endpoint1, s1, secAdv, cryptSvc,
		defaultSecureDialOpts, nil, gossipMetrics)
	assert.NoError(t, err)
	g2, err := NewGossipComponent(peerIdentity, endpoint2, s2, secAdv, cryptSvc,
		defaultSecureDialOpts, nil, gossipMetrics, endpoint1)
	assert.NoError(t, err)
	g3, err := NewGossipComponent(peerIdentity, endpoint3, s3, secAdv, cryptSvc,
		defaultSecureDialOpts, nil, gossipMetrics, endpoint1)
	assert.NoError(t, err)
	defer g1.Stop()
	defer g2.Stop()
	defer g3.Stop()
	go s1.Serve(ll1)
	go s2.Serve(ll2)
	go s3.Serve(ll3)
}

func setupTestEnv() {
	viper.SetConfigName("core")
	viper.SetEnvPrefix("CORE")
	configtest.AddDevConfigPath(nil)
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()
	err := viper.ReadInConfig()
	if err != nil { // Handle errors reading the config file
		panic(fmt.Errorf("fatal error config file: %s", err))
	}
}

type secAdviser struct {
}

func (sa *secAdviser) OrgByPeerIdentity(api.PeerIdentityType) api.OrgIdentityType {
	return api.OrgIdentityType("SampleOrg")
}

type cryptoService struct {
}

func (s *cryptoService) Expiration(peerIdentity api.PeerIdentityType) (time.Time, error) {
	return time.Now().Add(time.Hour), nil
}

func (s *cryptoService) GetPKIidOfCert(peerIdentity api.PeerIdentityType) common.PKIidType {
	return common.PKIidType(peerIdentity)
}

func (s *cryptoService) VerifyBlock(chainID common.ChainID, seqNum uint64, signedBlock []byte) error {
	return nil
}

func (s *cryptoService) Sign(msg []byte) ([]byte, error) {
	return msg, nil
}

func (s *cryptoService) Verify(peerIdentity api.PeerIdentityType, signature, message []byte) error {
	return nil
}

func (s *cryptoService) VerifyByChannel(chainID common.ChainID, peerIdentity api.PeerIdentityType, signature, message []byte) error {
	return nil
}

func (s *cryptoService) ValidateIdentity(peerIdentity api.PeerIdentityType) error {
	return nil
}
