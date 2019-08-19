// Copyright IBM Corp. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"github.com/chinaso/fabricGM/common/localmsp"
	"github.com/chinaso/fabricGM/common/tools/configtxgen/encoder"
	genesisconfig "github.com/chinaso/fabricGM/common/tools/configtxgen/localconfig"
	cb "github.com/chinaso/fabricGM/protos/common"
)

func newChainRequest(consensusType, creationPolicy, newChannelID string) *cb.Envelope {
	env, err := encoder.MakeChannelCreationTransaction(newChannelID, localmsp.NewSigner(), genesisconfig.Load(genesisconfig.SampleSingleMSPChannelProfile))
	if err != nil {
		panic(err)
	}
	return env
}
