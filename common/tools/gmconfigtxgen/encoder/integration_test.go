/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package encoder_test

import (
	"fmt"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/chinaso/fabricGM/common/channelconfig"
	"github.com/chinaso/fabricGM/common/tools/gmconfigtxgen/configtxgentest"
	"github.com/chinaso/fabricGM/common/tools/gmconfigtxgen/encoder"
	genesisconfig "github.com/chinaso/fabricGM/common/tools/gmconfigtxgen/localconfig"
	cb "github.com/chinaso/fabricGM/protos/common"

	"github.com/pkg/errors"
)

func hasModPolicySet(groupName string, cg *cb.ConfigGroup) error {
	if cg.ModPolicy == "" {
		return errors.Errorf("group %s has empty mod_policy", groupName)
	}

	for valueName, value := range cg.Values {
		if value.ModPolicy == "" {
			return errors.Errorf("group %s has value %s with empty mod_policy", groupName, valueName)
		}
	}

	for policyName, policy := range cg.Policies {
		if policy.ModPolicy == "" {
			return errors.Errorf("group %s has policy %s with empty mod_policy", groupName, policyName)
		}
	}

	for groupName, group := range cg.Groups {
		err := hasModPolicySet(groupName, group)
		if err != nil {
			return errors.WithMessage(err, fmt.Sprintf("missing sub-mod_policy for group %s", groupName))
		}
	}

	return nil
}

var _ = Describe("Integration", func() {
	for _, profile := range []string{
		genesisconfig.SampleInsecureSoloProfile,
		genesisconfig.SampleSingleMSPSoloProfile,
		genesisconfig.SampleDevModeSoloProfile,
		genesisconfig.SampleInsecureKafkaProfile,
		genesisconfig.SampleSingleMSPKafkaProfile,
		genesisconfig.SampleDevModeKafkaProfile,
	} {
		It(fmt.Sprintf("successfully parses the %s profile", profile), func() {
			config := configtxgentest.Load(profile)
			group, err := encoder.NewChannelGroup(config)
			Expect(err).NotTo(HaveOccurred())

			_, err = channelconfig.NewBundle("test", &cb.Config{
				ChannelGroup: group,
			})
			Expect(err).NotTo(HaveOccurred())

			err = hasModPolicySet("Channel", group)
			Expect(err).NotTo(HaveOccurred())
		})
	}
})
