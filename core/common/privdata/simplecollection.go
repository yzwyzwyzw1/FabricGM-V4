/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package privdata

import (
	"fmt"

	"github.com/golang/protobuf/proto"
	"github.com/chinaso/fabricGM/common/policies"
	"github.com/chinaso/fabricGM/msp"
	"github.com/chinaso/fabricGM/protos/common"
	m "github.com/chinaso/fabricGM/protos/msp"
	"github.com/pkg/errors"
)

// SimpleCollection implements a collection with static properties
// and a public member set
type SimpleCollection struct {
	name         string
	accessPolicy policies.Policy
	memberOrgs   []string
	conf         common.StaticCollectionConfig
}

type SimpleCollectionPersistenceConfigs struct {
	blockToLive uint64
}

// CollectionID returns the collection's ID
func (sc *SimpleCollection) CollectionID() string {
	return sc.name
}

// MemberOrgs returns the MSP IDs that are part of this collection
func (sc *SimpleCollection) MemberOrgs() []string {
	return sc.memberOrgs
}

// RequiredPeerCount returns the minimum number of peers
// required to send private data to
func (sc *SimpleCollection) RequiredPeerCount() int {
	return int(sc.conf.RequiredPeerCount)
}

func (sc *SimpleCollection) MaximumPeerCount() int {
	return int(sc.conf.MaximumPeerCount)
}

// AccessFilter returns the member filter function that evaluates signed data
// against the member access policy of this collection
func (sc *SimpleCollection) AccessFilter() Filter {
	return func(sd common.SignedData) bool {
		if err := sc.accessPolicy.Evaluate([]*common.SignedData{&sd}); err != nil {
			return false
		}
		return true
	}
}

func (sc *SimpleCollection) IsMemberOnlyRead() bool {
	return sc.conf.MemberOnlyRead
}

// Setup configures a simple collection object based on a given
// StaticCollectionConfig proto that has all the necessary information
func (sc *SimpleCollection) Setup(collectionConfig *common.StaticCollectionConfig, deserializer msp.IdentityDeserializer) error {
	if collectionConfig == nil {
		return errors.New("Nil config passed to collection setup")
	}
	sc.conf = *collectionConfig
	sc.name = collectionConfig.GetName()

	// get the access signature policy envelope
	collectionPolicyConfig := collectionConfig.GetMemberOrgsPolicy()
	if collectionPolicyConfig == nil {
		return errors.New("Collection config policy is nil")
	}
	accessPolicyEnvelope := collectionPolicyConfig.GetSignaturePolicy()
	if accessPolicyEnvelope == nil {
		return errors.New("Collection config access policy is nil")
	}

	err := sc.setupAccessPolicy(collectionPolicyConfig, deserializer)
	if err != nil {
		return err
	}

	// get member org MSP IDs from the envelope
	for _, principal := range accessPolicyEnvelope.Identities {
		switch principal.PrincipalClassification {
		case m.MSPPrincipal_ROLE:
			// Principal contains the msp role
			mspRole := &m.MSPRole{}
			err := proto.Unmarshal(principal.Principal, mspRole)
			if err != nil {
				return errors.Wrap(err, "Could not unmarshal MSPRole from principal")
			}
			sc.memberOrgs = append(sc.memberOrgs, mspRole.MspIdentifier)
		case m.MSPPrincipal_IDENTITY:
			principalId, err := deserializer.DeserializeIdentity(principal.Principal)
			if err != nil {
				return errors.Wrap(err, "Invalid identity principal, not a certificate")
			}
			sc.memberOrgs = append(sc.memberOrgs, principalId.GetMSPIdentifier())
		case m.MSPPrincipal_ORGANIZATION_UNIT:
			OU := &m.OrganizationUnit{}
			err := proto.Unmarshal(principal.Principal, OU)
			if err != nil {
				return errors.Wrap(err, "Could not unmarshal OrganizationUnit from principal")
			}
			sc.memberOrgs = append(sc.memberOrgs, OU.MspIdentifier)
		default:
			return errors.New(fmt.Sprintf("Invalid principal type %d", int32(principal.PrincipalClassification)))
		}
	}

	return nil
}

// setupAccessPolicy configures a simple collection object based on a given
// StaticCollectionConfig proto that has all the necessary information
func (sc *SimpleCollection) setupAccessPolicy(collectionPolicyConfig *common.CollectionPolicyConfig, deserializer msp.IdentityDeserializer) error {
	var err error
	sc.accessPolicy, err = getPolicy(collectionPolicyConfig, deserializer)
	return err
}

// BlockToLive return collection's block to live configuration
func (s *SimpleCollectionPersistenceConfigs) BlockToLive() uint64 {
	return s.blockToLive
}
