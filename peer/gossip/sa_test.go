/*
Copyright IBM Corp. 2017 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

		 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package gossip

import (
	"testing"

	"github.com/chinaso/fabricGM/msp"
	"github.com/chinaso/fabricGM/peer/gossip/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestMspSecurityAdvisor_OrgByPeerIdentity(t *testing.T) {
	dm := &mocks.DeserializersManager{
		LocalDeserializer: &mocks.IdentityDeserializer{Identity: []byte("Alice"), Msg: []byte("msg1"), Mock: mock.Mock{}},
		ChannelDeserializers: map[string]msp.IdentityDeserializer{
			"A": &mocks.IdentityDeserializer{Identity: []byte("Bob"), Msg: []byte("msg2"), Mock: mock.Mock{}},
		},
	}

	advisor := NewSecurityAdvisor(dm)
	assert.NotNil(t, advisor.OrgByPeerIdentity([]byte("Alice")))
	assert.NotNil(t, advisor.OrgByPeerIdentity([]byte("Bob")))
	assert.Nil(t, advisor.OrgByPeerIdentity([]byte("Charlie")))
	assert.Nil(t, advisor.OrgByPeerIdentity(nil))
}
