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

package crypto

import (
	cb "github.com/chinaso/fabricGM/protos/common"
)

// FakeLocalSigner is a signer which already has identity an nonce set to fake values
var FakeLocalSigner = &LocalSigner{
	Identity: []byte("IdentityBytes"),
	Nonce:    []byte("NonceValue"),
}

// LocalSigner is a mock implementation of crypto.LocalSigner
type LocalSigner struct {
	Identity []byte
	Nonce    []byte
}

// Sign returns the msg, nil
func (ls *LocalSigner) Sign(msg []byte) ([]byte, error) {
	return msg, nil
}

// NewSignatureHeader returns a new signature header, nil
func (ls *LocalSigner) NewSignatureHeader() (*cb.SignatureHeader, error) {
	return &cb.SignatureHeader{
		Creator: ls.Identity,
		Nonce:   ls.Nonce,
	}, nil
}
