/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package crypto

import (
	"github.com/chinaso/fabricGM/cryptopkg/golangGM/x509"
	"encoding/pem"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/chinaso/fabricGM/protos/msp"
)

// ExpiresAt returns when the given identity expires, or a zero time.Time
// in case we cannot determine that
func ExpiresAt(identityBytes []byte) time.Time {
	sId := &msp.SerializedIdentity{}
	// If protobuf parsing failed, we make no decisions about the expiration time
	if err := proto.Unmarshal(identityBytes, sId); err != nil {
		return time.Time{}
	}
	bl, _ := pem.Decode(sId.IdBytes)
	if bl == nil {
		// If the identity isn't a PEM block, we make no decisions about the expiration time
		return time.Time{}
	}
	cert, err := x509.ParseCertificate(bl.Bytes)
	if err != nil {
		return time.Time{}
	}
	return cert.NotAfter
}
