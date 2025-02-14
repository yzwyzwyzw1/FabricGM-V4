/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package idemix

import (
	"github.com/hyperledger/fabric-amcl/amcl"
	"github.com/hyperledger/fabric-amcl/amcl/FP256BN"
	"github.com/pkg/errors"
)

// credRequestLabel is the label used in zero-knowledge proof (ZKP) to identify that this ZKP is a credential request
const credRequestLabel = "credRequest"

// Credential issuance is an interactive protocol between a user and an issuer
// The issuer takes its secret and public keys and user attribute values as input
// The user takes the issuer public key and user secret as input
// The issuance protocol consists of the following steps:
// 1) The issuer sends a random nonce to the user
// 2) The user creates a Credential Request using the public key of the issuer, user secret, and the nonce as input
//    The request consists of a commitment to the user secret (can be seen as a public key) and a zero-knowledge proof
//     of knowledge of the user secret key
//    The user sends the credential request to the issuer
// 3) The issuer verifies the credential request by verifying the zero-knowledge proof
//    If the request is valid, the issuer issues a credential to the user by signing the commitment to the secret key
//    together with the attribute values and sends the credential back to the user
// 4) The user verifies the issuer's signature and stores the credential that consists of
//    the signature value, a randomness used to create the signature, the user secret, and the attribute values

// NewCredRequest creates a new Credential Request, the first message of the interactive credential issuance protocol
// (from user to issuer)
func NewCredRequest(sk *FP256BN.BIG, IssuerNonce []byte, ipk *IssuerPublicKey, rng *amcl.RAND) *CredRequest {
	// Set Nym as h_{sk}^{sk}
	HSk := EcpFromProto(ipk.HSk)
	Nym := HSk.Mul(sk)

	// generate a zero-knowledge proof of knowledge (ZK PoK) of the secret key

	// Sample the randomness needed for the proof
	rSk := RandModOrder(rng)

	// Step 1: First message (t-values)
	t := HSk.Mul(rSk) // t = h_{sk}^{r_{sk}}, cover Nym

	// Step 2: Compute the Fiat-Shamir hash, forming the challenge of the ZKP.
	// proofData is the data being hashed, it consists of:
	// the credential request label
	// 3 elements of G1 each taking 2*FieldBytes+1 bytes
	// hash of the issuer public key of length FieldBytes
	// issuer nonce of length FieldBytes
	proofData := make([]byte, len([]byte(credRequestLabel))+3*(2*FieldBytes+1)+2*FieldBytes)
	index := 0
	index = appendBytesString(proofData, index, credRequestLabel)
	index = appendBytesG1(proofData, index, t)
	index = appendBytesG1(proofData, index, HSk)
	index = appendBytesG1(proofData, index, Nym)
	index = appendBytes(proofData, index, IssuerNonce)
	copy(proofData[index:], ipk.Hash)
	proofC := HashModOrder("sha256",proofData)

	// Step 3: reply to the challenge message (s-values)
	proofS := Modadd(FP256BN.Modmul(proofC, sk, GroupOrder), rSk, GroupOrder) // s = r_{sk} + C \cdot sk

	// Done
	return &CredRequest{
		Nym:         EcpToProto(Nym),
		IssuerNonce: IssuerNonce,
		ProofC:      BigToBytes(proofC),
		ProofS:      BigToBytes(proofS)}
}

// Check cryptographically verifies the credential request
func (m *CredRequest) Check(ipk *IssuerPublicKey) error {
	Nym := EcpFromProto(m.GetNym())
	IssuerNonce := m.GetIssuerNonce()
	ProofC := FP256BN.FromBytes(m.GetProofC())
	ProofS := FP256BN.FromBytes(m.GetProofS())

	HSk := EcpFromProto(ipk.HSk)

	if Nym == nil || IssuerNonce == nil || ProofC == nil || ProofS == nil {
		return errors.Errorf("one of the proof values is undefined")
	}

	// Verify Proof

	// Recompute t-values using s-values
	t := HSk.Mul(ProofS)
	t.Sub(Nym.Mul(ProofC)) // t = h_{sk}^s / Nym^C

	// Recompute challenge
	proofData := make([]byte, len([]byte(credRequestLabel))+3*(2*FieldBytes+1)+2*FieldBytes)
	index := 0
	index = appendBytesString(proofData, index, credRequestLabel)
	index = appendBytesG1(proofData, index, t)
	index = appendBytesG1(proofData, index, HSk)
	index = appendBytesG1(proofData, index, Nym)
	index = appendBytes(proofData, index, IssuerNonce)
	copy(proofData[index:], ipk.Hash)

	if *ProofC != *HashModOrder("sha256",proofData) {
		return errors.Errorf("zero knowledge proof is invalid")
	}

	return nil
}
