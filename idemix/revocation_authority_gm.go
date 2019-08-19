/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package idemix

//type GMRevocationAlgorithm int32
//
//const (
//	GMALG_NO_REVOCATION GMRevocationAlgorithm = iota
//)
//
//var GMProofBytes = map[GMRevocationAlgorithm]int{
//	GMALG_NO_REVOCATION: 0,
//}
//
//// GMGenerateLongTermRevocationKey generates a long term signing key that will be used for revocation
//func GMGenerateLongTermRevocationKey() (*sm2.PrivateKey, error) {
//	return sm2.GenerateKey(rand.Reader)
//}
//
//// GMCreateCRI creates the Credential Revocation Information for a certain time period (epoch).
//// Users can use the CRI to prove that they are not revoked.
//// Note that when not using revocation (i.e., alg = GMALG_NO_REVOCATION), the entered unrevokedHandles are not used,
//// and the resulting CRI can be used by any signer.
//func GMCreateCRI(key *sm2.PrivateKey, unrevokedHandles []*FP256BN.BIG, epoch int, alg GMRevocationAlgorithm, rng *amcl.RAND) (*CredentialRevocationInformation, error) {
//	if key == nil || rng == nil {
//		return nil, errors.Errorf("CreateCRI received nil input")
//	}
//	cri := &CredentialRevocationInformation{}
//	cri.RevocationAlg = int32(alg)
//	cri.Epoch = int64(epoch)
//
//	if alg == GMALG_NO_REVOCATION {
//		// put a dummy PK in the proto
//		cri.EpochPk = Ecp2ToProto(GenG2)
//	} else {
//		// create epoch key
//		_, epochPk := WBBKeyGen(rng)
//		cri.EpochPk = Ecp2ToProto(epochPk)
//	}
//
//	// sign epoch + epoch key with long term key
//	bytesToSign, err := proto.Marshal(cri)
//	if err != nil {
//		return nil, errors.Wrap(err, "failed to marshal CRI")
//	}
//
//	digest := sm3.Sum(bytesToSign)
//
//	cri.EpochPkSig, err = key.Sign(rand.Reader, digest[:], nil)
//	if err != nil {
//		return nil, err
//	}
//
//	if alg == GMALG_NO_REVOCATION {
//		return cri, nil
//	} else {
//		return nil, errors.Errorf("the specified revocation algorithm is not supported.")
//	}
//}
//
//// GMVerifyEpochPK verifies that the revocation PK for a certain epoch is valid,
//// by checking that it was signed with the long term revocation key.
//// Note that even if we use no revocation (i.e., alg = GMALG_NO_REVOCATION), we need
//// to verify the signature to make sure the issuer indeed signed that no revocation
//// is used in this epoch.
//func GMVerifyEpochPK(pk *sm2.PublicKey, epochPK *ECP2, epochPkSig []byte, epoch int, alg GMRevocationAlgorithm) error {
//	if pk == nil || epochPK == nil {
//		return errors.Errorf("EpochPK invalid: received nil input")
//	}
//	cri := &CredentialRevocationInformation{}
//	cri.RevocationAlg = int32(alg)
//	cri.EpochPk = epochPK
//	cri.Epoch = int64(epoch)
//	bytesToSign, err := proto.Marshal(cri)
//	if err != nil {
//		return err
//	}
//	digest := sm3.Sum(bytesToSign)
//
//	r, s, err := gmutil.UnmarshalSM2Signature(epochPkSig)
//	if err != nil {
//		return errors.Wrap(err, "failed to unmarshal ECDSA signature")
//	}
//
//	if !sm2.SM2Verify(pk, digest[:],nil, r, s) {
//		return errors.Errorf("EpochPKSig invalid")
//	}
//
//	return nil
//}
