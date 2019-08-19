package idemix

//
//// GMVer verifies an idemix signature
//// Disclosure steers which attributes it expects to be disclosed
//// attributeValues contains the desired attribute values.
//// This function will check that if attribute i is disclosed, the i-th attribute equals attributeValues[i].
//func (sig *Signature) GMVer(Disclosure []byte, ipk *IssuerPublicKey, msg []byte, attributeValues []*FP256BN.BIG, rhIndex int, revPk *sm2.PublicKey, epoch int) error {
//	// Validate inputs
//	if ipk == nil || revPk == nil {
//		return errors.Errorf("cannot verify idemix signature: received nil input")
//	}
//
//	if rhIndex < 0 || rhIndex >= len(ipk.AttributeNames) || len(Disclosure) != len(ipk.AttributeNames) {
//		return errors.Errorf("cannot verify idemix signature: received invalid input")
//	}
//
//	if sig.NonRevocationProof.RevocationAlg != int32(ALG_NO_REVOCATION) && Disclosure[rhIndex] == 1 {
//		return errors.Errorf("Attribute %d is disclosed but is also used as revocation handle, which should remain hidden.", rhIndex)
//	}
//
//	HiddenIndices := hiddenIndices(Disclosure)
//
//	// Parse signature
//	APrime := EcpFromProto(sig.GetAPrime())
//	ABar := EcpFromProto(sig.GetABar())
//	BPrime := EcpFromProto(sig.GetBPrime())
//	Nym := EcpFromProto(sig.GetNym())
//	ProofC := FP256BN.FromBytes(sig.GetProofC())
//	ProofSSk := FP256BN.FromBytes(sig.GetProofSSk())
//	ProofSE := FP256BN.FromBytes(sig.GetProofSE())
//	ProofSR2 := FP256BN.FromBytes(sig.GetProofSR2())
//	ProofSR3 := FP256BN.FromBytes(sig.GetProofSR3())
//	ProofSSPrime := FP256BN.FromBytes(sig.GetProofSSPrime())
//	ProofSRNym := FP256BN.FromBytes(sig.GetProofSRNym())
//	ProofSAttrs := make([]*FP256BN.BIG, len(sig.GetProofSAttrs()))
//
//	if len(sig.ProofSAttrs) != len(HiddenIndices) {
//		return errors.Errorf("signature invalid: incorrect amount of s-values for AttributeProofSpec")
//	}
//	for i, b := range sig.ProofSAttrs {
//		ProofSAttrs[i] = FP256BN.FromBytes(b)
//	}
//	Nonce := FP256BN.FromBytes(sig.GetNonce())
//
//	// Parse issuer public key
//	W := Ecp2FromProto(ipk.W)
//	HRand := EcpFromProto(ipk.HRand)
//	HSk := EcpFromProto(ipk.HSk)
//
//	// Verify signature
//	if APrime.Is_infinity() {
//		return errors.Errorf("signature invalid: APrime = 1")
//	}
//	temp1 := FP256BN.Ate(W, APrime)
//	temp2 := FP256BN.Ate(GenG2, ABar)
//	temp2.Inverse()
//	temp1.Mul(temp2)
//	if !FP256BN.Fexp(temp1).Isunity() {
//		return errors.Errorf("signature invalid: APrime and ABar don't have the expected structure")
//	}
//
//	// Verify ZK proof
//
//	// Recover t-values
//
//	// Recompute t1
//	t1 := APrime.Mul2(ProofSE, HRand, ProofSR2)
//	temp := FP256BN.NewECP()
//	temp.Copy(ABar)
//	temp.Sub(BPrime)
//	t1.Sub(FP256BN.G1mul(temp, ProofC))
//
//	// Recompute t2
//	t2 := FP256BN.G1mul(HRand, ProofSSPrime)
//	t2.Add(BPrime.Mul2(ProofSR3, HSk, ProofSSk))
//	for i := 0; i < len(HiddenIndices)/2; i++ {
//		t2.Add(EcpFromProto(ipk.HAttrs[HiddenIndices[2*i]]).Mul2(ProofSAttrs[2*i], EcpFromProto(ipk.HAttrs[HiddenIndices[2*i+1]]), ProofSAttrs[2*i+1]))
//	}
//	if len(HiddenIndices)%2 != 0 {
//		t2.Add(FP256BN.G1mul(EcpFromProto(ipk.HAttrs[HiddenIndices[len(HiddenIndices)-1]]), ProofSAttrs[len(HiddenIndices)-1]))
//	}
//	temp = FP256BN.NewECP()
//	temp.Copy(GenG1)
//	for index, disclose := range Disclosure {
//		if disclose != 0 {
//			temp.Add(FP256BN.G1mul(EcpFromProto(ipk.HAttrs[index]), attributeValues[index]))
//		}
//	}
//	t2.Add(FP256BN.G1mul(temp, ProofC))
//
//	// Recompute t3
//	t3 := HSk.Mul2(ProofSSk, HRand, ProofSRNym)
//	t3.Sub(Nym.Mul(ProofC))
//
//	// add contribution from the non-revocation proof
//	nonRevokedVer, err := getNonRevocationVerifier(RevocationAlgorithm(sig.NonRevocationProof.RevocationAlg))
//	if err != nil {
//		return err
//	}
//
//	i := sort.SearchInts(HiddenIndices, rhIndex)
//	proofSRh := ProofSAttrs[i]
//	nonRevokedProofBytes, err := nonRevokedVer.recomputeFSContribution(sig.NonRevocationProof, ProofC, Ecp2FromProto(sig.RevocationEpochPk), proofSRh)
//	if err != nil {
//		return err
//	}
//
//	// Recompute challenge
//	// proofData is the data being hashed, it consists of:
//	// the signature label
//	// 7 elements of G1 each taking 2*FieldBytes+1 bytes
//	// one bigint (hash of the issuer public key) of length FieldBytes
//	// disclosed attributes
//	// message that was signed
//	proofData := make([]byte, len([]byte(signLabel))+7*(2*FieldBytes+1)+FieldBytes+len(Disclosure)+len(msg)+ProofBytes[RevocationAlgorithm(sig.NonRevocationProof.RevocationAlg)])
//	index := 0
//	index = appendBytesString(proofData, index, signLabel)
//	index = appendBytesG1(proofData, index, t1)
//	index = appendBytesG1(proofData, index, t2)
//	index = appendBytesG1(proofData, index, t3)
//	index = appendBytesG1(proofData, index, APrime)
//	index = appendBytesG1(proofData, index, ABar)
//	index = appendBytesG1(proofData, index, BPrime)
//	index = appendBytesG1(proofData, index, Nym)
//	index = appendBytes(proofData, index, nonRevokedProofBytes)
//	copy(proofData[index:], ipk.Hash)
//	index = index + FieldBytes
//	copy(proofData[index:], Disclosure)
//	index = index + len(Disclosure)
//	copy(proofData[index:], msg)
//
//	c := HashModOrder(proofData)
//	index = 0
//	proofData = proofData[:2*FieldBytes]
//	index = appendBytesBig(proofData, index, c)
//	index = appendBytesBig(proofData, index, Nonce)
//
//	if *ProofC != *HashModOrder(proofData) {
//		// This debug line helps identify where the mismatch happened
//		idemixLogger.Debugf("Signature Verification : \n"+
//			"	[t1:%v]\n,"+
//			"	[t2:%v]\n,"+
//			"	[t3:%v]\n,"+
//			"	[APrime:%v]\n,"+
//			"	[ABar:%v]\n,"+
//			"	[BPrime:%v]\n,"+
//			"	[Nym:%v]\n,"+
//			"	[nonRevokedProofBytes:%v]\n,"+
//			"	[ipk.Hash:%v]\n,"+
//			"	[Disclosure:%v]\n,"+
//			"	[msg:%v]\n,",
//			EcpToBytes(t1),
//			EcpToBytes(t2),
//			EcpToBytes(t3),
//			EcpToBytes(APrime),
//			EcpToBytes(ABar),
//			EcpToBytes(BPrime),
//			EcpToBytes(Nym),
//			nonRevokedProofBytes,
//			ipk.Hash,
//			Disclosure,
//			msg)
//		return errors.Errorf("signature invalid: zero-knowledge proof is invalid")
//	}
//
//	// Signature is valid
//	return nil
//}
