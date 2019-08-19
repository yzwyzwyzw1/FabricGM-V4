package gmsw

import (
	"crypto/elliptic"
	"crypto/rand"
	"encoding/asn1"
	"fmt"
	"github.com/chinaso/fabricGM/bccsp/gmutil"
	"github.com/chinaso/fabricGM/cryptopkg/golangGM/sm2"
	"github.com/chinaso/fabricGM/cryptopkg/golangGM/sm3"
	"github.com/stretchr/testify/assert"
	"math/big"
	"testing"
)

func TestSignSM2BadParameter(t *testing.T) {
	// Generate a key
	lowLevelPrivateKey,err := sm2.GenerateKey(rand.Reader)
	assert.NoError(t,err)

	// Induce an error on the underlying ecdsa algorithm
	msg := []byte("hello world")
	oldN :=lowLevelPrivateKey.Curve.Params().N
    defer func() {lowLevelPrivateKey.Curve.Params().N = oldN}()

	fmt.Println(msg)
	lowLevelPrivateKey.Curve.Params().N = big.NewInt(0)

	_,err =signSM2(lowLevelPrivateKey,msg,nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "zero parameter")  //捕捉错误输出
	lowLevelPrivateKey.Curve.Params().N = oldN

}
type SM2Signature struct {
	R,S *big.Int
}
func TestMarshal(t *testing.T) {
	lowLevelPrivateKey, _ := sm2.GenerateKey(rand.Reader)
	msg := []byte("hello world")
	sigma, _ := signSM2(lowLevelPrivateKey, msg, nil)
	fmt.Println("sigma",sigma)


	sig := new(SM2Signature)
	_, err := asn1.Unmarshal(sigma, sig)
	if err != nil {
		fmt.Println("err")
	}
	sigma2,err := asn1.Marshal(SM2Signature{sig.R,sig.S})
	fmt.Println("sigma2",sigma2)
	assert.Equal(t,sigma,sigma2)
}

func TestVerifySM2(t *testing.T) {
	t.Parallel()

	// Generate a key
	lowLevelPrivateKey, err := sm2.GenerateKey(rand.Reader)
	assert.NoError(t,err)

	msg := []byte("hello world")
	sigma, err := signSM2(lowLevelPrivateKey, msg, nil)
	assert.NoError(t, err)

	fmt.Println(sigma)

	fmt.Println("lowLevelPrivateKey",lowLevelPrivateKey)
	valid, err := verifySM2(&lowLevelPrivateKey.PublicKey, sigma, msg, nil)
	assert.NoError(t, err)
	assert.True(t, valid)

    fmt.Println("222",sigma)
	R, S, err := gmutil.UnmarshalSM2Signature(sigma)
	assert.NoError(t, err)

	//GetCurveHalfOrdersAtsm2
	//S.Add(utils.GetCurveHalfOrdersAt(elliptic.P256()), big.NewInt(1))
	S.Add(gmutil.GetCurveHalfOrdersAtsm2(sm2.SM2P256()), big.NewInt(1)) //这句话的作用是故意修改S,要求得到的sig值只有一般会变化

	sigmaWrongS, err := gmutil.MarshalSM2Signature(R, S)
	fmt.Println("111",sigmaWrongS)
	//

	// 暂且不支持脆弱密钥
	//assert.NoError(t, err)
	//_, err = verifySM2(&lowLevelPrivateKey.PublicKey, sigmaWrongS, msg, nil)
	//assert.Error(t, err)
	//assert.Contains(t, err.Error(), "Invalid S. Must be smaller than half the order [")
}


func TestSm2Sign(t *testing.T) {

	// Generate a key
	lowLevelPrivateKey, err := sm2.GenerateKey(rand.Reader)
	assert.NoError(t,err)
	msg := []byte("hello world")
	digest,err :=signSM2(lowLevelPrivateKey,msg,nil)
	fmt.Println("digest:",digest)

}

func TestSm2Verify(t *testing.T) {

	// Generate a key
	lowLevelPrivateKey, err := sm2.GenerateKey(rand.Reader)
	assert.NoError(t,err)

	msg := []byte("hello world")
	digest,err :=signSM2(lowLevelPrivateKey,msg,nil)
	fmt.Println("digest:",digest)


	sk := &sm2PrivateKey{lowLevelPrivateKey}
	//fmt.Println("sk",sk)

	//Sign
	signer := &sm2Signer{}
	sigma, err := signer.Sign(sk, msg, nil)
	//fmt.Println("sigma:",sigma)

	//fmt.Println("sk.privKey.PublicKey",sk.privKey.PublicKey)
	//fmt.Println("lowLevelPrivateKey.PublicKey",lowLevelPrivateKey.PublicKey)
	valid, err :=verifySM2(&(sk.privKey.PublicKey),sigma,msg,nil)
	assert.NoError(t, err)
	assert.True(t, valid)

}


func TestSM2SignerSign(t *testing.T) {

	t.Parallel()

	// Generate a key
	lowLevelPrivateKey, err := sm2.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	k := &sm2PrivateKey{lowLevelPrivateKey}
	assert.NoError(t, err)

	//Sign
	signer := &sm2Signer{}
	msg := []byte("Hello World")
	sigma, err := signer.Sign(k, msg, nil)
	fmt.Println("sigma",sigma)
	assert.NoError(t, err)
	assert.NotNil(t, sigma)


	//Verify
	valid, err := verifySM2(&lowLevelPrivateKey.PublicKey, sigma, msg, nil)
	assert.NoError(t, err)
	assert.True(t, valid)

	verifierPrivateKey := &sm2PrivateKeyVerifier{}
	valid, err = verifierPrivateKey.Verify(k, sigma, msg, nil)
	assert.NoError(t, err)
	assert.True(t, valid)

	verifierPublicKey := &sm2PublicKeyKeyVerifier{}
	pk, err := k.PublicKey()
	valid, err = verifierPublicKey.Verify(pk, sigma, msg, nil)
	assert.NoError(t, err)
	assert.True(t, valid)

}

//Testing默认一次执行四次
func TestSm2GenerateKey(t *testing.T) {
	t.Parallel()

	//Generate a key
	lowLevelPrivateKey, err := sm2.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	fmt.Println("lowLevelPrivateKey:",lowLevelPrivateKey)
	fmt.Println("lowLevelPublicKey:",lowLevelPrivateKey.PublicKey)
}

func TestSm2EncryptDecrypt(t *testing.T) {
	src := []byte{1,2,3,4,5,6,7,8,9,10}
	lowLevelPrivateKey, err := sm2.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	cipherText,err := sm2.SM2Encrypt(&lowLevelPrivateKey.PublicKey,src)
	assert.NoError(t, err)
	plainText,err := sm2.SM2Decrypt(lowLevelPrivateKey,cipherText)
	fmt.Println("plainText:",plainText)
	assert.Equal(t,src,plainText)

}

func TestSM2PrivateKey(t *testing.T) {
	t.Parallel()

	// Generate a key
	lowLevelPrivateKey, err := sm2.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	k := &sm2PrivateKey{lowLevelPrivateKey}

	assert.False(t, k.Symmetric())
	assert.True(t, k.Private())

	_, err = k.Bytes()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Not supported")


	fmt.Println("lowLevelPrivateKey:",lowLevelPrivateKey)
	fmt.Println("lowLevelPublicKey:",lowLevelPrivateKey.PublicKey)

	k.privKey = nil
	ski := k.SKI()
	assert.Nil(t, ski)

	k.privKey = lowLevelPrivateKey
	ski = k.SKI()
	raw,_:=sm2.MarshalSM2PrivateKey(k.privKey,nil)
	hash := sm3.New()
	hash.Write(raw)
	ski2 := hash.Sum(nil)
	assert.Equal(t, ski2, ski, "SKI is not computed in the right way.")

	pk, err := k.PublicKey()
	assert.NoError(t, err)
	assert.NotNil(t, pk)
	sm2PK, ok := pk.(*sm2PublicKey)

	assert.True(t, ok)
	assert.Equal(t, lowLevelPrivateKey.PublicKey, *sm2PK.pubKey)
}

func TestSM2PublicKey(t *testing.T) {
	t.Parallel()

	// Generate a key
	lowLevelPrivateKey, err := sm2.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	k := &sm2PublicKey{&lowLevelPrivateKey.PublicKey}

	assert.False(t, k.Symmetric())
	assert.False(t, k.Private())

	k.pubKey = nil
	ski := k.SKI()
	assert.Nil(t, ski)

	k.pubKey = &lowLevelPrivateKey.PublicKey
	ski = k.SKI()
	raw,_ := sm2.MarshalSM2PublicKey(k.pubKey)
	hash := sm3.New()
	hash.Write(raw)
	ski2 := hash.Sum(nil)
	assert.Equal(t, ski, ski2, "SKI is not computed in the right way.")

	pk, err := k.PublicKey()
	assert.NoError(t, err)
	assert.Equal(t, k, pk)

	bytes, err := k.Bytes()
	assert.NoError(t, err)
	bytes2,err := sm2.MarshalSM2PublicKey(k.pubKey)
	assert.Equal(t, bytes2, bytes, "bytes are not computed in the right way.")

	invalidCurve := &elliptic.CurveParams{Name: "P-Invalid"}
	invalidCurve.BitSize = 1024
	k.pubKey = &sm2.PublicKey{Curve: invalidCurve, X: big.NewInt(1), Y: big.NewInt(1)}

	//fmt.Println("k.pubKey",k.pubKey)
	//_, err = k.Bytes()
	//assert.Error(t, err)
	//assert.Contains(t, err.Error(), "Failed marshalling key [")

}
