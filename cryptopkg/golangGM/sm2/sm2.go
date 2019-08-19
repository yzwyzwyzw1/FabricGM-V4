/*
编写者:严志伟
编写时间:2018/08/01
公司:中国搜索信息科技股份有限公司

*/


/*

椭圆曲线加解密及签名算法的技术原理及其Go语言实现:http://www.jeepyurongfu.net/blog/45309.html
 */

package sm2

import "C"
import (
	"bytes"
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/chinaso/fabricGM/cryptopkg/golangGM/sm3"
	"io"
	"math/big"
)

const (
	aesIV = "IV for <SM2> CTR"
)

// -------------------------------------------------- //
// PublicKey represents an SM2 public key.
type PublicKey struct {
	elliptic.Curve
	//SM2P256Curve
	//sm2p256Curve
	X, Y *big.Int
}

// PrivateKey represents an Sm2 private key.
type PrivateKey struct {
	PublicKey
	D *big.Int
}

type sm2Signature struct {
	R, S *big.Int
}

// -------------------------------------------------- //


var errNoOneParam = errors.New("zero parameter")

var ONE = new(big.Int).SetInt64(1)

var (
	default_IDA = []byte{0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38}
)

// Public returns the public key corresponding to priv.
func (priv *PrivateKey) Public() crypto.PublicKey {
	return &priv.PublicKey
}




// GenerateKey generates a public and private key pair.
func GenerateKey(rand io.Reader) (*PrivateKey, error) {

	c := SM2P256()

	k, err := randFieldElement(c, rand)
	fmt.Println(k)
	if err != nil {
		return nil, err
	}
	priv := new(PrivateKey)
	priv.PublicKey.Curve= c
	priv.D = k

	priv.PublicKey.X, priv.PublicKey.Y = c.ScalarBaseMult(k.Bytes())
	return priv, nil
}



func randFieldElement(c elliptic.Curve, rand io.Reader) (k *big.Int, err error) {
	//params := c.Curve.Params()
	params := c.Params()

	b := make([]byte, params.BitSize/8+8)
	_, err = io.ReadFull(rand, b)
	if err != nil {
		return
	}
	k = new(big.Int).SetBytes(b)
	n := new(big.Int).Sub(params.N, ONE)
	k.Mod(k, n)
	k.Add(k, ONE)
	return
}


// -------------------------------------------------- //
//  SM2原理:https://blog.csdn.net/samsho2/article/details/80772228
//  国密标准:http://c.gb688.cn/bzgk/gb/showGb?type=online&hcno=370AF152CB5CA4A377EB4D1B21DECAE0

// ZA=H256(ENTLA || IDA || a || b || xG || yG|| xA || yA)
func ZA(pub *PublicKey, IDA []byte) ([]byte, error) {

	if len(IDA) <= 0 {
		IDA = default_IDA
	}
	entlenA := len(IDA)
	if entlenA >= 8192 {
		return []byte{}, errors.New("SM2: uid too large")
	}

	sm2util :=sm2P256Util{}
	ENTLA := uint16(8*entlenA)
	ZA := sm3.New()
	ZA.Write([]byte{byte((ENTLA >> 8) & 0xFF)})
	ZA.Write([]byte{byte(ENTLA & 0xFF)})
	ZA.Write(IDA)
	ZA.Write(sm2util.p256ToBig(&sm2p256Params.a).Bytes())
	//ZA.Write(sm2p256Params.A.Bytes())
	ZA.Write(sm2p256Params.B.Bytes())
	ZA.Write(sm2p256Params.Gx.Bytes())
	ZA.Write(sm2p256Params.Gy.Bytes())

	xBuf := pub.X.Bytes()
	yBuf := pub.Y.Bytes()

	if n := len(xBuf); n < 32 {
		xBuf = append(zeroByteSlice()[:32-n], xBuf...)
	}
	ZA.Write(xBuf)
	ZA.Write(yBuf)


	return ZA.Sum(nil)[:32], nil
}


// 32byte
func zeroByteSlice() []byte {
	return []byte{
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
	}
}


// sign format = 30 + len(z) + 02 + len(r) + r + 02 + len(s) + s, z being what follows its size, ie 02+len(r)+r+02+len(s)+s
func (priv *PrivateKey) Sign(rand io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error) {
	// r, s, err := Sign(priv, msg)
	r, s, err := SM2Sign(priv, msg, nil)
	fmt.Println("msg:",msg)

	if err != nil {
		return nil, err
	}
	return asn1.Marshal(sm2Signature{r, s})
}


// ---------------------------------------------------------------- //

func (pub *PublicKey) Verify(msg []byte, sign []byte) bool {
	var sm2Sign sm2Signature

	_, err := asn1.Unmarshal(sign, &sm2Sign)
	if err != nil {
		return false
	}

	return SM2Verify(pub, msg, nil, sm2Sign.R, sm2Sign.S)

}


// ---------------------------------------------------------------- //
func (pub *PublicKey) Encrypt(data []byte) ([]byte, error) {
	return SM2Encrypt(pub, data)
}

func (priv *PrivateKey) Decrypt(data []byte) ([]byte, error) {
	return SM2Decrypt(priv, data)
}


// -------------------------------------------------------------- //

// 参考网址:https://blog.csdn.net/samsho2/article/details/80772228
func SM2Sign(priv *PrivateKey, msg, IDA []byte) (r, s *big.Int, err error) {
	za, err := ZA(&priv.PublicKey, IDA)
	if err != nil {
		return nil, nil, err
	}
	e, err := hashMsg(za, msg)
	if err != nil {
		return nil, nil, err
	}
	//c := priv.PublicKey.sm2p256Curve
	c := priv.PublicKey.Curve
	N := c.Params().N
	if N.Sign() == 0 {
		return nil, nil, errNoOneParam
	}
	var k *big.Int
	for { // 调整算法细节以实现SM2


        // r = e + x  mod n
		for {
			k, err = randFieldElement(c, rand.Reader)
			if err != nil {
				r = nil
				return
			}
			r, _ = priv.Curve.ScalarBaseMult(k.Bytes())
			r.Add(r, e)
			r.Mod(r, N)
			if r.Sign() != 0 {
				if t := new(big.Int).Add(r, k); t.Cmp(N) != 0 {
					break
				}
			}

		}

		//s=(1+d)^(-1)  * (k - r*d) mod n
		rD := new(big.Int).Mul(priv.D, r)
		s = new(big.Int).Sub(k, rD)
		d1 := new(big.Int).Add(priv.D, ONE)
		d1Inv := new(big.Int).ModInverse(d1, N)
		s.Mul(s, d1Inv)
		s.Mod(s, N)

		if s.Sign() != 0 {
			break
		}
	}
	return
}



func hashMsg(za, msg []byte) (*big.Int, error) {
	e := sm3.New()
	e.Write(za)
	e.Write(msg)
	return new(big.Int).SetBytes(e.Sum(nil)[:32]), nil
}




// Verify verifies the signature in r, s of hash using the public key, pub. Its
// return value records whether the signature is valid.
func SM2Verify(pub *PublicKey, msg, IDA []byte, r, s *big.Int) bool {
	c := pub.Curve
	N := c.Params().N

	one := new(big.Int).SetInt64(1)
	if r.Cmp(one) < 0 || s.Cmp(one) < 0 {
		return false
	}
	if r.Cmp(N) >= 0 || s.Cmp(N) >= 0 {
		return false
	}

	//M=ZA || Msg
   ZA,err := ZA(pub,IDA)
   if err != nil {
   	return false
	}

   // e =H(M)
   e,err := hashMsg(ZA,msg)
	if err != nil {
		return false
	}

   // t= (r+s) mod n
	t := new(big.Int).Add(r, s)
	t.Mod(t, N)
	if t.Sign() == 0 {
		return false
	}

	// 计算椭圆曲线点C1＝[k]G＝(x1,y1)。其中G代表椭圆曲线的一个基点，其阶为素数，
	// k为整数，[k]G表示k倍点，(x1,y1)表示所计算出的椭圆曲线点C1的坐标

	//(x,y) = [s]G+[t]P
	var x *big.Int
	x1, y1 := c.ScalarBaseMult(s.Bytes()) //[s]G =p
	x2, y2 := c.ScalarMult(pub.X, pub.Y, t.Bytes())//[t]P=t*(px,py)
	x, _ = c.Add(x1, y1, x2, y2)

	//R=(e+x) modn
	x.Add(x, e)
	x.Mod(x, N)

	//R ?= r
	return x.Cmp(r) == 0
}




//　设私钥、公钥分别为k、K，即K = kG，其中G为G点。
// 公钥加密：
//　选择随机数r，将消息M生成密文C，该密文是一个点对，即：
//　C = {rG, M+rK}，其中K为公钥

func SM2Encrypt(pub *PublicKey, plaintest []byte) ([]byte, error){

	length := len(plaintest)

	for {
		c := []byte{}
		//curve := pub.sm2p256Curve
		curve := pub.Curve
		//获得随机数k
		k, err := randFieldElement(curve, rand.Reader)
		if err != nil {
			return nil, err
		}

       //(x,y) = [k]P
		x1, y1 := curve.ScalarBaseMult(k.Bytes())
		x2, y2 := curve.ScalarMult(pub.X, pub.Y, k.Bytes())

		x1Buf := x1.Bytes()
		y1Buf := y1.Bytes()
		x2Buf := x2.Bytes()
		y2Buf := y2.Bytes()

		if n := len(x1Buf); n < 32 {
			x1Buf = append(zeroByteSlice()[:32-n], x1Buf...)
		}
		if n := len(y1Buf); n < 32 {
			y1Buf = append(zeroByteSlice()[:32-n], y1Buf...)
		}
		if n := len(x2Buf); n < 32 {
			x2Buf = append(zeroByteSlice()[:32-n], x2Buf...)
		}
		if n := len(y2Buf); n < 32 {
			y2Buf = append(zeroByteSlice()[:32-n], y2Buf...)
		}

		//c1
		c = append(c, x1Buf...) // x分量
		c = append(c, y1Buf...) // y分量

		//hash(x || M || y)
		tm := []byte{}
		tm = append(tm, x2Buf...)
		tm = append(tm, plaintest...)
		tm = append(tm, y2Buf...)
		c3 := sm3.Sum(tm)


		c = append(c, c3...)

		ct, ok := kdf(x2Buf, y2Buf, length) // 密文
		if !ok {
			continue
		}
		c = append(c, ct...)
		for i := 0; i < length; i++ {
			c[96+i] ^= plaintest[i] //c2
		}

		//C = C1 || C2 || C3
		return append([]byte{0x04}, c...), nil
	}

}

/*
获取随机数 k
(x1, y1) = [k]G
S=[h]P //h为余因子
C1=(x2,y2)= [k]P
t=KDF(x2||y2,klen);//klen为M的长度。KDF是sm2的密钥派生函数
c2 = M+t
C3 = Hash(x2||M||y2)
C = C1||C2||C3
*/

//国密SM2算法密钥派生函数KDF的实现:https://blog.csdn.net/Heidlyn/article/details/53993002
//作用是从一个共享的比特位派生出密钥数据
func kdf(x, y []byte, length int) ([]byte, bool) {
	var c []byte

	//ct := intToBytes(1)//ct=0x00000001
	ct := 1
	h := sm3.New()
	x = append(x, y...) //Z
	for i, j := 0, (length+31)/32; i < j; i++ { // ct 从 1 到 klen/v

		// Hash(Z || ct )
		h.Reset()
		h.Write(x)
		h.Write(intToBytes(ct))
		hash := h.Sum(nil)

		if i+1 == j && length%32 != 0 {
			c = append(c, hash[:length%32]...)
		} else {
			c = append(c, hash...)
		}
		ct++
	}
	for i := 0; i < length; i++ {
		if c[i] != 0 {
			return c, true
		}
	}
	return c, false
}

func intToBytes(x int) []byte {
	var buf = make([]byte, 4)

	binary.BigEndian.PutUint32(buf, uint32(x))
	return buf
}


/*
C1 = C里面获取 ，验证C1是否满足椭圆曲线。//C2长度确定，可以获取C1内容。
S=[h]C1，S为无穷点，退出。
(x2,y2)=[d]C1
t=KDF(m2||y2,klen)
M' = C2+t
u=Hash(x2||M'||y2), u ?= C3
M`为明文
*/

//SM2 解密运算
func SM2Decrypt(priv *PrivateKey, ciphertext []byte) ([]byte, error) {
	ciphertext = ciphertext[1:]
	length := len(ciphertext) - 96
	curve := priv.Curve
	x := new(big.Int).SetBytes(ciphertext[:32])
	y := new(big.Int).SetBytes(ciphertext[32:64])

	// (x2,y2) = [dB]C1  C1=(x,y)
	x2, y2 := curve.ScalarMult(x, y, priv.D.Bytes())
	x2Buf := x2.Bytes()
	y2Buf := y2.Bytes()


	if n := len(x2Buf); n < 32 {
		x2Buf = append(zeroByteSlice()[:32-n], x2Buf...)
	}
	if n := len(y2Buf); n < 32 {
		y2Buf = append(zeroByteSlice()[:32-n], y2Buf...)
	}
	// t = KDF(x2 || y2 ,klen)
	t, ok := kdf(x2Buf, y2Buf, length)


	if !ok {
		return nil, errors.New("Decrypt: failed to decrypt")
	}


	for i := 0; i < length; i++ {
		t[i] ^= ciphertext[i+96]
	}

	//U = Hash(x2 || M || y)
	tm := []byte{}
	tm = append(tm, x2Buf...)
	tm = append(tm, t...)
	tm = append(tm, y2Buf...)
	h := sm3.Sum(tm)
	if bytes.Compare(h, ciphertext[64:96]) != 0 {
		return t, errors.New("Decrypt: failed to decrypt")
	}
	return t, nil
}

type zr struct {
	io.Reader
}

func (z *zr) Read(dst []byte) (n int, err error) {
	for i := range dst {
		dst[i] = 0
	}
	return len(dst), nil
}

var zeroReader = &zr{}

func getLastBit(a *big.Int) uint {
	return a.Bit(0)
}
func Compress(a *PublicKey) []byte {
	buf := []byte{}
	yp := getLastBit(a.Y)
	buf = append(buf, a.X.Bytes()...)
	if n := len(a.X.Bytes()); n < 32 {
		buf = append(zeroByteSlice()[:(32-n)], buf...)
	}
	buf = append([]byte{byte(yp)}, buf...)
	return buf
}

func Decompress(a []byte) *PublicKey {
	var aa, xx, xx3 sm2P256FieldElement

	SM2P256()
	x := new(big.Int).SetBytes(a[1:])
	curve := sm2p256Params

	sm2util :=sm2P256Util{}
	sm2util.p256FromBig(&xx, x)
	sm2util.p256Square(&xx3, &xx)       // x3 = x ^ 2
	sm2util.p256Mul(&xx3, &xx3, &xx)    // x3 = x ^ 2 * x
	sm2util.p256Mul(&aa, &curve.a, &xx) // a = a * x
	sm2util.p256Add(&xx3, &xx3, &aa)
	sm2util.p256Add(&xx3, &xx3, &curve.b)

	y2 := sm2util.p256ToBig(&xx3)
	y := new(big.Int).ModSqrt(y2, sm2p256Params.P)
	if getLastBit(y) != uint(a[0]) {
		y.Sub(sm2p256Params.P, y)
	}
	return &PublicKey{
		Curve: SM2P256(),
		X:     x,
		Y:     y,
	}
}





// ------------------------------------ //

const (
	BitSize    = 256
	KeyBytes   = (BitSize + 7) / 8
	UnCompress = 0x04
)

func (pub *PublicKey) GetUnCompressBytes() []byte {
	xBytes := pub.X.Bytes()
	yBytes := pub.Y.Bytes()
	xl := len(xBytes)
	yl := len(yBytes)

	raw := make([]byte, 1+KeyBytes*2)
	raw[0] = UnCompress
	if xl > KeyBytes {
		copy(raw[1:1+KeyBytes], xBytes[xl-KeyBytes:])
	} else if xl < KeyBytes {
		copy(raw[1+(KeyBytes-xl):1+KeyBytes], xBytes)
	} else {
		copy(raw[1:1+KeyBytes], xBytes)
	}

	if yl > KeyBytes {
		copy(raw[1+KeyBytes:], yBytes[yl-KeyBytes:])
	} else if yl < KeyBytes {
		copy(raw[1+KeyBytes+(KeyBytes-yl):], yBytes)
	} else {
		copy(raw[1+KeyBytes:], yBytes)
	}
	return raw
}

func (pub *PublicKey) GetRawBytes() []byte {
	raw := pub.GetUnCompressBytes()
	return raw[1:]
}