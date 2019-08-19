/*
编写者:严志伟
编写时间:2018/08/01
公司:中国搜索信息科技股份有限公司

*/
package sm2

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"testing"
	//"github.com/chinaso/fabricGM_V3_190801/cryptopkg/golangGM/sm3"
)

func TestP256(t *testing.T) {
	curve := SM2P256()
	fmt.Println(curve)
}

func TestGenerateKey(t *testing.T) {
	priv, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Error(err.Error())
		return
	}
	fmt.Printf("priv:%s\n", priv.D.Text(16))
	fmt.Printf("x:%s\n", priv.PublicKey.X.Text(16))
	fmt.Printf("y:%s\n", priv.PublicKey.Y.Text(16))

    //// curve := sm2.SM2P256()
	curve := SM2P256()
	if !curve.IsOnCurve(priv.PublicKey.X, priv.PublicKey.Y) {
		t.Error("x,y is not on Curve")
		return
	}
	fmt.Println("x,y is on sm2 Curve")
}

func TestGenerateKeyEqul(t *testing.T) {
	t.Parallel()
	PrivateKey, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Error(err.Error())
		return
	}

	PublicKey := new(PublicKey)
	PublicKey.Curve = SM2P256()
	PublicKey.X = PrivateKey.X
	PublicKey.Y = PrivateKey.Y
	fmt.Println("(pub1)",PrivateKey.PublicKey)
	fmt.Println("(pub2)",*PublicKey)
}


func TestSignerSignandVerify(t *testing.T) {
	in:="30450220213C6CD6EBD6A4D5C2D0AB38E29D441836D1457A8118D34864C247D727831962022100D9248480342AC8513CCDF0F89A2250DC8F6EB4F2471E144E9A812E0AF497F801"
	inBytes, _ := hex.DecodeString(in)
	priv, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Error(err.Error())
		return
	}

	//Sign
	sign,err :=priv.Sign(rand.Reader , inBytes,nil)
	fmt.Println(sign)

	//verify sign
	pub := &priv.PublicKey
	if !pub.Verify(inBytes,sign) {
		t.Error("verify sign filed!")
	}
	fmt.Println("s")

}

func TestEncryptDecrypt(t *testing.T) {
	src := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	priv, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Error(err.Error())
		return
	}

	cipherText, err := SM2Encrypt(&priv.PublicKey, src)
	if err != nil {
		t.Error(err.Error())
		return
	}
	fmt.Printf("cipher text:%s\n", hex.EncodeToString(cipherText))

	plainText, err := SM2Decrypt(priv, cipherText)
	if err != nil {
		t.Error(err.Error())
		return
	}
	fmt.Printf("plain text:%s\n", hex.EncodeToString(plainText))

	if !bytes.Equal(plainText, src) {
		t.Error("decrypt result not equal expected")
		return
	}
}


func TestSM2(t *testing.T) {
	priv, err := GenerateKey(rand.Reader) // 生成密钥对

	fmt.Println("priv.X", priv.X)
	fmt.Println("priv.Y", priv.Y)
	fmt.Println("priv.D", priv.D)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%v\n", priv.Curve.IsOnCurve(priv.X, priv.Y)) // 验证是否为sm2的曲线
	pub := &priv.PublicKey
	msg := []byte("123456")
	d0, err := pub.Encrypt(msg)
	if err != nil {
		fmt.Printf("Error: failed to encrypt %s: %v\n", msg, err)
		return
	}
	// fmt.Printf("Cipher text = %v\n", d0)
	d1, err := priv.Decrypt(d0)
	if err != nil {
		fmt.Printf("Error: failed to decrypt: %v\n", err)
	}
	fmt.Printf("clear text = %s\n", d1)
	ok, err := WritePrivateKeytoPem("priv.pem", priv, nil) // 生成密钥文件
	if ok != true {
		log.Fatal(err)
	}
	pubKey, _ := priv.Public().(*PublicKey)
	//pubKey, _ := priv.Public().(*PublicKey)
	ok, err = WritePublicKeytoPem("pub.pem", pubKey, nil) // 生成公钥文件
	if ok != true {
		log.Fatal(err)
	}
	msg = []byte("test")
	err = ioutil.WriteFile("ifile", msg, os.FileMode(0644)) // 生成测试文件
	if err != nil {
		log.Fatal(err)
	}
	privKey, err := ReadPrivateKeyFromPem("priv.pem", nil) // 读取密钥
	if err != nil {
		log.Fatal(err)
	}
	pubKey, err = ReadPublicKeyFromPem("pub.pem", nil) // 读取公钥
	if err != nil {
		log.Fatal(err)
	}
	msg, _ = ioutil.ReadFile("ifile")                // 从文件读取数据
	sign, err := privKey.Sign(rand.Reader, msg, nil) // 签名
	if err != nil {
		log.Fatal(err)
	}
	err = ioutil.WriteFile("ofile", sign, os.FileMode(0644))
	if err != nil {
		log.Fatal(err)
	}
	signdata, _ := ioutil.ReadFile("ofile")
	ok = privKey.Verify(msg, signdata) // 密钥验证
	if ok != true {
		fmt.Printf("Verify error\n")
	} else {
		fmt.Printf("Verify ok\n")
	}
	ok = pubKey.Verify(msg, signdata) // 公钥验证
	if ok != true {
		fmt.Printf("Verify error\n")
	} else {
		fmt.Printf("Verify ok\n")
	}

}

func BenchmarkSM2(t *testing.B) {
	t.ReportAllocs()
	msg := []byte("test")
	priv, err := GenerateKey(rand.Reader) // 生成密钥对
	if err != nil {
		log.Fatal(err)
	}
	t.ResetTimer()
	for i := 0; i < t.N; i++ {
		sign, err := priv.Sign(rand.Reader, msg, nil) // 签名
		if err != nil {
			log.Fatal(err)
		}
		priv.Verify(msg, sign) // 密钥验证

	}
}

