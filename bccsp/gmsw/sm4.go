package gmsw

import (
	//"github.com/chinaso/fabricGM/cryptopkg/golangGM/x509"

	"github.com/chinaso/fabricGM/cryptopkg/golangGM/sm4"
	"github.com/chinaso/fabricGM/cryptopkg/golangGM/util"
	//"encoding/pem"
	"fmt"
	"github.com/chinaso/fabricGM/bccsp"

	"crypto/cipher"
	"crypto/rand"
	"errors"

	"io"
)

// GetRandomBytes returns len random looking bytes
func GetRandomBytes(len int) ([]byte, error) {
	if len < 0 {
		return nil, errors.New("Len must be larger than 0")
	}

	buffer := make([]byte, len)

	n, err := rand.Read(buffer)
	if err != nil {
		return nil, err
	}
	if n != len {
		return nil, fmt.Errorf("Buffer not filled. Requested [%d], got [%d]", len, n)
	}

	return buffer, nil
}
// GetRandomBytes returns len random looking bytes
//func GetRandomBytes(len int) ([]byte, error) {
//	if len < 0 {
//		return nil, errors.New("Len must be larger than 0")
//	}
//
//	buffer := make([]byte, len)
//
//	n, err := rand.Read(buffer)
//	if err != nil {
//		return nil, err
//	}
//	if n != len {
//		return nil, fmt.Errorf("Buffer not filled. Requested [%d], got [%d]", len, n)
//	}
//
//	return buffer, nil
//}






func sm4CBCEncryptWithRand(prng io.Reader,key,s []byte) ([]byte,error) {
	if len(s)%sm4.BlockSize != 0 {
		return nil,errors.New("Invalid plaintext. It must be a multiple of the block size")
	}
	block,err := sm4.NewCipher(key)
	if err != nil {
		return nil ,err
	}

	ciphertext := make([]byte,sm4.BlockSize+len(s))
	iv := ciphertext[:sm4.BlockSize]
	if _,err := io.ReadFull(prng,iv);err != nil {
		return nil,err
	}
	mode := cipher.NewCBCEncrypter(block,iv)
	mode.CryptBlocks(ciphertext[sm4.BlockSize:],s)
	return ciphertext,nil
}

//区别在于IV是传入的
func sm4CBCEncryptWithIV(IV []byte,key,s []byte) ([]byte,error) {
	if len(s)%sm4.BlockSize != 0 {
		return nil,errors.New("Invalid plaintext. It must be a multiple of the block size")
	}
	if len(IV) != sm4.BlockSize {
		return nil,errors.New("Invalid IV. It must have length the block size")
	}

	block,err := sm4.NewCipher(key)
	if err != nil {
		return nil,err
	}
	ciphertext := make([]byte,sm4.BlockSize+len(s))
	copy(ciphertext[:sm4.BlockSize],IV)
	mode := cipher.NewCBCEncrypter(block,IV)
	mode.CryptBlocks(ciphertext[sm4.BlockSize:],s)
	return ciphertext,nil
}

func sm4CBCEncrypt(key,s []byte) ([]byte,error) {
	return sm4CBCEncryptWithRand(rand.Reader,key,s)
}

func SM4CBCPKCS7Encrypt(key,src []byte) ([]byte,error) {
	tmp := util.PKCS7Padding(src,sm4.BlockSize)
	return  sm4CBCEncrypt(key,tmp)
}

func SM4CBCPKCS7EncryptWithRand(prng io.Reader,key,src []byte) ([]byte,error) {
	tmp := util.PKCS7Padding(src,sm4.BlockSize)
	return  sm4CBCEncryptWithRand(prng,key,tmp)
}
func SM4CBCPKCS7EncryptWithIV(IV []byte,key,src []byte) ([]byte,error) {
	tmp := util.PKCS7Padding(src,sm4.BlockSize)
	return sm4CBCEncryptWithIV(IV,key,tmp)
}

func sm4CBCDecrypt(key,src []byte) ([]byte,error) {
	block,err := sm4.NewCipher(key)
	if err != nil {
		return nil,err
	}

	if len(src) < sm4.BlockSize {
		return nil,errors.New("Invalid ciphertext. It must be a multiple of the block size")
	}

	iv := src[:sm4.BlockSize]
	src = src[sm4.BlockSize:]

	if len(src)%sm4.BlockSize != 0 {
		return nil,errors.New("Invalid ciphertext. It must be a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block,iv)
	mode.CryptBlocks(src,src)

	return src,nil

}

func SM4CBCPKCS7Decrypt(key,src []byte) ([]byte,error) {
	pt,err := sm4CBCDecrypt(key,src)

	if err == nil {
		return util.PKCS7UnPadding(pt,sm4.BlockSize)
	}
	return nil,err
}


type sm4cbcpkcs7Encryptor struct {

}



func (e *sm4cbcpkcs7Encryptor) Encrypt(k bccsp.Key,plaintext []byte,opts bccsp.EncrypterOpts) ([]byte,error) {
	switch o := opts.(type) {
	case *bccsp.SM4CBCPKCS7ModeOpts:
		if len(o.IV) != 0 && o.PRNG != nil {
			return nil,errors.New("Invalid options. Either IV or PRNG should be different from nil, or both nil.")
		}

		if len(o.IV) != 0 {
			return SM4CBCPKCS7EncryptWithIV(o.IV,k.(*sm4PrivateKey).privKey,plaintext)
		} else if o.PRNG != nil {
			return SM4CBCPKCS7EncryptWithRand(o.PRNG,k.(*sm4PrivateKey).privKey,plaintext)
		}
		return SM4CBCPKCS7Encrypt(k.(*sm4PrivateKey).privKey,plaintext)
	case bccsp.SM4CBCPKCS7ModeOpts:
		return e.Encrypt(k,plaintext,&o)
	default:
		return nil,fmt.Errorf("Mode not recognized [%s]", opts)
	}
}

type sm4cbcpkcs7Decryptor struct {

}

func (*sm4cbcpkcs7Decryptor) Decrypt(k bccsp.Key,ciphertest []byte,opts bccsp.DecrypterOpts) ([]byte,error) {
	switch opts.(type) {
	case *bccsp.SM4CBCPKCS7ModeOpts,bccsp.SM4CBCPKCS7ModeOpts:
		return SM4CBCPKCS7Decrypt(k.(*sm4PrivateKey).privKey,ciphertest)
	default:
		return nil,fmt.Errorf("Mode not recognized [%s]",opts)
	}
}


///****************Domestic cryptographic algorithm*********************/

//// PEMtoAES extracts from the PEM an AES key
//func PEMtoSM4(raw []byte, pwd []byte) ([]byte, error) {
//	if len(raw) == 0 {
//		return nil, errors.New("Invalid PEM. It must be different from nil.")
//	}
//	block, _ := pem.Decode(raw)
//	if block == nil {
//		return nil, fmt.Errorf("Failed decoding PEM. Block must be different from nil. [% x]", raw)
//	}
//
//	if x509.IsEncryptedPEMBlock(block) {
//		if len(pwd) == 0 {
//			return nil, errors.New("Encrypted Key. Password must be different fom nil")
//		}
//
//		decrypted, err := x509.DecryptPEMBlock(block, pwd)
//		if err != nil {
//			return nil, fmt.Errorf("Failed PEM decryption. [%s]", err)
//		}
//		return decrypted, nil
//	}
//
//	return block.Bytes, nil
//}
//// SM4toPEM encapsulates an SM4 key in the PEM format
//func SM4toPEM(raw []byte) []byte {
//	return pem.EncodeToMemory(&pem.Block{Type: "SM4 PRIVATE KEY", Bytes: raw})
//}
//
//// AEStoEncryptedPEM encapsulates an AES key in the encrypted PEM format
//func SM4toEncryptedPEM(raw []byte, pwd []byte) ([]byte, error) {
//	if len(raw) == 0 {
//		return nil, errors.New("Invalid aes key. It must be different from nil")
//	}
//	if len(pwd) == 0 {
//		return SM4toPEM(raw), nil
//	}
//
//	block, err := x509.EncryptPEMBlock(
//		rand.Reader,
//		"SM4 PRIVATE KEY",
//		raw,
//		pwd,
//		x509.PEMCipherSM4)
//
//	if err != nil {
//		return nil, err
//	}
//
//	return pem.EncodeToMemory(block), nil
//}



///*********************************************************************/
