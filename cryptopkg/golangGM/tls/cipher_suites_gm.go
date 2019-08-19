package tls

import (
	"crypto/cipher"
	"crypto/hmac"
	"github.com/chinaso/fabricGM/cryptopkg/golangGM/sm3"
	"github.com/chinaso/fabricGM/cryptopkg/golangGM/sm4"
)

func ecdheSM2KA(version uint16) keyAgreement {
	return &ecdheSM2KeyAgreement{
		isRSA:   false,
		version: version,
	}
}


func cipherSM4(key, iv []byte, isRead bool) interface{} {
	block, _ := sm4.NewCipher(key)
	if isRead {
		return cipher.NewCBCDecrypter(block, iv)
	}
	return cipher.NewCBCEncrypter(block, iv)
}

// macSM3 returns a SM3-256 based MAC. These are only supported in TLS 1.2
// so the given version is ignored.
func macSM3(version uint16, key []byte) macFunction {
	return tls10MAC{hmac.New(sm3.New, key)}
}
