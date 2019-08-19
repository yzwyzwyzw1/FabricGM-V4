package gmsw

import (
	"github.com/chinaso/fabricGM/bccsp"
	"github.com/chinaso/fabricGM/cryptopkg/golangGM/sm2"
)



func GetSM2PrivKey(k bccsp.Key) *sm2.PrivateKey{

	sm2K:=k.(*sm2PrivateKey)

	//fmt.Println("sm2k",sm2K.privKey)
	return sm2K.privKey
}