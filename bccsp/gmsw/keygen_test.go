package gmsw

import (
	"fmt"
	"github.com/chinaso/fabricGM/cryptopkg/golangGM/sm2"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestSM2KeyGenerator(t *testing.T) {
	t.Parallel()

	kg := &sm2KeyGenerator{curve:sm2.SM2P256()}

	k, err := kg.KeyGen(nil)
	assert.NoError(t, err)

	sm2K, ok := k.(*sm2PrivateKey)

	fmt.Println("sm2k",sm2K.privKey)
	assert.True(t, ok)
	assert.NotNil(t, sm2K.privKey)
	assert.Equal(t, sm2K.privKey.Curve, sm2.SM2P256())

}



func TestSM4KeyGenerator(t *testing.T) {
	t.Parallel()

	kg := &sm4KeyGenerator{length: 32}

	k, err := kg.KeyGen(nil)
	assert.NoError(t, err)

	sm4K, ok := k.(*sm4PrivateKey)
	//fmt.Println(sm4)
	assert.True(t, ok)
	assert.NotNil(t, sm4K.privKey)
	assert.Equal(t, len(sm4K.privKey), 32)
}

