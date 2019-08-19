package accesscontrol

import (
	"github.com/chinaso/fabricGM/bccsp"
	"github.com/chinaso/fabricGM/bccsp/factory"
	"github.com/chinaso/fabricGM/common/crypto/tlsgen"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestGMPurge(t *testing.T) {
	ca, _ := tlsgen.NewCA()
	backupTTL := ttl
	defer func() {
		ttl = backupTTL
	}()
	ttl = time.Second
	m := gmnewCertMapper(ca.NewClientCertKeyPair)
	k, err := m.genCert("A")
	assert.NoError(t, err)
	hash, _ := factory.GetDefault().Hash(k.TLSCert.Raw, &bccsp.SM3Opts{})
	assert.Equal(t, "A", m.lookup(certHash(hash)))
	time.Sleep(time.Second * 3)
	assert.Empty(t, m.lookup(certHash(hash)))
}

