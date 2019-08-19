package accesscontrol

import (
	"context"
	"github.com/chinaso/fabricGM/common/crypto/tlsgen"
	"github.com/chinaso/fabricGM/common/util"
	"github.com/chinaso/fabricGM/cryptopkg/golangGM/grpc/credentials"
	"google.golang.org/grpc/peer"
	"sync"
	"time"
)


type gmcertMapper struct {
	keyGen KeyGenFunc
	sync.RWMutex
	m map[certHash]string
}

func gmnewCertMapper(keyGen KeyGenFunc) *gmcertMapper {
	return &gmcertMapper{
		keyGen: keyGen,
		m:      make(map[certHash]string),
	}
}

func (r *gmcertMapper) lookup(h certHash) string {
	r.RLock()
	defer r.RUnlock()
	return r.m[h]
}

func (r *gmcertMapper) register(hash certHash, name string) {
	r.Lock()
	defer r.Unlock()
	r.m[hash] = name
	time.AfterFunc(ttl, func() {
		r.purge(hash)
	})
}

func (r *gmcertMapper) purge(hash certHash) {
	r.Lock()
	defer r.Unlock()
	delete(r.m, hash)
}

func (r *gmcertMapper) genCert(name string) (*tlsgen.CertKeyPair, error) {
	keyPair, err := r.keyGen()
	if err != nil {
		return nil, err
	}
	hash := util.ComputeSM3(keyPair.TLSCert.Raw)
	r.register(certHash(hash), name)
	return keyPair, nil
}

// ExtractCertificateHash extracts the hash of the certificate from the stream
func gmextractCertificateHashFromContext(ctx context.Context) []byte {
	pr, extracted := peer.FromContext(ctx)
	if !extracted {
		return nil
	}

	authInfo := pr.AuthInfo
	if authInfo == nil {
		return nil
	}

	tlsInfo, isTLSConn := authInfo.(credentials.TLSInfo)
	if !isTLSConn {
		return nil
	}
	certs := tlsInfo.State.PeerCertificates
	if len(certs) == 0 {
		return nil
	}
	raw := certs[0].Raw
	if len(raw) == 0 {
		return nil
	}
	return util.ComputeSM3(raw)
}
