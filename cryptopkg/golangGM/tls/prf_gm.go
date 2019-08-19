package tls

import (

	"fmt"
	"github.com/chinaso/fabricGM/cryptopkg/golangGM/x509"
)

// lookupTLSHash looks up the corresponding crypto.Hash for a given
// hash from a TLS SignatureScheme.
func lookupTLSHashGM(signatureAlgorithm SignatureScheme) (x509.Hash, error) {
	switch signatureAlgorithm {

	case SM2WithSM3:
		return x509.SM3,nil
	default:
		return 0, fmt.Errorf("tls: unsupported signature algorithm: %#04x", signatureAlgorithm)
	}
}
