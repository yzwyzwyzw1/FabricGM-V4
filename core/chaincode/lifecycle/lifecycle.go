/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package lifecycle

import (
	"fmt"

	"github.com/chinaso/fabricGM/core/chaincode/persistence"
	"github.com/pkg/errors"
)

// ChaincodeStore provides a way to persist chaincodes
type ChaincodeStore interface {
	Save(name, version string, ccInstallPkg []byte) (hash []byte, err error)
	RetrieveHash(name, version string) (hash []byte, err error)
}

type PackageParser interface {
	Parse(data []byte) (*persistence.ChaincodePackage, error)
}

// Lifecycle implements the lifecycle operations which are invoked
// by the SCC as well as internally
type Lifecycle struct {
	ChaincodeStore ChaincodeStore
	PackageParser  PackageParser
}

// InstallChaincode installs a given chaincode to the peer's chaincode store.
// It returns the hash to reference the chaincode by or an error on failure.
func (l *Lifecycle) InstallChaincode(name, version string, chaincodeInstallPackage []byte) ([]byte, error) {
	// Let's validate that the chaincodeInstallPackage is at least well formed before writing it
	_, err := l.PackageParser.Parse(chaincodeInstallPackage)
	if err != nil {
		return nil, errors.WithMessage(err, "could not parse as a chaincode install package")
	}

	hash, err := l.ChaincodeStore.Save(name, version, chaincodeInstallPackage)
	if err != nil {
		return nil, errors.WithMessage(err, "could not save cc install package")
	}

	return hash, nil
}

// QueryInstalledChaincode returns the hash of an installed chaincode of a given name and version.
func (l *Lifecycle) QueryInstalledChaincode(name, version string) ([]byte, error) {
	hash, err := l.ChaincodeStore.RetrieveHash(name, version)
	if err != nil {
		return nil, errors.WithMessage(err, fmt.Sprintf("could not retrieve hash for chaincode '%s:%s'", name, version))
	}

	return hash, nil
}
