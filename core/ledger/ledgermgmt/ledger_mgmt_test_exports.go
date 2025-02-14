/*
Copyright IBM Corp. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package ledgermgmt

import (
	"fmt"
	"os"

	"github.com/chinaso/fabricGM/common/metrics/disabled"
	"github.com/chinaso/fabricGM/core/chaincode/platforms"
	"github.com/chinaso/fabricGM/core/chaincode/platforms/golang"
	"github.com/chinaso/fabricGM/core/ledger/ledgerconfig"
	"github.com/chinaso/fabricGM/core/ledger/mock"
)

// InitializeTestEnv initializes ledgermgmt for tests
func InitializeTestEnv() {
	remove()
	InitializeTestEnvWithInitializer(nil)
}

// InitializeTestEnvWithInitializer initializes ledgermgmt for tests with the supplied Initializer
func InitializeTestEnvWithInitializer(initializer *Initializer) {
	remove()
	InitializeExistingTestEnvWithInitializer(initializer)
}

// InitializeExistingTestEnvWithInitializer initializes ledgermgmt for tests with existing ledgers
// This function does not remove the existing ledgers and is used in upgrade tests
// TODO ledgermgmt should be reworked to move the package scoped functions to a struct
func InitializeExistingTestEnvWithInitializer(initializer *Initializer) {
	if initializer == nil {
		initializer = &Initializer{}
	}
	if initializer.DeployedChaincodeInfoProvider == nil {
		initializer.DeployedChaincodeInfoProvider = &mock.DeployedChaincodeInfoProvider{}
	}
	if initializer.MetricsProvider == nil {
		initializer.MetricsProvider = &disabled.Provider{}
	}
	if initializer.PlatformRegistry == nil {
		initializer.PlatformRegistry = platforms.NewRegistry(&golang.Platform{})
	}
	initialize(initializer)
}

// CleanupTestEnv closes the ledgermagmt and removes the store directory
func CleanupTestEnv() {
	Close()
	remove()
}

func remove() {
	path := ledgerconfig.GetRootPath()
	fmt.Printf("removing dir = %s\n", path)
	err := os.RemoveAll(path)
	if err != nil {
		logger.Errorf("Error: %s", err)
	}
}
