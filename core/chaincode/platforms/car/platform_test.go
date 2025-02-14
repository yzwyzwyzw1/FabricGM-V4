/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package car_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/chinaso/fabricGM/common/util"
	"github.com/chinaso/fabricGM/core/chaincode/platforms"
	"github.com/chinaso/fabricGM/core/chaincode/platforms/car"
	"github.com/chinaso/fabricGM/core/testutil"
	pb "github.com/chinaso/fabricGM/protos/peer"
)

var _ = platforms.Platform(&car.Platform{})

func TestMain(m *testing.M) {
	testutil.SetupTestConfig()
	os.Exit(m.Run())
}

func TestCar_BuildImage(t *testing.T) {
	vm, err := NewVM()
	if err != nil {
		t.Errorf("Error getting VM: %s", err)
		return
	}

	chaincodePath := filepath.Join("testdata", "/org.hyperledger.chaincode.example02-0.1-SNAPSHOT.car")
	spec := &pb.ChaincodeSpec{
		Type: pb.ChaincodeSpec_CAR,
		ChaincodeId: &pb.ChaincodeID{
			Name: "cartest",
			Path: chaincodePath,
		},
		Input: &pb.ChaincodeInput{
			Args: util.ToChaincodeArgs("f"),
		},
	}
	if err := vm.BuildChaincodeContainer(spec); err != nil {
		t.Error(err)
	}
}
