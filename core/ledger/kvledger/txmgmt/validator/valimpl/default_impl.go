/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package valimpl

import (
	"github.com/chinaso/fabricGM/common/flogging"
	"github.com/chinaso/fabricGM/core/ledger"
	"github.com/chinaso/fabricGM/core/ledger/kvledger/txmgmt/privacyenabledstate"
	"github.com/chinaso/fabricGM/core/ledger/kvledger/txmgmt/txmgr"
	"github.com/chinaso/fabricGM/core/ledger/kvledger/txmgmt/validator"
	"github.com/chinaso/fabricGM/core/ledger/kvledger/txmgmt/validator/internal"
	"github.com/chinaso/fabricGM/core/ledger/kvledger/txmgmt/validator/statebasedval"
	"github.com/chinaso/fabricGM/core/ledger/util"
	"github.com/chinaso/fabricGM/protos/common"
)

var logger = flogging.MustGetLogger("valimpl")

// DefaultImpl implements the interface validator.Validator
// This performs the common tasks that are independent of a particular scheme of validation
// and for actual validation of the public rwset, it encloses an internal validator (that implements interface
// internal.InternalValidator) such as statebased validator
type DefaultImpl struct {
	txmgr             txmgr.TxMgr
	db                privacyenabledstate.DB
	internalValidator internal.Validator
}

// NewStatebasedValidator constructs a validator that internally manages statebased validator and in addition
// handles the tasks that are agnostic to a particular validation scheme such as parsing the block and handling the pvt data
func NewStatebasedValidator(txmgr txmgr.TxMgr, db privacyenabledstate.DB) validator.Validator {
	return &DefaultImpl{txmgr, db, statebasedval.NewValidator(db)}
}

// ValidateAndPrepareBatch implements the function in interface validator.Validator
func (impl *DefaultImpl) ValidateAndPrepareBatch(blockAndPvtdata *ledger.BlockAndPvtData,
	doMVCCValidation bool) (*privacyenabledstate.UpdateBatch, []*txmgr.TxStatInfo, error) {
	block := blockAndPvtdata.Block
	logger.Debugf("ValidateAndPrepareBatch() for block number = [%d]", block.Header.Number)
	var internalBlock *internal.Block
	var txsStatInfo []*txmgr.TxStatInfo
	var pubAndHashUpdates *internal.PubAndHashUpdates
	var pvtUpdates *privacyenabledstate.PvtUpdateBatch
	var err error

	logger.Debug("preprocessing ProtoBlock...")
	if internalBlock, txsStatInfo, err = preprocessProtoBlock(impl.txmgr, impl.db.ValidateKeyValue, block, doMVCCValidation); err != nil {
		return nil, nil, err
	}

	if pubAndHashUpdates, err = impl.internalValidator.ValidateAndPrepareBatch(internalBlock, doMVCCValidation); err != nil {
		return nil, nil, err
	}
	logger.Debug("validating rwset...")
	if pvtUpdates, err = validateAndPreparePvtBatch(internalBlock, impl.db, pubAndHashUpdates, blockAndPvtdata.PvtData); err != nil {
		return nil, nil, err
	}
	logger.Debug("postprocessing ProtoBlock...")
	postprocessProtoBlock(block, internalBlock)
	logger.Debug("ValidateAndPrepareBatch() complete")

	txsFilter := util.TxValidationFlags(block.Metadata.Metadata[common.BlockMetadataIndex_TRANSACTIONS_FILTER])
	for i := range txsFilter {
		txsStatInfo[i].ValidationCode = txsFilter.Flag(i)
	}
	return &privacyenabledstate.UpdateBatch{
		PubUpdates:  pubAndHashUpdates.PubUpdates,
		HashUpdates: pubAndHashUpdates.HashUpdates,
		PvtUpdates:  pvtUpdates,
	}, txsStatInfo, nil
}
