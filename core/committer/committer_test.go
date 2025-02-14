/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package committer

import (
	"errors"
	"sync/atomic"
	"testing"

	"github.com/chinaso/fabricGM/common/configtx/test"
	"github.com/chinaso/fabricGM/common/ledger"
	"github.com/chinaso/fabricGM/common/ledger/testutil"
	"github.com/chinaso/fabricGM/common/tools/configtxgen/configtxgentest"
	"github.com/chinaso/fabricGM/common/tools/configtxgen/encoder"
	"github.com/chinaso/fabricGM/common/tools/configtxgen/localconfig"
	ledger2 "github.com/chinaso/fabricGM/core/ledger"
	cut "github.com/chinaso/fabricGM/core/ledger/util"
	"github.com/chinaso/fabricGM/protos/common"
	"github.com/chinaso/fabricGM/protos/peer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type mockLedger struct {
	height       uint64
	currentHash  []byte
	previousHash []byte
	mock.Mock
}

func (m *mockLedger) GetConfigHistoryRetriever() (ledger2.ConfigHistoryRetriever, error) {
	args := m.Called()
	return args.Get(0).(ledger2.ConfigHistoryRetriever), args.Error(1)
}

func (m *mockLedger) GetBlockchainInfo() (*common.BlockchainInfo, error) {
	info := &common.BlockchainInfo{
		Height:            m.height,
		CurrentBlockHash:  m.currentHash,
		PreviousBlockHash: m.previousHash,
	}
	return info, nil
}

func (m *mockLedger) DoesPvtDataInfoExist(blkNum uint64) (bool, error) {
	args := m.Called()
	return args.Get(0).(bool), args.Error(1)
}

func (m *mockLedger) GetBlockByNumber(blockNumber uint64) (*common.Block, error) {
	args := m.Called(blockNumber)
	return args.Get(0).(*common.Block), args.Error(1)
}

func (m *mockLedger) GetBlocksIterator(startBlockNumber uint64) (ledger.ResultsIterator, error) {
	args := m.Called(startBlockNumber)
	return args.Get(0).(ledger.ResultsIterator), args.Error(1)
}

func (m *mockLedger) Close() {

}

func (m *mockLedger) GetTransactionByID(txID string) (*peer.ProcessedTransaction, error) {
	args := m.Called(txID)
	return args.Get(0).(*peer.ProcessedTransaction), args.Error(1)
}

func (m *mockLedger) GetBlockByHash(blockHash []byte) (*common.Block, error) {
	args := m.Called(blockHash)
	return args.Get(0).(*common.Block), args.Error(1)
}

func (m *mockLedger) GetBlockByTxID(txID string) (*common.Block, error) {
	args := m.Called(txID)
	return args.Get(0).(*common.Block), args.Error(1)
}

func (m *mockLedger) GetTxValidationCodeByTxID(txID string) (peer.TxValidationCode, error) {
	args := m.Called(txID)
	return args.Get(0).(peer.TxValidationCode), args.Error(1)
}

func (m *mockLedger) NewTxSimulator(txid string) (ledger2.TxSimulator, error) {
	args := m.Called(txid)
	return args.Get(0).(ledger2.TxSimulator), args.Error(1)
}

func (m *mockLedger) NewQueryExecutor() (ledger2.QueryExecutor, error) {
	args := m.Called()
	return args.Get(0).(ledger2.QueryExecutor), args.Error(1)
}

func (m *mockLedger) NewHistoryQueryExecutor() (ledger2.HistoryQueryExecutor, error) {
	args := m.Called()
	return args.Get(0).(ledger2.HistoryQueryExecutor), args.Error(1)
}

func (m *mockLedger) GetPvtDataAndBlockByNum(blockNum uint64, filter ledger2.PvtNsCollFilter) (*ledger2.BlockAndPvtData, error) {
	args := m.Called(blockNum, filter)
	return args.Get(0).(*ledger2.BlockAndPvtData), args.Error(1)
}

func (m *mockLedger) GetPvtDataByNum(blockNum uint64, filter ledger2.PvtNsCollFilter) ([]*ledger2.TxPvtData, error) {
	args := m.Called(blockNum, filter)
	return args.Get(0).([]*ledger2.TxPvtData), args.Error(1)
}

func (m *mockLedger) CommitWithPvtData(blockAndPvtdata *ledger2.BlockAndPvtData, commitOpts *ledger2.CommitOptions) error {
	m.height += 1
	m.previousHash = m.currentHash
	m.currentHash = blockAndPvtdata.Block.Header.DataHash
	args := m.Called(blockAndPvtdata)
	return args.Error(0)
}

func (m *mockLedger) CommitPvtDataOfOldBlocks(blockPvtData []*ledger2.BlockPvtData) ([]*ledger2.PvtdataHashMismatch, error) {
	panic("implement me")
}

func (m *mockLedger) GetMissingPvtDataTracker() (ledger2.MissingPvtDataTracker, error) {
	panic("implement me")
}

func (m *mockLedger) PurgePrivateData(maxBlockNumToRetain uint64) error {
	args := m.Called(maxBlockNumToRetain)
	return args.Error(0)
}

func (m *mockLedger) PrivateDataMinBlockNum() (uint64, error) {
	args := m.Called()
	return args.Get(0).(uint64), args.Error(1)
}

func (m *mockLedger) Prune(policy ledger.PrunePolicy) error {
	args := m.Called(policy)
	return args.Error(0)
}

func createLedger(channelID string) (*common.Block, *mockLedger) {
	gb, _ := test.MakeGenesisBlock(channelID)
	ledger := &mockLedger{
		height:       1,
		previousHash: []byte{},
		currentHash:  gb.Header.DataHash,
	}
	return gb, ledger
}

func TestKVLedgerBlockStorage(t *testing.T) {
	t.Parallel()
	gb, ledger := createLedger("TestLedger")
	block1 := testutil.ConstructBlock(t, 1, gb.Header.DataHash, [][]byte{{1, 2, 3, 4}, {5, 6, 7, 8}}, true)

	ledger.On("CommitWithPvtData", mock.Anything).Run(func(args mock.Arguments) {
		b := args.Get(0).(*ledger2.BlockAndPvtData)
		assert.Equal(t, uint64(1), b.Block.Header.GetNumber())
		assert.Equal(t, gb.Header.DataHash, b.Block.Header.PreviousHash)
		assert.Equal(t, block1.Header.DataHash, b.Block.Header.DataHash)
	}).Return(nil)

	ledger.On("GetBlockByNumber", uint64(0)).Return(gb, nil)

	committer := NewLedgerCommitter(ledger)
	height, err := committer.LedgerHeight()
	assert.Equal(t, uint64(1), height)
	assert.NoError(t, err)

	err = committer.CommitWithPvtData(&ledger2.BlockAndPvtData{Block: block1}, &ledger2.CommitOptions{})
	assert.NoError(t, err)

	height, err = committer.LedgerHeight()
	assert.Equal(t, uint64(2), height)
	assert.NoError(t, err)

	blocks := committer.GetBlocks([]uint64{0})
	assert.Equal(t, 1, len(blocks))
	assert.NoError(t, err)
}

func TestNewLedgerCommitterReactive(t *testing.T) {
	t.Parallel()
	chainID := "TestLedger"
	_, ledger := createLedger(chainID)
	ledger.On("CommitWithPvtData", mock.Anything).Return(nil)
	var configArrived int32
	committer := NewLedgerCommitterReactive(ledger, func(_ *common.Block) error {
		atomic.AddInt32(&configArrived, 1)
		return nil
	})

	height, err := committer.LedgerHeight()
	assert.Equal(t, uint64(1), height)
	assert.NoError(t, err)

	profile := configtxgentest.Load(localconfig.SampleSingleMSPSoloProfile)
	block := encoder.New(profile).GenesisBlockForChannel(chainID)
	txsFilter := cut.NewTxValidationFlagsSetValue(len(block.Data.Data), peer.TxValidationCode_VALID)
	block.Metadata.Metadata[common.BlockMetadataIndex_TRANSACTIONS_FILTER] = txsFilter

	err = committer.CommitWithPvtData(&ledger2.BlockAndPvtData{Block: block}, &ledger2.CommitOptions{})
	assert.NoError(t, err)
	assert.Equal(t, int32(1), atomic.LoadInt32(&configArrived))
}

func TestNewLedgerCommitterReactiveFailedConfigUpdate(t *testing.T) {
	t.Parallel()
	chainID := "TestLedger"
	_, ledger := createLedger(chainID)
	ledger.On("CommitWithPvtData", mock.Anything).Return(nil)
	var configArrived int32
	committer := NewLedgerCommitterReactive(ledger, func(_ *common.Block) error {
		return errors.New("failed update config")
	})

	height, err := committer.LedgerHeight()
	assert.Equal(t, uint64(1), height)
	assert.NoError(t, err)

	profile := configtxgentest.Load(localconfig.SampleSingleMSPSoloProfile)
	block := encoder.New(profile).GenesisBlockForChannel(chainID)

	err = committer.CommitWithPvtData(&ledger2.BlockAndPvtData{Block: block}, &ledger2.CommitOptions{})

	assert.Error(t, err)
	assert.Equal(t, int32(0), atomic.LoadInt32(&configArrived))
}
