/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package peer

import (
	"runtime/debug"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/chinaso/fabricGM/common/deliver"
	"github.com/chinaso/fabricGM/common/flogging"
	"github.com/chinaso/fabricGM/common/metrics"
	"github.com/chinaso/fabricGM/core/aclmgmt/resources"
	"github.com/chinaso/fabricGM/core/ledger/util"
	"github.com/chinaso/fabricGM/protos/common"
	"github.com/chinaso/fabricGM/protos/peer"
	"github.com/chinaso/fabricGM/protos/utils"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
)

var logger = flogging.MustGetLogger("common.deliverevents")

// PolicyCheckerProvider provides the corresponding policy checker for a
// given resource name
type PolicyCheckerProvider func(resourceName string) deliver.PolicyCheckerFunc

// server holds the dependencies necessary to create a deliver server
type server struct {
	dh                    *deliver.Handler
	policyCheckerProvider PolicyCheckerProvider
}

// blockResponseSender structure used to send block responses
type blockResponseSender struct {
	peer.Deliver_DeliverServer
}

// SendStatusResponse generates status reply proto message
func (brs *blockResponseSender) SendStatusResponse(status common.Status) error {
	reply := &peer.DeliverResponse{
		Type: &peer.DeliverResponse_Status{Status: status},
	}
	return brs.Send(reply)
}

// SendBlockResponse generates deliver response with block message
func (brs *blockResponseSender) SendBlockResponse(block *common.Block) error {
	response := &peer.DeliverResponse{
		Type: &peer.DeliverResponse_Block{Block: block},
	}
	return brs.Send(response)
}

// filteredBlockResponseSender structure used to send filtered block responses
type filteredBlockResponseSender struct {
	peer.Deliver_DeliverFilteredServer
}

// SendStatusResponse generates status reply proto message
func (fbrs *filteredBlockResponseSender) SendStatusResponse(status common.Status) error {
	response := &peer.DeliverResponse{
		Type: &peer.DeliverResponse_Status{Status: status},
	}
	return fbrs.Send(response)
}

// IsFiltered is a marker method which indicates that this response sender
// sends filtered blocks.
func (fbrs *filteredBlockResponseSender) IsFiltered() bool {
	return true
}

// SendBlockResponse generates deliver response with block message
func (fbrs *filteredBlockResponseSender) SendBlockResponse(block *common.Block) error {
	// Generates filtered block response
	b := blockEvent(*block)
	filteredBlock, err := b.toFilteredBlock()
	if err != nil {
		logger.Warningf("Failed to generate filtered block due to: %s", err)
		return fbrs.SendStatusResponse(common.Status_BAD_REQUEST)
	}
	response := &peer.DeliverResponse{
		Type: &peer.DeliverResponse_FilteredBlock{FilteredBlock: filteredBlock},
	}
	return fbrs.Send(response)
}

// transactionActions aliasing for peer.TransactionAction pointers slice
type transactionActions []*peer.TransactionAction

// blockEvent an alias for common.Block structure, used to
// extend with auxiliary functionality
type blockEvent common.Block

// Deliver sends a stream of blocks to a client after commitment
func (s *server) DeliverFiltered(srv peer.Deliver_DeliverFilteredServer) error {
	logger.Debugf("Starting new DeliverFiltered handler")
	defer dumpStacktraceOnPanic()
	// getting policy checker based on resources.Event_FilteredBlock resource name
	deliverServer := &deliver.Server{
		Receiver:      srv,
		PolicyChecker: s.policyCheckerProvider(resources.Event_FilteredBlock),
		ResponseSender: &filteredBlockResponseSender{
			Deliver_DeliverFilteredServer: srv,
		},
	}
	return s.dh.Handle(srv.Context(), deliverServer)
}

// Deliver sends a stream of blocks to a client after commitment
func (s *server) Deliver(srv peer.Deliver_DeliverServer) (err error) {
	logger.Debugf("Starting new Deliver handler")
	defer dumpStacktraceOnPanic()
	// getting policy checker based on resources.Event_Block resource name
	deliverServer := &deliver.Server{
		PolicyChecker: s.policyCheckerProvider(resources.Event_Block),
		Receiver:      srv,
		ResponseSender: &blockResponseSender{
			Deliver_DeliverServer: srv,
		},
	}
	return s.dh.Handle(srv.Context(), deliverServer)
}

// NewDeliverEventsServer creates a peer.Deliver server to deliver block and
// filtered block events
func NewDeliverEventsServer(mutualTLS bool, policyCheckerProvider PolicyCheckerProvider, chainManager deliver.ChainManager, metricsProvider metrics.Provider) peer.DeliverServer {
	timeWindow := viper.GetDuration("peer.authentication.timewindow")
	if timeWindow == 0 {
		defaultTimeWindow := 15 * time.Minute
		logger.Warningf("`peer.authentication.timewindow` not set; defaulting to %s", defaultTimeWindow)
		timeWindow = defaultTimeWindow
	}
	metrics := deliver.NewMetrics(metricsProvider)
	return &server{
		dh:                    deliver.NewHandler(chainManager, timeWindow, mutualTLS, metrics),
		policyCheckerProvider: policyCheckerProvider,
	}
}

func (s *server) sendProducer(srv peer.Deliver_DeliverFilteredServer) func(msg proto.Message) error {
	return func(msg proto.Message) error {
		response, ok := msg.(*peer.DeliverResponse)
		if !ok {
			logger.Errorf("received wrong response type, expected response type peer.DeliverResponse")
			return errors.New("expected response type peer.DeliverResponse")
		}
		return srv.Send(response)
	}
}

func (block *blockEvent) toFilteredBlock() (*peer.FilteredBlock, error) {
	filteredBlock := &peer.FilteredBlock{
		Number: block.Header.Number,
	}

	txsFltr := util.TxValidationFlags(block.Metadata.Metadata[common.BlockMetadataIndex_TRANSACTIONS_FILTER])
	for txIndex, ebytes := range block.Data.Data {
		var env *common.Envelope
		var err error

		if ebytes == nil {
			logger.Debugf("got nil data bytes for tx index %d, "+
				"block num %d", txIndex, block.Header.Number)
			continue
		}

		env, err = utils.GetEnvelopeFromBlock(ebytes)
		if err != nil {
			logger.Errorf("error getting tx from block, %s", err)
			continue
		}

		// get the payload from the envelope
		payload, err := utils.GetPayload(env)
		if err != nil {
			return nil, errors.WithMessage(err, "could not extract payload from envelope")
		}

		if payload.Header == nil {
			logger.Debugf("transaction payload header is nil, %d, block num %d",
				txIndex, block.Header.Number)
			continue
		}
		chdr, err := utils.UnmarshalChannelHeader(payload.Header.ChannelHeader)
		if err != nil {
			return nil, err
		}

		filteredBlock.ChannelId = chdr.ChannelId

		filteredTransaction := &peer.FilteredTransaction{
			Txid:             chdr.TxId,
			Type:             common.HeaderType(chdr.Type),
			TxValidationCode: txsFltr.Flag(txIndex),
		}

		if filteredTransaction.Type == common.HeaderType_ENDORSER_TRANSACTION {
			tx, err := utils.GetTransaction(payload.Data)
			if err != nil {
				return nil, errors.WithMessage(err, "error unmarshal transaction payload for block event")
			}

			filteredTransaction.Data, err = transactionActions(tx.Actions).toFilteredActions()
			if err != nil {
				logger.Errorf(err.Error())
				return nil, err
			}
		}

		filteredBlock.FilteredTransactions = append(filteredBlock.FilteredTransactions, filteredTransaction)
	}

	return filteredBlock, nil
}

func (ta transactionActions) toFilteredActions() (*peer.FilteredTransaction_TransactionActions, error) {
	transactionActions := &peer.FilteredTransactionActions{}
	for _, action := range ta {
		chaincodeActionPayload, err := utils.GetChaincodeActionPayload(action.Payload)
		if err != nil {
			return nil, errors.WithMessage(err, "error unmarshal transaction action payload for block event")
		}

		if chaincodeActionPayload.Action == nil {
			logger.Debugf("chaincode action, the payload action is nil, skipping")
			continue
		}
		propRespPayload, err := utils.GetProposalResponsePayload(chaincodeActionPayload.Action.ProposalResponsePayload)
		if err != nil {
			return nil, errors.WithMessage(err, "error unmarshal proposal response payload for block event")
		}

		caPayload, err := utils.GetChaincodeAction(propRespPayload.Extension)
		if err != nil {
			return nil, errors.WithMessage(err, "error unmarshal chaincode action for block event")
		}

		ccEvent, err := utils.GetChaincodeEvents(caPayload.Events)
		if err != nil {
			return nil, errors.WithMessage(err, "error unmarshal chaincode event for block event")
		}

		if ccEvent.GetChaincodeId() != "" {
			filteredAction := &peer.FilteredChaincodeAction{
				ChaincodeEvent: &peer.ChaincodeEvent{
					TxId:        ccEvent.TxId,
					ChaincodeId: ccEvent.ChaincodeId,
					EventName:   ccEvent.EventName,
				},
			}
			transactionActions.ChaincodeActions = append(transactionActions.ChaincodeActions, filteredAction)
		}
	}
	return &peer.FilteredTransaction_TransactionActions{
		TransactionActions: transactionActions,
	}, nil
}

func dumpStacktraceOnPanic() {
	func() {
		if r := recover(); r != nil {
			logger.Criticalf("Deliver client triggered panic: %s\n%s", r, debug.Stack())
		}
		logger.Debugf("Closing Deliver stream")
	}()
}
