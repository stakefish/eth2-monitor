package pkg

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"eth2-monitor/cmd/opts"
	"eth2-monitor/prysmgrpc"
	"eth2-monitor/spec"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/pkg/errors"
	bitfield "github.com/prysmaticlabs/go-bitfield"
	primitives "github.com/prysmaticlabs/prysm/v4/consensus-types/primitives"
	ethpbservice "github.com/prysmaticlabs/prysm/v4/proto/eth/service"
	ethpbv1 "github.com/prysmaticlabs/prysm/v4/proto/eth/v1"
	ethpbv2 "github.com/prysmaticlabs/prysm/v4/proto/eth/v2"
	ethpb "github.com/prysmaticlabs/prysm/v4/proto/prysm/v1alpha1"
	"github.com/rs/zerolog/log"
	"golang.org/x/exp/maps"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/push"
)

// IndexPubkeys transforms validator public keys into their indexes.
// It returns direct and reversed mapping.
func IndexPubkeys(ctx context.Context, s *prysmgrpc.Service, pubkeys []string) (map[string]spec.ValidatorIndex, map[spec.ValidatorIndex]string, error) {
	cache := LoadCache()

	result := make(map[string]spec.ValidatorIndex)
	reversed := make(map[spec.ValidatorIndex]string)

	for _, pubkey := range pubkeys {
		pubkey := strings.TrimPrefix(pubkey, "0x")
		pubkey = strings.ToLower(pubkey)

		if cachedIndex, ok := cache.Validators[pubkey]; ok {
			if cachedIndex.Index != ^spec.ValidatorIndex(0) {
				result[pubkey] = cachedIndex.Index
				reversed[cachedIndex.Index] = pubkey
				continue
			}
			if time.Until(cachedIndex.At) < 8*time.Hour {
				continue
			}
		}

		binPubKey, err := hex.DecodeString(pubkey)
		if err != nil {
			return nil, nil, errors.Wrap(err, "call ValidatorIndexhex.DecodeString failed")
		}
		index, err := s.GetValidatorIndex(binPubKey)
		if err != nil {
			// Cache and skip validators with pending indexes.
			cache.Validators[pubkey] = CachedIndex{
				Index: ^spec.ValidatorIndex(0),
				At:    time.Now(),
			}
			// Ignore pending indexes.
			continue
		}

		result[pubkey] = index
		reversed[index] = pubkey
		cache.Validators[pubkey] = CachedIndex{
			Index: index,
			At:    time.Now(),
		}

		log.Debug().Msgf("Retrieved index %v for pubkey %s", index, pubkey)
	}

	SaveCache(cache)

	return result, reversed, nil
}

func processDeposits(ctx context.Context, s *prysmgrpc.Service, hashedKeys map[string]interface{}, deposits []*ethpbv1.Deposit) (map[string]spec.ValidatorIndex, map[spec.ValidatorIndex]string, error) {
	var pubkeys []string

	for _, deposit := range deposits {
		binPubkey := deposit.GetData().GetPubkey()
		pubkey := hex.EncodeToString(binPubkey)
		pubkey = strings.ToLower(pubkey)

		if _, ok := hashedKeys[pubkey]; !ok {
			continue
		}

		Info("Validator %v has been deposited", pubkey)

		pubkeys = append(pubkeys, pubkey)
	}

	return IndexPubkeys(ctx, s, pubkeys)
}

// ListProposers returns block proposers scheduled for epoch.
// To improve performance, it has to narrow the set of validators for which it checks duties.
func ListProposers(ctx context.Context, s *prysmgrpc.Service, epoch spec.Epoch, validators map[string]spec.ValidatorIndex, epochCommittees map[spec.Slot]BeaconCommittees) (map[spec.Slot]spec.ValidatorIndex, error) {
	// Filter out non-activated validator indexes and use only active ones.
	var indexes []primitives.ValidatorIndex
	activeIndexes := make(map[spec.ValidatorIndex]interface{})
	for _, committees := range epochCommittees {
		for _, indexes := range committees {
			for _, index := range indexes {
				activeIndexes[index] = nil
			}
		}
	}
	for _, index := range validators {
		if _, ok := activeIndexes[index]; ok {
			indexes = append(indexes, primitives.ValidatorIndex(index))
		}
	}

	// Make ListValidatorAssignments RPC calls to iterate through assignments and aggregate
	// block proposers into result map.
	chunkSize := 250
	result := make(map[spec.Slot]spec.ValidatorIndex)
	conn := ethpb.NewBeaconChainClient(s.Connection())
	for i := 0; i < len(indexes); i += chunkSize {
		end := i + chunkSize
		if end > len(indexes) {
			end = len(indexes)
		}
		req := &ethpb.ListValidatorAssignmentsRequest{
			QueryFilter: &ethpb.ListValidatorAssignmentsRequest_Epoch{Epoch: primitives.Epoch(epoch)},
			Indices:     indexes[i:end],
		}

		for {
			opCtx, cancel := context.WithTimeout(ctx, s.Timeout())
			resp, err := conn.ListValidatorAssignments(opCtx, req)
			cancel()
			if err != nil {
				return nil, errors.Wrap(err, "rpc call ListValidatorAssignments failed")
			}

			for _, assignment := range resp.Assignments {
				for _, proposerSlot := range assignment.ProposerSlots {
					result[spec.Slot(proposerSlot)] = spec.ValidatorIndex(assignment.ValidatorIndex)
				}
			}

			req.PageToken = resp.NextPageToken
			if req.PageToken == "" {
				break
			}
		}
	}

	return result, nil
}

type BeaconCommittees map[spec.CommitteeIndex][]spec.ValidatorIndex

// ListBeaconCommittees lists committees for a specific epoch.
func ListBeaconCommittees(ctx context.Context, s *prysmgrpc.Service, epoch spec.Epoch) (map[spec.Slot]BeaconCommittees, error) {
	req := &ethpb.ListCommitteesRequest{
		QueryFilter: &ethpb.ListCommitteesRequest_Epoch{Epoch: primitives.Epoch(epoch)},
	}

	conn := ethpb.NewBeaconChainClient(s.Connection())

	opCtx, cancel := context.WithTimeout(ctx, s.Timeout())
	resp, err := conn.ListBeaconCommittees(opCtx, req)
	cancel()
	if err != nil {
		return nil, errors.Wrap(err, "rpc call ListBeaconCommittees failed")
	}

	result := make(map[spec.Slot]BeaconCommittees)

	for slot, committees := range resp.Committees {
		if _, ok := result[slot]; !ok {
			result[slot] = make(BeaconCommittees)
		}

		for committeeIndex, items := range committees.Committees {
			var indexes []spec.ValidatorIndex
			for _, index := range items.ValidatorIndices {
				indexes = append(indexes, spec.ValidatorIndex(index))
			}
			result[slot][spec.CommitteeIndex(committeeIndex)] = indexes
		}
	}

	return result, nil
}

type ChainBlock struct {
	IsCanonical       bool
	Slot              spec.Slot
	ProposerIndex     spec.ValidatorIndex
	ChainAttestations []*ChainAttestation
	BlockContainer    *ethpbv2.SignedBeaconBlockContainer
	Attestations      []*ethpbv1.Attestation
	Deposits          []*ethpbv1.Deposit
	AttesterSlashings []*ethpbv1.AttesterSlashing
	ProposerSlashings []*ethpbv1.ProposerSlashing
	VoluntaryExits    []*ethpbv1.SignedVoluntaryExit
	Transactions      []types.Transaction
}

type ChainAttestation struct {
	Slot            spec.Slot
	InclusionSlot   spec.Slot
	CommitteeIndex  spec.CommitteeIndex
	AggregationBits []byte
}

// getBlock retrieves the block for a specific block root.
func getBlock(ctx context.Context, s *prysmgrpc.Service, root []byte) (*ethpbv2.SignedBeaconBlockContainer, error) {
	conn := ethpbservice.NewBeaconChainClient(s.Connection())
	opCtx, cancel := context.WithTimeout(ctx, s.Timeout())
	req := &ethpbv2.BlockRequestV2{
		BlockId: root,
	}
	resp, err := conn.GetBlockV2(opCtx, req)
	cancel()
	if err != nil {
		return nil, errors.Wrapf(err, "rpc call GetBlockV2 failed, root=%q", root)
	}
	return resp.GetData(), nil
}

func unmarshallTransactions(rlpEncodedTxs [][]byte) (txs []types.Transaction, err error) {
	for _, rlpEncodedTx := range rlpEncodedTxs {
		var tx types.Transaction
		if err := tx.UnmarshalBinary(rlpEncodedTx); err != nil {
			return nil, err
		}
		txs = append(txs, tx)
	}
	return txs, nil
}

// ListBlocks lists blocks and attestations for a specific epoch.
func ListBlocks(ctx context.Context, s *prysmgrpc.Service, epoch spec.Epoch) (map[spec.Slot][]*ChainBlock, error) {
	conn := ethpbservice.NewBeaconChainClient(s.Connection())

	result := make(map[spec.Slot][]*ChainBlock)
	lastSlot := (epoch + 1) * spec.SLOTS_PER_EPOCH
	for slot := epoch * spec.SLOTS_PER_EPOCH; slot < lastSlot; slot++ {
		opCtx, cancel := context.WithTimeout(ctx, s.Timeout())
		pslot := primitives.Slot(slot)
		req := &ethpbv1.BlockHeadersRequest{
			Slot: &pslot,
		}
		resp, err := conn.ListBlockHeaders(opCtx, req)
		cancel()
		if err != nil && status.Code(err) == codes.NotFound {
			continue
		}
		if err != nil {
			return nil, errors.Wrapf(err, "rpc call ListBlockHeaders failed, req=%q", req)
		}

		for _, blockHeaderContainer := range resp.GetData() {
			proposerIndex := spec.ValidatorIndex(blockHeaderContainer.GetHeader().GetMessage().GetProposerIndex())

			signedBeaconBlockContainer, err := getBlock(ctx, s, blockHeaderContainer.GetRoot())
			if err != nil {
				return nil, err
			}

			var blockAttestations []*ethpbv1.Attestation
			var attesterSlashings []*ethpbv1.AttesterSlashing
			var proposerSlashings []*ethpbv1.ProposerSlashing
			var marshalledTransactions [][]byte
			var deposits []*ethpbv1.Deposit
			switch signedBeaconBlockContainer.GetMessage().(type) {
			case *ethpbv2.SignedBeaconBlockContainer_Phase0Block:
				phase0Block := signedBeaconBlockContainer.GetPhase0Block()
				blockAttestations = phase0Block.GetBody().GetAttestations()
				attesterSlashings = phase0Block.GetBody().GetAttesterSlashings()
				proposerSlashings = phase0Block.GetBody().GetProposerSlashings()
				deposits = phase0Block.GetBody().GetDeposits()
			case *ethpbv2.SignedBeaconBlockContainer_AltairBlock:
				altairBlock := signedBeaconBlockContainer.GetAltairBlock()
				blockAttestations = altairBlock.GetBody().GetAttestations()
				attesterSlashings = altairBlock.GetBody().GetAttesterSlashings()
				proposerSlashings = altairBlock.GetBody().GetProposerSlashings()
				deposits = altairBlock.GetBody().GetDeposits()
			case *ethpbv2.SignedBeaconBlockContainer_BellatrixBlock:
				bellatrixBlock := signedBeaconBlockContainer.GetBellatrixBlock()
				blockAttestations = bellatrixBlock.GetBody().GetAttestations()
				attesterSlashings = bellatrixBlock.GetBody().GetAttesterSlashings()
				proposerSlashings = bellatrixBlock.GetBody().GetProposerSlashings()
				deposits = bellatrixBlock.GetBody().GetDeposits()
				marshalledTransactions = bellatrixBlock.GetBody().GetExecutionPayload().GetTransactions()
			case *ethpbv2.SignedBeaconBlockContainer_CapellaBlock:
				capellaBlock := signedBeaconBlockContainer.GetCapellaBlock()
				blockAttestations = capellaBlock.GetBody().GetAttestations()
				attesterSlashings = capellaBlock.GetBody().GetAttesterSlashings()
				proposerSlashings = capellaBlock.GetBody().GetProposerSlashings()

				// https://github.com/ethereum/annotated-spec/blob/98c63ebcdfee6435e8b2a76e1fca8549722f6336/merge/beacon-chain.md#custom-types%C2%B6
				//      [...] execution blocks are stored in SSZ form, but the
				//      transactions inside them are encoded with RLP, and so
				//      to software that only understands SSZ they are
				//      presented as "opaque" byte arrays.
				marshalledTransactions = capellaBlock.GetBody().GetExecutionPayload().GetTransactions()
			default:
				fmt.Println("Unknown Hardfork, exiting...")
				log.Fatal()
			}

			var chainAttestations []*ChainAttestation
			for _, att := range blockAttestations {
				chainAttestations = append(chainAttestations, &ChainAttestation{
					AggregationBits: att.GetAggregationBits(),
					CommitteeIndex:  spec.CommitteeIndex(att.GetData().GetIndex()),
					Slot:            spec.Slot(att.GetData().GetSlot()),
					InclusionSlot:   slot,
				})
			}

			var unmarshalledTransactions []types.Transaction
			if marshalledTransactions != nil {
				txs, err := unmarshallTransactions(marshalledTransactions)
				if err == nil {
					unmarshalledTransactions = txs
				}
			}

			result[slot] = append(result[slot], &ChainBlock{
				IsCanonical:       blockHeaderContainer.GetCanonical(),
				ProposerIndex:     proposerIndex,
				Slot:              slot,
				AttesterSlashings: attesterSlashings,
				ProposerSlashings: proposerSlashings,
				BlockContainer:    signedBeaconBlockContainer,
				ChainAttestations: chainAttestations,
				Deposits:          deposits,
				Transactions:      unmarshalledTransactions,
			})
		}
	}

	return result, nil
}

// SubscribeToEpochs subscribes to changings of the beacon chain head.
// Note, if --replay-epoch or --since-epoch options passed, SubscribeToEpochs will not
// listen to real-time changes.
func SubscribeToEpochs(ctx context.Context, s *prysmgrpc.Service, useJustified bool, wg *sync.WaitGroup) {
	defer wg.Done()

	getEpoch := func(chainHead *ethpb.ChainHead) spec.Epoch {
		if useJustified {
			return spec.Epoch(chainHead.JustifiedEpoch)
		}
		return spec.Epoch(chainHead.HeadEpoch)
	}

	lastChainHead, err := s.GetChainHead()
	Must(err)

	if len(opts.Monitor.ReplayEpoch) > 0 {
		for _, epoch := range opts.Monitor.ReplayEpoch {
			epochsChan <- spec.Epoch(epoch)
		}
		close(epochsChan)
		return
	}
	if opts.Monitor.SinceEpoch != ^uint64(0) {
		for epoch := opts.Monitor.SinceEpoch; epoch < getEpoch(lastChainHead); epoch++ {
			epochsChan <- epoch
		}
		close(epochsChan)
		return
	}

	stream, err := s.StreamChainHead()
	if err != nil {
		log.Error().Err(err).Msg("StreamChainHead failed")
		return
	}
	defer stream.CloseSend()

	waitc := make(chan struct{})
	go func() {
		epochsChan <- getEpoch(lastChainHead)

		for {
			chainHead, err := stream.Recv()
			if err == io.EOF {
				waitc <- struct{}{}
				return
			}
			if err != nil {
				close(epochsChan)
				Must(err)
			}

			if getEpoch(chainHead) > getEpoch(lastChainHead) {
				lastChainHead = chainHead

				epochsChan <- getEpoch(lastChainHead)
			}
		}
	}()
	<-waitc
}

type AttestationLoggingStatus struct {
	IsAttested  bool
	IsCanonical bool
	IsPrinted   bool
	Slot        spec.Slot
}

const (
	// Attestation is assumed to be missed if it was not included within two consequent epochs.
	missedAttestationDistance = 2
)

func LoadKeys(pubkeysFiles []string) ([]string, error) {
	plainKeys := opts.Monitor.Pubkeys[:]
	for _, fname := range pubkeysFiles {
		file, err := os.Open(fname)
		if err != nil {
			return nil, err
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			plainKeys = append(plainKeys, scanner.Text())
		}

		err = scanner.Err()
		if err != nil {
			return nil, err
		}
	}

	return plainKeys, nil
}

// MonitorAttestationsAndProposals listens to the beacon chain head changes and checks new blocks and attestations.
func MonitorAttestationsAndProposals(ctx context.Context, s *prysmgrpc.Service, plainKeys []string, wg *sync.WaitGroup) {
	defer wg.Done()

	hashedKeys := make(map[string]interface{})
	for _, pubkey := range plainKeys {
		pubkey := strings.TrimPrefix(pubkey, "0x")
		pubkey = strings.ToLower(pubkey)
		hashedKeys[pubkey] = nil
	}
	directIndexes, reversedIndexes, err := IndexPubkeys(ctx, s, plainKeys)
	Must(err)

	committees := make(map[spec.Slot]BeaconCommittees)
	blocks := make(map[spec.Slot][]*ChainBlock)

	includedAttestations := make(map[spec.Epoch]map[spec.ValidatorIndex]*ChainAttestation)
	attestedEpoches := make(map[spec.Epoch]map[spec.ValidatorIndex]*AttestationLoggingStatus)

	epochGauge := prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "ETH2",
			Name:      "epoch",
			Help:      "Current justified epoch",
		})
	prometheus.MustRegister(epochGauge)

	var epochMissedAttestationsTracker float64

	epochMissedProposalsGauge := prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "ETH2",
			Name:      "epochMissedProposals",
			Help:      "Proposals missed in current justified epoch",
		})
	prometheus.MustRegister(epochMissedProposalsGauge)

	epochCanonicalProposalsGauge := prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "ETH2",
			Name:      "epochCanonicalProposals",
			Help:      "Canonical proposals in current justified epoch",
		})
	prometheus.MustRegister(epochCanonicalProposalsGauge)

	epochOrphanedProposalsGauge := prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "ETH2",
			Name:      "epochOrphanedProposals",
			Help:      "Orphaned proposals in current justified epoch",
		})
	prometheus.MustRegister(epochOrphanedProposalsGauge)

	epochMissedAttestationsGauge := prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "ETH2",
			Name:      "epochMissedAttestations",
			Help:      "Attestations missed in current justified epoch",
		})
	prometheus.MustRegister(epochMissedAttestationsGauge)

	lastEpochMissedAttestationsGauge := prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "ETH2",
			Name:      "lastEpochMissedAttestations",
			Help:      "Attestations missed in last (n-1) justified epoch",
		})
	prometheus.MustRegister(lastEpochMissedAttestationsGauge)

	epochCanonicalAttestationsGauge := prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "ETH2",
			// TODO(deni): Rename to epochCanonicalAttestations
			Name: "epochServedAttestations",
			Help: "Canonical attestations in current justified epoch",
		})
	prometheus.MustRegister(epochCanonicalAttestationsGauge)

	epochOrphanedAttestationsGauge := prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "ETH2",
			Name:      "epochOrphanedAttestations",
			Help:      "Attestations orphaned in current justified epoch",
		})
	prometheus.MustRegister(epochOrphanedAttestationsGauge)

	epochDelayedAttestationsOverToleranceGauge := prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "ETH2",
			Name:      "epochDelayedAttestationsOverTolerance",
			Help:      "Attestation delayed over tolerance distance setting in current justified epoch",
		})
	prometheus.MustRegister(epochDelayedAttestationsOverToleranceGauge)

	totalMissedProposalsCounter := prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: "ETH2",
			Name:      "totalMissedProposals",
			Help:      "Proposals missed since monitoring started",
		})
	prometheus.MustRegister(totalMissedProposalsCounter)

	totalCanonicalProposalsCounter := prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: "ETH2",
			Name:      "totalServedProposals",
			Help:      "Canonical proposals since monitoring started",
		})
	prometheus.MustRegister(totalCanonicalProposalsCounter)

	totalOrphanedProposalsCounter := prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: "ETH2",
			Name:      "totalOrphanedProposals",
			Help:      "Proposals orphaned since monitoring started",
		})
	prometheus.MustRegister(totalOrphanedProposalsCounter)

	totalMissedAttestationsCounter := prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: "ETH2",
			Name:      "totalMissedAttestations",
			Help:      "Attestations missed since monitoring started",
		})
	prometheus.MustRegister(totalMissedAttestationsCounter)

	totalProposedEmptyBlocksCounter := prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: "ETH2",
			Name:      "totalProposedEmptyBlocks",
			Help:      "Proposed blocks containing no transactions",
		})
	prometheus.MustRegister(totalProposedEmptyBlocksCounter)

	totalCanonicalAttestationsCounter := prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: "ETH2",
			// TODO(deni): Rename to totalCanonicalAttestations
			Name: "totalServedAttestations",
			Help: "Canonical attestations since monitoring started",
		})
	prometheus.MustRegister(totalCanonicalAttestationsCounter)

	totalOrphanedAttestationsCounter := prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: "ETH2",
			Name:      "totalOrphanedAttestations",
			Help:      "Attestations orphaned since monitoring started",
		})
	prometheus.MustRegister(totalOrphanedAttestationsCounter)

	totalDelayedAttestationsOverToleranceCounter := prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: "ETH2",
			Name:      "totalDelayedAttestationsOverTolerance",
			Help:      "Attestation delayed over tolerance distance setting since monitoring started",
		})
	prometheus.MustRegister(totalDelayedAttestationsOverToleranceCounter)

	canonicalAttestationDistances := prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: "ETH2",
		Name:      "canonicalAttestationDistances",
		Help:      "Histogram of canonical attestation distances.",
		Buckets:   prometheus.LinearBuckets(1, 1, 32),
	})
	prometheus.MustRegister(canonicalAttestationDistances)
	orphanedAttestationDistances := prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: "ETH2",
		Name:      "orphanedAttestationDistances",
		Help:      "Histogram of orphaned attestation distances.",
		Buckets:   prometheus.LinearBuckets(1, 1, 32),
	})
	prometheus.MustRegister(orphanedAttestationDistances)

	var pusher *push.Pusher
	if opts.PushGatewayUrl != "" && opts.PushGatewayJob != "" {
		registry := prometheus.NewRegistry()
		registry.MustRegister(epochGauge, epochMissedProposalsGauge, epochCanonicalProposalsGauge,
			epochOrphanedProposalsGauge, epochMissedAttestationsGauge, lastEpochMissedAttestationsGauge,
			epochCanonicalAttestationsGauge, epochOrphanedAttestationsGauge, epochDelayedAttestationsOverToleranceGauge,
			totalMissedProposalsCounter, totalCanonicalProposalsCounter, totalOrphanedProposalsCounter,
			totalMissedAttestationsCounter, totalCanonicalAttestationsCounter, totalOrphanedAttestationsCounter,
			totalDelayedAttestationsOverToleranceCounter, canonicalAttestationDistances, orphanedAttestationDistances)
		pusher = push.New(opts.PushGatewayUrl, opts.PushGatewayJob).Gatherer(registry)
	}

	for justifiedEpoch := range epochsChan {
		// On every chain head update we:
		// * Retrieve new committees for the new epoch,
		// * Mark scheduled attestations as attested,
		// * Check attestations if some of them too old.
		log.Info().Msgf("New justified epoch %v", justifiedEpoch)
		epochGauge.Set(float64(justifiedEpoch))
		// Reset all metrics for new epoch.
		epochMissedProposalsGauge.Set(float64(0))
		epochCanonicalProposalsGauge.Set(float64(0))
		epochOrphanedProposalsGauge.Set(float64(0))
		lastEpochMissedAttestationsGauge.Set(epochMissedAttestationsTracker)
		epochMissedAttestationsTracker = 0
		epochMissedAttestationsGauge.Set(float64(0))
		epochCanonicalAttestationsGauge.Set(float64(0))
		epochOrphanedAttestationsGauge.Set(float64(0))
		epochDelayedAttestationsOverToleranceGauge.Set(float64(0))

		var err error
		var epochCommittees map[spec.Slot]BeaconCommittees
		var epochBlocks map[spec.Slot][]*ChainBlock
		var proposals map[spec.Slot]spec.ValidatorIndex

		epoch := justifiedEpoch
		Measure(func() {
			epochCommittees, err = ListBeaconCommittees(ctx, s, spec.Epoch(epoch))
			Must(err)
		}, "ListBeaconCommittees(epoch=%v)", epoch)
		Measure(func() {
			epochBlocks, err = ListBlocks(ctx, s, spec.Epoch(epoch))
			Must(err)
		}, "ListBlocks(epoch=%v)", epoch)
		Measure(func() {
			proposals, err = ListProposers(ctx, s, spec.Epoch(epoch), directIndexes, epochCommittees)
			Must(err)
		}, "ListProposers(epoch=%v)", epoch)

		for slot, v := range epochCommittees {
			committees[slot] = v
		}
		for slot, v := range epochBlocks {
			blocks[slot] = v
		}

		attestingValidatorsCount := 0
		for slot, slotCommittees := range epochCommittees {
			var epoch spec.Epoch = slot / spec.SLOTS_PER_EPOCH
			if _, ok := attestedEpoches[epoch]; !ok {
				attestedEpoches[epoch] = make(map[spec.ValidatorIndex]*AttestationLoggingStatus)
			}

			for _, committee := range slotCommittees {
				for _, index := range committee {
					if _, ok := reversedIndexes[index]; ok {
						attestingValidatorsCount++
					}

					if _, ok := attestedEpoches[epoch][index]; !ok {
						attestedEpoches[epoch][index] = &AttestationLoggingStatus{
							Slot: slot,
						}
					}
				}
			}
		}

		log.Info().Msgf("Number of attesting validators is %v", attestingValidatorsCount)

		for _, slotBlocks := range blocks {
			for _, chainBlock := range slotBlocks {
				newDirectIndexes, newReversedIndexes, err := processDeposits(ctx, s, hashedKeys, chainBlock.Deposits)
				Must(err)
				maps.Copy(directIndexes, newDirectIndexes)
				maps.Copy(reversedIndexes, newReversedIndexes)
				for _, attestation := range chainBlock.ChainAttestations {
					isCanonical := chainBlock.IsCanonical
					// Every included attestation contains aggregation bits, i.e. a list of validators
					// from which attestations were aggregated.
					// We check if a validator was included in this list and, if not, such validator
					// may have missed the attestation.
					// The attestation of such validator might be aggregated and be included in later blocks.
					bits := bitfield.Bitlist(attestation.AggregationBits)

					var epoch spec.Epoch = attestation.Slot / spec.SLOTS_PER_EPOCH
					committee := committees[attestation.Slot][attestation.CommitteeIndex]
					for i, index := range committee {
						if _, ok := includedAttestations[epoch]; !ok {
							includedAttestations[epoch] = make(map[spec.ValidatorIndex]*ChainAttestation)
						}
						if bits.BitAt(uint64(i)) {
							attestedEpoch := attestedEpoches[epoch][index]
							att := includedAttestations[epoch][index]
							if att == nil || att.InclusionSlot > attestation.InclusionSlot || !attestedEpoch.IsCanonical {
								includedAttestations[epoch][index] = attestation
								attestedEpoches[epoch][index].IsAttested = true
								attestedEpoches[epoch][index].IsCanonical = isCanonical
							}
						}
					}
				}
			}
		}

		// Find timed-out attestations and missed blocks. Then, report it.
		var epochsToGarbage []spec.Epoch
		for epoch, validators := range attestedEpoches {
			if epoch <= justifiedEpoch-missedAttestationDistance {
				epochsToGarbage = append(epochsToGarbage, epoch)
			}

			for index, attStatus := range validators {
				if _, ok := reversedIndexes[index]; !ok {
					continue
				}
				if epoch <= justifiedEpoch-missedAttestationDistance && !attStatus.IsAttested && !attStatus.IsPrinted {
					Report("❌ 🧾 Validator %v did not attest epoch %v slot %v", index, epoch, attStatus.Slot)
					epochMissedAttestationsTracker += 1
					epochMissedAttestationsGauge.Add(1)
					totalMissedAttestationsCounter.Inc()
					attStatus.IsPrinted = true
				} else if att := includedAttestations[epoch][index]; att != nil && !attStatus.IsPrinted {
					var absDistance spec.Slot = att.InclusionSlot - att.Slot
					var optimalDistance spec.Slot = absDistance - 1
					for e := att.Slot + 1; e < att.InclusionSlot; e++ {
						if _, ok := blocks[e]; !ok {
							optimalDistance--
						}
					}
					distanceToCompare := optimalDistance
					if opts.Monitor.UseAbsoluteDistance {
						distanceToCompare = absDistance
					}
					if distanceToCompare > opts.Monitor.DistanceTolerance {
						Report("⚠️ 🧾 Validator %v attested epoch %v slot %v at slot %v, opt distance is %v, abs distance is %v",
							index, epoch, att.Slot, att.InclusionSlot, optimalDistance, absDistance)
						epochDelayedAttestationsOverToleranceGauge.Add(1)
						totalDelayedAttestationsOverToleranceCounter.Inc()
					} else if opts.Monitor.PrintSuccessful {
						Info("✅ 🧾 Validator %v attested epoch %v slot %v at slot %v, opt distance is %v, abs distance is %v",
							index, epoch, att.Slot, att.InclusionSlot, optimalDistance, absDistance)
					}
					attStatus.IsPrinted = true

					if attStatus.IsCanonical {
						epochCanonicalAttestationsGauge.Add(1)
						totalCanonicalAttestationsCounter.Inc()
						canonicalAttestationDistances.Observe(float64(absDistance))
					} else {
						epochOrphanedAttestationsGauge.Add(1)
						totalOrphanedAttestationsCounter.Inc()
						orphanedAttestationDistances.Observe(float64(absDistance))
					}
				}
			}
		}

		for slot, validatorIndex := range proposals {
			slotBlocks, ok := blocks[slot]
			if !ok {
				Report("❌ 🧱 Validator %v missed block at epoch %v and slot %v",
					validatorIndex, justifiedEpoch, slot)
				epochMissedProposalsGauge.Add(1)
				totalMissedProposalsCounter.Inc()
				break
			}

			for _, slotBlock := range slotBlocks {
				if len(slotBlock.Transactions) != 0 {
					continue
				}
				if slotBlock.ProposerIndex == validatorIndex {
					validatorPublicKey := reversedIndexes[validatorIndex]
					Report("⚠️ 🧱 Validator %v (%v) proposed a block containing no transaction at epoch %v and slot %v", validatorPublicKey, validatorIndex, justifiedEpoch, slot)
					totalProposedEmptyBlocksCounter.Inc()
				}
			}

			isCanonical := false
			for _, slotBlock := range slotBlocks {
				if slotBlock.ProposerIndex == validatorIndex && slotBlock.IsCanonical {
					isCanonical = true
					break
				}
			}
			if isCanonical {
				epochCanonicalProposalsGauge.Add(1)
				totalCanonicalProposalsCounter.Inc()
			} else {
				Report("⚠️ 🧱 Validator %v has got block orphaned at epoch %v and slot %v",
					validatorIndex, justifiedEpoch, slot)
				epochOrphanedProposalsGauge.Add(1)
				totalOrphanedProposalsCounter.Inc()
			}
		}

		if pusher != nil {
			if err := pusher.Add(); err != nil {
				log.Error().Msgf("❌ Could not push to Pushgateway: %v", err)
			}
		}

		// Garbage collect unnessary epochs and blocks.
		for _, epoch := range epochsToGarbage {
			delete(attestedEpoches, epoch)
			delete(includedAttestations, epoch)
			for slot := epoch * spec.SLOTS_PER_EPOCH; slot < (epoch+1)*spec.SLOTS_PER_EPOCH; slot++ {
				delete(blocks, slot)
				delete(committees, slot)
			}
		}
	}
}

// MonitorSlashings listens to the beacon chain head changes and checks for slashings.
func MonitorSlashings(ctx context.Context, s *prysmgrpc.Service, wg *sync.WaitGroup) {
	defer wg.Done()

	for justifiedEpoch := range epochsChan {
		log.Info().Msgf("New justified epoch %v", justifiedEpoch)

		var err error
		var blocks map[spec.Slot][]*ChainBlock

		epoch := justifiedEpoch
		Measure(func() {
			blocks, err = ListBlocks(ctx, s, spec.Epoch(epoch))
			Must(err)
		}, "ListBlocks(epoch=%v)", epoch)

		ProcessSlashings(ctx, blocks)
	}
}

// MonitorMaintenanceWindows monitors possible gaps between block proposals for possible maintenance windows.
func MonitorMaintenanceWindows(ctx context.Context, s *prysmgrpc.Service, plainKeys []string, wg *sync.WaitGroup) {
	directIndexes, reversedIndexes, err := IndexPubkeys(ctx, s, plainKeys)
	Must(err)

	validatorIndexes := make(map[spec.ValidatorIndex]interface{})
	for index := range reversedIndexes {
		validatorIndexes[index] = nil
	}

	genesis, err := s.GetGenesis()
	Must(err)
	genesisAt := time.Unix(genesis.GenesisTime.GetSeconds(), int64(genesis.GenesisTime.GetNanos()%1e9))

	log.Info().Msgf("Genesis happened at %v", genesisAt)

	for epoch := range epochsChan {
		log.Info().Msgf("Using epoch %v", epoch)

		var proposals map[spec.Slot]spec.ValidatorIndex
		var committees map[spec.Slot]BeaconCommittees
		Measure(func() {
			committees, err = ListBeaconCommittees(ctx, s, spec.Epoch(epoch))
			Must(err)
		}, "ListBeaconCommittees(epoch=%v)", epoch)
		Measure(func() {
			proposals, err = ListProposers(ctx, s, spec.Epoch(epoch), directIndexes, committees)
			Must(err)
		}, "ListProposers(epoch=%v)", epoch)

		closestSlot := (epoch + 1) * spec.SLOTS_PER_EPOCH
		for slot, index := range proposals {
			if _, ok := validatorIndexes[index]; ok {
				if slot < closestSlot {
					closestSlot = slot
				}

				now := time.Now()
				slotAt := genesisAt.Add(time.Duration(int64(slot*spec.SECONDS_PER_SLOT)) * time.Second)
				if now.After(slotAt) {
					gap := now.Sub(slotAt)
					Report("🚧 🧱 Validator %v proposed a block at epoch %v slot %v %v ago at %v",
						index, epoch, slot, gap, slotAt)
				} else {
					gap := slotAt.Sub(now)
					Report("🚧 🧱 Validator %v proposes a block at epoch %v slot %v in %v at %v",
						index, epoch, slot, gap, slotAt)
				}
			}
		}

		now := time.Now()
		slotAt := genesisAt.Add(time.Duration(int64(closestSlot*spec.SECONDS_PER_SLOT)) * time.Second)
		if now.After(slotAt) {
			now = genesisAt.Add(time.Duration(int64(epoch*spec.SLOTS_PER_EPOCH*spec.SECONDS_PER_SLOT)) * time.Second)
			Report("🚧 🪟 Retrospectively at %v, epoch %v had a maintenance window ending in %v at %v",
				now, epoch, slotAt.Sub(now), slotAt)
		} else {
			Report("🚧 🪟 Epoch %v has a maintenance window ending in %v at %v",
				epoch, slotAt.Sub(now), slotAt)
		}
	}
}
