package pkg

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"slices"
	"strconv"
	"sync"
	"time"

	"eth2-monitor/beaconchain"
	"eth2-monitor/cmd/opts"
	"eth2-monitor/spec"

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/api"
	v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2spec "github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/pkg/errors"
	bitfield "github.com/prysmaticlabs/go-bitfield"
	"github.com/rs/zerolog/log"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/push"
)

const VALIDATOR_INDEX_INVALID = ^spec.ValidatorIndex(0)

// ResolveValidatorKeys transforms validator public keys into their indexes.
// It returns direct and reversed mapping.
func ResolveValidatorKeys(ctx context.Context, beacon *beaconchain.BeaconChain, plainPubKeys []string, epoch spec.Epoch) (map[string]phase0.ValidatorIndex, map[phase0.ValidatorIndex]string, error) {
	normalized := make([]string, len(plainPubKeys))
	for i, key := range plainPubKeys {
		normalized[i] = beaconchain.NormalizedPublicKey(key)
	}

	result := make(map[string]phase0.ValidatorIndex)
	reversed := make(map[phase0.ValidatorIndex]string)

	// Resolve cached validators to indexes
	cache := LoadCache()
	uncached := []string{}
	for _, pubkey := range normalized {
		if cachedIndex, ok := cache.Validators[pubkey]; ok && time.Until(cachedIndex.At) < 8*time.Hour {
			if cachedIndex.Index != VALIDATOR_INDEX_INVALID {
				result[pubkey] = phase0.ValidatorIndex(cachedIndex.Index)
				reversed[phase0.ValidatorIndex(cachedIndex.Index)] = pubkey
			}
		} else {
			uncached = append(uncached, pubkey)
		}
	}

	// Resolve validators not in cache
	for chunk := range slices.Chunk(uncached, 100) {
		partial, err := beacon.GetValidatorIndexes(ctx, chunk, epoch)
		if err != nil {
			return nil, nil, errors.Wrap(err, "Could not retrieve validator indexes")
		}
		for _, pubkey := range chunk {
			if index, ok := partial[pubkey]; ok {
				result[pubkey] = index
				reversed[index] = pubkey
				cache.Validators[pubkey] = CachedIndex{
					Index: uint64(index),
					At:    time.Now(),
				}
			} else {
				cache.Validators[pubkey] = CachedIndex{
					Index: VALIDATOR_INDEX_INVALID,
					At:    time.Now(),
				}
			}
		}
	}

	SaveCache(cache)

	return result, reversed, nil
}

// ListProposers returns block proposers scheduled for epoch.
// To improve performance, it has to narrow the set of validators for which it checks duties.
func ListProposers(ctx context.Context, beacon *beaconchain.BeaconChain, epoch phase0.Epoch, validators []phase0.ValidatorIndex) (map[spec.Slot]phase0.ValidatorIndex, error) {
	result := make(map[spec.Slot]phase0.ValidatorIndex)
	for chunk := range slices.Chunk(validators, 250) {
		duties, err := beacon.GetProposerDuties(ctx, epoch, chunk)
		if err != nil {
			return nil, err
		}

		for _, duty := range duties {
			result[spec.Slot(duty.Slot)] = phase0.ValidatorIndex(duty.ValidatorIndex)
		}
	}
	return result, nil
}

type BeaconCommittees map[spec.CommitteeIndex][]phase0.ValidatorIndex

// ListBeaconCommittees lists committees for a specific epoch.
func ListBeaconCommittees(ctx context.Context, beacon *beaconchain.BeaconChain, epoch spec.Epoch) (map[spec.Slot]BeaconCommittees, error) {
	committees, err := beacon.GetBeaconCommitees(ctx, phase0.Epoch(epoch))
	if err != nil {
		return nil, err
	}

	result := make(map[spec.Slot]BeaconCommittees)

	for _, committee := range committees {
		slot := uint64(committee.Slot)
		if _, ok := result[slot]; !ok {
			result[slot] = make(BeaconCommittees)
		}
		var indexes []phase0.ValidatorIndex
		for _, index := range committee.Validators {
			indexes = append(indexes, phase0.ValidatorIndex(index))
		}
		result[slot][spec.CommitteeIndex(committee.Index)] = indexes
	}

	return result, nil
}

type ChainBlock struct {
	IsCanonical       bool
	Slot              spec.Slot
	ProposerIndex     phase0.ValidatorIndex
	ChainAttestations []*ChainAttestation

	BlockContainer    *eth2spec.VersionedSignedBeaconBlock
	Attestations      []*phase0.Attestation
	Deposits          []*phase0.Deposit
	AttesterSlashings []*phase0.AttesterSlashing
	ProposerSlashings []*phase0.ProposerSlashing
	VoluntaryExits    []*phase0.SignedVoluntaryExit
	Transactions      []types.Transaction
}

type ChainAttestation struct {
	AggregationBits []byte
	Slot            spec.Slot
	InclusionSlot   spec.Slot
	CommitteeIndex  spec.CommitteeIndex
}

func unmarshallTransactions(rlpEncodedTxs []bellatrix.Transaction) (txs []types.Transaction, err error) {
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
func ListBlocks(ctx context.Context, beacon *beaconchain.BeaconChain, epoch spec.Epoch) (map[spec.Slot][]*ChainBlock, error) {
	blockHeadersProvider := beacon.Service().(eth2client.BeaconBlockHeadersProvider)
	blockProvider := beacon.Service().(eth2client.SignedBeaconBlockProvider)

	result := make(map[spec.Slot][]*ChainBlock)
	lastSlot := (epoch + 1) * spec.SLOTS_PER_EPOCH
	for slot := epoch * spec.SLOTS_PER_EPOCH; slot < lastSlot; slot++ {
		resp, err := blockHeadersProvider.BeaconBlockHeader(ctx, &api.BeaconBlockHeaderOpts{
			Common: api.CommonOpts{},
			Block:  fmt.Sprintf("%v", slot),
		})

		if resp == nil {
			// Missed slot
			continue
		}
		log.Trace().Msgf("Block at slot %v root=%v", slot, hex.EncodeToString(resp.Data.Root[:]))
		if err != nil {
			log.Error().Err(err).Msg("BeaconBlockHeader")
			continue
		}

		proposerIndex := phase0.ValidatorIndex(resp.Data.Header.Message.ProposerIndex)

		signedBeaconBlock, err := blockProvider.SignedBeaconBlock(ctx, &api.SignedBeaconBlockOpts{
			Block: strconv.FormatUint(uint64(resp.Data.Header.Message.Slot), 10),
		})
		if err != nil {
			log.Error().Err(err).Msg("SignedBeaconBlock")
			continue
		}

		blockAttestations, err := signedBeaconBlock.Data.Attestations()
		if err != nil {
			return nil, err
		}
		var chainAttestations []*ChainAttestation
		for _, att := range blockAttestations {
			chainAttestations = append(chainAttestations, &ChainAttestation{
				AggregationBits: att.AggregationBits,
				CommitteeIndex:  spec.CommitteeIndex(att.Data.Index),
				Slot:            spec.Slot(att.Data.Slot),
				InclusionSlot:   slot,
			})
		}

		attesterSlashings, err := signedBeaconBlock.Data.AttesterSlashings()
		if err != nil {
			return nil, err
		}

		proposerSlashings, err := signedBeaconBlock.Data.ProposerSlashings()
		if err != nil {
			return nil, err
		}

		deposits, err := signedBeaconBlock.Data.Deposits()
		if err != nil {
			return nil, err
		}

		// https://github.com/ethereum/annotated-spec/blob/98c63ebcdfee6435e8b2a76e1fca8549722f6336/merge/beacon-chain.md#custom-types%C2%B6
		//      [...] execution blocks are stored in SSZ form, but the
		//      transactions inside them are encoded with RLP, and so
		//      to software that only understands SSZ they are
		//      presented as "opaque" byte arrays.
		marshalledTransactions, err := signedBeaconBlock.Data.ExecutionTransactions()
		if err != nil {
			return nil, err
		}
		var unmarshalledTransactions []types.Transaction
		if marshalledTransactions != nil {
			txs, err := unmarshallTransactions(marshalledTransactions)
			if err == nil {
				unmarshalledTransactions = txs
			}
		}

		result[slot] = append(result[slot], &ChainBlock{
			IsCanonical:       resp.Data.Canonical,
			ProposerIndex:     proposerIndex,
			Slot:              slot,
			AttesterSlashings: attesterSlashings,
			ProposerSlashings: proposerSlashings,
			BlockContainer:    signedBeaconBlock.Data,
			ChainAttestations: chainAttestations,
			Deposits:          deposits,
			Transactions:      unmarshalledTransactions,
		})
	}

	return result, nil
}

// SubscribeToEpochs subscribes to changings of the beacon chain head.
// Note, if --replay-epoch or --since-epoch options passed, SubscribeToEpochs will not
// listen to real-time changes.
func SubscribeToEpochs(ctx context.Context, beacon *beaconchain.BeaconChain, wg *sync.WaitGroup, epochsChan chan spec.Epoch) {
	defer wg.Done()

	finalityProvider := beacon.Service().(eth2client.FinalityProvider)
	resp, err := finalityProvider.Finality(ctx, &api.FinalityOpts{State: "head"})
	Must(err)

	lastEpoch := uint64(resp.Data.Justified.Epoch)

	if len(opts.Monitor.ReplayEpoch) > 0 {
		for _, epoch := range opts.Monitor.ReplayEpoch {
			epochsChan <- spec.Epoch(epoch)
		}
		close(epochsChan)
		return
	}
	if opts.Monitor.SinceEpoch != ^uint64(0) {
		for epoch := opts.Monitor.SinceEpoch; epoch < lastEpoch; epoch++ {
			epochsChan <- epoch
		}
		close(epochsChan)
		return
	}

	eventsHandlerFunc := func(event *v1.Event) {
		headEvent := event.Data.(*v1.HeadEvent)
		log.Trace().Msgf("New head slot %v block %v", headEvent.Slot, headEvent.Block.String())
		thisEpoch := uint64(headEvent.Slot / spec.SLOTS_PER_EPOCH)
		if thisEpoch > lastEpoch {
			log.Trace().Msgf("New epoch %v at slot %v", thisEpoch, headEvent.Slot)
			epochsChan <- lastEpoch // send the epoch that has just ended
			lastEpoch = thisEpoch
		}
	}

	eventsProvider := beacon.Service().(eth2client.EventsProvider)
	err = eventsProvider.Events(ctx, []string{"head"}, eventsHandlerFunc)
	Must(err)
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

func LoadMEVRelays(mevRelaysFilePath string) ([]string, error) {
	relays := []string{}

	contents, err := os.ReadFile(mevRelaysFilePath)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(contents, &relays)
	if err != nil {
		return nil, err
	}

	return relays, nil
}

// MonitorAttestationsAndProposals listens to the beacon chain head changes and checks new blocks and attestations.
func MonitorAttestationsAndProposals(ctx context.Context, beacon *beaconchain.BeaconChain, plainKeys []string, mevRelays []string, wg *sync.WaitGroup, epochsChan chan spec.Epoch) {
	defer wg.Done()

	committees := make(map[spec.Slot]BeaconCommittees)
	blocks := make(map[spec.Slot][]*ChainBlock)

	includedAttestations := make(map[spec.Epoch]map[phase0.ValidatorIndex]*ChainAttestation)
	attestedEpoches := make(map[spec.Epoch]map[phase0.ValidatorIndex]*AttestationLoggingStatus)

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

	lastProposedEmptyBlockSlotGauge := prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "ETH2",
			Name:      "lastProposedEmptyBlockSlot",
			Help:      "Slot of the last proposed block containing no transactions",
		})
	prometheus.MustRegister(lastProposedEmptyBlockSlotGauge)

	totalMissedProposalsCounter := prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: "ETH2",
			Name:      "totalMissedProposals",
			Help:      "Proposals missed since monitoring started",
		})
	prometheus.MustRegister(totalMissedProposalsCounter)

	lastMissedProposalSlotGauge := prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "ETH2",
			Name:      "lastMissedProposalSlot",
			Help:      "Slot of the last missed proposal",
		})
	prometheus.MustRegister(lastMissedProposalSlotGauge)

	lastMissedProposalValidatorIndexGauge := prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "ETH2",
			Name:      "lastMissedProposalValidatorIndex",
			Help:      "Validator index of the last missed proposal",
		})
	prometheus.MustRegister(lastMissedProposalValidatorIndexGauge)

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

	totalVanillaBlocksCounter := prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: "ETH2",
			Name:      "totalVanillaBlocks",
			Help:      "Proposed blocks not matching those built by MEV relays",
		})
	prometheus.MustRegister(totalVanillaBlocksCounter)

	lastVanillaBlockSlotGauge := prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "ETH2",
			Name:      "lastVanillaBlockSlot",
			Help:      "Slot of the last proposed vanilla block",
		})
	prometheus.MustRegister(lastVanillaBlockSlotGauge)

	lastVanillaBlockValidatorGauge := prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "ETH2",
			Name:      "lastVanillaBlockValidator",
			Help:      "Index of the last validator that proposed a vanilla block",
		})
	prometheus.MustRegister(lastVanillaBlockValidatorGauge)

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
		registry.MustRegister(
			epochGauge,

			// Attestations
			epochMissedAttestationsGauge,
			lastEpochMissedAttestationsGauge,
			epochCanonicalAttestationsGauge,
			epochOrphanedAttestationsGauge,
			epochDelayedAttestationsOverToleranceGauge,
			totalMissedAttestationsCounter,
			totalCanonicalAttestationsCounter,
			totalOrphanedAttestationsCounter,
			totalDelayedAttestationsOverToleranceCounter,
			canonicalAttestationDistances,
			orphanedAttestationDistances,

			// Proposals
			epochMissedProposalsGauge,
			epochCanonicalProposalsGauge,
			epochOrphanedProposalsGauge,
			totalMissedProposalsCounter,
			totalCanonicalProposalsCounter,
			totalOrphanedProposalsCounter,
			lastMissedProposalSlotGauge,
			lastMissedProposalValidatorIndexGauge,

			// Misc
			lastProposedEmptyBlockSlotGauge,
		)
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
		var proposals map[spec.Slot]phase0.ValidatorIndex
		var bestBids map[spec.Slot]BidTrace

		epoch := justifiedEpoch

		_, reversedIndexes, err := ResolveValidatorKeys(ctx, beacon, plainKeys, epoch)
		Must(err)

		Measure(func() {
			epochCommittees, err = ListBeaconCommittees(ctx, beacon, spec.Epoch(epoch))
			Must(err)
		}, "ListBeaconCommittees(epoch=%v)", epoch)
		Measure(func() {
			epochBlocks, err = ListBlocks(ctx, beacon, spec.Epoch(epoch))
			Must(err)
		}, "ListBlocks(epoch=%v)", epoch)
		Measure(func() {
			proposals, err = ListProposers(ctx, beacon, phase0.Epoch(epoch), slices.Collect(maps.Keys(reversedIndexes)))
			Must(err)
		}, "ListProposers(epoch=%v)", epoch)
		if len(mevRelays) > 0 {
			Measure(func() {
				bestBids, err = ListBestBids(ctx, 4*time.Second, mevRelays, epoch, reversedIndexes, proposals)
				if err != nil {
					log.Error().Stack().Err(err)
					// Even if RequestEpochBidTraces() returned an error, there may still be valuable partial results in bidtraces, so process them!
				}
			}, "RequestEpochBidTraces(epoch=%v)", epoch)
		}

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
				attestedEpoches[epoch] = make(map[phase0.ValidatorIndex]*AttestationLoggingStatus)
			}

			for _, committee := range slotCommittees {
				for _, index := range committee {
					if _, ok := reversedIndexes[phase0.ValidatorIndex(index)]; ok {
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
							includedAttestations[epoch] = make(map[phase0.ValidatorIndex]*ChainAttestation)
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
					Report("❌ 🧾 Validator %v (%v) did not attest slot %v (epoch %v)", index, reversedIndexes[index], attStatus.Slot, epoch)
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
						Report("⚠️ 🧾 Validator %v (%v) attested slot %v at slot %v, epoch %v, opt distance is %v, abs distance is %v",
							index, reversedIndexes[index], att.Slot, att.InclusionSlot, epoch, optimalDistance, absDistance)
						epochDelayedAttestationsOverToleranceGauge.Add(1)
						totalDelayedAttestationsOverToleranceCounter.Inc()
					} else if opts.Monitor.PrintSuccessful {
						Info("✅ 🧾 Validator %v (%v) attested slot %v at slot %v, epoch %v, opt distance is %v, abs distance is %v",
							index, reversedIndexes[index], att.Slot, att.InclusionSlot, epoch, optimalDistance, absDistance)
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

		log.Info().Msgf("Number of epoch %v tracked proposals is %v", epoch, len(proposals))
		for slot, validatorIndex := range proposals {
			slotBlocks, ok := blocks[slot]
			if !ok {
				Report("❌ 🧱 Validator %v missed proposal at slot %v",
					validatorIndex, slot)
				epochMissedProposalsGauge.Add(1)
				totalMissedProposalsCounter.Inc()
				lastMissedProposalSlotGauge.Set(float64(slot))
				lastMissedProposalValidatorIndexGauge.Set(float64(validatorIndex))
				break
			}

			for _, slotBlock := range slotBlocks {
				if len(slotBlock.Transactions) != 0 {
					continue
				}
				if slotBlock.ProposerIndex == validatorIndex {
					validatorPublicKey := reversedIndexes[validatorIndex]
					Report("⚠️ 🧱 Validator %v (%v) proposed a block containing no transactions at epoch %v and slot %v", validatorPublicKey, validatorIndex, justifiedEpoch, slot)
					lastProposedEmptyBlockSlotGauge.Set(float64(slot))
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

		if len(mevRelays) > 0 {
			if len(proposals) > 0 {
				log.Info().Msgf("Number of MEV boosts is %v", len(bestBids))
			}
			for slot, validatorIndex := range proposals {
				trace, ok := bestBids[slot]
				if !ok {
					totalVanillaBlocksCounter.Inc()
					lastVanillaBlockSlotGauge.Set(float64(slot))
					lastVanillaBlockValidatorGauge.Set(float64(validatorIndex))
					log.Error().Msgf("❌ Missing bid trace for proposal slot %v, validator %v (%v)", slot, validatorIndex, reversedIndexes[validatorIndex])
					continue
				}
				slotBlocks, ok := blocks[slot]
				if !ok {
					// Missed proposal reported earlier.  Don't report again
					continue
				}
				for _, slotBlock := range slotBlocks {
					if slotBlock.ProposerIndex != validatorIndex {
						continue
					}
					execution_block_hash, err := slotBlock.BlockContainer.ExecutionBlockHash()
					if err != nil {
						log.Error().Msgf("❌ Failed to obtain execution block hash at slot %v", slot)
						continue
					}
					if execution_block_hash.String() == trace.BlockHash {
						// Our validator proposed the best block -- all good
						if opts.Monitor.PrintSuccessful {
							Info("✅ 🧾 Validator %v (%v) proposed optimal MEV execution block %v at slot %v, epoch %v", validatorIndex, reversedIndexes[validatorIndex], trace.BlockHash, slot, epoch)
						}
						continue
					}
					totalVanillaBlocksCounter.Inc()
					lastVanillaBlockSlotGauge.Set(float64(slot))
					lastVanillaBlockValidatorGauge.Set(float64(validatorIndex))
					log.Error().Msgf("❌ Validator %v (%v) proposed a vanilla block %v at slot %v", validatorIndex, reversedIndexes[validatorIndex], execution_block_hash, slot)
				}
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
func MonitorSlashings(ctx context.Context, beacon *beaconchain.BeaconChain, wg *sync.WaitGroup, epochsChan chan spec.Epoch) {
	defer wg.Done()

	for justifiedEpoch := range epochsChan {
		log.Info().Msgf("New justified epoch %v", justifiedEpoch)

		var err error
		var blocks map[spec.Slot][]*ChainBlock

		epoch := justifiedEpoch
		Measure(func() {
			blocks, err = ListBlocks(ctx, beacon, spec.Epoch(epoch))
			Must(err)
		}, "ListBlocks(epoch=%v)", epoch)

		ProcessSlashings(ctx, beacon, blocks)
	}
}
