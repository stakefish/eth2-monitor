package pkg

import (
	"bufio"
	"context"
	"encoding/json"
	"maps"
	"os"
	"slices"
	"sync"
	"time"

	"eth2-monitor/beaconchain"
	"eth2-monitor/cmd/opts"
	"eth2-monitor/spec"

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/api"
	v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2spec "github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/push"
)

const VALIDATOR_INDEX_INVALID = ^spec.ValidatorIndex(0)

// ResolveValidatorKeys transforms validator public keys into their indexes.
// It returns direct and reversed mapping.
func ResolveValidatorKeys(ctx context.Context, beacon *beaconchain.BeaconChain, plainPubKeys []string, epoch spec.Epoch) (map[phase0.ValidatorIndex]string, error) {
	normalized := make([]string, len(plainPubKeys))
	for i, key := range plainPubKeys {
		normalized[i] = beaconchain.NormalizedPublicKey(key)
	}

	result := make(map[phase0.ValidatorIndex]string)

	// Resolve cached validators to indexes
	cache := LoadCache()
	uncached := []string{}
	for _, pubkey := range normalized {
		if cachedIndex, ok := cache.Validators[pubkey]; ok && time.Until(cachedIndex.At) < 8*time.Hour {
			if cachedIndex.Index != VALIDATOR_INDEX_INVALID {
				result[phase0.ValidatorIndex(cachedIndex.Index)] = pubkey
			}
		} else {
			uncached = append(uncached, pubkey)
		}
	}

	// Resolve validators not in cache
	for chunk := range slices.Chunk(uncached, 100) {
		partial, err := beacon.GetValidatorIndexes(ctx, chunk, epoch)
		if err != nil {
			return nil, errors.Wrap(err, "Could not retrieve validator indexes")
		}
		for _, pubkey := range chunk {
			if index, ok := partial[pubkey]; ok {
				result[index] = pubkey
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

	return result, nil
}

// Returns: per-slot mapping: validator index in the committee -> global validator index
// The in-committee index is very small -- ~few hundred, whereas the global one is 6-digit+
func ListCommittees(ctx context.Context, beacon *beaconchain.BeaconChain, epoch spec.Epoch, validators Set[phase0.ValidatorIndex]) (map[spec.Slot]map[phase0.CommitteeIndex]map[int]phase0.ValidatorIndex, error) {
	committees, err := beacon.GetBeaconCommitees(ctx, phase0.Epoch(epoch))
	if err != nil {
		return nil, err
	}

	result := make(map[spec.Slot]map[phase0.CommitteeIndex]map[int]phase0.ValidatorIndex)

	for _, committee := range committees {
		slot := uint64(committee.Slot)
		for intraCommitteeValidatorIndex, globalValidatorIndex := range committee.Validators {
			if validators.Contains(globalValidatorIndex) {
				if _, ok := result[slot]; !ok {
					result[slot] = make(map[phase0.CommitteeIndex]map[int]phase0.ValidatorIndex)
				}
				if _, ok := result[slot][committee.Index]; !ok {
					result[slot][committee.Index] = make(map[int]phase0.ValidatorIndex)
				}
				result[slot][committee.Index][intraCommitteeValidatorIndex] = globalValidatorIndex
			}
		}
	}

	return result, nil
}

// ListProposerDuties returns block proposers scheduled for epoch.
// To improve performance, it has to narrow the set of validators for which it checks duties.
func ListProposerDuties(ctx context.Context, beacon *beaconchain.BeaconChain, epoch phase0.Epoch, validators []phase0.ValidatorIndex) (map[spec.Slot]phase0.ValidatorIndex, error) {
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

func ListAttesterDuties(ctx context.Context, beacon *beaconchain.BeaconChain, epoch phase0.Epoch, validators []phase0.ValidatorIndex) (map[spec.Slot]Set[phase0.ValidatorIndex], error) {
	duties, err := beacon.GetAttesterDuties(ctx, epoch, validators)
	if err != nil {
		return nil, err
	}

	result := make(map[spec.Slot]Set[phase0.ValidatorIndex])
	for _, duty := range duties {
		slot := uint64(duty.Slot)
		if _, ok := result[slot]; !ok {
			result[slot] = NewSet[phase0.ValidatorIndex]()
		}
		result[slot].Add(duty.ValidatorIndex)
	}
	return result, nil
}

func ListEpochBlocks(ctx context.Context, beacon *beaconchain.BeaconChain, epoch spec.Epoch) (map[spec.Slot]*eth2spec.VersionedSignedBeaconBlock, error) {
	result := make(map[spec.Slot]*eth2spec.VersionedSignedBeaconBlock, spec.SLOTS_PER_EPOCH)
	low := spec.EpochLowestSlot(epoch)
	high := spec.EpochHighestSlot(epoch)
	for slot := low; slot <= high; slot++ {
		block, err := beacon.GetBlock(ctx, phase0.Slot(slot))

		if err != nil {
			log.Error().Err(err)
			continue
		}

		if block == nil {
			// Missed slot
			continue
		}

		result[slot] = block
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
		thisEpoch := spec.EpochFromSlot(uint64(headEvent.Slot))
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

	epochGauge := prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "ETH2",
			Name:      "epoch",
			Help:      "Current justified epoch",
		})
	prometheus.MustRegister(epochGauge)

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

	var pusher *push.Pusher
	if opts.PushGatewayUrl != "" && opts.PushGatewayJob != "" {
		registry := prometheus.NewRegistry()
		registry.MustRegister(
			epochGauge,

			// Attestations
			totalMissedAttestationsCounter,
			totalCanonicalAttestationsCounter,
			totalDelayedAttestationsOverToleranceCounter,
			canonicalAttestationDistances,

			// Proposals
			totalMissedProposalsCounter,
			totalCanonicalProposalsCounter,
			lastMissedProposalSlotGauge,
			lastMissedProposalValidatorIndexGauge,

			// Misc
			lastProposedEmptyBlockSlotGauge,
		)
		pusher = push.New(opts.PushGatewayUrl, opts.PushGatewayJob).Gatherer(registry)
	}

	unfulfilledAttesterDuties := make(map[spec.Slot]Set[phase0.ValidatorIndex])
	validatorFromIntraCommitteeValidator := make(map[spec.Slot]map[phase0.CommitteeIndex]map[int]phase0.ValidatorIndex)
	for epoch := range epochsChan {
		log.Info().Msgf("New epoch %v", epoch)
		epochGauge.Set(float64(epoch))

		var validatorPubkeyFromIndex map[phase0.ValidatorIndex]string
		Measure(func() {
			var err error
			validatorPubkeyFromIndex, err = ResolveValidatorKeys(ctx, beacon, plainKeys, epoch)
			Must(err)
		}, "ResolveValidatorKeys(epoch=%v)", epoch)

		Measure(func() {
			epochCommittees, err := ListCommittees(ctx, beacon, spec.Epoch(epoch), NewSet(slices.Collect(maps.Keys(validatorPubkeyFromIndex))...))
			Must(err)
			for slot, slotGlobalFromIntra := range epochCommittees {
				validatorFromIntraCommitteeValidator[slot] = slotGlobalFromIntra
			}
		}, "ListCommittees(epoch=%v)", epoch)
		Measure(func() {
			epochAttesterDuties, err := ListAttesterDuties(ctx, beacon, phase0.Epoch(epoch), slices.Collect(maps.Keys(validatorPubkeyFromIndex)))
			Must(err)
			for slot, attesters := range epochAttesterDuties {
				unfulfilledAttesterDuties[slot] = attesters
			}
		}, "ListAttesterDuties(epoch=%v)", epoch)

		var proposerDuties map[spec.Slot]phase0.ValidatorIndex
		Measure(func() {
			var err error
			proposerDuties, err = ListProposerDuties(ctx, beacon, phase0.Epoch(epoch), slices.Collect(maps.Keys(validatorPubkeyFromIndex)))
			Must(err)
		}, "ListProposerDuties(epoch=%v)", epoch)

		var bestBids map[spec.Slot]BidTrace
		if len(mevRelays) > 0 {
			Measure(func() {
				var err error
				bestBids, err = ListBestBids(ctx, 4*time.Second, mevRelays, epoch, validatorPubkeyFromIndex, proposerDuties)
				if err != nil {
					log.Error().Stack().Err(err)
					// Even if RequestEpochBidTraces() returned an error, there may still be valuable partial results in bidtraces, so process them!
				}
			}, "ListBestBids(epoch=%v)", epoch)
		}

		var epochBlocks map[spec.Slot]*eth2spec.VersionedSignedBeaconBlock
		Measure(func() {
			var err error
			epochBlocks, err = ListEpochBlocks(ctx, beacon, spec.Epoch(epoch))
			Must(err)
		}, "ListEpochBlocks(epoch=%v)", epoch)

		for _, block := range epochBlocks {
			attestations, err := block.Attestations()
			if err != nil {
				log.Error().Err(err).Msg("Get block attestations")
				continue
			}
			for _, attestation := range attestations {
				for _, intraCommitteeValidatorIndex := range attestation.AggregationBits.BitIndices() {
					attestedSlot := uint64(attestation.Data.Slot)
					if _, ok := validatorFromIntraCommitteeValidator[attestedSlot]; !ok {
						continue
					}
					if _, ok := validatorFromIntraCommitteeValidator[attestedSlot][attestation.Data.Index]; !ok {
						continue
					}
					if _, ok := validatorFromIntraCommitteeValidator[attestedSlot][attestation.Data.Index][intraCommitteeValidatorIndex]; !ok {
						continue
					}
					validatorIndex := validatorFromIntraCommitteeValidator[attestedSlot][attestation.Data.Index][intraCommitteeValidatorIndex]

					unfulfilledAttesterDuties[attestedSlot].Remove(validatorIndex)
					if unfulfilledAttesterDuties[attestedSlot].IsEmpty() {
						delete(unfulfilledAttesterDuties, attestedSlot)
					}
					totalCanonicalAttestationsCounter.Inc()

					blockSlot, err := block.Slot()
					if err != nil {
						log.Error().Err(err).Msg("Get block slot")
						continue
					}

					attestationDistance := blockSlot - phase0.Slot(attestedSlot) - 1
					// Take skipped slots into account
					for s := attestedSlot; s < uint64(blockSlot); s++ {
						if _, ok := epochBlocks[s]; !ok {
							attestationDistance--
						}
					}

					if attestationDistance > 2 {
						Report("⚠️ 🧾 Validator %v (%v) attested slot %v at slot %v, epoch %v, attestation distance is %v",
							validatorIndex, validatorPubkeyFromIndex[validatorIndex], attestedSlot, blockSlot, epoch, attestationDistance)
						totalDelayedAttestationsOverToleranceCounter.Inc()
					} else if opts.Monitor.PrintSuccessful {
						Info("✅ 🧾 Validator %v (%v) attested slot %v at slot %v, epoch %v", validatorIndex, validatorPubkeyFromIndex[validatorIndex], attestedSlot, blockSlot, epoch)
					}

					totalCanonicalAttestationsCounter.Inc()
					canonicalAttestationDistances.Observe(float64(attestationDistance))
				}
			}
		}

		// Attestation is assumed to be missed if it was not included within
		// current epoch or one after the current.  Normally, attestations should
		// land in 1-2 *slots* after the attested one.
		missedAttestationEpoch := epoch - 1
		missedAttestationSlotHigh := spec.EpochHighestSlot(missedAttestationEpoch)
		log.Trace().Msgf("Unfulfilled attester duties: %v", unfulfilledAttesterDuties)
		for _, slot := range slices.Sorted(maps.Keys(unfulfilledAttesterDuties)) {
			if slot > missedAttestationSlotHigh {
				break
			}
			for validatorIndex := range unfulfilledAttesterDuties[slot].Elems() {
				Report("❌ 🧾 Validator %v (%v) did not attest slot %v (epoch %v)", validatorIndex, validatorPubkeyFromIndex[validatorIndex], slot, epoch)
				totalMissedAttestationsCounter.Inc()
			}
			delete(unfulfilledAttesterDuties, slot)
			delete(validatorFromIntraCommitteeValidator, slot)
		}

		log.Info().Msgf("Number of epoch %v tracked proposals is %v", epoch, len(proposerDuties))
		for slot, validatorIndex := range proposerDuties {
			block, ok := epochBlocks[slot]
			if !ok {
				Report("❌ 🧱 Validator %v missed proposal at slot %v", validatorIndex, slot)
				totalMissedProposalsCounter.Inc()
				lastMissedProposalSlotGauge.Set(float64(slot))
				lastMissedProposalValidatorIndexGauge.Set(float64(validatorIndex))
				break
			}

			txns, err := block.ExecutionTransactions()
			if err != nil {
				log.Error().Msgf("Error obtaining execution layer transaction for block")
				continue
			}
			if len(txns) != 0 {
				continue
			}
			proposerIndex, err := block.ProposerIndex()
			if err != nil {
				log.Error().Msgf("Error obtaining proposer index for block")
				continue
			}
			if proposerIndex == validatorIndex {
				validatorPublicKey := validatorPubkeyFromIndex[validatorIndex]
				Report("⚠️ 🧱 Validator %v (%v) proposed a block containing no transactions at epoch %v and slot %v", validatorPublicKey, validatorIndex, epoch, slot)
				lastProposedEmptyBlockSlotGauge.Set(float64(slot))
				totalProposedEmptyBlocksCounter.Inc()
			}

			totalCanonicalProposalsCounter.Inc()
		}

		if len(mevRelays) > 0 {
			if len(proposerDuties) > 0 {
				log.Info().Msgf("Number of MEV boosts is %v", len(bestBids))
			}
			for slot, validatorIndex := range proposerDuties {
				trace, ok := bestBids[slot]
				if !ok {
					totalVanillaBlocksCounter.Inc()
					lastVanillaBlockSlotGauge.Set(float64(slot))
					lastVanillaBlockValidatorGauge.Set(float64(validatorIndex))
					log.Error().Msgf("❌ Missing bid trace for proposal slot %v, validator %v (%v)", slot, validatorIndex, validatorPubkeyFromIndex[validatorIndex])
					continue
				}
				block, ok := epochBlocks[slot]
				if !ok {
					// Missed proposal reported earlier.  Don't report again
					continue
				}
				proposerIndex, err := block.ProposerIndex()
				if err != nil {
					log.Error().Msgf("Error obtaining proposer index for block")
					continue
				}
				if proposerIndex != validatorIndex {
					continue
				}
				execution_block_hash, err := block.ExecutionBlockHash()
				if err != nil {
					log.Error().Msgf("❌ Failed to obtain execution block hash at slot %v", slot)
					continue
				}
				if execution_block_hash.String() == trace.BlockHash {
					// Our validator proposed the best block -- all good
					if opts.Monitor.PrintSuccessful {
						Info("✅ 🧾 Validator %v (%v) proposed optimal MEV execution block %v at slot %v, epoch %v", validatorIndex, validatorPubkeyFromIndex[validatorIndex], trace.BlockHash, slot, epoch)
					}
					continue
				}
				totalVanillaBlocksCounter.Inc()
				lastVanillaBlockSlotGauge.Set(float64(slot))
				lastVanillaBlockValidatorGauge.Set(float64(validatorIndex))
				log.Error().Msgf("❌ Validator %v (%v) proposed a vanilla block %v at slot %v", validatorIndex, validatorPubkeyFromIndex[validatorIndex], execution_block_hash, slot)
			}
		}

		if pusher != nil {
			if err := pusher.Add(); err != nil {
				log.Error().Msgf("❌ Could not push to Pushgateway: %v", err)
			}
		}
	}
}
