package pkg

import (
	"bufio"
	"context"
	"encoding/json"
	"maps"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"eth2-monitor/beaconchain"
	"eth2-monitor/cmd/opts"
	"eth2-monitor/spec"

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/api"
	v1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec/electra"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"

	"github.com/prometheus/client_golang/prometheus"
)

const VALIDATOR_INDEX_INVALID = ^phase0.ValidatorIndex(0)

// CommitteeInfo holds the committee length and tracked validator positions.
// Built from AttesterDuty responses instead of fetching full committee lists.
type CommitteeInfo struct {
	Length     uint64                              // committee size (from duty.CommitteeLength)
	Validators map[uint64]phase0.ValidatorIndex    // position → validatorIndex (tracked only)
}

// BuildCommitteeLookup creates a sparse committee map from attester duties,
// containing only tracked validators and their positions.
func BuildCommitteeLookup(duties []*v1.AttesterDuty, tracked map[phase0.ValidatorIndex]string) map[phase0.Slot]map[phase0.CommitteeIndex]*CommitteeInfo {
	result := make(map[phase0.Slot]map[phase0.CommitteeIndex]*CommitteeInfo)
	for _, duty := range duties {
		if _, ok := tracked[duty.ValidatorIndex]; !ok {
			continue
		}
		if result[duty.Slot] == nil {
			result[duty.Slot] = make(map[phase0.CommitteeIndex]*CommitteeInfo)
		}
		info := result[duty.Slot][duty.CommitteeIndex]
		if info == nil {
			info = &CommitteeInfo{Length: duty.CommitteeLength, Validators: make(map[uint64]phase0.ValidatorIndex)}
			result[duty.Slot][duty.CommitteeIndex] = info
		}
		info.Validators[duty.ValidatorCommitteeIndex] = duty.ValidatorIndex
	}
	return result
}

// ResolveValidatorKeys transforms validator public keys into their indexes.
// It returns direct and reversed mapping.
func ResolveValidatorKeys(ctx context.Context, beacon *beaconchain.BeaconChain, plainPubKeys []string, epoch phase0.Epoch) (map[phase0.ValidatorIndex]string, error) {
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
				result[cachedIndex.Index] = pubkey
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
					Index: index,
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

// ListProposerDuties returns block proposers scheduled for epoch.
// To improve performance, it has to narrow the set of validators for which it checks duties.
func ListProposerDuties(ctx context.Context, beacon *beaconchain.BeaconChain, epoch phase0.Epoch, validators []phase0.ValidatorIndex) (map[phase0.Slot]phase0.ValidatorIndex, error) {
	result := make(map[phase0.Slot]phase0.ValidatorIndex)
	for chunk := range slices.Chunk(validators, 250) {
		duties, err := beacon.GetProposerDuties(ctx, epoch, chunk)
		if err != nil {
			return nil, err
		}

		for _, duty := range duties {
			result[duty.Slot] = phase0.ValidatorIndex(duty.ValidatorIndex)
		}
	}
	return result, nil
}

func ListAttesterDuties(ctx context.Context, beacon *beaconchain.BeaconChain, epoch phase0.Epoch, validators []phase0.ValidatorIndex) (map[phase0.Slot]Set[phase0.ValidatorIndex], error) {
	duties, err := beacon.GetAttesterDuties(ctx, epoch, validators)
	if err != nil {
		return nil, err
	}

	result := make(map[phase0.Slot]Set[phase0.ValidatorIndex])
	for _, duty := range duties {
		slot := duty.Slot
		if _, ok := result[slot]; !ok {
			result[slot] = NewSet[phase0.ValidatorIndex]()
		}
		result[slot].Add(duty.ValidatorIndex)
	}
	return result, nil
}

func ListEpochBlocks(ctx context.Context, beacon *beaconchain.BeaconChain, epoch phase0.Epoch) (map[phase0.Slot]*electra.SignedBeaconBlock, error) {
	result := make(map[phase0.Slot]*electra.SignedBeaconBlock, spec.SLOTS_PER_EPOCH)
	low := spec.EpochLowestSlot(epoch)
	high := spec.EpochHighestSlot(epoch)

	// H09 fix: fetch a few slots past the epoch end to catch cross-epoch attestations.
	// Attestations from the last slots of an epoch are routinely included in the first
	// slots of the next epoch. Without this look-ahead, those attestations appear "missed".
	lookAhead := phase0.Slot(4)

	for slot := low; slot <= high+lookAhead; slot++ {
		block, err := beacon.GetBlock(ctx, phase0.Slot(slot))

		if err != nil {
			log.Error().Err(err).Msg("failed to fetch block")
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
func SubscribeToEpochs(ctx context.Context, beacon *beaconchain.BeaconChain, wg *sync.WaitGroup, epochsChan chan phase0.Epoch) {
	defer wg.Done()

	finalityProvider := beacon.Service().(eth2client.FinalityProvider)
	resp, err := finalityProvider.Finality(ctx, &api.FinalityOpts{State: "head"})
	Must(err)

	lastEpoch := resp.Data.Justified.Epoch

	if len(opts.Monitor.ReplayEpoch) > 0 {
		for _, epoch := range opts.Monitor.ReplayEpoch {
			epochsChan <- phase0.Epoch(epoch)
		}
		close(epochsChan)
		return
	}
	if opts.Monitor.SinceEpoch != ^uint64(0) {
		for epoch := opts.Monitor.SinceEpoch; phase0.Epoch(epoch) < lastEpoch; epoch++ {
			epochsChan <- phase0.Epoch(epoch)
		}
		close(epochsChan)
		return
	}

	eventsHandlerFunc := func(event *v1.Event) {
		headEvent := event.Data.(*v1.HeadEvent)
		log.Trace().Msgf("New head slot %v block %v", headEvent.Slot, headEvent.Block.String())
		thisEpoch := spec.EpochFromSlot(headEvent.Slot)
		if thisEpoch > lastEpoch {
			log.Trace().Msgf("New epoch %v at slot %v", thisEpoch, headEvent.Slot)
			// Emit every ended epoch in [lastEpoch, thisEpoch). Skipping
			// any of them silently breaks attestation tracking: an
			// attestation for the last slot of epoch N can only be
			// included in blocks of epoch N+1, so failing to process
			// N+1 causes false "did not attest" reports.
			for e := lastEpoch; e < thisEpoch; e++ {
				epochsChan <- e
			}
			lastEpoch = thisEpoch
		}
	}

	eventsProvider := beacon.Service().(eth2client.EventsProvider)
	err = eventsProvider.Events(ctx, &api.EventsOpts{
		Topics:  []string{"head"},
		Handler: eventsHandlerFunc,
	})
	Must(err)
}

func LoadKeys(pubkeysFiles []string) ([]string, error) {
	plainKeys := opts.Monitor.Pubkeys[:]
	for _, fname := range pubkeysFiles {
		file, err := os.Open(fname)
		if err != nil {
			return nil, err
		}
		defer func() { _ = file.Close() }()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if len(line) == 0 {
				continue
			}
			plainKeys = append(plainKeys, line)
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

// processAttestations processes attestations from epoch blocks, updating metrics and unfulfilled duties.
// seenAttestations is persistent across epoch iterations so cross-call duplicates
// (a block scanned both in epoch N's lookahead window and in epoch N+1's main range)
// are counted exactly once.
func processAttestations(
	epochBlocks map[phase0.Slot]*electra.SignedBeaconBlock,
	committeeLookup map[phase0.Slot]map[phase0.CommitteeIndex]*CommitteeInfo,
	validatorPubkeyFromIndex map[phase0.ValidatorIndex]string,
	unfulfilledAttesterDuties map[phase0.Slot]Set[phase0.ValidatorIndex],
	seenAttestations map[phase0.Slot]Set[phase0.ValidatorIndex],
	m *MonitorMetrics,
	epoch phase0.Epoch,
) {
	// Iterate blocks in sorted slot order so earliest inclusion is processed first
	// https://eips.ethereum.org/EIPS/eip-7549
	for _, slot := range slices.Sorted(maps.Keys(epochBlocks)) {
		block := epochBlocks[slot]
		for _, attestation := range block.Message.Body.Attestations {
			attesters := NewSet[phase0.ValidatorIndex]()

			// Sanity check: verify AggregationBits length matches committee lengths.
			// Only check when we have info for ALL committees in the attestation.
			committeesLen := uint64(0)
			allCommitteesKnown := true
			for _, committeeIndex := range attestation.CommitteeBits.BitIndices() {
				slotCommittees := committeeLookup[attestation.Data.Slot]
				if info := slotCommittees[phase0.CommitteeIndex(committeeIndex)]; info != nil {
					committeesLen += info.Length
				} else {
					allCommitteesKnown = false
				}
			}
			if allCommitteesKnown && committeesLen > 0 && attestation.AggregationBits.Len() != committeesLen {
				log.Error().Msgf("Sanity check violation: AggregationBits length mismatch: computed=%v actual=%v", committeesLen, attestation.AggregationBits.Len())
			}

			// https://github.com/ethereum/consensus-specs/blob/8410e4fa376b74f550d5981f4c42d6593401046c/specs/electra/beacon-chain.md#new-get_committee_indices
			committeeOffset := uint64(0)
			for _, committeeIndex := range attestation.CommitteeBits.BitIndices() {
				slotCommittees := committeeLookup[attestation.Data.Slot]
				info := slotCommittees[phase0.CommitteeIndex(committeeIndex)]
				if info == nil {
					continue // no tracked validators in this committee
				}
				// https://github.com/ethereum/consensus-specs/blob/8410e4fa376b74f550d5981f4c42d6593401046c/specs/electra/beacon-chain.md#modified-get_attesting_indices
				for pos, validatorIndex := range info.Validators {
					if attestation.AggregationBits.BitAt(committeeOffset + pos) {
						attesters.Add(validatorIndex)
					}
				}
				committeeOffset += info.Length
			}

			attestedSlot := attestation.Data.Slot
			for validatorIndex := range attesters {
				if _, ok := validatorPubkeyFromIndex[validatorIndex]; !ok {
					continue
				}

				// Skip duplicate (validator, slot) pairs. The dedup map is
				// shared across epoch iterations, so this also catches the
				// case where an attestation lands inside an epoch's lookahead
				// window and is rescanned during the next epoch.
				if seenAttestations[attestedSlot].Contains(validatorIndex) {
					m.DuplicateAttestationsSkipped.Inc()
					continue
				}
				if seenAttestations[attestedSlot] == nil {
					seenAttestations[attestedSlot] = NewSet[phase0.ValidatorIndex]()
				}
				seenAttestations[attestedSlot].Add(validatorIndex)

				unfulfilledAttesterDuties[attestedSlot].Remove(validatorIndex)
				if unfulfilledAttesterDuties[attestedSlot].IsEmpty() {
					delete(unfulfilledAttesterDuties, attestedSlot)
				}

				// https://www.attestant.io/posts/defining-attestation-effectiveness/
				earliestInclusionSlot := attestedSlot + 1
				attestationDistance := block.Message.Slot - phase0.Slot(earliestInclusionSlot)
				m.RawAttestationDistances.Observe(float64(attestationDistance))
				// Do not penalize validator for skipped slots
				for s := earliestInclusionSlot; s < block.Message.Slot; s++ {
					if _, ok := epochBlocks[phase0.Slot(s)]; !ok {
						attestationDistance--
					}
				}

				if attestationDistance > 2 {
					Report("⚠️ 🧾 Validator %v (%v) attested slot %v at slot %v, epoch %v, attestation distance is %v",
						validatorIndex, validatorPubkeyFromIndex[validatorIndex], attestedSlot, block.Message.Slot, epoch, attestationDistance)
					m.TotalDelayedOverTolerance.Inc()
				} else if opts.Monitor.PrintSuccessful {
					Info("✅ 🧾 Validator %v (%v) attested slot %v at slot %v, epoch %v", validatorIndex, validatorPubkeyFromIndex[validatorIndex], attestedSlot, block.Message.Slot, epoch)
				}

				m.TotalCanonicalAttestations.Inc()
				m.CanonicalAttestationDistances.Observe(float64(attestationDistance))

				// H09 fix: track cross-epoch attestations
				if spec.EpochFromSlot(block.Message.Slot) != spec.EpochFromSlot(attestedSlot) {
					m.CrossEpochAttestations.Inc()
				}
			}
		}
	}
}

// MonitorAttestationsAndProposals listens to the beacon chain head changes and checks new blocks and attestations.
func MonitorAttestationsAndProposals(ctx context.Context, beacon *beaconchain.BeaconChain, plainKeys []string, mevRelays []string, wg *sync.WaitGroup, epochsChan chan phase0.Epoch) {
	defer wg.Done()

	m := NewMonitorMetrics(prometheus.DefaultRegisterer)

	unfulfilledAttesterDuties := make(map[phase0.Slot]Set[phase0.ValidatorIndex])
	// Persistent dedup so an attestation observed both in epoch N's lookahead
	// blocks and in epoch N+1's main range is only counted once. Pruned each
	// iteration to bound memory.
	seenAttestations := make(map[phase0.Slot]Set[phase0.ValidatorIndex])
	for epoch := range epochsChan {
		log.Debug().Msgf("New epoch %v", epoch)
		m.Epoch.Set(float64(epoch))

		// Prune dedup entries for slots older than the earliest reachable
		// attestedSlot in this iteration's scan window
		// (block range [Low(epoch), High(epoch)+lookAhead], attestedSlot
		// is at least block-32, hence Low(epoch)-32 = Low(epoch-1)).
		if epoch > 0 {
			pruneCutoff := spec.EpochLowestSlot(epoch - 1)
			for s := range seenAttestations {
				if s < pruneCutoff {
					delete(seenAttestations, s)
				}
			}
		}

		var validatorPubkeyFromIndex map[phase0.ValidatorIndex]string
		Measure(func() {
			var err error
			validatorPubkeyFromIndex, err = ResolveValidatorKeys(ctx, beacon, plainKeys, epoch)
			Must(err)
		}, "ResolveValidatorKeys(epoch=%v)", epoch)

		if len(validatorPubkeyFromIndex) == 0 {
			panic("No active validators")
		}
		log.Debug().Msgf("Epoch %v validators: %v/%v", epoch, len(validatorPubkeyFromIndex), len(plainKeys))

		trackedValidators := slices.Collect(maps.Keys(validatorPubkeyFromIndex))

		// Fetch attester duties for 3 epochs (prev, current, next) and build committee lookup.
		// AttesterDuty provides CommitteeLength and ValidatorCommitteeIndex for tracked validators only.
		var allDuties []*v1.AttesterDuty
		var committeeLookup map[phase0.Slot]map[phase0.CommitteeIndex]*CommitteeInfo
		Measure(func() {
			for e := epoch - 1; e <= epoch+1; e++ {
				duties, err := beacon.GetAttesterDuties(ctx, phase0.Epoch(e), trackedValidators)
				Must(err)
				allDuties = append(allDuties, duties...)
			}
			// Build unfulfilled duties for current epoch only
			for _, duty := range allDuties {
				if spec.EpochFromSlot(duty.Slot) == epoch {
					if _, ok := unfulfilledAttesterDuties[duty.Slot]; !ok {
						unfulfilledAttesterDuties[duty.Slot] = NewSet[phase0.ValidatorIndex]()
					}
					unfulfilledAttesterDuties[duty.Slot].Add(duty.ValidatorIndex)
				}
			}
			committeeLookup = BuildCommitteeLookup(allDuties, validatorPubkeyFromIndex)
		}, "ListAttesterDuties(epoch=%v)", epoch)

		var unfulfilledProposerDuties map[phase0.Slot]phase0.ValidatorIndex
		Measure(func() {
			var err error
			unfulfilledProposerDuties, err = ListProposerDuties(ctx, beacon, phase0.Epoch(epoch), slices.Collect(maps.Keys(validatorPubkeyFromIndex)))
			Must(err)
		}, "ListProposerDuties(epoch=%v)", epoch)

		var bestBids map[phase0.Slot]BidTrace
		if len(mevRelays) > 0 {
			Measure(func() {
				var err error
				bestBids, err = ListBestBids(ctx, 4*time.Second, mevRelays, epoch, validatorPubkeyFromIndex, unfulfilledProposerDuties)
				if err != nil {
					log.Error().Stack().Err(err).Msg("failed to fetch MEV bid traces")
					// Even if RequestEpochBidTraces() returned an error, there may still be valuable partial results in bidtraces, so process them!
				}
			}, "ListBestBids(epoch=%v)", epoch)
			log.Debug().Msgf("Number of MEV boosts is %v", len(bestBids))
		}

		var epochBlocks map[phase0.Slot]*electra.SignedBeaconBlock
		Measure(func() {
			var err error
			epochBlocks, err = ListEpochBlocks(ctx, beacon, phase0.Epoch(epoch))
			Must(err)
		}, "ListEpochBlocks(epoch=%v)", epoch)

		// Count missed slots within the epoch range (exclude look-ahead blocks)
		epochSlotsWithBlocks := 0
		for slot := spec.EpochLowestSlot(epoch); slot <= spec.EpochHighestSlot(epoch); slot++ {
			if _, ok := epochBlocks[slot]; ok {
				epochSlotsWithBlocks++
			}
		}
		m.MissedSlotsInEpoch.Set(float64(spec.SLOTS_PER_EPOCH - epochSlotsWithBlocks))

		processAttestations(epochBlocks, committeeLookup, validatorPubkeyFromIndex, unfulfilledAttesterDuties, seenAttestations, m, epoch)

		// Attestation is assumed to be missed if it was not included within
		// current epoch or one after the current.  Normally, attestations should
		// land in 1-2 *slots* after the attested one.
		missedAttestationEpoch := epoch - 1
		missedAttestationSlotHigh := spec.EpochHighestSlot(missedAttestationEpoch)
		log.Debug().Msgf("Unfulfilled attester duties at the end of epoch %v (map[SLOT]{VALIDATOR_INDEX...}): %v", epoch, unfulfilledAttesterDuties)
		for _, slot := range slices.Sorted(maps.Keys(unfulfilledAttesterDuties)) {
			if slot > missedAttestationSlotHigh {
				break
			}
			for validatorIndex := range unfulfilledAttesterDuties[slot].Elems() {
				Report("❌ 🧾 Validator %v (%v) did not attest slot %v (epoch %v)", validatorIndex, validatorPubkeyFromIndex[validatorIndex], slot, epoch)
				m.TotalMissedAttestations.Inc()
			}
			delete(unfulfilledAttesterDuties, slot)
		}

		log.Trace().Msgf("Epoch %v proposer duties: %v", epoch, unfulfilledProposerDuties)
		for slot, block := range epochBlocks {
			validatorIndex, ok := unfulfilledProposerDuties[slot]
			if !ok {
				continue
			}
			if block.Message.ProposerIndex != validatorIndex {
				log.Error().Msgf("Block proposed by an unexpected validator")
				continue
			}

			m.TotalCanonicalProposals.Inc()
			delete(unfulfilledProposerDuties, slot)

			if len(block.Message.Body.ExecutionPayload.Transactions) == 0 {
				validatorPublicKey := validatorPubkeyFromIndex[validatorIndex]
				Report("⚠️ 🧱 Validator %v (%v) proposed a block containing no transactions at epoch %v and slot %v", validatorPublicKey, validatorIndex, epoch, slot)
				m.LastProposedEmptyBlockSlot.Set(float64(slot))
				m.TotalProposedEmptyBlocks.Inc()
			}

			if len(mevRelays) > 0 {
				execution_block_hash := block.Message.Body.ExecutionPayload.BlockHash
				trace, ok := bestBids[slot]
				if !ok {
					m.TotalVanillaBlocks.Inc()
					m.LastVanillaBlockSlot.Set(float64(slot))
					m.LastVanillaBlockValidator.Set(float64(validatorIndex))
					log.Error().Msgf("Missing bid trace for proposal slot %v, validator %v (%v)", slot, validatorIndex, validatorPubkeyFromIndex[validatorIndex])
					continue
				}
				if execution_block_hash.String() != trace.BlockHash {
					m.TotalVanillaBlocks.Inc()
					m.LastVanillaBlockSlot.Set(float64(slot))
					m.LastVanillaBlockValidator.Set(float64(validatorIndex))
					log.Error().Msgf("Validator %v (%v) proposed a vanilla block %v at slot %v", validatorIndex, validatorPubkeyFromIndex[validatorIndex], execution_block_hash, slot)
					continue
				}
				if opts.Monitor.PrintSuccessful {
					// Our validator proposed the best block -- all good
					Info("✅ 🧾 Validator %v (%v) proposed optimal MEV execution block %v at slot %v, epoch %v", validatorIndex, validatorPubkeyFromIndex[validatorIndex], trace.BlockHash, slot, epoch)
				}
			}
		}
		for slot, validatorIndex := range unfulfilledProposerDuties {
			Report("❌ 🧱 Validator %v missed proposal at slot %v", validatorIndex, slot)
			m.TotalMissedProposals.Inc()
			m.LastMissedProposalSlot.Set(float64(slot))
			m.LastMissedProposalValidator.Set(float64(validatorIndex))
		}
	}
}
