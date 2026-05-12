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
)

const VALIDATOR_INDEX_INVALID = ^phase0.ValidatorIndex(0)

// CommitteeInfo holds the committee length and tracked validator positions.
// Built from AttesterDuty responses instead of fetching full committee lists.
type CommitteeInfo struct {
	Length     uint64                              // committee size (from duty.CommitteeLength)
	Validators map[uint64]phase0.ValidatorIndex    // position → validatorIndex (tracked only)
}

// BuildCommitteeLookup builds a per-(slot, committee) view that processAttestations
// needs to read EIP-7549 attestations correctly.
//
// committeeLengths must contain the size of EVERY committee in every slot that
// could appear in an attestation we process — not only committees containing
// tracked validators. This is required because an attestation can aggregate
// across multiple committees, and we need to advance the AggregationBits offset
// past committees with no tracked validators by their actual length. Without
// full lengths, the offset drifts and we attribute bits to the wrong validators.
//
// duties supplies the (position, validatorIndex) entries for tracked validators
// only — those are all we ever need to look up.
func BuildCommitteeLookup(
	duties []*v1.AttesterDuty,
	committeeLengths map[phase0.Slot]map[phase0.CommitteeIndex]uint64,
	tracked map[phase0.ValidatorIndex]string,
) map[phase0.Slot]map[phase0.CommitteeIndex]*CommitteeInfo {
	result := make(map[phase0.Slot]map[phase0.CommitteeIndex]*CommitteeInfo, len(committeeLengths))
	for slot, byIdx := range committeeLengths {
		entry := make(map[phase0.CommitteeIndex]*CommitteeInfo, len(byIdx))
		for idx, length := range byIdx {
			entry[idx] = &CommitteeInfo{Length: length, Validators: make(map[uint64]phase0.ValidatorIndex)}
		}
		result[slot] = entry
	}

	for _, duty := range duties {
		if _, ok := tracked[duty.ValidatorIndex]; !ok {
			continue
		}
		if result[duty.Slot] == nil {
			result[duty.Slot] = make(map[phase0.CommitteeIndex]*CommitteeInfo)
		}
		info := result[duty.Slot][duty.CommitteeIndex]
		if info == nil {
			// Slot/committee not in committeeLengths; fall back to the
			// duty's reported length so the tracked validator is still
			// considered. Offsets remain correct as long as committeeLengths
			// covers the rest.
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
		// time.Since(at) is positive (now − at); the previous code used
		// time.Until(at) which returns a negative duration for past times,
		// always satisfying "< 8h" → cache never expired. Shortened to 30m
		// to bound staleness exposure after a validator exit / key rotation.
		if cachedIndex, ok := cache.Validators[pubkey]; ok && time.Since(cachedIndex.At) < 30*time.Minute {
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
// The beacon API returns at most SLOTS_PER_EPOCH duties regardless of the
// indices filter (filtering is client-side in go-eth2-client), so chunking
// inputs has no effect on response size.
func ListProposerDuties(ctx context.Context, beacon *beaconchain.BeaconChain, epoch phase0.Epoch, validators []phase0.ValidatorIndex) (map[phase0.Slot]phase0.ValidatorIndex, error) {
	duties, err := beacon.GetProposerDuties(ctx, epoch, validators)
	if err != nil {
		return nil, err
	}

	result := make(map[phase0.Slot]phase0.ValidatorIndex, len(duties))
	for _, duty := range duties {
		result[duty.Slot] = phase0.ValidatorIndex(duty.ValidatorIndex)
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

	// Anchor at max(persisted, justified). The persisted value lets us
	// resume after a crash/restart without re-processing already-counted
	// epochs (which would spike cumulative counters); justified is the
	// floor for cold starts.
	lastEpoch := resp.Data.Justified.Epoch
	if persisted := LoadCache().LastEpoch; persisted > lastEpoch {
		lastEpoch = persisted
	}

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

// isBlockEmpty returns true when the block body carries no execution-layer
// payload of any value to the proposer: no EL transactions, no blobs, and no
// post-Pectra execution_requests (deposits/withdrawals/consolidations). A
// block carrying only blob commitments still earns the proposer the blob base
// fee, so it isn't "empty" from a validator-economic perspective.
func isBlockEmpty(body *electra.BeaconBlockBody) bool {
	if len(body.ExecutionPayload.Transactions) > 0 {
		return false
	}
	if len(body.BlobKZGCommitments) > 0 {
		return false
	}
	if body.ExecutionRequests != nil &&
		(len(body.ExecutionRequests.Deposits) > 0 ||
			len(body.ExecutionRequests.Withdrawals) > 0 ||
			len(body.ExecutionRequests.Consolidations) > 0) {
		return false
	}
	return true
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

			// We need the length of EVERY committee referenced by this
			// attestation to walk AggregationBits correctly — even committees
			// containing zero tracked validators, because we still have to
			// advance the offset past them to read later committees correctly.
			// If we lack any committee's length the offset drifts and we
			// attribute bits to the wrong validators, producing false missed
			// attestation reports. Skip the attestation in that case rather
			// than corrupt our state.
			slotCommittees := committeeLookup[attestation.Data.Slot]
			committeesLen := uint64(0)
			allCommitteesKnown := true
			for _, committeeIndex := range attestation.CommitteeBits.BitIndices() {
				if info := slotCommittees[phase0.CommitteeIndex(committeeIndex)]; info != nil {
					committeesLen += info.Length
				} else {
					allCommitteesKnown = false
				}
			}
			if !allCommitteesKnown {
				log.Warn().Msgf("Attestation at slot %v references committee with no lookup entry; skipping (block slot %v)", attestation.Data.Slot, block.Message.Slot)
				continue
			}
			if committeesLen > 0 && attestation.AggregationBits.Len() != committeesLen {
				log.Error().Msgf("Sanity check violation: AggregationBits length mismatch at slot %v: computed=%v actual=%v", attestation.Data.Slot, committeesLen, attestation.AggregationBits.Len())
				continue
			}

			// https://github.com/ethereum/consensus-specs/blob/8410e4fa376b74f550d5981f4c42d6593401046c/specs/electra/beacon-chain.md#new-get_committee_indices
			committeeOffset := uint64(0)
			for _, committeeIndex := range attestation.CommitteeBits.BitIndices() {
				info := slotCommittees[phase0.CommitteeIndex(committeeIndex)]
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

				// Always clear unfulfilled, even on a duplicate observation.
				// The earlier observation may have happened during the
				// previous epoch's lookahead scan — at that point the current
				// epoch's duties weren't yet populated in
				// unfulfilledAttesterDuties, so the Remove call was a silent
				// no-op. Re-running it here keeps state consistent. Dedup
				// only controls the per-(validator, slot) metric counters
				// below.
				unfulfilledAttesterDuties[attestedSlot].Remove(validatorIndex)
				if unfulfilledAttesterDuties[attestedSlot].IsEmpty() {
					delete(unfulfilledAttesterDuties, attestedSlot)
				}

				if seenAttestations[attestedSlot].Contains(validatorIndex) {
					m.DuplicateAttestationsSkipped.Inc()
					continue
				}
				if seenAttestations[attestedSlot] == nil {
					seenAttestations[attestedSlot] = NewSet[phase0.ValidatorIndex]()
				}
				seenAttestations[attestedSlot].Add(validatorIndex)

				// https://www.attestant.io/posts/defining-attestation-effectiveness/
				earliestInclusionSlot := attestedSlot + 1

				// If the earliest possible inclusion slot is before our scan
				// window, we cannot reliably compute the inclusion distance:
				// the attestation may have been included in a block we never
				// fetched, and any "missed slot" adjustment below would
				// treat those un-fetched slots as missed (under-counting the
				// real distance). For a long-running monitor this case is
				// covered by the previous epoch's iteration, which records
				// the correct distance there; the duplicate-observation
				// dedup above prevents double counting. On a fresh start
				// the metric is genuinely unknown — skip it rather than
				// emit a misleading "delayed attestation" warning.
				if earliestInclusionSlot < spec.EpochLowestSlot(epoch) {
					continue
				}

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
func MonitorAttestationsAndProposals(ctx context.Context, beacon *beaconchain.BeaconChain, plainKeys []string, mevRelays []string, wg *sync.WaitGroup, epochsChan chan phase0.Epoch, m *MonitorMetrics) {
	defer wg.Done()

	unfulfilledAttesterDuties := make(map[phase0.Slot]Set[phase0.ValidatorIndex])
	// Persistent dedup so an attestation observed both in epoch N's lookahead
	// blocks and in epoch N+1's main range is only counted once. Pruned each
	// iteration to bound memory.
	seenAttestations := make(map[phase0.Slot]Set[phase0.ValidatorIndex])
	for epoch := range epochsChan {
		log.Debug().Msgf("New epoch %v", epoch)
		m.Epoch.Set(float64(epoch))

		// Skip genesis: there's no E-1 to look back at, and several places
		// below (duty/committee window fetch, missedAttestationEpoch) would
		// underflow `epoch - 1` to max uint64.
		if epoch == 0 {
			log.Debug().Msg("Skipping epoch 0 (genesis)")
			continue
		}

		// Prune dedup entries for slots older than the earliest reachable
		// attestedSlot in this iteration's scan window
		// (block range [Low(epoch), High(epoch)+lookAhead], attestedSlot
		// is at least block-32, hence Low(epoch)-32 = Low(epoch-1)).
		pruneCutoff := spec.EpochLowestSlot(epoch - 1)
		for s := range seenAttestations {
			if s < pruneCutoff {
				delete(seenAttestations, s)
			}
		}

		var validatorPubkeyFromIndex map[phase0.ValidatorIndex]string
		Measure(func() {
			var err error
			validatorPubkeyFromIndex, err = ResolveValidatorKeys(ctx, beacon, plainKeys, epoch)
			Must(err)
		}, "ResolveValidatorKeys(epoch=%v)", epoch)

		if len(validatorPubkeyFromIndex) == 0 {
			// Soft-fail: can happen on mass exit, key rotation gap, or
			// beacon-node desync. Don't crash the monitor — skip this
			// epoch and re-resolve next iteration.
			log.Warn().Msgf("No active validators in epoch %v; skipping", epoch)
			continue
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

			// Fetch lengths for EVERY committee (not just those containing
			// tracked validators) across the same epoch window. This is
			// required so processAttestations can advance AggregationBits
			// offsets correctly across EIP-7549 attestations that span
			// committees we don't track. Without full lengths the offset
			// drifts and we report false missed attestations — especially
			// against clients like Caplin that aggregate across many
			// committees per attestation.
			committeeLengths := make(map[phase0.Slot]map[phase0.CommitteeIndex]uint64)
			for e := epoch - 1; e <= epoch+1; e++ {
				cl, err := beacon.GetCommitteeLengths(ctx, phase0.Epoch(e))
				Must(err)
				for slot, byIdx := range cl {
					if committeeLengths[slot] == nil {
						committeeLengths[slot] = make(map[phase0.CommitteeIndex]uint64, len(byIdx))
					}
					for idx, length := range byIdx {
						committeeLengths[slot][idx] = length
					}
				}
			}
			committeeLookup = BuildCommitteeLookup(allDuties, committeeLengths, validatorPubkeyFromIndex)
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

		// Treat an attestation as missed if it isn't seen by the end of E+1.
		// Pre-Deneb the spec capped inclusion at `data.slot + SLOTS_PER_EPOCH`,
		// so E+1 was a hard limit. EIP-7045 removed that upper bound, so this is
		// now a QoS heuristic: real attestations land in 1-2 slots, and any
		// inclusion >32 slots later is operationally indistinguishable from a
		// missed duty for validator performance reporting.
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
		// Sort for deterministic Slack report ordering.
		for _, slot := range slices.Sorted(maps.Keys(epochBlocks)) {
			block := epochBlocks[slot]
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

			if isBlockEmpty(block.Message.Body) {
				validatorPublicKey := validatorPubkeyFromIndex[validatorIndex]
				Report("⚠️ 🧱 Validator %v (%v) proposed an empty block at epoch %v and slot %v", validatorPublicKey, validatorIndex, epoch, slot)
				m.LastProposedEmptyBlockSlot.Set(float64(slot))
				m.TotalProposedEmptyBlocks.Inc()
			}

			if len(mevRelays) > 0 {
				execution_block_hash := block.Message.Body.ExecutionPayload.BlockHash
				trace, ok := bestBids[slot]
				if !ok {
					// No bid trace found across configured relays. This could be a
					// truly vanilla block, or it could be a relay-side failure —
					// kept distinct from confirmed hash-mismatch vanilla blocks.
					m.TotalMissingBidTraces.Inc()
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
		for _, slot := range slices.Sorted(maps.Keys(unfulfilledProposerDuties)) {
			validatorIndex := unfulfilledProposerDuties[slot]
			Report("❌ 🧱 Validator %v missed proposal at slot %v", validatorIndex, slot)
			m.TotalMissedProposals.Inc()
			m.LastMissedProposalSlot.Set(float64(slot))
			m.LastMissedProposalValidator.Set(float64(validatorIndex))
		}

		// Persist progress so a crash/restart can skip already-processed
		// epochs and avoid spiking cumulative metric counters.
		SaveCache(&LocalCache{LastEpoch: epoch})
	}
}
