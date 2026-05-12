package pkg

import (
	"context"
	"maps"
	"slices"
	"time"

	"eth2-monitor/beaconchain"
	"eth2-monitor/spec"

	v1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec/electra"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
)

// VALIDATOR_INDEX_INVALID is the sentinel cached for pubkeys the beacon API
// reports no index for; entries with this value are skipped by
// ResolveValidatorKeys instead of being re-resolved every cache hit.
const VALIDATOR_INDEX_INVALID = ^phase0.ValidatorIndex(0)

// EpochContext bundles everything fetched once per epoch. Built fresh each
// iteration; never reused across epochs.
//
// Lifetime asymmetry vs the orchestrator's persistent state:
//
//   - ProposerDuties is per-epoch (a block can only be proposed at its
//     assigned slot; lookahead doesn't help). The orchestrator deletes
//     entries as it confirms canonical proposals, then hands the remainder
//     to FinalizeMissedProposals.
//   - AttesterDuties spans (epoch-1, epoch, epoch+1) because attestations
//     can be included in blocks up to ~32 slots later. Only the current-epoch
//     duties seed the orchestrator's long-lived unfulfilledAttesterDuties
//     map; the prev/next-epoch duties feed BuildCommitteeLookup so
//     AggregationBits offsets resolve correctly for cross-epoch attestations.
type EpochContext struct {
	Epoch                    phase0.Epoch
	ValidatorPubkeyFromIndex map[phase0.ValidatorIndex]string
	AttesterDuties           []*v1.AttesterDuty
	CommitteeLookup          map[phase0.Slot]map[phase0.CommitteeIndex]*CommitteeInfo
	ProposerDuties           map[phase0.Slot]phase0.ValidatorIndex
	Blocks                   map[phase0.Slot]*electra.SignedBeaconBlock
	BestBids                 map[phase0.Slot]BidTrace
	MEVEnabled               bool
}

// BuildEpochContext fetches all per-epoch state in the same order as the
// previous monolithic loop body. Returns (nil, nil) when no tracked
// validators are active in the epoch (caller treats as a soft skip). Returns
// (nil, err) on hard fetch failures.
//
// ListBestBids errors are intentionally swallowed inside (logged, partial
// results retained) to preserve the existing soft-error contract — relay
// misbehavior never crashes the monitor.
//
// All five Measure(...) wrappers preserve the exact label strings used by
// the previous code so operator log analysis is unaffected.
func BuildEpochContext(
	ctx context.Context,
	beacon *beaconchain.BeaconChain,
	epoch phase0.Epoch,
	plainKeys []string,
	mevRelays []string,
) (*EpochContext, error) {
	var (
		validatorPubkeyFromIndex map[phase0.ValidatorIndex]string
		resolveErr               error
	)
	Measure(func() {
		validatorPubkeyFromIndex, resolveErr = ResolveValidatorKeys(ctx, beacon, plainKeys, epoch)
	}, "ResolveValidatorKeys(epoch=%v)", epoch)
	if resolveErr != nil {
		return nil, errors.Wrap(resolveErr, "ResolveValidatorKeys")
	}

	if len(validatorPubkeyFromIndex) == 0 {
		// Soft-fail: can happen on mass exit, key rotation gap, or
		// beacon-node desync. Don't crash the monitor — caller skips this
		// epoch and re-resolves next iteration.
		return nil, nil
	}
	log.Debug().Msgf("Epoch %v validators: %v/%v", epoch, len(validatorPubkeyFromIndex), len(plainKeys))

	trackedValidators := slices.Collect(maps.Keys(validatorPubkeyFromIndex))

	var (
		allDuties       []*v1.AttesterDuty
		committeeLookup map[phase0.Slot]map[phase0.CommitteeIndex]*CommitteeInfo
		dutiesErr       error
	)
	Measure(func() {
		// Fetch attester duties for 3 epochs (prev, current, next).
		// AttesterDuty provides CommitteeLength and ValidatorCommitteeIndex
		// for tracked validators only.
		for e := epoch - 1; e <= epoch+1; e++ {
			duties, err := beacon.GetAttesterDuties(ctx, phase0.Epoch(e), trackedValidators)
			if err != nil {
				dutiesErr = errors.Wrapf(err, "GetAttesterDuties(epoch=%v)", e)
				return
			}
			allDuties = append(allDuties, duties...)
		}

		// Fetch lengths for EVERY committee (not just those containing
		// tracked validators) across the same epoch window. This is required
		// so processAttestations can advance AggregationBits offsets
		// correctly across EIP-7549 attestations that span committees we
		// don't track. Without full lengths the offset drifts and we report
		// false missed attestations — especially against clients like Caplin
		// that aggregate across many committees per attestation.
		committeeLengths := make(map[phase0.Slot]map[phase0.CommitteeIndex]uint64)
		for e := epoch - 1; e <= epoch+1; e++ {
			cl, err := beacon.GetCommitteeLengths(ctx, phase0.Epoch(e))
			if err != nil {
				dutiesErr = errors.Wrapf(err, "GetCommitteeLengths(epoch=%v)", e)
				return
			}
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
	if dutiesErr != nil {
		return nil, dutiesErr
	}

	var (
		proposerDuties    map[phase0.Slot]phase0.ValidatorIndex
		proposerDutiesErr error
	)
	Measure(func() {
		proposerDuties, proposerDutiesErr = ListProposerDuties(ctx, beacon, epoch, trackedValidators)
	}, "ListProposerDuties(epoch=%v)", epoch)
	if proposerDutiesErr != nil {
		return nil, errors.Wrap(proposerDutiesErr, "ListProposerDuties")
	}

	mevEnabled := len(mevRelays) > 0
	var bestBids map[phase0.Slot]BidTrace
	if mevEnabled {
		Measure(func() {
			var err error
			bestBids, err = ListBestBids(ctx, 4*time.Second, mevRelays, epoch, validatorPubkeyFromIndex, proposerDuties)
			if err != nil {
				// Soft error: partial results in bestBids are still usable.
				log.Error().Stack().Err(err).Msg("failed to fetch MEV bid traces")
			}
		}, "ListBestBids(epoch=%v)", epoch)
		log.Debug().Msgf("Number of MEV boosts is %v", len(bestBids))
	}

	var (
		blocks    map[phase0.Slot]*electra.SignedBeaconBlock
		blocksErr error
	)
	Measure(func() {
		blocks, blocksErr = ListEpochBlocks(ctx, beacon, epoch)
	}, "ListEpochBlocks(epoch=%v)", epoch)
	if blocksErr != nil {
		return nil, errors.Wrap(blocksErr, "ListEpochBlocks")
	}

	return &EpochContext{
		Epoch:                    epoch,
		ValidatorPubkeyFromIndex: validatorPubkeyFromIndex,
		AttesterDuties:           allDuties,
		CommitteeLookup:          committeeLookup,
		ProposerDuties:           proposerDuties,
		Blocks:                   blocks,
		BestBids:                 bestBids,
		MEVEnabled:               mevEnabled,
	}, nil
}

// SlotsWithBlocks returns the count of slots in [EpochLowestSlot(e.Epoch),
// EpochHighestSlot(e.Epoch)] that have a block (i.e. excludes the lookahead
// window). Callers derive the missed-slot gauge as
// SLOTS_PER_EPOCH - SlotsWithBlocks().
func (e *EpochContext) SlotsWithBlocks() int {
	count := 0
	for slot := spec.EpochLowestSlot(e.Epoch); slot <= spec.EpochHighestSlot(e.Epoch); slot++ {
		if _, ok := e.Blocks[slot]; ok {
			count++
		}
	}
	return count
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

// blockFetcher is the narrow GetBlock surface ListEpochBlocks depends on,
// extracted so tests can inject transient errors without standing up a fake
// beacon node. *beaconchain.BeaconChain satisfies it via its GetBlock method.
type blockFetcher interface {
	GetBlock(ctx context.Context, slot phase0.Slot) (*electra.SignedBeaconBlock, error)
}

func ListEpochBlocks(ctx context.Context, beacon *beaconchain.BeaconChain, epoch phase0.Epoch) (map[phase0.Slot]*electra.SignedBeaconBlock, error) {
	return listEpochBlocks(ctx, beacon, epoch)
}

func listEpochBlocks(ctx context.Context, fetch blockFetcher, epoch phase0.Epoch) (map[phase0.Slot]*electra.SignedBeaconBlock, error) {
	result := make(map[phase0.Slot]*electra.SignedBeaconBlock, spec.SLOTS_PER_EPOCH)
	low := spec.EpochLowestSlot(epoch)
	high := spec.EpochHighestSlot(epoch)

	// Fetch a few slots past the epoch end so attestations included in the
	// first blocks of E+1 are visible while processing E. Without this look-
	// ahead, attestations for E's last slots would appear missed.
	lookAhead := phase0.Slot(4)

	for slot := low; slot <= high+lookAhead; slot++ {
		block, err := fetchBlockWithRetries(ctx, fetch, slot, 3)
		if err != nil {
			// Treat persistent fetch errors as missed slots to keep the
			// monitor running, but log at ERROR so operators can alert on
			// repeated occurrences. The alternative (return the error and
			// crash the orchestrator) would break attestation-dedup
			// contiguity by skipping ahead on restart.
			log.Error().Err(err).Uint64("slot", uint64(slot)).Msg("failed to fetch block after retries; treating as missed")
			continue
		}
		if block == nil {
			// Genuine missed slot (GetBlock translates a 404 to (nil, nil)).
			continue
		}
		result[slot] = block
	}
	return result, nil
}

// fetchBlockWithRetries calls fetch.GetBlock up to maxAttempts times,
// backing off between failures. A nil block with a nil error is treated as
// success (404 → genuinely missed slot) and is returned immediately.
//
// Honours ctx cancellation: any sleep is short-circuited so shutdown is
// instant rather than blocked on backoff.
func fetchBlockWithRetries(ctx context.Context, fetch blockFetcher, slot phase0.Slot, maxAttempts int) (*electra.SignedBeaconBlock, error) {
	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		block, err := fetch.GetBlock(ctx, slot)
		if err == nil {
			return block, nil
		}
		lastErr = err
		if attempt == maxAttempts-1 {
			break
		}
		backoff := time.Duration(200<<attempt) * time.Millisecond
		// Use NewTimer instead of time.After so we can Stop the unfired
		// timer when ctx.Done wins the select. time.After's timer keeps
		// running until it fires naturally; a fleet-wide shutdown with
		// many slots backing off would otherwise leak ~36 timers per
		// orchestrator goroutine for up to ~800ms.
		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
	return nil, lastErr
}
