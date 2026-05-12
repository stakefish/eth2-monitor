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

	"eth2-monitor/beaconchain"
	"eth2-monitor/cmd/opts"
	"eth2-monitor/spec"

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/api"
	v1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/rs/zerolog/log"
)

// SubscribeToEpochs subscribes to changings of the beacon chain head.
// Note, if --replay-epoch or --since-epoch options passed, SubscribeToEpochs will not
// listen to real-time changes.
func SubscribeToEpochs(ctx context.Context, beacon *beaconchain.BeaconChain, wg *sync.WaitGroup, epochsChan chan phase0.Epoch) {
	defer wg.Done()
	// Closing the channel on exit is critical: MonitorAttestationsAndProposals
	// blocks on `for range epochsChan` and only unblocks when the channel is
	// closed. Without this defer, an SSE-path Must(err) panic (or any normal
	// return from the SSE Events call) leaves the orchestrator hanging on a
	// silent channel, and wg.Wait() in main deadlocks until SIGKILL.
	defer close(epochsChan)

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
			if !sendEpoch(ctx, epochsChan, phase0.Epoch(epoch)) {
				return
			}
		}
		return
	}
	if opts.Monitor.SinceEpoch != ^uint64(0) {
		for epoch := opts.Monitor.SinceEpoch; phase0.Epoch(epoch) < lastEpoch; epoch++ {
			if !sendEpoch(ctx, epochsChan, phase0.Epoch(epoch)) {
				return
			}
		}
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
				if !sendEpoch(ctx, epochsChan, e) {
					return
				}
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

// sendEpoch publishes one epoch on ch, honouring ctx cancellation. Returns
// false if ctx was cancelled before the send completed — caller should treat
// that as a shutdown signal and return.
//
// Without this guard, a send on an unread epochsChan blocks indefinitely
// once the consumer goroutine has died (e.g. via Must(err)) — and because
// SubscribeToEpochs holds the only producer side, the whole process hangs
// until forcibly killed.
func sendEpoch(ctx context.Context, ch chan<- phase0.Epoch, epoch phase0.Epoch) bool {
	select {
	case ch <- epoch:
		return true
	case <-ctx.Done():
		return false
	}
}

func LoadKeys(pubkeysFiles []string) ([]string, error) {
	plainKeys := opts.Monitor.Pubkeys[:]
	for _, fname := range pubkeysFiles {
		keys, err := readPubkeysFile(fname)
		if err != nil {
			return nil, err
		}
		plainKeys = append(plainKeys, keys...)
	}
	return plainKeys, nil
}

// readPubkeysFile reads one pubkey file end-to-end and closes the file before
// returning. Splitting this out of LoadKeys ensures each fd is released as
// soon as the file is consumed — the previous loop deferred Close inside the
// loop body, so all N files stayed open until LoadKeys itself returned.
func readPubkeysFile(fname string) ([]string, error) {
	file, err := os.Open(fname)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()

	var keys []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		keys = append(keys, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return keys, nil
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
//
// Per epoch:
//  1. PruneSeenAttestations to bound the cross-call dedup map's memory.
//  2. BuildEpochContext (validator resolution, duties, blocks, bids, lookup).
//  3. Seed unfulfilledAttesterDuties for the *current* epoch only — prev/next
//     duties exist in ec.AttesterDuties to anchor BuildCommitteeLookup's
//     offsets but are not tracked for missed-attestation reporting (already
//     reported last/next iteration).
//  4. Record the missed-slot gauge.
//  5. processAttestations updates per-attestation metrics and clears
//     unfulfilledAttesterDuties as observations come in.
//  6. FinalizeMissedAttestations reports anything still unfulfilled in E-1.
//  7. Walk each block: CheckProposal returns true on success (delete the
//     proposer-duty entry); false on proposer-index mismatch (leave the
//     entry so FinalizeMissedProposals reports it as missed).
//  8. FinalizeMissedProposals.
//  9. SaveCache persists LastEpoch so a restart skips re-processed epochs.
//
// Persistent state across iterations:
//   - unfulfilledAttesterDuties — entries linger from prev iteration's seed
//     and are cleared either by processAttestations (observed) or
//     FinalizeMissedAttestations (missed at end of E-1).
//   - seenAttestations — dedup map for cross-iteration lookahead-window
//     overlap. Pruned each iteration to bound memory.
//
// Both maps are single-goroutine; never shared.
func MonitorAttestationsAndProposals(ctx context.Context, cancel context.CancelFunc, beacon *beaconchain.BeaconChain, plainKeys []string, mevRelays []string, wg *sync.WaitGroup, epochsChan chan phase0.Epoch, m *MonitorMetrics) {
	defer wg.Done()
	// Cancel the shared ctx on any exit (normal return OR Must(err) panic).
	// Without this, the SSE goroutine in SubscribeToEpochs keeps trying to
	// emit epochs into a channel that has no reader — its sendEpoch select
	// only bails on ctx.Done, and ctx never gets cancelled if main is still
	// blocked in ListenAndServe. The result is a zombie process: dead
	// orchestrator, leaked SSE goroutine, /metrics serving stale data.
	defer cancel()

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
		PruneSeenAttestations(seenAttestations, spec.EpochLowestSlot(epoch-1))

		ec, err := BuildEpochContext(ctx, beacon, epoch, plainKeys, mevRelays)
		Must(err)
		if ec == nil {
			// Soft skip: no tracked validators active this epoch.
			log.Warn().Msgf("No active validators in epoch %v; skipping", epoch)
			continue
		}

		// Seed unfulfilled duties for the *current* epoch only.
		for _, duty := range ec.AttesterDuties {
			// AttesterDuties is []*v1.AttesterDuty — slice of pointers.
			// A non-conforming API response could leave entries nil.
			if duty == nil {
				continue
			}
			if spec.EpochFromSlot(duty.Slot) != epoch {
				continue
			}
			if _, ok := unfulfilledAttesterDuties[duty.Slot]; !ok {
				unfulfilledAttesterDuties[duty.Slot] = NewSet[phase0.ValidatorIndex]()
			}
			unfulfilledAttesterDuties[duty.Slot].Add(duty.ValidatorIndex)
		}

		m.MissedSlotsInEpoch.Set(float64(spec.SLOTS_PER_EPOCH - ec.SlotsWithBlocks()))

		processAttestations(ec.Blocks, ec.CommitteeLookup, ec.ValidatorPubkeyFromIndex, unfulfilledAttesterDuties, seenAttestations, m, epoch)

		// Treat an attestation as missed if it isn't seen by the end of E-1's
		// highest slot. Pre-Deneb the spec capped inclusion at
		// `data.slot + SLOTS_PER_EPOCH` so E+1 was a hard limit; EIP-7045
		// removed that upper bound, making this a QoS heuristic (>32-slot
		// inclusions are operationally indistinguishable from missed duties).
		FinalizeMissedAttestations(unfulfilledAttesterDuties, spec.EpochHighestSlot(epoch-1), ec.ValidatorPubkeyFromIndex, epoch, m)

		log.Trace().Msgf("Epoch %v proposer duties: %v", epoch, ec.ProposerDuties)
		// Sort for deterministic Slack report ordering.
		for _, slot := range slices.Sorted(maps.Keys(ec.Blocks)) {
			block := ec.Blocks[slot]
			expected, ok := ec.ProposerDuties[slot]
			if !ok {
				continue
			}
			if CheckProposal(block, slot, expected, ec.BestBids, ec.MEVEnabled, ec.ValidatorPubkeyFromIndex, epoch, m) {
				delete(ec.ProposerDuties, slot)
			}
			// On proposer-index mismatch CheckProposal returns false; we
			// intentionally leave the entry in ec.ProposerDuties so
			// FinalizeMissedProposals reports it as missed (matches the
			// previous code's continue-without-delete path).
		}
		FinalizeMissedProposals(ec.ProposerDuties, ec.ValidatorPubkeyFromIndex, m)

		// Persist progress so a crash/restart can skip already-processed
		// epochs and avoid spiking cumulative metric counters.
		SaveCache(&LocalCache{LastEpoch: epoch})
	}
}
