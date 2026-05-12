package pkg

import (
	"maps"
	"slices"

	"eth2-monitor/cmd/opts"

	"github.com/attestantio/go-eth2-client/spec/electra"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/rs/zerolog/log"
)

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

// CheckProposal evaluates a single proposed block against its expected duty
// and writes all proposal-side metrics. Returns true when the duty was
// fulfilled (canonical proposal observed for the expected validator) and the
// caller should remove the slot from unfulfilled proposer duties.
//
// Returns false on proposer-index mismatch — i.e. a block exists at this slot
// but a different validator proposed it. In that case the caller MUST NOT
// delete the slot from unfulfilled duties; FinalizeMissedProposals will later
// report it as missed.
//
// Writes are independent and can stack on a single call (preserving the
// original code's fall-through; an empty block on a MEV-enabled run with a
// missing bid trace fires both the empty-block metrics AND
// TotalMissingBidTraces, never neither):
//
//   - Canonical proposal observed:  TotalCanonicalProposals++
//   - Block is empty:               TotalProposedEmptyBlocks++,
//     LastProposedEmptyBlockSlot.Set(slot)
//   - MEV enabled + no bid trace:   TotalMissingBidTraces++
//   - MEV enabled + hash mismatch:  TotalVanillaBlocks++,
//     LastVanillaBlockSlot.Set(slot),
//     LastVanillaBlockValidator.Set(validator)
func CheckProposal(
	block *electra.SignedBeaconBlock,
	slot phase0.Slot,
	expectedValidator phase0.ValidatorIndex,
	bestBids map[phase0.Slot]BidTrace,
	mevEnabled bool,
	pubkeys map[phase0.ValidatorIndex]string,
	epoch phase0.Epoch,
	m *MonitorMetrics,
) bool {
	if block.Message.ProposerIndex != expectedValidator {
		log.Error().Msgf("Block proposed by an unexpected validator")
		return false
	}

	m.TotalCanonicalProposals.Inc()

	if isBlockEmpty(block.Message.Body) {
		Report("⚠️ 🧱 Validator %v (%v) proposed an empty block at epoch %v and slot %v",
			expectedValidator, pubkeys[expectedValidator], epoch, slot)
		m.LastProposedEmptyBlockSlot.Set(float64(slot))
		m.TotalProposedEmptyBlocks.Inc()
	}

	if mevEnabled {
		executionBlockHash := block.Message.Body.ExecutionPayload.BlockHash
		trace, ok := bestBids[slot]
		if !ok {
			// No bid trace found across configured relays. This could be a
			// truly vanilla block, or it could be a relay-side failure —
			// kept distinct from confirmed hash-mismatch vanilla blocks.
			m.TotalMissingBidTraces.Inc()
			log.Error().Msgf("Missing bid trace for proposal slot %v, validator %v (%v)", slot, expectedValidator, pubkeys[expectedValidator])
			return true
		}
		if executionBlockHash.String() != trace.BlockHash {
			m.TotalVanillaBlocks.Inc()
			m.LastVanillaBlockSlot.Set(float64(slot))
			m.LastVanillaBlockValidator.Set(float64(expectedValidator))
			log.Error().Msgf("Validator %v (%v) proposed a vanilla block %v at slot %v", expectedValidator, pubkeys[expectedValidator], executionBlockHash, slot)
			return true
		}
		if opts.Monitor.PrintSuccessful {
			Info("✅ 🧾 Validator %v (%v) proposed optimal MEV execution block %v at slot %v, epoch %v", expectedValidator, pubkeys[expectedValidator], trace.BlockHash, slot, epoch)
		}
	}

	return true
}

// FinalizeMissedProposals reports each remaining unfulfilled proposer duty as
// a missed proposal and updates the Last* gauges. Caller is expected to have
// already deleted slots whose proposals were confirmed via CheckProposal.
func FinalizeMissedProposals(
	unfulfilledProposerDuties map[phase0.Slot]phase0.ValidatorIndex,
	pubkeys map[phase0.ValidatorIndex]string,
	m *MonitorMetrics,
) {
	// Sort for deterministic Slack report ordering and so the Last* gauges
	// settle on the highest-slot entry.
	for _, slot := range slices.Sorted(maps.Keys(unfulfilledProposerDuties)) {
		validatorIndex := unfulfilledProposerDuties[slot]
		Report("❌ 🧱 Validator %v (%v) missed proposal at slot %v", validatorIndex, pubkeys[validatorIndex], slot)
		m.TotalMissedProposals.Inc()
		m.LastMissedProposalSlot.Set(float64(slot))
		m.LastMissedProposalValidator.Set(float64(validatorIndex))
	}
}
