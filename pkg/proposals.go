package pkg

import (
	"maps"
	"slices"
	"strings"

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
//
// Treats a nil ExecutionPayload as empty: post-Bellatrix the field is
// mandatory per spec, but a non-conforming JSON response (Caplin quirk,
// future fork change, missing field) could leave it nil. Crashing the
// orchestrator on bad data is worse than recording it as an empty proposal.
func isBlockEmpty(body *electra.BeaconBlockBody) bool {
	if body == nil {
		// A nil body cannot carry any execution-layer payload by definition;
		// callers reach this through the same data-validity check as
		// CheckProposal, but guarding here too means a stray nil from a
		// future caller won't deref body.BlobKZGCommitments below.
		return true
	}
	if body.ExecutionPayload != nil && len(body.ExecutionPayload.Transactions) > 0 {
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
	// Defensive: block, Message, and Body are pointer fields on the
	// go-eth2-client types. A non-conforming JSON response or future
	// caller could leave any of them nil; we'd otherwise nil-deref
	// reading ProposerIndex or Body.ExecutionPayload. Treat as missed
	// proposal so FinalizeMissedProposals reports it.
	if block == nil || block.Message == nil || block.Message.Body == nil {
		log.Error().
			Uint64("slot", uint64(slot)).
			Uint64("expected_validator", uint64(expectedValidator)).
			Msg("block has nil Message or Body; treating as missed proposal")
		return false
	}
	if block.Message.ProposerIndex != expectedValidator {
		// Surface the slot + both validator indices so an operator hitting
		// this in the field can diagnose without grepping around the
		// timestamp. Typically signals a stale cached proposer duty (reorg
		// invalidated assignment) — the bare "unexpected validator" message
		// it replaces gave no actionable context.
		log.Error().
			Uint64("slot", uint64(slot)).
			Uint64("expected_validator", uint64(expectedValidator)).
			Uint64("actual_validator", uint64(block.Message.ProposerIndex)).
			Msg("Block proposed by an unexpected validator (stale duty?)")
		return false
	}

	m.TotalCanonicalProposals.Inc()

	if isBlockEmpty(block.Message.Body) {
		Report("⚠️ 🧱 Validator %v (%v) proposed an empty block at epoch %v and slot %v",
			expectedValidator, pubkeyOrUnknown(pubkeys, expectedValidator), epoch, slot)
		m.LastProposedEmptyBlockSlot.Set(float64(slot))
		m.TotalProposedEmptyBlocks.Inc()
	}

	if mevEnabled {
		if block.Message.Body.ExecutionPayload == nil {
			// Without an execution payload there's nothing to compare against
			// the relay-delivered hash. Treat the slot as "no bid trace
			// usable" rather than crashing — the operator still gets a
			// metric bump and a log line.
			m.TotalMissingBidTraces.Inc()
			log.Error().Msgf("Block at slot %v has nil ExecutionPayload; cannot compare to bid trace (validator %v %v)", slot, expectedValidator, pubkeyOrUnknown(pubkeys, expectedValidator))
			return true
		}
		executionBlockHash := block.Message.Body.ExecutionPayload.BlockHash
		trace, ok := bestBids[slot]
		if !ok {
			// No bid trace found across configured relays. This could be a
			// truly vanilla block, or it could be a relay-side failure —
			// kept distinct from confirmed hash-mismatch vanilla blocks.
			m.TotalMissingBidTraces.Inc()
			log.Error().Msgf("Missing bid trace for proposal slot %v, validator %v (%v)", slot, expectedValidator, pubkeyOrUnknown(pubkeys, expectedValidator))
			return true
		}
		// Compare hashes case-insensitively. phase0.Hash32.String() emits
		// lowercase 0x-prefixed hex, but trace.BlockHash from the relay
		// JSON is not case-canonical per relay spec — a relay emitting
		// uppercase or mixed-case hex would otherwise flag every
		// MEV-built proposal as vanilla.
		if !strings.EqualFold(executionBlockHash.String(), trace.BlockHash) {
			m.TotalVanillaBlocks.Inc()
			m.LastVanillaBlockSlot.Set(float64(slot))
			m.LastVanillaBlockValidator.Set(float64(expectedValidator))
			log.Error().Msgf("Validator %v (%v) proposed a vanilla block %v at slot %v", expectedValidator, pubkeyOrUnknown(pubkeys, expectedValidator), executionBlockHash, slot)
			return true
		}
		if opts.Monitor.PrintSuccessful {
			Info("✅ 🧾 Validator %v (%v) proposed optimal MEV execution block %v at slot %v, epoch %v", expectedValidator, pubkeyOrUnknown(pubkeys, expectedValidator), trace.BlockHash, slot, epoch)
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
		Report("❌ 🧱 Validator %v (%v) missed proposal at slot %v", validatorIndex, pubkeyOrUnknown(pubkeys, validatorIndex), slot)
		m.TotalMissedProposals.Inc()
		m.LastMissedProposalSlot.Set(float64(slot))
		m.LastMissedProposalValidator.Set(float64(validatorIndex))
	}
}
