package monitoring

import (
	"bytes"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/stakefish/eth2-monitor/internal/opts"

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
// Defensive nil handling: a nil body or a non-nil body with a nil
// ExecutionPayload both classify as empty. Post-Bellatrix these fields
// are mandatory per spec, but a non-conforming JSON response (Caplin
// quirk, future fork change, missing field) could leave either nil.
// Crashing the orchestrator on bad data is worse than recording it as
// an empty proposal.
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
// Returns false on:
//   - Nil block, Message, or Body — defensive against malformed JSON that
//     leaves these pointer fields unset; caller MUST leave the slot in
//     unfulfilled duties so FinalizeMissedProposals reports it.
//   - Proposer-index mismatch — a block exists at this slot but a different
//     validator proposed it (typically a stale cached duty from a reorg);
//     same handling: leave in unfulfilled, will be reported as missed.
//
// Writes are independent and can stack on a single call (preserving the
// original code's fall-through; an empty block on a MEV-enabled run with a
// missing bid trace fires both the empty-block metrics AND
// TotalMissingBidTraces, never neither):
//
//   - Canonical proposal observed:    TotalCanonicalProposals++
//   - Block is empty:                 TotalProposedEmptyBlocks++,
//     LastProposedEmptyBlockSlot.Set(slot)
//   - MEV enabled + nil ExecPayload:  TotalMissingBidTraces++ (fold into
//     missing-bid since there's nothing to compare to)
//   - MEV enabled + no bid trace + client-default or empty extra_data:
//     TotalVanillaBlocks++, LastVanillaBlock* gauges, Slack Report. The
//     block was built locally; this is the common vanilla case (a locally
//     built block never appears in any relay's delivered list). Decided
//     from the on-chain evidence alone so a slow relay cannot hide a real
//     vanilla block; the report says whether the relay sweep was complete
//     and states the relay-side registration: not registered anywhere
//     (mev-boost registration broken), fee recipient differing from the
//     registered one (local EL misconfigured), matching, or unknown.
//   - MEV enabled + no bid trace + builder tag in extra_data +
//     RelaysComplete: TotalRelayAbsentBuilderBlocks++, Slack Report. A
//     builder made the block but no configured relay delivered it: relay
//     missing from --mev-relays, or a direct builder deal. Not vanilla.
//   - MEV enabled + no bid trace + builder tag + !RelaysComplete:
//     TotalMissingBidTraces++ (log only). Most likely the failed relay
//     delivered it; the slot cannot be classified.
//   - MEV enabled + hash mismatch:    TotalVanillaBlocks++,
//     LastVanillaBlock* gauges, Slack Report (a relay says it delivered
//     a payload but the chain carries a different one)
//
// Vanilla reports carry the block's graffiti, execution extra_data and
// fee recipient so an operator can confirm the classification at a
// glance (builders stamp extra_data and use their own coinbase; local
// blocks carry the EL client tag and the proposer's fee recipient). For
// SSV clusters the graffiti names the leader operator's node.
func CheckProposal(
	block *electra.SignedBeaconBlock,
	slot phase0.Slot,
	expectedValidator phase0.ValidatorIndex,
	mev MEVContext,
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
			Msg("block/Message/Body is nil; treating as missed proposal")
		return false
	}
	if block.Message.ProposerIndex != expectedValidator {
		// Surface epoch + slot + both validator indices so an operator
		// hitting this in the field can diagnose without grepping around
		// the timestamp. Typically signals a stale cached proposer duty
		// (reorg invalidated assignment) — the bare "unexpected validator"
		// message it replaces gave no actionable context.
		log.Error().
			Uint64("epoch", uint64(epoch)).
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

	if mev.Enabled {
		if block.Message.Body.ExecutionPayload == nil {
			// Without an execution payload there's nothing to compare against
			// the relay-delivered hash. Treat the slot as "no bid trace
			// usable" rather than crashing — the operator still gets a
			// metric bump and a log line.
			m.TotalMissingBidTraces.Inc()
			log.Error().
				Uint64("slot", uint64(slot)).
				Uint64("epoch", uint64(epoch)).
				Uint64("validator", uint64(expectedValidator)).
				Str("pubkey", pubkeyOrUnknown(pubkeys, expectedValidator)).
				Msg("proposed block has nil ExecutionPayload; cannot compare to bid trace")
			return true
		}
		executionBlockHash := block.Message.Body.ExecutionPayload.BlockHash
		graffiti, extraData, feeRecipient := proposalEvidence(block.Message.Body)
		trace, ok := mev.BestBids[slot]
		if !ok {
			if !isClientDefaultExtraData(block.Message.Body.ExecutionPayload.ExtraData) {
				// Builders stamp extra_data; a locally built block carries
				// the EL client's default. A tag here with no delivering
				// relay is not a vanilla block: either the relay is not in
				// our list (or the builder dealt with the proposer
				// directly), or — when a relay failed this epoch — the
				// failed relay most likely delivered it.
				if !mev.RelaysComplete {
					m.TotalMissingBidTraces.Inc()
					log.Error().
						Uint64("slot", uint64(slot)).
						Uint64("epoch", uint64(epoch)).
						Uint64("validator", uint64(expectedValidator)).
						Str("pubkey", pubkeyOrUnknown(pubkeys, expectedValidator)).
						Str("extraData", extraData).
						Msg("builder-tagged block without a bid trace while the relay sweep was incomplete; cannot classify")
					return true
				}
				m.TotalRelayAbsentBuilderBlocks.Inc()
				Report("⚠️ 🏗️ Validator %v (%v) proposed a block at slot %v (epoch %v) that looks builder-built but no configured relay delivered it: relay missing from --mev-relays or a direct builder deal. graffiti=%q extra_data=%q fee_recipient=%s",
					expectedValidator, pubkeyOrUnknown(pubkeys, expectedValidator), slot, epoch, graffiti, extraData, feeRecipient)
				return true
			}
			// Client-default extra_data: built locally. The on-chain
			// evidence decides, so a slow relay cannot hide the alert;
			// the sweep state is reported for context.
			m.TotalVanillaBlocks.Inc()
			m.LastVanillaBlockSlot.Set(float64(slot))
			m.LastVanillaBlockValidator.Set(float64(expectedValidator))
			sweep := "no relay delivered a payload"
			if !mev.RelaysComplete {
				sweep = "no answering relay delivered a payload (relay sweep incomplete)"
			}
			Report("⚠️ 🧱 Validator %v (%v) proposed a vanilla block at slot %v (epoch %v): %s. graffiti=%q extra_data=%q fee_recipient=%s %s",
				expectedValidator, pubkeyOrUnknown(pubkeys, expectedValidator), slot, epoch, sweep, graffiti, extraData, feeRecipient,
				registrationNote(mev.Registrations[expectedValidator], feeRecipient))
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
			Report("⚠️ 🧱 Validator %v (%v) proposed a vanilla block at slot %v (epoch %v): chain block %s differs from relay-delivered %s. graffiti=%q extra_data=%q fee_recipient=%s",
				expectedValidator, pubkeyOrUnknown(pubkeys, expectedValidator), slot, epoch, executionBlockHash.String(), trace.BlockHash, graffiti, extraData, feeRecipient)
			return true
		}
		if opts.Monitor.PrintSuccessful {
			Info("✅ 🧾 Validator %v (%v) proposed optimal MEV execution block %v at slot %v, epoch %v", expectedValidator, pubkeyOrUnknown(pubkeys, expectedValidator), trace.BlockHash, slot, epoch)
		}
	}

	return true
}

// clientExtraDataTags are substrings (lower-case) that execution clients
// write into extra_data by default: geth's RLP list contains "geth",
// Nethermind/besu/reth/erigon/nimbus write a version string. Builders
// replace extra_data with their own branding, so any of these tags (or an
// empty field) marks a locally built payload. Observed on 636 mainnet
// blocks in October 2026 with zero overlap between the two populations.
var clientExtraDataTags = [][]byte{
	[]byte("geth"), []byte("nethermind"), []byte("besu"), []byte("reth"), []byte("erigon"), []byte("nimbus"),
}

// isClientDefaultExtraData reports whether extra_data looks like an EL
// client default (or is empty) rather than a builder tag.
func isClientDefaultExtraData(extraData []byte) bool {
	if len(extraData) == 0 {
		return true
	}
	lower := bytes.ToLower(extraData)
	for _, tag := range clientExtraDataTags {
		if bytes.Contains(lower, tag) {
			return true
		}
	}
	return false
}

// registrationNote renders the relay-side registration outcome for a
// vanilla-block report. The two actionable cases name the misconfiguration.
func registrationNote(reg Registration, blockFeeRecipient string) string {
	switch {
	case reg.Status == RegistrationNotFound:
		return "validator is NOT registered with any configured relay (mev-boost registration broken)"
	case reg.Status == RegistrationRegistered && !reg.matches(blockFeeRecipient):
		return fmt.Sprintf("fee_recipient differs from registered %s (local EL fee recipient misconfigured)", reg.FeeRecipient)
	case reg.Status == RegistrationRegistered:
		return "registered_fee_recipient=" + reg.FeeRecipient
	default:
		return "registration=unknown"
	}
}

// proposalEvidence extracts the three block fields that tell a human (or
// a later heuristic) whether a block was builder-made or locally built:
// graffiti (SSV: the leader operator's node), execution extra_data (builder
// tag vs EL client tag) and the payload fee recipient (builder coinbase vs
// the proposer's own address). Callers format the strings with %q because
// geth's extra_data is binary RLP. Caller guarantees a non-nil
// ExecutionPayload.
func proposalEvidence(body *electra.BeaconBlockBody) (graffiti, extraData, feeRecipient string) {
	graffiti = string(bytes.TrimRight(body.Graffiti[:], "\x00"))
	extraData = string(body.ExecutionPayload.ExtraData)
	feeRecipient = body.ExecutionPayload.FeeRecipient.String()
	return graffiti, extraData, feeRecipient
}

// FinalizeMissedProposals reports each remaining unfulfilled proposer duty as
// a missed proposal and updates the Last* gauges. Caller is expected to have
// already deleted slots whose proposals were confirmed via CheckProposal.
// The epoch argument is the current epoch being processed; it appears in
// the Slack Report message for operator correlation (the slot alone forces
// a slot/32 calculation against the alert text).
//
// Iteration is sorted by slot ascending, so the Last* gauges settle on the
// highest unfulfilled slot's value. Reports go to Slack inline — for a chain
// incident with many missed proposals, this serialises Slack POSTs and
// stalls the orchestrator for ~5s per validator (the slackClient timeout).
// Acceptable in normal operation; documented limitation under load.
func FinalizeMissedProposals(
	unfulfilledProposerDuties map[phase0.Slot]phase0.ValidatorIndex,
	pubkeys map[phase0.ValidatorIndex]string,
	epoch phase0.Epoch,
	m *MonitorMetrics,
) {
	// Sort for deterministic Slack report ordering and so the Last* gauges
	// settle on the highest-slot entry.
	for _, slot := range slices.Sorted(maps.Keys(unfulfilledProposerDuties)) {
		validatorIndex := unfulfilledProposerDuties[slot]
		Report("❌ 🧱 Validator %v (%v) missed proposal at slot %v (epoch %v)", validatorIndex, pubkeyOrUnknown(pubkeys, validatorIndex), slot, epoch)
		m.TotalMissedProposals.Inc()
		m.LastMissedProposalSlot.Set(float64(slot))
		m.LastMissedProposalValidator.Set(float64(validatorIndex))
	}
}
