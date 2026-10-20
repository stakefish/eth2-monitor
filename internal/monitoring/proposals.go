package monitoring

import (
	"bytes"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/stakefish/eth2-monitor/internal/opts"

	"github.com/attestantio/go-eth2-client/spec/deneb"
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
//   - MEV enabled + hash mismatch:    TotalVanillaBlocks++ and
//     TotalRelayHashMismatches++, LastVanillaBlock* gauges, Slack Report
//     (a relay says it delivered a payload but the chain carries a
//     different one)
//
// The MEV outcomes are decided by classifyProposal; this function only
// records metrics and reports.
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
		payload := block.Message.Body.ExecutionPayload
		trace := mev.trace(slot)
		who := fmt.Sprintf("Validator %v (%v)", expectedValidator, pubkeyOrUnknown(pubkeys, expectedValidator))
		where := fmt.Sprintf("slot %v (epoch %v)", slot, epoch)
		evidence := evidenceOf(block.Message.Body)
		switch classifyProposal(payload, trace, mev.RelaysComplete) {
		case verdictMEV:
			if opts.Monitor.PrintSuccessful {
				Info("✅ 🧾 %s proposed optimal MEV execution block %v at slot %v, epoch %v", who, trace.BlockHash, slot, epoch)
			}
		case verdictHashMismatch:
			m.vanillaBlock(slot, expectedValidator)
			m.TotalRelayHashMismatches.Inc()
			Report("⚠️ 🧱 %s proposed a vanilla block at %s: chain block %s differs from relay-delivered %s. %s",
				who, where, payload.BlockHash.String(), trace.BlockHash, evidence)
		case verdictVanilla:
			m.vanillaBlock(slot, expectedValidator)
			sweep := "no relay delivered a payload"
			if !mev.RelaysComplete {
				sweep = "no answering relay delivered a payload (relay sweep incomplete)"
			}
			Report("⚠️ 🧱 %s proposed a vanilla block at %s: %s. %s %s",
				who, where, sweep, evidence, registrationNote(mev.Registrations[expectedValidator], evidence.feeRecipient))
		case verdictRelayAbsentBuilder:
			m.TotalRelayAbsentBuilderBlocks.Inc()
			Report("⚠️ 🏗️ %s proposed a block at %s that looks builder-built but no configured relay delivered it: relay missing from --mev-relays or a direct builder deal. %s",
				who, where, evidence)
		case verdictUnclassified:
			// No payload to compare, or a builder-tagged block while a relay
			// failed this epoch (the failed relay most likely delivered it).
			m.TotalMissingBidTraces.Inc()
			log.Error().
				Uint64("slot", uint64(slot)).
				Uint64("epoch", uint64(epoch)).
				Uint64("validator", uint64(expectedValidator)).
				Str("pubkey", pubkeyOrUnknown(pubkeys, expectedValidator)).
				Bool("hasExecutionPayload", payload != nil).
				Bool("relaysComplete", mev.RelaysComplete).
				Str("extraData", evidence.extraData).
				Msg("proposal cannot be classified: no bid trace and no on-chain evidence of a local build")
		}
	}

	return true
}

// clientExtraDataTags are substrings (lower-case) that execution clients
// write into extra_data by default: geth's RLP list contains "geth",
// Nethermind/besu/reth/erigon/nimbus/ethrex write a version string. Builders
// replace extra_data with their own branding, so any of these tags (or an
// empty field) marks a locally built payload. Observed on 636 mainnet
// blocks in October 2026 with zero overlap between the two populations.
var clientExtraDataTags = [][]byte{
	[]byte("geth"), []byte("nethermind"), []byte("besu"), []byte("reth"), []byte("erigon"), []byte("nimbus"), []byte("ethrex"),
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

// proposalVerdict is the outcome of comparing a tracked, canonical
// proposal with what the relays delivered. See classifyProposal.
type proposalVerdict int

const (
	verdictMEV                proposalVerdict = iota // a relay delivered the payload that is on chain
	verdictHashMismatch                              // a relay delivered a payload but the chain carries another one: vanilla
	verdictVanilla                                   // no relay delivered and extra_data is an EL client default or empty: built locally
	verdictRelayAbsentBuilder                        // no relay delivered, extra_data carries a builder tag, every relay answered: relay missing from the list or a direct deal
	verdictUnclassified                              // nothing to compare (no payload), or builder-tagged while a relay failed
)

// classifyProposal is CheckProposal's outcome table as a pure function.
// trace is the best relay-delivered trace for the slot, nil when no
// configured relay reported one (after the per-slot re-check), and
// relaysComplete says whether every relay answered the epoch sweep. The
// vanilla rule is decided on-chain alone so a slow relay cannot hide a
// locally built block. BuildEpochContext picks registration candidates
// with this same function, so the rule lives here and nowhere else.
func classifyProposal(payload *deneb.ExecutionPayload, trace *BidTrace, relaysComplete bool) proposalVerdict {
	switch {
	case payload == nil:
		return verdictUnclassified
	case trace == nil && isClientDefaultExtraData(payload.ExtraData):
		return verdictVanilla
	case trace == nil && relaysComplete:
		return verdictRelayAbsentBuilder
	case trace == nil:
		return verdictUnclassified
	// phase0.Hash32.String() emits lower-case hex; relays are not
	// case-canonical, so compare case-insensitively.
	case !strings.EqualFold(payload.BlockHash.String(), trace.BlockHash):
		return verdictHashMismatch
	default:
		return verdictMEV
	}
}

// registrationNote renders the relay-side registration outcome for a
// vanilla-block report. The two actionable cases name the misconfiguration.
func registrationNote(reg Registration, blockFeeRecipient string) string {
	switch {
	case reg.Status == RegistrationNotFound:
		return "validator is NOT registered with any configured relay (mev-boost registration broken)"
	case reg.Status == RegistrationRegistered && !reg.matches(blockFeeRecipient):
		return fmt.Sprintf("fee_recipient differs from registered %s (local EL fee recipient misconfigured)", reg.newest())
	case reg.Status == RegistrationRegistered:
		return "registered_fee_recipient=" + reg.newest()
	default:
		return "registration=unknown"
	}
}

// proposalEvidence is what tells a human (or a later heuristic) whether a
// block was builder-made or built locally: graffiti (SSV: the leader
// operator's node), execution extra_data (builder tag vs EL client tag)
// and the payload fee recipient (builder coinbase vs the proposer's own
// address).
type proposalEvidence struct {
	graffiti, extraData, feeRecipient string
}

func evidenceOf(body *electra.BeaconBlockBody) proposalEvidence {
	ev := proposalEvidence{graffiti: string(bytes.TrimRight(body.Graffiti[:], "\x00"))}
	if body.ExecutionPayload != nil {
		ev.extraData = string(body.ExecutionPayload.ExtraData)
		ev.feeRecipient = body.ExecutionPayload.FeeRecipient.String()
	}
	return ev
}

// String quotes graffiti and extra_data because geth's extra_data is
// binary RLP.
func (e proposalEvidence) String() string {
	return fmt.Sprintf("graffiti=%q extra_data=%q fee_recipient=%s", e.graffiti, e.extraData, e.feeRecipient)
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
