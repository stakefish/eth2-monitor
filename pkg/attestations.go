package pkg

import (
	"maps"
	"slices"

	"eth2-monitor/cmd/opts"
	"eth2-monitor/spec"

	v1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec/electra"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/rs/zerolog/log"
)

// CommitteeInfo holds the committee length and tracked validator positions.
// Built from AttesterDuty responses instead of fetching full committee lists.
type CommitteeInfo struct {
	Length     uint64                           // committee size (from duty.CommitteeLength)
	Validators map[uint64]phase0.ValidatorIndex // position → validatorIndex (tracked only)
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
// only — those are all we ever need to look up. Nil entries in the slice
// (defensive against malformed API responses) are skipped silently.
func BuildCommitteeLookup(
	duties []*v1.AttesterDuty,
	committeeLengths map[phase0.Slot]map[phase0.CommitteeIndex]uint64,
	tracked map[phase0.ValidatorIndex]string,
) map[phase0.Slot]map[phase0.CommitteeIndex]*CommitteeInfo {
	result := make(map[phase0.Slot]map[phase0.CommitteeIndex]*CommitteeInfo, len(committeeLengths))
	for slot, byIdx := range committeeLengths {
		entry := make(map[phase0.CommitteeIndex]*CommitteeInfo, len(byIdx))
		for idx, length := range byIdx {
			// Validators starts nil — lazily allocated when a tracked duty
			// for this committee is overlayed below. Most committees on a
			// busy network don't contain any tracked validator, so eagerly
			// allocating ~6000 empty maps per orchestrator iteration was
			// pure GC pressure. processAttestations ranges over the field;
			// `range nil map` is a no-op, so the read side stays safe.
			entry[idx] = &CommitteeInfo{Length: length}
		}
		result[slot] = entry
	}

	for _, duty := range duties {
		// duties is []*v1.AttesterDuty — slice of pointers; defensively
		// skip nil entries that a malformed API response could leave.
		if duty == nil {
			continue
		}
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
			info = &CommitteeInfo{Length: duty.CommitteeLength}
			result[duty.Slot][duty.CommitteeIndex] = info
		}
		if info.Validators == nil {
			info.Validators = make(map[uint64]phase0.ValidatorIndex)
		}
		info.Validators[duty.ValidatorCommitteeIndex] = duty.ValidatorIndex
	}
	return result
}

// pubkeyOrUnknown returns the validator's lowercase-canonical pubkey if
// known, or the literal "unknown" otherwise. Reports for stale validators
// (exited / no longer tracked / not yet resolved) previously formatted as
// "Validator 1234 ()" — empty parens read as a bug rather than missing
// data. The sentinel makes the situation explicit.
func pubkeyOrUnknown(pubkeys map[phase0.ValidatorIndex]string, idx phase0.ValidatorIndex) string {
	if pk, ok := pubkeys[idx]; ok && pk != "" {
		return pk
	}
	return "unknown"
}

// PruneSeenAttestations drops dedup entries older than cutoff, keeping only
// entries that could still recur in a future iteration's scan window.
//
// Caller invariant: cutoff = spec.EpochLowestSlot(epoch-1) at the start of
// each iteration. Pre-Deneb that's the earliest reachable attestedSlot
// (block.slot - SLOTS_PER_EPOCH = EpochLowestSlot(E) - 32 = EpochLowestSlot(E-1));
// post-Deneb late inclusions are processed at the inclusion epoch's iteration
// with fresh seenAttestations entries, so the conservative prune is still safe.
func PruneSeenAttestations(seen map[phase0.Slot]Set[phase0.ValidatorIndex], cutoff phase0.Slot) {
	for s := range seen {
		if s < cutoff {
			delete(seen, s)
		}
	}
}

// processAttestations processes attestations from epoch blocks, updating metrics and unfulfilled duties.
// seenAttestations is persistent across epoch iterations so cross-call duplicates
// (a block scanned both in epoch N's lookahead window and in epoch N+1's main range)
// are counted exactly once.
//
// Defensive nil handling: a block with nil pointer fields (block itself,
// Message, or Body) or an attestation entry with nil pointer (Attestation
// or its Data) is logged at WARN and skipped. These shapes shouldn't occur
// in valid Beacon API responses but are robust against malformed JSON
// from non-conforming clients.
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
		// Defensive: block, Message, and Body are pointer fields.
		// ListEpochBlocks filters out fully-nil blocks but a future caller
		// (or a map mutated mid-iteration) could surface either nil; the
		// nested derefs below would otherwise crash the orchestrator.
		if block == nil || block.Message == nil || block.Message.Body == nil {
			log.Warn().Uint64("slot", uint64(slot)).Msg("block at slot has nil block/Message/Body; skipping")
			continue
		}
		for _, attestation := range block.Message.Body.Attestations {
			// Defensive: Attestations is []*Attestation and AttestationData
			// is a pointer field, so a malformed JSON response could leave
			// either nil. Spec requires both on every canonical attestation;
			// crashing the orchestrator on bad data is worse than skipping
			// the offending entry.
			if attestation == nil || attestation.Data == nil {
				log.Warn().Uint64("blockSlot", uint64(block.Message.Slot)).Msg("attestation entry is nil or has nil Data; skipping")
				continue
			}
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
			// attestedSlotEpoch is constant per attestation; hoist out of
			// the per-validator loop so we don't recompute it for every
			// tracked attester in this committee.
			attestedSlotEpoch := spec.EpochFromSlot(attestedSlot)
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

				// Spec invariant: attestation.data.slot < block.slot, i.e.
				// earliestInclusionSlot (= attestedSlot+1) <= block.slot.
				// Any node misbehaviour that surfaces an attestation in the
				// same-or-earlier slot would otherwise underflow the
				// uint64 subtraction below and emit a huge "delayed
				// attestation" report.
				if earliestInclusionSlot > block.Message.Slot {
					log.Warn().Uint64("attestedSlot", uint64(attestedSlot)).Uint64("blockSlot", uint64(block.Message.Slot)).Msg("attestation included in or before its target slot; spec invariant violated, skipping")
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

				// attestedSlotEpoch hoisted outside the per-validator loop
				// (see above) — it's the epoch the validator was
				// supposed to attest in, NOT the iteration epoch
				// (which can differ during cross-epoch lookahead
				// observation).
				if attestationDistance > 2 {
					Report("⚠️ 🧾 Validator %v (%v) attested slot %v at slot %v, epoch %v, attestation distance is %v",
						validatorIndex, pubkeyOrUnknown(validatorPubkeyFromIndex, validatorIndex), attestedSlot, block.Message.Slot, attestedSlotEpoch, attestationDistance)
					m.TotalDelayedOverTolerance.Inc()
				} else if opts.Monitor.PrintSuccessful {
					Info("✅ 🧾 Validator %v (%v) attested slot %v at slot %v, epoch %v", validatorIndex, pubkeyOrUnknown(validatorPubkeyFromIndex, validatorIndex), attestedSlot, block.Message.Slot, attestedSlotEpoch)
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

// FinalizeMissedAttestations reports any attester duties left unfulfilled at
// the end of the cutoff epoch (caller invariant: missedEpochHighSlot =
// spec.EpochHighestSlot(epoch-1)) as missed, then removes them from the map.
//
// Pre-Deneb the spec capped inclusion at `data.slot + SLOTS_PER_EPOCH`, so E+1
// was a hard limit. EIP-7045 (Deneb) removed that upper bound, so this is now
// a QoS heuristic: real attestations land in 1-2 slots, and any inclusion >32
// slots later is operationally indistinguishable from a missed duty for
// validator performance reporting.
//
// Reports are delivered to Slack inline via Report — for a mass-incident
// scenario with many missed validators, the per-call ~5s timeout serialises
// and stalls the orchestrator. Acceptable in normal operation; documented
// limitation under load.
func FinalizeMissedAttestations(
	unfulfilled map[phase0.Slot]Set[phase0.ValidatorIndex],
	missedEpochHighSlot phase0.Slot,
	pubkeys map[phase0.ValidatorIndex]string,
	epoch phase0.Epoch,
	m *MonitorMetrics,
) {
	log.Debug().Msgf("Unfulfilled attester duties at the end of epoch %v (map[SLOT]{VALIDATOR_INDEX...}): %v", epoch, unfulfilled)
	for _, slot := range slices.Sorted(maps.Keys(unfulfilled)) {
		if slot > missedEpochHighSlot {
			break
		}
		// Report the SLOT's epoch (where the validator should have attested)
		// rather than the iteration epoch that's reporting it. Operators
		// reading "did not attest slot S (epoch E)" expect E = S/32, not
		// "the epoch in which the report fired".
		slotEpoch := spec.EpochFromSlot(slot)
		for validatorIndex := range unfulfilled[slot].Elems() {
			Report("❌ 🧾 Validator %v (%v) did not attest slot %v (epoch %v)", validatorIndex, pubkeyOrUnknown(pubkeys, validatorIndex), slot, slotEpoch)
			m.TotalMissedAttestations.Inc()
		}
		delete(unfulfilled, slot)
	}
}
