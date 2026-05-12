package pkg

import (
	"testing"

	"github.com/OffchainLabs/go-bitfield"
	v1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec/electra"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/prometheus/client_golang/prometheus"
)

// TestFinalizeMissedAttestations — slots ≤ cutoff get cleared from
// unfulfilled and counted as missed; slots > cutoff stay (they may still be
// observed in a future iteration).
func TestFinalizeMissedAttestations(t *testing.T) {
	const (
		v1 = phase0.ValidatorIndex(11)
		v2 = phase0.ValidatorIndex(22)
		v3 = phase0.ValidatorIndex(33)
	)
	cutoff := phase0.Slot(63) // end of epoch 1, SLOTS_PER_EPOCH=32
	unfulfilled := map[phase0.Slot]Set[phase0.ValidatorIndex]{
		31: NewSet(v1),                            // ≤ cutoff: missed
		63: NewSet(v2),                            // == cutoff: missed (boundary)
		64: NewSet(v3),                            // > cutoff: retained
		32: NewSet(phase0.ValidatorIndex(44), v1), // ≤ cutoff, two validators: both missed
	}
	pubkeys := map[phase0.ValidatorIndex]string{
		v1:                        "pk1",
		v2:                        "pk2",
		v3:                        "pk3",
		phase0.ValidatorIndex(44): "pk44",
	}
	m := NewMonitorMetrics(prometheus.NewRegistry())

	FinalizeMissedAttestations(unfulfilled, cutoff, pubkeys, 2, m)

	// Three missed-attestation reports: v1@31, v44@32 + v1@32, v2@63 = 4 total
	if got := counterValue(t, m.TotalMissedAttestations); got != 4 {
		t.Errorf("TotalMissedAttestations = %v, want 4 (validators at slots ≤ cutoff)", got)
	}
	for _, s := range []phase0.Slot{31, 32, 63} {
		if _, still := unfulfilled[s]; still {
			t.Errorf("slot %v still in unfulfilled after finalize; expected delete", s)
		}
	}
	if _, still := unfulfilled[64]; !still {
		t.Errorf("slot 64 (> cutoff) was deleted; should be retained for future observation")
	}
}

// TestPruneSeenAttestations — entries strictly below cutoff dropped; entries
// at cutoff or above retained. The current code uses `< cutoff`, not
// `<= cutoff`; this test pins that exact boundary.
func TestPruneSeenAttestations(t *testing.T) {
	cutoff := phase0.Slot(32)
	seen := map[phase0.Slot]Set[phase0.ValidatorIndex]{
		0:  NewSet(phase0.ValidatorIndex(1)), // < cutoff: pruned
		31: NewSet(phase0.ValidatorIndex(2)), // < cutoff: pruned
		32: NewSet(phase0.ValidatorIndex(3)), // == cutoff: kept (strict <)
		63: NewSet(phase0.ValidatorIndex(4)), // > cutoff: kept
	}

	PruneSeenAttestations(seen, cutoff)

	for _, s := range []phase0.Slot{0, 31} {
		if _, ok := seen[s]; ok {
			t.Errorf("slot %v not pruned; expected delete (strictly < %v)", s, cutoff)
		}
	}
	for _, s := range []phase0.Slot{32, 63} {
		if _, ok := seen[s]; !ok {
			t.Errorf("slot %v incorrectly pruned; expected retain (slot >= %v)", s, cutoff)
		}
	}
}

// TestProcessAttestationsDedupsAcrossCalls pins down the cross-epoch dedup invariant:
// an attestation observed twice (in epoch N's lookahead window and again in epoch N+1's
// main scan) must increment TotalCanonicalAttestations exactly once, and
// DuplicateAttestationsSkipped exactly once on the second observation.
func TestProcessAttestationsDedupsAcrossCalls(t *testing.T) {
	const (
		validatorIndex = phase0.ValidatorIndex(100)
		committeeIndex = phase0.CommitteeIndex(0)
		attestedSlot   = phase0.Slot(31) // last slot of epoch 0
		inclusionSlot  = phase0.Slot(32) // first slot of epoch 1
	)

	block := &electra.SignedBeaconBlock{
		Message: &electra.BeaconBlock{
			Slot: inclusionSlot,
			Body: &electra.BeaconBlockBody{
				Attestations: []*electra.Attestation{
					buildSingleValidatorAttestation(attestedSlot),
				},
			},
		},
	}
	epochBlocks := map[phase0.Slot]*electra.SignedBeaconBlock{inclusionSlot: block}

	committeeLookup := map[phase0.Slot]map[phase0.CommitteeIndex]*CommitteeInfo{
		attestedSlot: {
			committeeIndex: {
				Length:     1,
				Validators: map[uint64]phase0.ValidatorIndex{0: validatorIndex},
			},
		},
	}
	validatorPubkeyFromIndex := map[phase0.ValidatorIndex]string{
		validatorIndex: "pubkey",
	}
	unfulfilledAttesterDuties := map[phase0.Slot]Set[phase0.ValidatorIndex]{
		attestedSlot: NewSet(validatorIndex),
	}
	seenAttestations := make(map[phase0.Slot]Set[phase0.ValidatorIndex])

	m := NewMonitorMetrics(prometheus.NewRegistry())

	// First call: epoch 0 — block at slot 32 is in the lookahead window.
	processAttestations(epochBlocks, committeeLookup, validatorPubkeyFromIndex, unfulfilledAttesterDuties, seenAttestations, m, 0)

	if got := counterValue(t, m.TotalCanonicalAttestations); got != 1 {
		t.Fatalf("after epoch 0 call: TotalCanonicalAttestations = %v, want 1", got)
	}
	if got := counterValue(t, m.DuplicateAttestationsSkipped); got != 0 {
		t.Fatalf("after epoch 0 call: DuplicateAttestationsSkipped = %v, want 0", got)
	}
	if got := histogramSampleCount(t, m.CanonicalAttestationDistances); got != 1 {
		t.Fatalf("after epoch 0 call: CanonicalAttestationDistances samples = %v, want 1", got)
	}
	if _, stillUnfulfilled := unfulfilledAttesterDuties[attestedSlot]; stillUnfulfilled {
		t.Fatalf("after epoch 0 call: slot %v still in unfulfilledAttesterDuties, expected removal", attestedSlot)
	}

	// Second call: epoch 1 — the same block lands in the main scan range.
	// Without the persistent dedup, this would double-count every metric.
	processAttestations(epochBlocks, committeeLookup, validatorPubkeyFromIndex, unfulfilledAttesterDuties, seenAttestations, m, 1)

	if got := counterValue(t, m.TotalCanonicalAttestations); got != 1 {
		t.Fatalf("after epoch 1 call: TotalCanonicalAttestations = %v, want 1 (dedup must skip)", got)
	}
	if got := counterValue(t, m.DuplicateAttestationsSkipped); got != 1 {
		t.Fatalf("after epoch 1 call: DuplicateAttestationsSkipped = %v, want 1", got)
	}
	if got := histogramSampleCount(t, m.CanonicalAttestationDistances); got != 1 {
		t.Fatalf("after epoch 1 call: CanonicalAttestationDistances samples = %v, want 1 (no extra observation)", got)
	}
}

// TestProcessAttestationsHonorsUntrackedCommitteeOffsets is the regression test for
// the false-missed-attestation bug. When an attestation aggregates across multiple
// committees (EIP-7549) and only some of those committees contain tracked validators,
// the AggregationBits offset must still advance past untracked committees by their
// actual length — otherwise bits get attributed to the wrong validator and our
// tracked validator looks like they missed.
//
// Setup: 3 committees of length 4 in the same slot. The attestation aggregates
// committees 0, 1, 2 (CommitteeBits = 0b111). AggregationBits is 12 bits:
//
//	[0000 1111 1000]
//	 c0   c1   c2
//
// Our tracked validator is at position 0 in committee 2. Their actual bit is
// AggregationBits[8+0]=8, which is 1 (set) — they DID attest.
//
// The pre-fix code skipped committees with no tracked validators without
// advancing the offset, so it would have read AggregationBits[0+0]=0 (unset)
// for our validator → false-negative "did not attest".
//
// The post-fix code seeds committeeLookup with Length entries for ALL three
// committees, advances offset to 8 by the time we reach c2, and reads bit 8
// (set) → correctly marks the validator as attested.
func TestProcessAttestationsHonorsUntrackedCommitteeOffsets(t *testing.T) {
	const (
		validatorIndex = phase0.ValidatorIndex(200)
		attestedSlot   = phase0.Slot(63) // last slot of epoch 1
		inclusionSlot  = phase0.Slot(64) // first slot of epoch 2
	)

	// 12 bits: c0=0000, c1=1111, c2=1000
	aggBits := bitfield.NewBitlist(12)
	for i := uint64(4); i < 8; i++ {
		aggBits.SetBitAt(i, true) // c1 all set
	}
	aggBits.SetBitAt(8, true) // c2 pos 0 — our tracked validator

	committeeBits := bitfield.NewBitvector64()
	committeeBits.SetBitAt(0, true)
	committeeBits.SetBitAt(1, true)
	committeeBits.SetBitAt(2, true)

	att := &electra.Attestation{
		AggregationBits: aggBits,
		Data:            &phase0.AttestationData{Slot: attestedSlot},
		CommitteeBits:   committeeBits,
	}

	block := &electra.SignedBeaconBlock{
		Message: &electra.BeaconBlock{
			Slot: inclusionSlot,
			Body: &electra.BeaconBlockBody{
				Attestations: []*electra.Attestation{att},
			},
		},
	}
	epochBlocks := map[phase0.Slot]*electra.SignedBeaconBlock{inclusionSlot: block}

	// committeeLookup has ALL three committees with Length=4; only committee 2
	// has a tracked validator entry.
	committeeLookup := map[phase0.Slot]map[phase0.CommitteeIndex]*CommitteeInfo{
		attestedSlot: {
			0: {Length: 4, Validators: map[uint64]phase0.ValidatorIndex{}},
			1: {Length: 4, Validators: map[uint64]phase0.ValidatorIndex{}},
			2: {Length: 4, Validators: map[uint64]phase0.ValidatorIndex{0: validatorIndex}},
		},
	}
	validatorPubkeyFromIndex := map[phase0.ValidatorIndex]string{
		validatorIndex: "pubkey",
	}
	unfulfilledAttesterDuties := map[phase0.Slot]Set[phase0.ValidatorIndex]{
		attestedSlot: NewSet(validatorIndex),
	}
	seenAttestations := make(map[phase0.Slot]Set[phase0.ValidatorIndex])
	m := NewMonitorMetrics(prometheus.NewRegistry())

	processAttestations(epochBlocks, committeeLookup, validatorPubkeyFromIndex, unfulfilledAttesterDuties, seenAttestations, m, 2)

	if got := counterValue(t, m.TotalCanonicalAttestations); got != 1 {
		t.Fatalf("TotalCanonicalAttestations = %v, want 1 (validator's bit at offset 8 is set)", got)
	}
	if _, stillUnfulfilled := unfulfilledAttesterDuties[attestedSlot]; stillUnfulfilled {
		t.Fatalf("slot %v still in unfulfilledAttesterDuties — offset bug regressed (validator's actual bit is set)", attestedSlot)
	}
}

// TestProcessAttestationsSkipsAttestationWithUnknownCommittee verifies the
// defensive skip: if the attestation references a committee we don't have
// length data for, processAttestations must NOT process it (a corrupt offset
// would falsely credit or discredit our validators).
func TestProcessAttestationsSkipsAttestationWithUnknownCommittee(t *testing.T) {
	const (
		validatorIndex = phase0.ValidatorIndex(300)
		attestedSlot   = phase0.Slot(63)
		inclusionSlot  = phase0.Slot(64)
	)

	aggBits := bitfield.NewBitlist(8)
	for i := uint64(0); i < 8; i++ {
		aggBits.SetBitAt(i, true)
	}

	committeeBits := bitfield.NewBitvector64()
	committeeBits.SetBitAt(0, true)
	committeeBits.SetBitAt(1, true)

	att := &electra.Attestation{
		AggregationBits: aggBits,
		Data:            &phase0.AttestationData{Slot: attestedSlot},
		CommitteeBits:   committeeBits,
	}

	block := &electra.SignedBeaconBlock{
		Message: &electra.BeaconBlock{
			Slot: inclusionSlot,
			Body: &electra.BeaconBlockBody{
				Attestations: []*electra.Attestation{att},
			},
		},
	}
	epochBlocks := map[phase0.Slot]*electra.SignedBeaconBlock{inclusionSlot: block}

	// Only committee 0 is known; committee 1 (also referenced in the
	// attestation) has no entry. The whole attestation must be skipped.
	committeeLookup := map[phase0.Slot]map[phase0.CommitteeIndex]*CommitteeInfo{
		attestedSlot: {
			0: {Length: 4, Validators: map[uint64]phase0.ValidatorIndex{0: validatorIndex}},
		},
	}
	validatorPubkeyFromIndex := map[phase0.ValidatorIndex]string{
		validatorIndex: "pubkey",
	}
	unfulfilledAttesterDuties := map[phase0.Slot]Set[phase0.ValidatorIndex]{
		attestedSlot: NewSet(validatorIndex),
	}
	seenAttestations := make(map[phase0.Slot]Set[phase0.ValidatorIndex])
	m := NewMonitorMetrics(prometheus.NewRegistry())

	processAttestations(epochBlocks, committeeLookup, validatorPubkeyFromIndex, unfulfilledAttesterDuties, seenAttestations, m, 2)

	if got := counterValue(t, m.TotalCanonicalAttestations); got != 0 {
		t.Fatalf("TotalCanonicalAttestations = %v, want 0 (attestation must be skipped)", got)
	}
	if _, stillUnfulfilled := unfulfilledAttesterDuties[attestedSlot]; !stillUnfulfilled {
		t.Fatalf("slot %v removed from unfulfilledAttesterDuties; skipped attestation must not clear state", attestedSlot)
	}
}

// TestBuildCommitteeLookupPopulatesLengthsFromAPI verifies that BuildCommitteeLookup
// uses committeeLengths for ALL committees (not just tracked ones) and overlays
// tracked validator positions from duties.
func TestBuildCommitteeLookupPopulatesLengthsFromAPI(t *testing.T) {
	const (
		tracked    = phase0.ValidatorIndex(1000)
		untracked  = phase0.ValidatorIndex(2000)
		slot       = phase0.Slot(50)
		trackedCmt = phase0.CommitteeIndex(2)
	)

	committeeLengths := map[phase0.Slot]map[phase0.CommitteeIndex]uint64{
		slot: {0: 7, 1: 6, 2: 8, 3: 7},
	}
	duties := []*v1.AttesterDuty{
		{Slot: slot, ValidatorIndex: tracked, CommitteeIndex: trackedCmt, CommitteeLength: 8, ValidatorCommitteeIndex: 3},
		{Slot: slot, ValidatorIndex: untracked, CommitteeIndex: 1, CommitteeLength: 6, ValidatorCommitteeIndex: 0},
	}
	trackedMap := map[phase0.ValidatorIndex]string{tracked: "pk"}

	result := BuildCommitteeLookup(duties, committeeLengths, trackedMap)

	got := result[slot]
	if got == nil {
		t.Fatalf("no entry for slot %v", slot)
	}
	for idx, wantLen := range map[phase0.CommitteeIndex]uint64{0: 7, 1: 6, 2: 8, 3: 7} {
		info := got[idx]
		if info == nil {
			t.Errorf("committee %v missing in lookup", idx)
			continue
		}
		if info.Length != wantLen {
			t.Errorf("committee %v Length = %v, want %v", idx, info.Length, wantLen)
		}
	}
	if v, ok := got[trackedCmt].Validators[3]; !ok || v != tracked {
		t.Errorf("tracked validator at committee %v position 3 missing: got %v ok=%v", trackedCmt, v, ok)
	}
	if len(got[1].Validators) != 0 {
		t.Errorf("committee 1 should have no tracked validators (the duty entry was for an untracked index); got %v", got[1].Validators)
	}
}

// TestProcessAttestationsLookaheadDoesNotMaskAttestation is the regression test for
// the cross-epoch lookahead/dedup bug. processAttestations runs once during the
// previous epoch's lookahead (when the current epoch's duties are NOT yet in
// unfulfilledAttesterDuties) and again during the current epoch's main scan.
// The dedup in seenAttestations must not prevent the unfulfilled removal on the
// second pass — otherwise validators whose attestations land in the lookahead
// window of the previous epoch are permanently stuck in unfulfilled and get
// falsely reported as missed.
//
// Scenario: an attestation for slot 31 (first slot of epoch 1 in a SLOTS_PER_EPOCH=32
// world — boundary) is included in block at slot 32, which sits in BOTH epoch 0's
// lookahead window AND epoch 1's main scan.
func TestProcessAttestationsLookaheadDoesNotMaskAttestation(t *testing.T) {
	const (
		validatorIndex = phase0.ValidatorIndex(400)
		committeeIndex = phase0.CommitteeIndex(0)
		attestedSlot   = phase0.Slot(32) // first slot of epoch 1
		inclusionSlot  = phase0.Slot(33)
	)

	block := &electra.SignedBeaconBlock{
		Message: &electra.BeaconBlock{
			Slot: inclusionSlot,
			Body: &electra.BeaconBlockBody{
				Attestations: []*electra.Attestation{
					buildSingleValidatorAttestation(attestedSlot),
				},
			},
		},
	}
	epochBlocks := map[phase0.Slot]*electra.SignedBeaconBlock{inclusionSlot: block}

	committeeLookup := map[phase0.Slot]map[phase0.CommitteeIndex]*CommitteeInfo{
		attestedSlot: {
			committeeIndex: {
				Length:     1,
				Validators: map[uint64]phase0.ValidatorIndex{0: validatorIndex},
			},
		},
	}
	validatorPubkeyFromIndex := map[phase0.ValidatorIndex]string{
		validatorIndex: "pubkey",
	}

	// State persists across the two iterations, exactly like the real run.
	unfulfilledAttesterDuties := map[phase0.Slot]Set[phase0.ValidatorIndex]{}
	seenAttestations := make(map[phase0.Slot]Set[phase0.ValidatorIndex])
	m := NewMonitorMetrics(prometheus.NewRegistry())

	// First call: epoch 0 processing. The attestation for slot 32 (epoch 1) is
	// observed during epoch 0's lookahead, but epoch 1's duties are not yet
	// in the unfulfilled map. seenAttestations records the observation.
	processAttestations(epochBlocks, committeeLookup, validatorPubkeyFromIndex, unfulfilledAttesterDuties, seenAttestations, m, 0)

	if !seenAttestations[attestedSlot].Contains(validatorIndex) {
		t.Fatalf("after epoch 0: seenAttestations missing validator %v at slot %v", validatorIndex, attestedSlot)
	}
	if got := counterValue(t, m.TotalCanonicalAttestations); got != 1 {
		t.Fatalf("after epoch 0: TotalCanonicalAttestations = %v, want 1", got)
	}

	// Now epoch 1 starts: duties get added for slot 32, validator V is included.
	unfulfilledAttesterDuties[attestedSlot] = NewSet(validatorIndex)

	// Second call: epoch 1 main scan re-processes the same block. The dedup
	// hit must NOT prevent V from being removed from unfulfilled.
	processAttestations(epochBlocks, committeeLookup, validatorPubkeyFromIndex, unfulfilledAttesterDuties, seenAttestations, m, 1)

	if _, stillUnfulfilled := unfulfilledAttesterDuties[attestedSlot]; stillUnfulfilled {
		t.Fatalf("after epoch 1: slot %v still in unfulfilled — dedup must not mask the Remove (regression)", attestedSlot)
	}
	if got := counterValue(t, m.DuplicateAttestationsSkipped); got != 1 {
		t.Errorf("DuplicateAttestationsSkipped = %v, want 1 (second observation is the duplicate)", got)
	}
	if got := counterValue(t, m.TotalCanonicalAttestations); got != 1 {
		t.Errorf("TotalCanonicalAttestations = %v, want 1 (no double count)", got)
	}
}

// TestProcessAttestationsSkipsDistanceMetricForPreScanInclusion is the regression
// test for the inflated-distance bug. When the container starts fresh at epoch E
// (no prev-epoch processing), it still fetches AttesterDuties for E-1 and may see
// cross-epoch attestations from prev epoch's slots in current scan blocks. The
// "actual" first inclusion of those attestations is often in prev-epoch blocks
// that we never fetched. The naive distance computation would therefore report
// a large distance against a much later block in our scan and a missed-slot
// adjustment that treats out-of-scan blocks as missed — producing false
// "delayed attestation" warnings.
//
// Scenario (mimics the live bug):
//   - SLOTS_PER_EPOCH = 32
//   - attestedSlot = 30 (in epoch 0; earliest inclusion at slot 31)
//   - inclusionSlot = 34 (in epoch 1; epoch 1's scan window starts at slot 32)
//   - actual first inclusion (per chain) would have been at slot 31 — but we
//     never fetched that block because we're processing epoch 1
//
// processAttestations should NOT emit a delayed-attestation warning or
// CanonicalAttestationDistances sample for this attestation, because the
// earliest-possible-inclusion slot (31) is before our scan window (32).
func TestProcessAttestationsSkipsDistanceMetricForPreScanInclusion(t *testing.T) {
	const (
		validatorIndex = phase0.ValidatorIndex(500)
		committeeIndex = phase0.CommitteeIndex(0)
		attestedSlot   = phase0.Slot(30) // in epoch 0; earliest inclusion at slot 31 (also in epoch 0)
		inclusionSlot  = phase0.Slot(34) // in epoch 1; first block in epoch 1's scan
	)

	block := &electra.SignedBeaconBlock{
		Message: &electra.BeaconBlock{
			Slot: inclusionSlot,
			Body: &electra.BeaconBlockBody{
				Attestations: []*electra.Attestation{
					buildSingleValidatorAttestation(attestedSlot),
				},
			},
		},
	}
	epochBlocks := map[phase0.Slot]*electra.SignedBeaconBlock{inclusionSlot: block}

	committeeLookup := map[phase0.Slot]map[phase0.CommitteeIndex]*CommitteeInfo{
		attestedSlot: {
			committeeIndex: {
				Length:     1,
				Validators: map[uint64]phase0.ValidatorIndex{0: validatorIndex},
			},
		},
	}
	validatorPubkeyFromIndex := map[phase0.ValidatorIndex]string{
		validatorIndex: "pubkey",
	}
	unfulfilledAttesterDuties := map[phase0.Slot]Set[phase0.ValidatorIndex]{}
	seenAttestations := make(map[phase0.Slot]Set[phase0.ValidatorIndex])
	m := NewMonitorMetrics(prometheus.NewRegistry())

	// Process as epoch 1 (epoch's lowest slot = 32 > earliestInclusion = 31).
	processAttestations(epochBlocks, committeeLookup, validatorPubkeyFromIndex, unfulfilledAttesterDuties, seenAttestations, m, 1)

	if got := counterValue(t, m.TotalCanonicalAttestations); got != 0 {
		t.Fatalf("TotalCanonicalAttestations = %v, want 0 (distance metric must be skipped for pre-scan inclusion)", got)
	}
	if got := counterValue(t, m.TotalDelayedOverTolerance); got != 0 {
		t.Fatalf("TotalDelayedOverTolerance = %v, want 0 (must not emit delayed warning when actual inclusion is before scan)", got)
	}
	if got := histogramSampleCount(t, m.CanonicalAttestationDistances); got != 0 {
		t.Fatalf("CanonicalAttestationDistances samples = %v, want 0", got)
	}
	if !seenAttestations[attestedSlot].Contains(validatorIndex) {
		t.Errorf("seenAttestations must still record the observation so future iterations dedup correctly")
	}
}

// TestProcessAttestationsSkipsMalformedAttestation is the regression test for
// the unsigned-subtraction underflow. Per spec attestation.data.slot < block.slot;
// if a malformed attestation surfaces with data.slot == block.slot then
// earliestInclusionSlot (data.slot + 1) > block.slot, and the naive
// uint64 subtraction produces a huge distance recorded in metrics. The
// defensive check must log + skip instead.
func TestProcessAttestationsSkipsMalformedAttestation(t *testing.T) {
	const (
		validatorIndex = phase0.ValidatorIndex(700)
		committeeIndex = phase0.CommitteeIndex(0)
		slot           = phase0.Slot(32) // attestation Data.Slot == block.Slot
	)

	block := &electra.SignedBeaconBlock{
		Message: &electra.BeaconBlock{
			Slot: slot,
			Body: &electra.BeaconBlockBody{
				Attestations: []*electra.Attestation{
					buildSingleValidatorAttestation(slot), // data.Slot == block.Slot
				},
			},
		},
	}
	epochBlocks := map[phase0.Slot]*electra.SignedBeaconBlock{slot: block}

	committeeLookup := map[phase0.Slot]map[phase0.CommitteeIndex]*CommitteeInfo{
		slot: {
			committeeIndex: {
				Length:     1,
				Validators: map[uint64]phase0.ValidatorIndex{0: validatorIndex},
			},
		},
	}
	validatorPubkeyFromIndex := map[phase0.ValidatorIndex]string{
		validatorIndex: "pubkey",
	}
	unfulfilledAttesterDuties := map[phase0.Slot]Set[phase0.ValidatorIndex]{
		slot: NewSet(validatorIndex),
	}
	seenAttestations := make(map[phase0.Slot]Set[phase0.ValidatorIndex])
	m := NewMonitorMetrics(prometheus.NewRegistry())

	processAttestations(epochBlocks, committeeLookup, validatorPubkeyFromIndex, unfulfilledAttesterDuties, seenAttestations, m, 1)

	if got := counterValue(t, m.TotalCanonicalAttestations); got != 0 {
		t.Errorf("TotalCanonicalAttestations = %v, want 0 (malformed attestation must be skipped)", got)
	}
	if got := counterValue(t, m.TotalDelayedOverTolerance); got != 0 {
		t.Errorf("TotalDelayedOverTolerance = %v, want 0 (must not emit delayed warning on underflow)", got)
	}
	if got := histogramSampleCount(t, m.CanonicalAttestationDistances); got != 0 {
		t.Errorf("CanonicalAttestationDistances samples = %v, want 0 (no underflow record)", got)
	}
}

// TestProcessAttestationsDedupsWithinCall confirms the in-call branch still fires
// for a block that lists the same validator/slot in two attestations
// (rare but possible; the pre-existing within-call dedup must keep working).
func TestProcessAttestationsDedupsWithinCall(t *testing.T) {
	const (
		validatorIndex = phase0.ValidatorIndex(100)
		committeeIndex = phase0.CommitteeIndex(0)
		attestedSlot   = phase0.Slot(31)
		inclusionSlot  = phase0.Slot(32)
	)

	block := &electra.SignedBeaconBlock{
		Message: &electra.BeaconBlock{
			Slot: inclusionSlot,
			Body: &electra.BeaconBlockBody{
				Attestations: []*electra.Attestation{
					buildSingleValidatorAttestation(attestedSlot),
					buildSingleValidatorAttestation(attestedSlot),
				},
			},
		},
	}
	epochBlocks := map[phase0.Slot]*electra.SignedBeaconBlock{inclusionSlot: block}

	committeeLookup := map[phase0.Slot]map[phase0.CommitteeIndex]*CommitteeInfo{
		attestedSlot: {
			committeeIndex: {
				Length:     1,
				Validators: map[uint64]phase0.ValidatorIndex{0: validatorIndex},
			},
		},
	}
	validatorPubkeyFromIndex := map[phase0.ValidatorIndex]string{
		validatorIndex: "pubkey",
	}
	unfulfilledAttesterDuties := map[phase0.Slot]Set[phase0.ValidatorIndex]{
		attestedSlot: NewSet(validatorIndex),
	}
	seenAttestations := make(map[phase0.Slot]Set[phase0.ValidatorIndex])

	m := NewMonitorMetrics(prometheus.NewRegistry())

	processAttestations(epochBlocks, committeeLookup, validatorPubkeyFromIndex, unfulfilledAttesterDuties, seenAttestations, m, 0)

	if got := counterValue(t, m.TotalCanonicalAttestations); got != 1 {
		t.Fatalf("TotalCanonicalAttestations = %v, want 1", got)
	}
	if got := counterValue(t, m.DuplicateAttestationsSkipped); got != 1 {
		t.Fatalf("DuplicateAttestationsSkipped = %v, want 1", got)
	}
}
