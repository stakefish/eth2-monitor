package pkg

import (
	"testing"

	"github.com/OffchainLabs/go-bitfield"
	v1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec/electra"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// counterValue extracts the current value of a Prometheus counter.
func counterValue(t *testing.T, c prometheus.Counter) float64 {
	t.Helper()
	var metric dto.Metric
	if err := c.Write(&metric); err != nil {
		t.Fatalf("counter.Write: %v", err)
	}
	return metric.GetCounter().GetValue()
}

// histogramSampleCount extracts the total sample count from a Prometheus histogram.
func histogramSampleCount(t *testing.T, h prometheus.Histogram) uint64 {
	t.Helper()
	var metric dto.Metric
	if err := h.Write(&metric); err != nil {
		t.Fatalf("histogram.Write: %v", err)
	}
	return metric.GetHistogram().GetSampleCount()
}

// buildSingleValidatorAttestation creates a minimal Electra attestation where exactly
// one validator (at position 0 in committee 0) attested for attestedSlot.
func buildSingleValidatorAttestation(attestedSlot phase0.Slot) *electra.Attestation {
	aggBits := bitfield.NewBitlist(1)
	aggBits.SetBitAt(0, true)

	committeeBits := bitfield.NewBitvector64()
	committeeBits.SetBitAt(0, true)

	return &electra.Attestation{
		AggregationBits: aggBits,
		Data:            &phase0.AttestationData{Slot: attestedSlot},
		CommitteeBits:   committeeBits,
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
