package pkg

import (
	"testing"

	"github.com/OffchainLabs/go-bitfield"
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
