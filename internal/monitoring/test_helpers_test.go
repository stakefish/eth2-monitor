package monitoring

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

// gaugeValue extracts the current value of a Prometheus gauge.
func gaugeValue(t *testing.T, g prometheus.Gauge) float64 {
	t.Helper()
	var metric dto.Metric
	if err := g.Write(&metric); err != nil {
		t.Fatalf("gauge.Write: %v", err)
	}
	return metric.GetGauge().GetValue()
}

// counterVecTotal sums the value of every child counter in a CounterVec.
// Lets existing assertions that only care about "did the total tick?" stay
// validator-agnostic after the per-validator labels were added.
func counterVecTotal(t *testing.T, vec *prometheus.CounterVec) float64 {
	t.Helper()
	ch := make(chan prometheus.Metric, 1024)
	go func() {
		vec.Collect(ch)
		close(ch)
	}()
	var total float64
	for c := range ch {
		var m dto.Metric
		if err := c.Write(&m); err != nil {
			t.Fatalf("CounterVec child Write: %v", err)
		}
		total += m.GetCounter().GetValue()
	}
	return total
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
