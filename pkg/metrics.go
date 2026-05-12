package pkg

import (
	"errors"

	"eth2-monitor/beaconchain"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog/log"
)

// MonitorMetrics holds all Prometheus metrics for the attestation/proposal monitor.
// Pass prometheus.DefaultRegisterer for production, prometheus.NewRegistry() for tests.
type MonitorMetrics struct {
	Epoch                         prometheus.Gauge
	TotalCanonicalAttestations    prometheus.Counter
	TotalDelayedOverTolerance     prometheus.Counter
	TotalMissedAttestations       prometheus.Counter
	CanonicalAttestationDistances prometheus.Histogram
	TotalMissedProposals          prometheus.Counter
	TotalCanonicalProposals       prometheus.Counter
	TotalProposedEmptyBlocks      prometheus.Counter
	TotalVanillaBlocks            prometheus.Counter
	TotalMissingBidTraces         prometheus.Counter
	LastProposedEmptyBlockSlot    prometheus.Gauge
	LastMissedProposalSlot        prometheus.Gauge
	LastMissedProposalValidator   prometheus.Gauge
	LastVanillaBlockSlot          prometheus.Gauge
	LastVanillaBlockValidator     prometheus.Gauge
	// New metrics from THE_FIX:
	DuplicateAttestationsSkipped prometheus.Counter
	RawAttestationDistances      prometheus.Histogram
	MissedSlotsInEpoch           prometheus.Gauge
	CrossEpochAttestations       prometheus.Counter
	// Beacon API request instrumentation
	BeaconAPIRequests *prometheus.CounterVec
	BeaconAPIDuration *prometheus.HistogramVec
}

// BeaconRequestMetrics returns the subset of metrics consumed by the
// beaconchain HTTP transport.
func (m *MonitorMetrics) BeaconRequestMetrics() *beaconchain.RequestMetrics {
	return &beaconchain.RequestMetrics{
		Requests: m.BeaconAPIRequests,
		Duration: m.BeaconAPIDuration,
	}
}

// NewMonitorMetrics creates and registers every metric on reg.
//
// Registration error handling:
//   - AlreadyRegisteredError is silent (integration tests re-call with a
//     shared registry; production calls NewMonitorMetrics exactly once).
//   - Any other registration failure is logged at ERROR — the metric
//     is still placed on the returned struct but won't appear in
//     /metrics scrapes; operators see the log so they can diagnose.
//
// Pass prometheus.DefaultRegisterer in production, prometheus.NewRegistry()
// in tests for isolation.
func NewMonitorMetrics(reg prometheus.Registerer) *MonitorMetrics {
	m := &MonitorMetrics{
		Epoch: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "ETH2",
			Name:      "epoch",
			Help:      "Most recently processed epoch (the just-ended SSE-emitted epoch, typically head-1; not the justified epoch despite the historical metric name)",
		}),
		LastProposedEmptyBlockSlot: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "ETH2",
			Name:      "lastProposedEmptyBlockSlot",
			Help:      "Slot of the last proposed block with no execution-layer payload of value to the proposer (no EL transactions, no blobs, no post-Pectra exec requests)",
		}),
		TotalMissedProposals: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "ETH2",
			Name:      "totalMissedProposals",
			Help:      "Proposals missed since monitoring started",
		}),
		LastMissedProposalSlot: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "ETH2",
			Name:      "lastMissedProposalSlot",
			Help:      "Slot of the last missed proposal",
		}),
		LastMissedProposalValidator: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "ETH2",
			Name:      "lastMissedProposalValidatorIndex",
			Help:      "Validator index of the last missed proposal",
		}),
		TotalCanonicalProposals: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "ETH2",
			Name:      "totalServedProposals",
			Help:      "Canonical proposals since monitoring started",
		}),
		TotalMissedAttestations: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "ETH2",
			Name:      "totalMissedAttestations",
			Help:      "Attestations missed since monitoring started",
		}),
		TotalProposedEmptyBlocks: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "ETH2",
			Name:      "totalProposedEmptyBlocks",
			Help:      "Proposed blocks with no execution-layer payload of value to the proposer (see LastProposedEmptyBlockSlot for the full definition)",
		}),
		TotalVanillaBlocks: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "ETH2",
			Name:      "totalVanillaBlocks",
			Help:      "Proposed blocks whose execution_block_hash did not match any tracked MEV relay bid (hash-mismatch case only; see totalMissingBidTraces for the no-bid case)",
		}),
		TotalMissingBidTraces: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "ETH2",
			Name:      "totalMissingBidTraces",
			Help:      "Proposed blocks for which no MEV bid trace was found across configured relays — could be a truly vanilla block (validator built locally) or a relay-side failure",
		}),
		LastVanillaBlockSlot: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "ETH2",
			Name:      "lastVanillaBlockSlot",
			Help:      "Slot of the last proposed vanilla block",
		}),
		LastVanillaBlockValidator: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "ETH2",
			Name:      "lastVanillaBlockValidator",
			Help:      "Index of the last validator that proposed a vanilla block",
		}),
		TotalCanonicalAttestations: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "ETH2",
			// TODO(deni): Rename to totalCanonicalAttestations
			Name: "totalServedAttestations",
			Help: "Canonical attestations since monitoring started",
		}),
		TotalDelayedOverTolerance: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "ETH2",
			Name:      "totalDelayedAttestationsOverTolerance",
			Help:      "Attestations whose shifted inclusion distance exceeds 2 (spec-distance > 3 in Attestant's convention) after missed-slot adjustment",
		}),
		// https://www.attestant.io/posts/defining-attestation-effectiveness/
		CanonicalAttestationDistances: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: "ETH2",
			Name:      "canonicalAttestationDistances",
			Help:      "Histogram of canonical attestation distances after missed-slot adjustment. Distance is computed as (block.slot - attestedSlot - 1), so 0 = optimal (included in attestedSlot+1); Attestant's spec-distance is this + 1.",
			Buckets:   prometheus.LinearBuckets(1, 1, 32),
		}),
		// New metrics for bug fixes
		DuplicateAttestationsSkipped: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "ETH2",
			Name:      "duplicateAttestationsSkipped",
			Help:      "Attestations skipped due to duplicate (validator, slot) dedup",
		}),
		RawAttestationDistances: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: "ETH2",
			Name:      "rawAttestationDistances",
			Help:      "Histogram of raw attestation distances before the missed-slot adjustment. Same numbering convention as canonicalAttestationDistances (0 = optimal).",
			Buckets:   prometheus.LinearBuckets(1, 1, 32),
		}),
		MissedSlotsInEpoch: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "ETH2",
			Name:      "missedSlotsInEpoch",
			Help:      "Missed slots in the most recently processed epoch (updated once per non-skip iteration; stays at the previous value during ctx-cancel, epoch=0, or soft-skip iterations)",
		}),
		CrossEpochAttestations: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "ETH2",
			Name:      "crossEpochAttestations",
			Help:      "Attestations included in a block from a different epoch than the attested slot",
		}),
		BeaconAPIRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "ETH2",
			Name:      "beaconAPIRequestsTotal",
			Help:      "Beacon API requests grouped by endpoint, HTTP method, and status class",
		}, []string{"endpoint", "method", "status_class"}),
		BeaconAPIDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: "ETH2",
			Name:      "beaconAPIRequestDurationSeconds",
			Help:      "Beacon API request latency in seconds",
			Buckets:   prometheus.DefBuckets,
		}, []string{"endpoint", "method"}),
	}

	// Use Register (not MustRegister) so a name collision doesn't crash
	// the binary at startup; the AlreadyRegisteredError case is expected
	// in tests that share registries. Any *other* registration error is a
	// real bug (invalid metric shape, name conflict with a different-typed
	// collector, etc.) and must surface — silently dropping it would mean
	// the metric disappears from /metrics with no warning to operators.
	register := func(c prometheus.Collector) {
		err := reg.Register(c)
		if err == nil {
			return
		}
		var already prometheus.AlreadyRegisteredError
		if errors.As(err, &already) {
			return
		}
		log.Error().Err(err).Msgf("NewMonitorMetrics: failed to register collector %T", c)
	}
	for _, c := range []prometheus.Collector{
		m.Epoch,
		m.LastProposedEmptyBlockSlot,
		m.TotalMissedProposals,
		m.LastMissedProposalSlot,
		m.LastMissedProposalValidator,
		m.TotalCanonicalProposals,
		m.TotalMissedAttestations,
		m.TotalProposedEmptyBlocks,
		m.TotalVanillaBlocks,
		m.TotalMissingBidTraces,
		m.LastVanillaBlockSlot,
		m.LastVanillaBlockValidator,
		m.TotalCanonicalAttestations,
		m.TotalDelayedOverTolerance,
		m.CanonicalAttestationDistances,
		m.DuplicateAttestationsSkipped,
		m.RawAttestationDistances,
		m.MissedSlotsInEpoch,
		m.CrossEpochAttestations,
		m.BeaconAPIRequests,
		m.BeaconAPIDuration,
	} {
		register(c)
	}

	return m
}
