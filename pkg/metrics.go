package pkg

import (
	"eth2-monitor/beaconchain"

	"github.com/prometheus/client_golang/prometheus"
)

// MonitorMetrics holds all Prometheus metrics for the attestation/proposal monitor.
// Pass prometheus.DefaultRegisterer for production, prometheus.NewRegistry() for tests.
type MonitorMetrics struct {
	Epoch                          prometheus.Gauge
	TotalCanonicalAttestations     prometheus.Counter
	TotalDelayedOverTolerance      prometheus.Counter
	TotalMissedAttestations        prometheus.Counter
	CanonicalAttestationDistances  prometheus.Histogram
	TotalMissedProposals           prometheus.Counter
	TotalCanonicalProposals        prometheus.Counter
	TotalProposedEmptyBlocks       prometheus.Counter
	TotalVanillaBlocks             prometheus.Counter
	LastProposedEmptyBlockSlot     prometheus.Gauge
	LastMissedProposalSlot         prometheus.Gauge
	LastMissedProposalValidator    prometheus.Gauge
	LastVanillaBlockSlot           prometheus.Gauge
	LastVanillaBlockValidator      prometheus.Gauge
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

// NewMonitorMetrics creates and registers all metrics with the given registerer.
func NewMonitorMetrics(reg prometheus.Registerer) *MonitorMetrics {
	m := &MonitorMetrics{
		Epoch: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "ETH2",
			Name:      "epoch",
			Help:      "Current justified epoch",
		}),
		LastProposedEmptyBlockSlot: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "ETH2",
			Name:      "lastProposedEmptyBlockSlot",
			Help:      "Slot of the last proposed block containing no transactions",
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
			Help:      "Proposed blocks containing no transactions",
		}),
		TotalVanillaBlocks: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "ETH2",
			Name:      "totalVanillaBlocks",
			Help:      "Proposed blocks not matching those built by MEV relays",
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
			Help:      "Attestation delayed over tolerance distance setting since monitoring started",
		}),
		// https://www.attestant.io/posts/defining-attestation-effectiveness/
		CanonicalAttestationDistances: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: "ETH2",
			Name:      "canonicalAttestationDistances",
			Help:      "Histogram of canonical attestation distances.",
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
			Help:      "Histogram of raw attestation distances before dedup.",
			Buckets:   prometheus.LinearBuckets(1, 1, 32),
		}),
		MissedSlotsInEpoch: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "ETH2",
			Name:      "missedSlotsInEpoch",
			Help:      "Number of missed slots in the current epoch",
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

	// Use Register (not MustRegister) to allow re-registration in integration tests.
	// In production, this only runs once. In tests, the default registry may already have metrics.
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
		_ = reg.Register(c)
	}

	return m
}
