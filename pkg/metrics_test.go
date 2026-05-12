package pkg

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

// TestNewMonitorMetrics_FreshRegistry — happy path: with an empty registry,
// every collector registers successfully and Inc/Set work end-to-end.
func TestNewMonitorMetrics_FreshRegistry(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewMonitorMetrics(reg)

	m.TotalCanonicalAttestations.Inc()
	// Round-trip via the registry to verify the collector is actually
	// attached: Gather scrapes only collectors registered with `reg`.
	mf, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	found := false
	for _, family := range mf {
		if family.GetName() == "ETH2_totalServedAttestations" {
			found = true
			break
		}
	}
	if !found {
		t.Error("TotalCanonicalAttestations (ETH2_totalServedAttestations) not visible in Gather; registration silently failed")
	}
}

// TestNewMonitorMetrics_DuplicateRegistration — calling NewMonitorMetrics
// twice with the same registry triggers AlreadyRegisteredError for every
// collector. That branch must be silent (no panic, no spurious log) so
// integration tests can re-call without noise.
func TestNewMonitorMetrics_DuplicateRegistration(t *testing.T) {
	reg := prometheus.NewRegistry()
	_ = NewMonitorMetrics(reg)
	// Second call: every Register returns AlreadyRegisteredError; the
	// register helper must short-circuit on that without panicking.
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("NewMonitorMetrics panicked on duplicate registration: %v", r)
		}
	}()
	_ = NewMonitorMetrics(reg)
}

// TestNewMonitorMetrics_TypeCollisionLogged — register a different-typed
// collector under the same name BEFORE creating MonitorMetrics. The second
// Register call returns a non-AlreadyRegistered error (it's a real conflict).
// We can't easily intercept zerolog output here, but we CAN verify the
// function still returns a non-nil struct and doesn't panic, so callers
// see a degraded-but-functional MonitorMetrics rather than a crash.
func TestNewMonitorMetrics_TypeCollisionDoesNotPanic(t *testing.T) {
	reg := prometheus.NewRegistry()
	// Pre-register a Gauge under the same name as our Counter
	// (TotalMissedProposals). The library treats same-name-different-type
	// as a non-AlreadyRegistered error.
	conflict := prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "ETH2",
		Name:      "totalMissedProposals",
		Help:      "intentional conflict",
	})
	if err := reg.Register(conflict); err != nil {
		t.Fatalf("seed Register failed: %v", err)
	}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("NewMonitorMetrics panicked on type collision: %v", r)
		}
	}()
	m := NewMonitorMetrics(reg)
	if m == nil {
		t.Fatal("NewMonitorMetrics returned nil on collision; degraded-but-functional struct expected")
	}
}
