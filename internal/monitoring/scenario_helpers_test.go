package monitoring

// Shared helpers for the per-scenario fixture-backed integration tests
// (scenario_*_test.go). Each scenario test stands up the standard
// fixture server, builds a real BeaconChain wired to an isolated
// metrics registry, drives the relevant detection helper, and asserts
// on BOTH the monitoring failure metric AND the BeaconAPI request
// metric labels.
//
// Why two metric layers: when production reports a missed proposal,
// the underlying signal is a 4xx on /eth/v2/beacon/blocks/{block_id}.
// If the instrumenting transport regresses (endpoint-template breakage,
// status_class miscategorization), the monitoring metric still fires
// but the operator-visible "which beacon endpoint is slow / erroring"
// signal silently disappears. The scenario tests guard against both
// regressions in one pass.

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stakefish/eth2-monitor/internal/beaconchain"
	"github.com/stakefish/eth2-monitor/internal/spec"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/rs/zerolog"
)

// scenarioFixturesPresent returns true when the scenario's meta.json
// exists under the active chain directory. Tests Skip when false so a
// not-yet-captured scenario doesn't fail the suite — refreshing
// fixtures is an operator action, not a test prerequisite.
func scenarioFixturesPresent(scenario string) bool {
	_, err := os.Stat(filepath.Join(beaconTestdataRel, "beacon", defaultBeaconChain, scenario, "meta.json"))
	return err == nil
}

// quietScenarioLogging raises zerolog above the warn-spam emitted by
// processAttestations when it encounters committees-coverage gaps
// (expected on slot-filtered fixtures — see CLAUDE.md "Test Fixtures").
// Reverted on t.Cleanup so the next test gets the baseline level.
func quietScenarioLogging(t *testing.T) {
	t.Helper()
	prev := zerolog.GlobalLevel()
	zerolog.SetGlobalLevel(zerolog.ErrorLevel)
	t.Cleanup(func() { zerolog.SetGlobalLevel(prev) })
}

// scenarioRig bundles the everything a scenario test needs: a real
// BeaconChain pointed at the fixture server, the shared isolated
// metrics registry, and the MonitorMetrics that owns both the failure
// counters and the BeaconAPI request-metric vectors.
type scenarioRig struct {
	server  fixtureServerKind
	bc      *beaconchain.BeaconChain
	metrics *MonitorMetrics
	meta    beaconFixtureMeta
}

// fixtureServerKind narrows the surface of httptest.Server we use to
// just the URL field, which is all a scenario test needs. Keeps the
// helper independent of whether the server is built directly by
// fixtureServer() or composed inline (e.g. SSE replay).
type fixtureServerKind interface {
	URL() string
}

type httpTestServerURL struct{ url string }

func (h httpTestServerURL) URL() string { return h.url }

// newScenarioRig wires up the standard scenario-test infrastructure.
// fixturegen captures every block it observed during the wait as
// block_<slot>.json, so we register routes for ALL captured slots —
// the orchestrator can then fetch any block in the captured epoch
// (not just the canonical anchor) and the test exercises the full
// detection path including the orchestrator's per-slot scan.
func newScenarioRig(t *testing.T, scenario string) *scenarioRig {
	t.Helper()
	if !scenarioFixturesPresent(scenario) {
		t.Skipf("scenario %q fixtures not captured — run `make refresh-scenario SCENARIO=%s`", scenario, scenario)
	}
	quietGoEth2Client(t)
	quietScenarioLogging(t)

	meta := loadBeaconMeta(t, scenario)
	if meta.TestEpoch == 0 || meta.CanonicalSlot == 0 {
		t.Fatalf("scenario %q meta.json missing TestEpoch or CanonicalSlot — run `make refresh-scenario SCENARIO=%s`", scenario, scenario)
	}

	routes := scenarioRoutes(t, scenario, meta)
	server := fixtureServer(t, scenario, routes)

	// Isolated registry: every scenario test gets its own MonitorMetrics
	// so cross-test counter pollution can't mask a regression.
	reg := prometheus.NewRegistry()
	metrics := NewMonitorMetrics(reg)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	bc, err := beaconchain.New(ctx, server.URL, 10*time.Second, metrics.BeaconRequestMetrics())
	if err != nil {
		t.Fatalf("BeaconChain.New(%s): %v", server.URL, err)
	}

	return &scenarioRig{
		server:  httpTestServerURL{url: server.URL},
		bc:      bc,
		metrics: metrics,
		meta:    meta,
	}
}

// scenarioRoutes builds the route set for a given scenario. Always
// registers the standard per-epoch endpoints (finality, validators,
// duties, committees), the canonical block, plus one route per
// captured block_<slot>.json file (so the orchestrator can fetch the
// full epoch without 404 noise for slots fixturegen happened to
// capture). For missed_proposal it additionally registers a 404 route
// for the missed slot.
func scenarioRoutes(t *testing.T, scenario string, meta beaconFixtureMeta) []fixtureRoute {
	t.Helper()
	epoch := phase0.Epoch(meta.TestEpoch)
	routes := []fixtureRoute{
		{Path: "/eth/v1/beacon/states/head/finality_checkpoints", Status: http.StatusOK, File: "finality_checkpoints.json"},
		// ResolveValidatorKeys POSTs against /eth/v1/beacon/states/{slot}/validators.
		// Production uses State=fmt.Sprintf("%d", EpochLowestSlot(epoch)).
		{Path: fmt.Sprintf("/eth/v1/beacon/states/%d/validators", spec.EpochLowestSlot(epoch)), Status: http.StatusOK, File: "validators_indices_0_1_2.json"},
		// fixturegen captures with State="head" so the head route gets the
		// same body — register both forms for tests that don't go through
		// the epoch-resolution path.
		{Path: "/eth/v1/beacon/states/head/validators", Status: http.StatusOK, File: "validators_indices_0_1_2.json"},
		{Path: fmt.Sprintf("/eth/v1/validator/duties/proposer/%d", epoch), Status: http.StatusOK, File: "proposer_duties.json"},
		{Path: fmt.Sprintf("/eth/v1/validator/duties/attester/%d", epoch), Status: http.StatusOK, File: "attester_duties.json"},
		// Committees: production passes State="head" with epoch/slot query
		// params. fixturegen captures the slot-filtered response.
		{Path: "/eth/v1/beacon/states/head/committees", Status: http.StatusOK, File: "committees.json"},
		// Canonical block (mirror of block_<CanonicalSlot>.json).
		{Path: fmt.Sprintf("/eth/v2/beacon/blocks/%d", meta.CanonicalSlot), Status: http.StatusOK, File: "block_canonical.json"},
	}
	// Per-slot captures: the head-stream-based fixturegen records every
	// block it observed during the scenario wait as block_<slot>.json.
	// Register each so the orchestrator can fetch real blocks at those
	// slots rather than the synthetic 404 stand-ins used in earlier tests.
	// Skip the missed slot (handled below) and the canonical slot (already
	// registered above) to avoid duplicate route registration which
	// http.ServeMux panics on.
	for _, slot := range meta.CapturedSlots {
		if slot == meta.CanonicalSlot {
			continue
		}
		if meta.HasMissed && slot == meta.MissedSlot {
			continue
		}
		routes = append(routes, fixtureRoute{
			Path:   fmt.Sprintf("/eth/v2/beacon/blocks/%d", slot),
			Status: http.StatusOK,
			File:   fmt.Sprintf("block_%d.json", slot),
		})
	}
	// missed_proposal carries a 404 envelope captured at the gap slot.
	if meta.HasMissed && meta.MissedSlot != 0 {
		routes = append(routes, fixtureRoute{
			Path:   fmt.Sprintf("/eth/v2/beacon/blocks/%d", meta.MissedSlot),
			Status: http.StatusNotFound,
			File:   "block_missed.json",
		})
	}
	// cross_epoch_attestation needs a prev-epoch block for the
	// orchestrator's cross-epoch lookahead window.
	if scenario == "cross_epoch_attestation" && meta.PrevCanonicalSlot != 0 {
		routes = append(routes, fixtureRoute{
			Path:   fmt.Sprintf("/eth/v2/beacon/blocks/%d", meta.PrevCanonicalSlot),
			Status: http.StatusOK,
			File:   "block_prev.json",
		})
	}
	return routes
}

// beaconAPILabelKey identifies one (endpoint, method, status_class)
// tuple. Used to snapshot + delta-assert across a test action.
type beaconAPILabelKey struct {
	endpoint    string
	method      string
	statusClass string
}

// beaconAPISnapshot reads the current value of the named label tuple
// (counter + histogram sample count). Returns a snapshot so the test
// can assert the DELTA caused by a specific action, not the absolute
// count (which can be polluted by go-eth2-client's startup probes or
// by Validators() calls made during BeaconChain.New).
type beaconAPISnapshot struct {
	counter   float64
	histogram uint64
}

func snapshotBeaconAPI(t *testing.T, m *MonitorMetrics, k beaconAPILabelKey) beaconAPISnapshot {
	t.Helper()
	c, err := m.BeaconAPIRequests.GetMetricWithLabelValues(k.endpoint, k.method, k.statusClass)
	if err != nil {
		t.Fatalf("GetMetricWithLabelValues(counter, %v): %v", k, err)
	}
	var cm dto.Metric
	if err := c.Write(&cm); err != nil {
		t.Fatalf("counter.Write: %v", err)
	}
	h, err := m.BeaconAPIDuration.GetMetricWithLabelValues(k.endpoint, k.method)
	if err != nil {
		t.Fatalf("GetMetricWithLabelValues(histogram, %v): %v", k, err)
	}
	hist, ok := h.(prometheus.Histogram)
	if !ok {
		t.Fatalf("histogram at %v is not a Histogram: %T", k, h)
	}
	var hm dto.Metric
	if err := hist.Write(&hm); err != nil {
		t.Fatalf("histogram.Write: %v", err)
	}
	return beaconAPISnapshot{
		counter:   cm.GetCounter().GetValue(),
		histogram: hm.GetHistogram().GetSampleCount(),
	}
}

// assertBeaconAPIDelta asserts that the (endpoint, method, status_class)
// counter increased by at least delta between before and now, and that
// the (endpoint, method) histogram sample count increased by at least
// delta as well. Failure messages name the specific label tuple so a
// regression is diagnosable from CI output without re-running the test.
func assertBeaconAPIDelta(t *testing.T, m *MonitorMetrics, before beaconAPISnapshot, k beaconAPILabelKey, delta float64) {
	t.Helper()
	now := snapshotBeaconAPI(t, m, k)
	if got := now.counter - before.counter; got < delta {
		t.Errorf("BeaconAPI counter[%s %s %s] increased by %g, want >= %g (before=%g, after=%g)",
			k.endpoint, k.method, k.statusClass, got, delta, before.counter, now.counter)
	}
	if got := float64(now.histogram) - float64(before.histogram); got < delta {
		t.Errorf("BeaconAPI histogram[%s %s] samples increased by %g, want >= %g (before=%d, after=%d)",
			k.endpoint, k.method, got, delta, before.histogram, now.histogram)
	}
}

// requireMonitorCounter asserts a monitor counter equals the expected
// value. Used for failure metrics where we know exactly how many times
// the detection path should fire in a single test action.
func requireMonitorCounter(t *testing.T, c prometheus.Counter, want float64, label string) {
	t.Helper()
	if got := counterValue(t, c); got != want {
		t.Errorf("%s = %v, want %v", label, got, want)
	}
}

// assertNoOtherLabel walks the BeaconAPI requests counter looking for
// any sample with endpoint="other" and value > 0. The "other" template
// is the catch-all for URL paths endpointTemplate didn't recognise —
// in production traffic, hitting it means an endpoint URL changed and
// the instrumenting transport silently lost its labeling. The live
// e2e test (metrics_e2e_test.go:451) carries the same assertion;
// porting it here gives fixture-backed coverage that runs in default
// `go test` without the e2e tag.
func assertNoOtherLabel(t *testing.T, m *MonitorMetrics) {
	t.Helper()
	ch := make(chan prometheus.Metric, 64)
	go func() {
		m.BeaconAPIRequests.Collect(ch)
		close(ch)
	}()
	for metric := range ch {
		var dm dto.Metric
		if err := metric.Write(&dm); err != nil {
			t.Fatalf("collect Write: %v", err)
		}
		labels := map[string]string{}
		for _, lp := range dm.GetLabel() {
			labels[lp.GetName()] = lp.GetValue()
		}
		if labels["endpoint"] == "other" && dm.GetCounter().GetValue() > 0 {
			t.Errorf("BeaconAPI counter with endpoint=other (method=%s status_class=%s value=%g) — endpointTemplate failed for some real beacon URL",
				labels["method"], labels["status_class"], dm.GetCounter().GetValue())
		}
	}
}
