//go:build e2e

package beaconchain

// Tests in this file hit a real beacon node and are gated by the `e2e`
// build tag. They feed live on-chain HTTP responses through the
// instrumentingTransport to verify that the two detection helpers in
// metrics.go (endpointTemplate and statusClass) emit the right
// Prometheus labels for every endpoint the monitor talks to in
// production. The synthetic table-driven tests in metrics_test.go cover
// pathological inputs (missing /eth/v prefix, the 5xx branch, transport
// errors) — this file covers the happy and 404 paths against an actual
// beacon chain so a future endpoint rename or routing quirk surfaces
// here rather than as silently-dropped metrics in production.
//
// Run via `make test-e2e`.

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/stakefish/eth2-monitor/internal/spec"

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/api"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/rs/zerolog"
)

// liveRequestMetrics builds a fresh *RequestMetrics backed by an isolated
// registry so this test never collides with anything else and so its
// assertions only see traffic generated inside the test.
func liveRequestMetrics(t *testing.T) *RequestMetrics {
	t.Helper()
	reg := prometheus.NewRegistry()
	requests := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "beacon_api_requests_total",
	}, []string{"endpoint", "method", "status_class"})
	duration := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "beacon_api_request_duration_seconds",
		Buckets: prometheus.DefBuckets,
	}, []string{"endpoint", "method"})
	reg.MustRegister(requests, duration)
	return &RequestMetrics{Requests: requests, Duration: duration}
}

func counterValueAt(t *testing.T, vec *prometheus.CounterVec, endpoint, method, statusClass string) float64 {
	t.Helper()
	c, err := vec.GetMetricWithLabelValues(endpoint, method, statusClass)
	if err != nil {
		t.Fatalf("GetMetricWithLabelValues(%q,%q,%q): %v", endpoint, method, statusClass, err)
	}
	var m dto.Metric
	if err := c.Write(&m); err != nil {
		t.Fatalf("counter Write: %v", err)
	}
	return m.GetCounter().GetValue()
}

func histogramSamplesAt(t *testing.T, vec *prometheus.HistogramVec, endpoint, method string) uint64 {
	t.Helper()
	o, err := vec.GetMetricWithLabelValues(endpoint, method)
	if err != nil {
		t.Fatalf("GetMetricWithLabelValues(%q,%q): %v", endpoint, method, err)
	}
	h, ok := o.(prometheus.Histogram)
	if !ok {
		t.Fatalf("observer at (%q,%q) is not a histogram: %T", endpoint, method, o)
	}
	var m dto.Metric
	if err := h.Write(&m); err != nil {
		t.Fatalf("histogram Write: %v", err)
	}
	return m.GetHistogram().GetSampleCount()
}

// expectAtLeast asserts that the (endpoint, method, status_class) counter
// strictly increased by at least `delta` between `before` and the current
// reading, and that the (endpoint, method) histogram sample count
// strictly increased by at least `delta` as well. Using deltas (rather
// than absolutes) makes the assertions robust to background traffic from
// go-eth2-client's startup probes or any prior subtest that already hit
// the same endpoint.
func expectAtLeast(t *testing.T, m *RequestMetrics, before snapshot, endpoint, method, statusClass string, delta float64) {
	t.Helper()
	got := counterValueAt(t, m.Requests, endpoint, method, statusClass)
	prev := before.counter[snapKey{endpoint, method, statusClass}]
	if got-prev < delta {
		t.Errorf("counter[%s %s %s] increased by %g, want >= %g (before=%g, after=%g)",
			endpoint, method, statusClass, got-prev, delta, prev, got)
	}
	gotH := histogramSamplesAt(t, m.Duration, endpoint, method)
	prevH := before.histogram[snapKey{endpoint, method, ""}]
	if float64(gotH)-float64(prevH) < delta {
		t.Errorf("histogram[%s %s] samples increased by %d, want >= %g (before=%d, after=%d)",
			endpoint, method, gotH-prevH, delta, prevH, gotH)
	}
}

type snapKey struct{ endpoint, method, statusClass string }

type snapshot struct {
	counter   map[snapKey]float64
	histogram map[snapKey]uint64
}

// snap reads the current value of a single (endpoint, method, statusClass)
// triple plus the (endpoint, method) histogram. Returning a snapshot lets
// each subtest assert the *delta* it caused, not the absolute count which
// can be polluted by go-eth2-client startup probes.
func snap(t *testing.T, m *RequestMetrics, endpoint, method, statusClass string) snapshot {
	t.Helper()
	return snapshot{
		counter:   map[snapKey]float64{{endpoint, method, statusClass}: counterValueAt(t, m.Requests, endpoint, method, statusClass)},
		histogram: map[snapKey]uint64{{endpoint, method, ""}: histogramSamplesAt(t, m.Duration, endpoint, method)},
	}
}

func TestRequestMetricsAgainstLiveBeacon(t *testing.T) {
	// Suppress trace logging — go-eth2-client logs every URL (including
	// any token in the path) at trace level. See the equivalent block in
	// service_e2e_test.go for the longer rationale.
	prevLevel := zerolog.GlobalLevel()
	zerolog.SetGlobalLevel(zerolog.WarnLevel)
	t.Cleanup(func() { zerolog.SetGlobalLevel(prevLevel) })

	endpoint := loadE2EEndpoint(t)
	host := endpointHost(endpoint)
	t.Logf("e2e: beacon endpoint host=%s", host)

	ctx, cancel := context.WithTimeout(context.Background(), e2eTestTimeout)
	defer cancel()

	metrics := liveRequestMetrics(t)
	bc, err := New(ctx, endpoint, e2eReqTimeout, metrics)
	if err != nil {
		t.Fatalf("New(host=%s): %v", host, err)
	}

	// Anchor every subtest to a finalized epoch to avoid racing the head.
	finProvider, ok := bc.Service().(eth2client.FinalityProvider)
	if !ok {
		t.Fatalf("service does not implement FinalityProvider")
	}

	t.Run("finality_checkpoints_2xx", func(t *testing.T) {
		const ep = "/eth/v1/beacon/states/{state_id}/finality_checkpoints"
		before := snap(t, metrics, ep, http.MethodGet, "2xx")
		subCtx, c := context.WithTimeout(ctx, e2eReqTimeout)
		defer c()
		resp, err := finProvider.Finality(subCtx, &api.FinalityOpts{State: "head"})
		if err != nil {
			t.Fatalf("Finality: %v", err)
		}
		if resp == nil || resp.Data == nil || resp.Data.Finalized == nil {
			t.Fatal("Finality: nil response data")
		}
		expectAtLeast(t, metrics, before, ep, http.MethodGet, "2xx", 1)
	})

	// All remaining subtests need a stable test epoch and a known canonical
	// block + a known missed slot inside that epoch.
	finCtx, finCancel := context.WithTimeout(ctx, e2eReqTimeout)
	defer finCancel()
	finResp, err := finProvider.Finality(finCtx, &api.FinalityOpts{State: "head"})
	if err != nil {
		t.Fatalf("Finality: %v", err)
	}
	if finResp.Data.Finalized.Epoch < 2 {
		t.Fatalf("finalized epoch (%d) too low to choose a stable test epoch", finResp.Data.Finalized.Epoch)
	}

	const epochSearchWindow = 64
	var (
		testEpoch     phase0.Epoch
		canonicalSlot phase0.Slot
		missedSlot    phase0.Slot
		hasMissed     bool
		// Fallback: the first epoch we find with a canonical first slot,
		// in case nothing in the search window has a missed slot.
		fallbackEpoch phase0.Epoch
		fallbackSlot  phase0.Slot
	)
	// Walk recent finalized epochs looking for one with both a canonical
	// block at its first slot (so GetValidatorIndexes' slot-id state lookup
	// succeeds — same Caplin gotcha as service_e2e_test.go) AND a missed
	// slot somewhere in the epoch (so we can fixture the 4xx path).
	// Continue walking even after finding a viable epoch until a missed
	// slot turns up, so the 4xx detection is exercised on this run.
	for cand := finResp.Data.Finalized.Epoch - 1; cand+epochSearchWindow > finResp.Data.Finalized.Epoch && cand > 0; cand-- {
		probeCtx, probeCancel := context.WithTimeout(ctx, e2eReqTimeout)
		first, err := bc.GetBlock(probeCtx, spec.EpochLowestSlot(cand))
		probeCancel()
		if err != nil {
			t.Fatalf("probe GetBlock(slot=%d): %v", spec.EpochLowestSlot(cand), err)
		}
		if first == nil {
			continue
		}
		if fallbackEpoch == 0 {
			fallbackEpoch = cand
			fallbackSlot = spec.EpochLowestSlot(cand)
		}
		// Scan the rest of the epoch for a missed slot.
		for slot := spec.EpochLowestSlot(cand) + 1; slot <= spec.EpochHighestSlot(cand); slot++ {
			scanCtx, scanCancel := context.WithTimeout(ctx, e2eReqTimeout)
			b, err := bc.GetBlock(scanCtx, slot)
			scanCancel()
			if err != nil {
				t.Fatalf("scan GetBlock(slot=%d): %v", slot, err)
			}
			if b == nil {
				testEpoch = cand
				canonicalSlot = spec.EpochLowestSlot(cand)
				missedSlot = slot
				hasMissed = true
				break
			}
		}
		if hasMissed {
			break
		}
	}
	if !hasMissed && fallbackEpoch != 0 {
		// No missed slot in the search window — testnets sometimes go
		// runs of fully canonical epochs. The 4xx subtest will skip,
		// but the rest of the suite still runs against a real epoch.
		testEpoch = fallbackEpoch
		canonicalSlot = fallbackSlot
	}
	if testEpoch == 0 {
		t.Fatalf("no canonical block at any epoch-first-slot within %d epochs of finalized %d",
			epochSearchWindow, finResp.Data.Finalized.Epoch)
	}
	t.Logf("e2e: finalizedEpoch=%d testEpoch=%d canonicalSlot=%d missedSlot=%d hasMissed=%v",
		finResp.Data.Finalized.Epoch, testEpoch, canonicalSlot, missedSlot, hasMissed)

	// Discover real validator pubkeys at indices [0..2] for the
	// validators/POST roundtrip subtest.
	var probePubkeys []string
	t.Run("validators_lookup_2xx_and_template", func(t *testing.T) {
		const ep = "/eth/v1/beacon/states/{state_id}/validators"
		before := snap(t, metrics, ep, http.MethodPost, "2xx")
		provider := bc.Service().(eth2client.ValidatorsProvider)
		subCtx, c := context.WithTimeout(ctx, e2eReqTimeout)
		defer c()
		resp, err := provider.Validators(subCtx, &api.ValidatorsOpts{
			State:   "head",
			Indices: []phase0.ValidatorIndex{0, 1, 2},
		})
		if err != nil {
			t.Fatalf("Validators: %v", err)
		}
		for _, v := range resp.Data {
			probePubkeys = append(probePubkeys, NormalizedPublicKey(v.Validator.PublicKey.String()))
		}
		// go-eth2-client switches to POST when the body is large enough
		// (it batches indices/pubkeys via POST to avoid URL-length limits)
		// — for [0,1,2] it should POST.
		expectAtLeast(t, metrics, before, ep, http.MethodPost, "2xx", 1)
	})

	t.Run("get_validator_indexes_2xx_with_state_id_template", func(t *testing.T) {
		if len(probePubkeys) == 0 {
			t.Skip("no probe pubkeys available")
		}
		const ep = "/eth/v1/beacon/states/{state_id}/validators"
		before := snap(t, metrics, ep, http.MethodPost, "2xx")
		subCtx, c := context.WithTimeout(ctx, e2eReqTimeout)
		defer c()
		_, err := bc.GetValidatorIndexes(subCtx, probePubkeys, testEpoch)
		if err != nil {
			t.Fatalf("GetValidatorIndexes: %v", err)
		}
		// Production code calls Validators() with State=fmt.Sprintf("%d",
		// EpochLowestSlot(epoch)) — the {state_id} placeholder must
		// absorb that numeric slot id.
		expectAtLeast(t, metrics, before, ep, http.MethodPost, "2xx", 1)
	})

	t.Run("get_block_canonical_2xx_with_block_id_template", func(t *testing.T) {
		const ep = "/eth/v2/beacon/blocks/{block_id}"
		before := snap(t, metrics, ep, http.MethodGet, "2xx")
		subCtx, c := context.WithTimeout(ctx, e2eReqTimeout)
		defer c()
		b, err := bc.GetBlock(subCtx, canonicalSlot)
		if err != nil {
			t.Fatalf("GetBlock(canonical=%d): %v", canonicalSlot, err)
		}
		if b == nil {
			t.Fatalf("expected canonical block at slot %d, got nil", canonicalSlot)
		}
		expectAtLeast(t, metrics, before, ep, http.MethodGet, "2xx", 1)
	})

	t.Run("get_block_missed_4xx_with_block_id_template", func(t *testing.T) {
		if !hasMissed {
			t.Skip("no missed slot found in test epoch — 4xx detection not fixture-verifiable this run")
		}
		const ep = "/eth/v2/beacon/blocks/{block_id}"
		before := snap(t, metrics, ep, http.MethodGet, "4xx")
		subCtx, c := context.WithTimeout(ctx, e2eReqTimeout)
		defer c()
		b, err := bc.GetBlock(subCtx, missedSlot)
		// GetBlock translates 404 to (nil, nil); any other outcome is wrong.
		if err != nil {
			t.Fatalf("GetBlock(missed=%d): unexpected err %v", missedSlot, err)
		}
		if b != nil {
			t.Fatalf("GetBlock(missed=%d) returned non-nil block — slot is no longer missed?", missedSlot)
		}
		// The transport saw a 404 from the upstream beacon, so statusClass
		// must categorize it as 4xx.
		expectAtLeast(t, metrics, before, ep, http.MethodGet, "4xx", 1)
	})

	t.Run("proposer_duties_2xx_with_epoch_template", func(t *testing.T) {
		const ep = "/eth/v1/validator/duties/proposer/{epoch}"
		before := snap(t, metrics, ep, http.MethodGet, "2xx")
		subCtx, c := context.WithTimeout(ctx, e2eReqTimeout)
		defer c()
		_, err := bc.GetProposerDuties(subCtx, testEpoch, nil)
		if err != nil {
			t.Fatalf("GetProposerDuties: %v", err)
		}
		expectAtLeast(t, metrics, before, ep, http.MethodGet, "2xx", 1)
	})

	t.Run("attester_duties_2xx_with_epoch_template", func(t *testing.T) {
		const ep = "/eth/v1/validator/duties/attester/{epoch}"
		before := snap(t, metrics, ep, http.MethodPost, "2xx")
		subCtx, c := context.WithTimeout(ctx, e2eReqTimeout)
		defer c()
		_, err := bc.GetAttesterDuties(subCtx, testEpoch, []phase0.ValidatorIndex{0, 1, 2})
		if err != nil {
			t.Fatalf("GetAttesterDuties: %v", err)
		}
		// Attester duties are POSTed (indices in body), per CLAUDE.md.
		expectAtLeast(t, metrics, before, ep, http.MethodPost, "2xx", 1)
	})

	t.Run("committees_2xx_with_state_id_template", func(t *testing.T) {
		const ep = "/eth/v1/beacon/states/{state_id}/committees"
		before := snap(t, metrics, ep, http.MethodGet, "2xx")
		subCtx, c := context.WithTimeout(ctx, e2eReqTimeout)
		defer c()
		_, err := bc.GetCommitteeLengths(subCtx, testEpoch)
		if err != nil {
			t.Fatalf("GetCommitteeLengths: %v", err)
		}
		// Production calls BeaconCommittees with State="head".
		expectAtLeast(t, metrics, before, ep, http.MethodGet, "2xx", 1)
	})

	t.Run("events_template_strips_query", func(t *testing.T) {
		// Production talks to /eth/v1/events?topics=head via go-eth2-client's
		// EventsProvider. We don't use that here because go-eth2-client's
		// SSE client does NOT route through eth2http.WithHTTPClient
		// (verified empirically — Events() doesn't increment our counter
		// even after a successful subscription). That is a separate
		// observability gap worth flagging upstream; for the purposes of
		// this test we drive the same URL through the same instrumenting
		// transport directly, which is what verifies metrics.go's
		// detection paths against this endpoint's real on-chain response.
		//
		// What we're verifying for THIS endpoint specifically:
		//   - endpointTemplate must strip the `?topics=head` query and
		//     produce the bare "/eth/v1/events" label (otherwise the
		//     metric cardinality would explode by topic combination).
		//   - statusClass must categorise whatever the upstream returned.
		//
		// We DON'T assert "2xx" here because SSE handshake timing on the
		// staging gateway is unreliable — what matters is that *some*
		// status class lands under the "/eth/v1/events" template (i.e.
		// the query strip worked).
		const ep = "/eth/v1/events"
		// Trim trailing slash on the configured endpoint so "/eth/v1/..."
		// concatenation doesn't produce a double slash that the upstream
		// gateway may route differently.
		base := endpoint
		for len(base) > 0 && base[len(base)-1] == '/' {
			base = base[:len(base)-1]
		}
		client := &http.Client{Transport: &instrumentingTransport{base: http.DefaultTransport, m: metrics}}
		subCtx, c := context.WithTimeout(ctx, 8*time.Second)
		defer c()
		req, err := http.NewRequestWithContext(subCtx, http.MethodGet, base+"/eth/v1/events?topics=head", nil)
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		req.Header.Set("Accept", "text/event-stream")
		resp, err := client.Do(req)
		// Either outcome (resp+nil, or nil+timeout) records a metric — we
		// just need the right endpoint label.
		var observedClass string
		if err != nil {
			observedClass = "error"
		} else {
			defer func() { _ = resp.Body.Close() }()
			observedClass = http.StatusText(resp.StatusCode)
			class := "2xx"
			switch resp.StatusCode / 100 {
			case 3:
				class = "3xx"
			case 4:
				class = "4xx"
			case 5:
				class = "5xx"
			}
			observedClass = class
		}
		// Sum counters across all status classes for this endpoint+method.
		ch := make(chan prometheus.Metric, 16)
		go func() {
			metrics.Requests.Collect(ch)
			close(ch)
		}()
		var totalForEvents float64
		var classesSeen []string
		for m := range ch {
			var dtoM dto.Metric
			if err := m.Write(&dtoM); err != nil {
				t.Fatalf("collect Write: %v", err)
			}
			labels := map[string]string{}
			for _, lp := range dtoM.GetLabel() {
				labels[lp.GetName()] = lp.GetValue()
			}
			if labels["endpoint"] == ep && labels["method"] == http.MethodGet {
				totalForEvents += dtoM.GetCounter().GetValue()
				if dtoM.GetCounter().GetValue() > 0 {
					classesSeen = append(classesSeen, labels["status_class"])
				}
			}
		}
		if totalForEvents < 1 {
			t.Fatalf("counter sum across status classes for endpoint=%s method=GET = %g, want >= 1 — endpointTemplate did not strip the query string from /eth/v1/events?topics=head",
				ep, totalForEvents)
		}
		t.Logf("e2e: events endpoint observed under classes=%v (this run reported %s)", classesSeen, observedClass)
	})

	// Final guard: make sure no production-path call ended up under the
	// "other" template. Anything labelled "other" means endpointTemplate
	// failed to recognise a real beacon URL — exactly the regression this
	// suite exists to catch.
	t.Run("no_other_label_for_real_beacon_traffic", func(t *testing.T) {
		ch := make(chan prometheus.Metric, 64)
		go func() {
			metrics.Requests.Collect(ch)
			close(ch)
		}()
		for m := range ch {
			var dtoM dto.Metric
			if err := m.Write(&dtoM); err != nil {
				t.Fatalf("collect Write: %v", err)
			}
			labels := map[string]string{}
			for _, lp := range dtoM.GetLabel() {
				labels[lp.GetName()] = lp.GetValue()
			}
			if labels["endpoint"] == "other" && dtoM.GetCounter().GetValue() > 0 {
				t.Errorf("got counter with endpoint=other (method=%s status_class=%s value=%g) — endpointTemplate failed for a real beacon URL",
					labels["method"], labels["status_class"], dtoM.GetCounter().GetValue())
			}
		}
	})
}
