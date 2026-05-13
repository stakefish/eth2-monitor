package monitoring

// Integration tests for the orchestrator (MonitorAttestationsAndProposals)
// and the SSE consumer (SubscribeToEpochs). Replaces the previous mock-
// driven coverage in monitoring_test.go: the orchestrator now runs against
// a real BeaconChain pointed at fixtureServer (no nil-beacon shortcut),
// and the SSE consumer reads from a streaming httptest.Server replaying
// the captured events_head.sse fixture.
//
// The runSSESubscription helper-isolation tests stay in
// monitoring_helpers_test.go — those test goroutine-blocking semantics
// of a small helper, where a fakeEventsProvider mock is the right tool;
// a real-beacon overlay would not exercise any additional code path.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// TestMonitorAttestationsAndProposals_PreCancelledCtx_RealBeacon
// regresses the early ctx.Err() bail at the top of the per-epoch loop.
// With a pre-cancelled ctx, the orchestrator must not invoke any
// per-epoch beacon work — m.Epoch.Set is the canary (it's the first
// per-iteration write).
//
// Now uses a real BeaconChain backed by fixtureServer instead of the
// previous nil-beacon shortcut. Even though the bail happens before
// any beacon call in this test, having a real beacon attached confirms
// no startup-path beacon work leaks past the ctx check either.
func TestMonitorAttestationsAndProposals_PreCancelledCtx_RealBeacon(t *testing.T) {
	quietGoEth2Client(t)

	server := fixtureServer(t, nil)
	bc := newBeaconChainAgainst(t, server.URL)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancel

	epochsChan := make(chan phase0.Epoch, 1)
	epochsChan <- 99
	close(epochsChan)

	var wg sync.WaitGroup
	wg.Add(1)
	m := NewMonitorMetrics(prometheus.NewRegistry())

	go MonitorAttestationsAndProposals(ctx, cancel, bc, nil, nil, &wg, epochsChan, m)

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("orchestrator did not exit on pre-cancelled ctx within 2s")
	}

	var metric dto.Metric
	if err := m.Epoch.Write(&metric); err != nil {
		t.Fatalf("Epoch.Write: %v", err)
	}
	if got := metric.GetGauge().GetValue(); got != 0 {
		t.Errorf("m.Epoch = %v, want 0 (orchestrator should bail before any per-epoch work)", got)
	}
}

// TestMonitorAttestationsAndProposals_ClosedChannelCancelsCtx_RealBeacon
// regresses the zombie-goroutine fix. When the orchestrator returns
// (here via a closed epochsChan), the deferred cancel() must propagate
// to the shared ctx so the SSE goroutine observes it and exits.
// Without that defer, the orchestrator-empty-channel return would
// leave SubscribeToEpochs blocked indefinitely.
func TestMonitorAttestationsAndProposals_ClosedChannelCancelsCtx_RealBeacon(t *testing.T) {
	quietGoEth2Client(t)

	server := fixtureServer(t, nil)
	bc := newBeaconChainAgainst(t, server.URL)

	ctx, cancel := context.WithCancel(context.Background())

	epochsChan := make(chan phase0.Epoch)
	close(epochsChan)

	var wg sync.WaitGroup
	wg.Add(1)
	m := NewMonitorMetrics(prometheus.NewRegistry())

	go MonitorAttestationsAndProposals(ctx, cancel, bc, nil, nil, &wg, epochsChan, m)

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("orchestrator did not exit on closed channel within 2s")
	}

	select {
	case <-ctx.Done():
		// good — defer cancel() ran
	default:
		t.Fatal("orchestrator exited without cancelling ctx; SSE goroutine would zombie")
	}
}

// sseStreamServer replays a captured SSE transcript (events_head.sse)
// to clients hitting /eth/v1/events. The transcript already contains
// "event: head\ndata: {...}\n\n" framing, so we just write the bytes
// verbatim with periodic Flush() so go-eth2-client's SSE reader sees
// each event arrive distinctly. Connection stays open until the
// client cancels.
func sseStreamServer(t *testing.T, sseFixture []byte) *http.ServeMux {
	t.Helper()
	mux := http.NewServeMux()
	// Add the events route plus all the routes fixtureServer normally
	// registers (probes + finality). Caller wires this mux into
	// httptest.NewServer.
	mux.HandleFunc("/eth/v1/events", func(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming unsupported", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)
		flusher.Flush()

		// Write the entire fixture once and flush; the fixture itself
		// contains the framing. After that, hold the connection open
		// until the client (go-eth2-client) cancels.
		_, _ = w.Write(sseFixture)
		flusher.Flush()
		<-r.Context().Done()
	})
	return mux
}

// TestSubscribeToEpochs_ReceivesFromCapturedSSE drives SubscribeToEpochs
// against a real BeaconChain where /eth/v1/events streams the captured
// events_head.sse fixture. Verifies at least one epoch lands on the
// channel — proving the full SSE → head event → epoch projection
// pipeline works end-to-end against real wire data.
//
// The captured fixture has 3 head events; SubscribeToEpochs only sends
// to the channel when the epoch advances (not on every head event), so
// the assertion is "at least one epoch received within a bounded
// window" rather than "exactly N".
func TestSubscribeToEpochs_ReceivesFromCapturedSSE(t *testing.T) {
	quietGoEth2Client(t)

	// Read the captured SSE fixture verbatim.
	sseBody, err := os.ReadFile(filepath.Join(beaconTestdataRel, "beacon", "events_head.sse"))
	if err != nil {
		t.Fatalf("read events_head.sse: %v (run `make refresh-fixtures`)", err)
	}
	if len(sseBody) == 0 {
		t.Skip("captured SSE fixture is empty — relay had no events at capture time")
	}

	// Build a server that combines:
	//   - The standard go-eth2-client startup probes (auto)
	//   - /eth/v1/beacon/states/head/finality_checkpoints (SubscribeToEpochs's bootstrap)
	//   - /eth/v1/events (streaming the captured fixture)
	//
	// fixtureServer doesn't expose its mux, so build one by composing
	// its registration logic inline.
	mux := sseStreamServer(t, sseBody)
	for path, file := range beaconStartupProbes {
		path := path
		file := file
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			body := loadBeaconFixture(t, file)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(body)
		})
	}
	mux.HandleFunc("/eth/v1/beacon/states/head/finality_checkpoints", func(w http.ResponseWriter, r *http.Request) {
		body := loadBeaconFixture(t, "finality_checkpoints.json")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	bc := newBeaconChainAgainst(t, server.URL)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	epochsChan := make(chan phase0.Epoch, 8)
	var wg sync.WaitGroup
	wg.Add(1)
	go SubscribeToEpochs(ctx, bc, &wg, epochsChan)

	// Bound wait at 5s — captured stream has 3 events, all should
	// arrive within ms once the SSE handshake completes. If we don't
	// see at least one epoch by 5s the integration is broken.
	var received int32
	deadline := time.After(5 * time.Second)
	for {
		select {
		case _, ok := <-epochsChan:
			if !ok {
				goto done
			}
			atomic.AddInt32(&received, 1)
			if atomic.LoadInt32(&received) >= 1 {
				goto done
			}
		case <-deadline:
			goto done
		}
	}
done:
	cancel()
	// Drain the SubscribeToEpochs goroutine.
	doneCh := make(chan struct{})
	go func() { wg.Wait(); close(doneCh) }()
	select {
	case <-doneCh:
	case <-time.After(2 * time.Second):
		t.Fatal("SubscribeToEpochs did not exit within 2s of ctx cancel")
	}

	if atomic.LoadInt32(&received) < 1 {
		t.Fatal("no epochs received from SSE pipeline — captured events_head.sse not driving the consumer end-to-end")
	}
}
