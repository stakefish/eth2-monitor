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
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stakefish/eth2-monitor/internal/opts"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// withSSEMode resets opts.Monitor.SinceEpoch to its production sentinel
// (^uint64(0) — "no since-epoch override") for the duration of the
// test. Without this, the Go zero-value 0 makes SubscribeToEpochs take
// the `--since-epoch` backfill path instead of subscribing to the SSE
// stream — emitting every epoch from 0 to lastEpoch and returning,
// which means the test never exercises the SSE handler at all. The
// production cli wires this default through cobra's `^uint64(0)`
// flag default, but tests don't invoke cobra registration so they
// inherit Go's zero value unless explicitly reset.
func withSSEMode(t *testing.T) {
	t.Helper()
	prev := opts.Monitor.SinceEpoch
	opts.Monitor.SinceEpoch = ^uint64(0)
	t.Cleanup(func() { opts.Monitor.SinceEpoch = prev })
}

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

	server := fixtureServer(t, "happy_path", nil)
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

	server := fixtureServer(t, "happy_path", nil)
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

// TestRunMonitorPair_ReturnsCleanlyOnCtxCancel: the cli supervisor
// relies on RunMonitorPair returning nil whenever its ctx is cancelled,
// regardless of which goroutine winds down first. This regresses the
// pre-supervisor zombie behaviour: when the orchestrator hit a wrapped
// ctx.DeadlineExceeded it returned cleanly + cancelled the shared ctx,
// SubscribeToEpochs followed, and the process was left serving stale
// /metrics with no way out. RunMonitorPair must surface that condition
// as a normal return (nil) so the caller's supervisor can decide
// whether to restart based on the parent ctx.
//
// Drives the goroutine pair against a minimal fixture server whose
// /eth/v1/events handler holds the connection without ever emitting a
// head event. plainPubkeys=nil + no SSE events means
// MonitorAttestationsAndProposals stays in `for range epochsChan`
// without performing any per-epoch work — the wg.Wait/cancel/close
// plumbing is the only thing under test here.
func TestRunMonitorPair_ReturnsCleanlyOnCtxCancel(t *testing.T) {
	quietGoEth2Client(t)
	withSSEMode(t)

	mux := http.NewServeMux()
	mux.HandleFunc("/eth/v1/events", func(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming unsupported", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher.Flush()
		<-r.Context().Done()
	})
	for path, file := range beaconStartupProbes {
		p, f := path, file
		mux.HandleFunc(p, func(w http.ResponseWriter, r *http.Request) {
			body := loadSharedBeaconFixture(t, f)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(body)
		})
	}
	mux.HandleFunc("/eth/v1/beacon/states/head/finality_checkpoints", func(w http.ResponseWriter, r *http.Request) {
		body := loadBeaconFixture(t, "happy_path", "finality_checkpoints.json")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	bc := newBeaconChainAgainst(t, server.URL)
	metrics := NewMonitorMetrics(prometheus.NewRegistry())

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() {
		done <- RunMonitorPair(ctx, bc, nil, nil, metrics)
	}()

	// Brief grace so both goroutines reach steady state, then cancel.
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("RunMonitorPair returned %v; want nil after ctx cancel", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("RunMonitorPair did not return within 3s of ctx cancel; goroutine pair leaked")
	}
}

// TestSubscribeToEpochs_SurvivesMidStreamSSEClose is the end-to-end
// resilience proof for the auto-resubscribe fix. The server streams
// the captured SSE transcript once and then closes the connection;
// SubscribeToEpochs must keep running. The server's second connection
// repeats the same transcript — at least one epoch should land on the
// channel AFTER the first connection closed.
//
// Note: in practice go-eth2-client's internal Events() goroutine
// already implements an SSE reconnect loop, so this test usually exits
// through that path rather than incrementing
// ETH2_sseResubscribes. The test therefore asserts on observable
// behaviour (epochs still flowing after a reconnect) rather than the
// counter — the counter is exercised at unit-level in
// TestSubscribeWithRetry_RetriesOnTransientErrorAndIncrementsCounter.
//
// Pre-supervisor, this scenario would have been benign too (Events
// already retried), but ANY downstream change to the library, or any
// path that surfaced a non-ctx error from Events, would have leaked
// to Must(err) and crashed the process. The new layering means even
// a regression at the library boundary self-heals.
func TestSubscribeToEpochs_SurvivesMidStreamSSEClose(t *testing.T) {
	quietGoEth2Client(t)
	withSSEMode(t)

	sseBody := loadBeaconFixture(t, "happy_path", "events_head.sse")
	if len(sseBody) == 0 {
		t.Skip("captured SSE fixture is empty — relay had no events at capture time")
	}

	// Connection counter so the server returns the same transcript on
	// every connection but drops the first one explicitly to force a
	// reconnect.
	var connCount int32
	mux := http.NewServeMux()
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

		_, _ = w.Write(sseBody)
		flusher.Flush()

		// First connection: return early (close the response writer).
		// Subsequent connections: hold open until the client cancels.
		if atomic.AddInt32(&connCount, 1) == 1 {
			return
		}
		<-r.Context().Done()
	})
	for path, file := range beaconStartupProbes {
		p, f := path, file
		mux.HandleFunc(p, func(w http.ResponseWriter, r *http.Request) {
			body := loadSharedBeaconFixture(t, f)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(body)
		})
	}
	mux.HandleFunc("/eth/v1/beacon/states/head/finality_checkpoints", func(w http.ResponseWriter, r *http.Request) {
		body := loadBeaconFixture(t, "happy_path", "finality_checkpoints.json")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	bc := newBeaconChainAgainst(t, server.URL)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	epochsChan := make(chan phase0.Epoch, 16)
	var wg sync.WaitGroup
	wg.Add(1)
	metrics := NewMonitorMetrics(prometheus.NewRegistry())
	go SubscribeToEpochs(ctx, bc, &wg, epochsChan, metrics)

	// Wait long enough for: first connection to deliver events + close,
	// reconnect (eth2-client's internal 1s loop), second connection to
	// deliver events again. 5s is comfortably above the library's 1s
	// backoff + handshake.
	var received int32
	deadline := time.After(5 * time.Second)
loop:
	for {
		select {
		case _, ok := <-epochsChan:
			if !ok {
				break loop
			}
			atomic.AddInt32(&received, 1)
		case <-deadline:
			break loop
		}
	}

	// At least 2 connections must have happened — proving the server
	// kept serving after the first drop AND the client reconnected.
	if got := atomic.LoadInt32(&connCount); got < 2 {
		cancel()
		<-doneOf(&wg)
		t.Fatalf("server only saw %d /eth/v1/events connections; client did not reconnect after mid-stream close", got)
	}

	if got := atomic.LoadInt32(&received); got < 1 {
		cancel()
		<-doneOf(&wg)
		t.Fatalf("no epochs received across %d connections; SSE pipeline broken after reconnect", atomic.LoadInt32(&connCount))
	}

	cancel()
	select {
	case <-doneOf(&wg):
	case <-time.After(2 * time.Second):
		t.Fatal("SubscribeToEpochs did not exit within 2s of ctx cancel after mid-stream close")
	}
}

// doneOf returns a channel that closes when wg.Wait() returns. Lets
// reconnect tests put bounded wg-drain in a select alongside a
// deadline. Defined here so it's local to the integration-test scope.
func doneOf(wg *sync.WaitGroup) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	return done
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
	withSSEMode(t)

	// Read the captured SSE fixture verbatim. Each scenario captures
	// its own SSE transcript while waiting for a matching head event,
	// so the SSE bytes are anchored to that scenario's slot range.
	// happy_path is the natural choice for a generic SSE-replay test
	// — the test only cares that SOME slots flow through the pipeline,
	// not which scenario produced them.
	sseBody := loadBeaconFixture(t, "happy_path", "events_head.sse")
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
			body := loadSharedBeaconFixture(t, file)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(body)
		})
	}
	mux.HandleFunc("/eth/v1/beacon/states/head/finality_checkpoints", func(w http.ResponseWriter, r *http.Request) {
		body := loadBeaconFixture(t, "happy_path", "finality_checkpoints.json")
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
	metrics := NewMonitorMetrics(prometheus.NewRegistry())
	go SubscribeToEpochs(ctx, bc, &wg, epochsChan, metrics)

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
