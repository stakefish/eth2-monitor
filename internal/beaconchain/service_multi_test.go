package beaconchain

// Offline tests for the multi-endpoint BeaconChain: failover when the
// primary stalls, and start-up while no endpoint is reachable yet.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/rs/zerolog"
)

func quietClientLogs(t *testing.T) {
	t.Helper()
	prevLevel := zerolog.GlobalLevel()
	zerolog.SetGlobalLevel(zerolog.WarnLevel)
	t.Cleanup(func() { zerolog.SetGlobalLevel(prevLevel) })
}

// TestNew_FailsOverWhenPrimaryStalls reproduces the failure shape: the
// first endpoint answers its start-up probes but a committees request
// hangs past the per-request timeout. The call must come back from the
// second endpoint instead of surfacing context.DeadlineExceeded.
func TestNew_FailsOverWhenPrimaryStalls(t *testing.T) {
	quietClientLogs(t)

	const committeesPath = "/eth/v1/beacon/states/head/committees"
	var stalledHits, goodHits atomic.Int32

	stalled := fixtureServer(t, "happy_path", []fixtureRoute{{
		Path: committeesPath,
		Handler: func(w http.ResponseWriter, r *http.Request) {
			stalledHits.Add(1)
			select {
			case <-r.Context().Done():
			case <-time.After(10 * time.Second):
			}
			w.WriteHeader(http.StatusGatewayTimeout)
		},
	}})
	good := fixtureServer(t, "happy_path", []fixtureRoute{{
		Path: committeesPath,
		Handler: func(w http.ResponseWriter, _ *http.Request) {
			goodHits.Add(1)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(loadFixture(t, "happy_path", "committees.json"))
		},
	}})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	bc, err := New(ctx, []string{stalled.URL, good.URL}, 500*time.Millisecond, nil)
	if err != nil {
		t.Fatalf("New(stalled, good): %v", err)
	}

	lengths, err := bc.GetCommitteeLengths(ctx, phase0.Epoch(loadMeta(t, "happy_path").TestEpoch))
	if err != nil {
		t.Fatalf("GetCommitteeLengths did not fail over: %v", err)
	}
	if len(lengths) == 0 {
		t.Fatal("GetCommitteeLengths returned no committees from the healthy endpoint")
	}
	if got := stalledHits.Load(); got != 1 {
		t.Errorf("stalled endpoint hits = %d, want 1", got)
	}
	if got := goodHits.Load(); got != 1 {
		t.Errorf("healthy endpoint hits = %d, want 1", got)
	}
}

// TestNew_StartsWhileEndpointsUnreachable covers start-up before the
// network path to the beacon node exists, so every probe fails. New must
// still return a usable client instead of "client is not active"; the
// first real call happens later, once the endpoint answers.
func TestNew_StartsWhileEndpointsUnreachable(t *testing.T) {
	quietClientLogs(t)

	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(down.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	bc, err := New(ctx, []string{down.URL}, time.Second, nil)
	if err != nil {
		t.Fatalf("New(down) = %v; want a client that waits for the endpoint", err)
	}
	if bc.Service().IsActive() {
		t.Fatal("Service().IsActive() = true against an endpoint that only returns 503")
	}
}
