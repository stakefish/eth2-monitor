package monitoring

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/prometheus/client_golang/prometheus"
)

// TestSubscribeToEpochs_ReturnsWhenNoEndpointIsReachable covers start-up
// while no beacon endpoint answers yet (network path not up). The producer
// must return cleanly (closing the epoch channel) so the supervisor
// retries with backoff, instead of panicking the process on the first
// call.
func TestSubscribeToEpochs_ReturnsWhenNoEndpointIsReachable(t *testing.T) {
	quietGoEth2Client(t)
	withSSEMode(t)

	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(down.Close)
	bc := newBeaconChainAgainst(t, down.URL)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	epochsChan := make(chan phase0.Epoch)
	var wg sync.WaitGroup
	wg.Add(1)
	m := NewMonitorMetrics(prometheus.NewRegistry())

	done := make(chan any, 1)
	go func() {
		defer func() { done <- recover() }()
		SubscribeToEpochs(ctx, bc, &wg, epochsChan, m)
	}()

	select {
	case r := <-done:
		if r != nil {
			t.Fatalf("SubscribeToEpochs panicked with no reachable endpoint: %v; want a clean return so the supervisor can retry", r)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("SubscribeToEpochs did not return within 15s with no reachable endpoint")
	}
	if _, open := <-epochsChan; open {
		t.Fatal("epochsChan still open after SubscribeToEpochs returned; orchestrator would hang")
	}
}
