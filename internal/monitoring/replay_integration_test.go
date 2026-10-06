package monitoring

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stakefish/eth2-monitor/internal/beaconchain"
	"github.com/stakefish/eth2-monitor/internal/opts"
)

func withReplayEpochs(t *testing.T, epochs []uint) {
	t.Helper()
	previous := opts.Monitor.ReplayEpoch
	opts.Monitor.ReplayEpoch = epochs
	t.Cleanup(func() { opts.Monitor.ReplayEpoch = previous })
	withTempCachePath(t)
}

// Drive the real producer and orchestrator through a finite replay. There are
// no active validators, so both epoch delivery and the soft-skip path must finish.
func TestSupervise_ReplayCompletesWithoutRestart(t *testing.T) {
	withReplayEpochs(t, []uint{0, 94894})
	rig := newScenarioRig(t, "happy_path")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	runs := 0
	err := Supervise(ctx, func(runCtx context.Context) error {
		runs++
		if runs > 1 {
			cancel()
		} // bound a regression that restarts the replay
		return RunMonitorPair(runCtx, rig.bc, nil, nil, rig.metrics)
	}, zeroBackoff())
	if !errors.Is(err, ErrReplayComplete) {
		t.Fatalf("replay result = %v, want completion", err)
	}
	if runs != 1 {
		t.Fatalf("replay ran %d times, want once", runs)
	}
	if got := gaugeValue(t, rig.metrics.Epoch); got != 94894 {
		t.Fatalf("last processed epoch = %v, want 94894", got)
	}
	if ctx.Err() != nil {
		t.Fatalf("replay canceled its parent: %v", ctx.Err())
	}
}

// Interrupted runs must not signal completion, even after the last epoch has
// been sent. The supervisor parent remains alive so this work can be restarted.
func TestRunMonitorPair_InterruptedReplayDoesNotComplete(t *testing.T) {
	for _, stage := range []string{"finality", "last_epoch"} {
		t.Run(stage, func(t *testing.T) {
			withReplayEpochs(t, []uint{94894})
			quietGoEth2Client(t)
			routes := []fixtureRoute{{Path: "/eth/v1/beacon/states/head/finality_checkpoints", Status: http.StatusOK, File: "finality_checkpoints.json"}}
			blockedPath := "/eth/v1/beacon/states/head/finality_checkpoints"
			entered := make(chan struct{}, 1)
			var keys []string
			if stage == "last_epoch" {
				blockedPath = "/eth/v1/beacon/states/3036608/validators"
				keys = []string{"0x" + strings.Repeat("00", 48)}
			}
			routes = append(routes, fixtureRoute{Path: blockedPath, Handler: func(_ http.ResponseWriter, r *http.Request) {
				entered <- struct{}{}
				_, _ = io.Copy(io.Discard, r.Body)
				select {
				case <-r.Context().Done():
				case <-time.After(time.Second): // bound server cleanup even on a test failure
				}
			}})
			// Avoid duplicate finality routes when the bootstrap itself is blocked.
			if stage == "finality" {
				routes = routes[1:]
			}
			server := fixtureServer(t, "happy_path", routes)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			metrics := NewMonitorMetrics(prometheus.NewRegistry())
			bc, err := beaconchain.New(ctx, server.URL, 100*time.Millisecond, metrics.BeaconRequestMetrics())
			if err != nil {
				t.Fatal(err)
			}
			runCtx, cancelRun := context.WithTimeout(ctx, 100*time.Millisecond)
			defer cancelRun()
			err = RunMonitorPair(runCtx, bc, keys, nil, metrics)
			if err != nil {
				t.Fatalf("interrupted replay result = %v, want restartable nil", err)
			}
			select {
			case <-entered:
			default:
				t.Fatal("replay never reached the blocked request")
			}
			if !errors.Is(runCtx.Err(), context.DeadlineExceeded) {
				t.Fatalf("run stopped without its deadline: %v", runCtx.Err())
			}
			if ctx.Err() != nil {
				t.Fatalf("interrupted run canceled supervisor parent: %v", ctx.Err())
			}
		})
	}
}
