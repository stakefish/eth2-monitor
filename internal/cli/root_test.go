package cli

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stakefish/eth2-monitor/internal/monitoring"
)

func TestRunMonitorUntilShutdown_PreservesCompletedReplay(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ran := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- runMonitorUntilShutdown(ctx, func(context.Context) error {
			close(ran) // a second invocation would panic
			return fmt.Errorf("completed: %w", monitoring.ErrReplayComplete)
		})
	}()
	select {
	case <-ran:
	case <-time.After(time.Second):
		t.Fatal("replay did not run")
	}
	// The command must remain alive so its HTTP server can serve replay metrics.
	select {
	case err := <-done:
		t.Fatalf("returned before shutdown: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("shutdown result = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("did not stop on cancellation")
	}
}
