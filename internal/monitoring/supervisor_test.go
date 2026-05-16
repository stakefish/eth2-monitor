package monitoring

import (
	"context"
	"errors"
	"iter"
	"sync/atomic"
	"testing"
	"time"
)

// zeroBackoff yields 0 forever. Keeps tests fast — Supervise's
// real backoff would block for seconds between restarts.
func zeroBackoff() iter.Seq[time.Duration] {
	return func(yield func(time.Duration) bool) {
		for {
			if !yield(0) {
				return
			}
		}
	}
}

// fixedBackoff yields the given duration forever.
func fixedBackoff(d time.Duration) iter.Seq[time.Duration] {
	return func(yield func(time.Duration) bool) {
		for {
			if !yield(d) {
				return
			}
		}
	}
}

// TestSupervise_ReturnsImmediatelyIfCtxAlreadyDone: a Supervise call
// against a pre-cancelled ctx must return ctx.Err() without invoking
// run even once. This is the "fast path on shutdown" guarantee — when
// the supervisor is about to start a new iteration but shutdown has
// already been signalled, we skip the iteration entirely.
func TestSupervise_ReturnsImmediatelyIfCtxAlreadyDone(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var calls int32
	run := func(context.Context) error {
		atomic.AddInt32(&calls, 1)
		return nil
	}

	err := Supervise(ctx, run, zeroBackoff())
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != 0 {
		t.Fatalf("run should not have been invoked, got %d calls", got)
	}
}

// TestSupervise_RestartsRunUntilCtxCancel: run returns nil repeatedly;
// Supervise must keep re-invoking it until ctx is cancelled. Counts
// at least 3 invocations to prove the loop is real (a one-shot would
// return after a single call).
func TestSupervise_RestartsRunUntilCtxCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var calls int32
	run := func(context.Context) error {
		n := atomic.AddInt32(&calls, 1)
		if n >= 3 {
			cancel()
		}
		return nil
	}

	err := Supervise(ctx, run, zeroBackoff())
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if got := atomic.LoadInt32(&calls); got < 3 {
		t.Fatalf("expected at least 3 run calls, got %d", got)
	}
}

// TestSupervise_RestartsOnError: run returning a non-nil error must
// trigger the same restart loop as run returning nil. The supervisor
// treats both as "iteration ended unexpectedly".
func TestSupervise_RestartsOnError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	wantErr := errors.New("transient failure")
	var calls int32
	run := func(context.Context) error {
		n := atomic.AddInt32(&calls, 1)
		if n >= 3 {
			cancel()
		}
		return wantErr
	}

	err := Supervise(ctx, run, zeroBackoff())
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if got := atomic.LoadInt32(&calls); got < 3 {
		t.Fatalf("expected at least 3 run calls, got %d", got)
	}
}

// TestSupervise_CancelDuringBackoffWakesPromptly: if the supervisor is
// asleep on a long backoff and ctx is cancelled mid-sleep, it must
// return promptly rather than waiting out the full backoff duration.
// Without ctx-aware sleep this would deadlock for the duration of the
// configured backoff (up to 64s with the production iterator).
func TestSupervise_CancelDuringBackoffWakesPromptly(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	run := func(context.Context) error { return nil }

	// 10s backoff between iterations; we cancel after 50ms.
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	err := Supervise(ctx, run, fixedBackoff(10*time.Second))
	elapsed := time.Since(start)

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("Supervise blocked for %v on cancel — expected prompt return", elapsed)
	}
}

// TestSupervise_PassesCtxToRun: the ctx handed to run is the same one
// Supervise watches. When run honours its own ctx parameter, cancelling
// the parent ctx propagates cleanly without need for a separate signal.
func TestSupervise_PassesCtxToRun(t *testing.T) {
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()

	got := make(chan context.Context, 1)
	run := func(ctx context.Context) error {
		got <- ctx
		<-ctx.Done()
		return ctx.Err()
	}

	done := make(chan error, 1)
	go func() { done <- Supervise(parent, run, zeroBackoff()) }()

	var runCtx context.Context
	select {
	case runCtx = <-got:
	case <-time.After(time.Second):
		t.Fatal("run was not invoked within 1s")
	}

	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context.Canceled, got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Supervise did not return within 1s of parent cancel")
	}

	if err := runCtx.Err(); !errors.Is(err, context.Canceled) {
		t.Fatalf("runCtx should be cancelled, got %v", err)
	}
}
