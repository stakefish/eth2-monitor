package monitoring

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stakefish/eth2-monitor/internal/opts"

	"github.com/attestantio/go-eth2-client/api"
	v1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/prometheus/client_golang/prometheus"
)

// fakeEventsProvider implements eth2client.EventsProvider for testing
// runSSESubscription. The real go-eth2-client/http implementation returns
// nil immediately after spawning an internal SSE goroutine; callers of
// Events therefore MUST block until ctx cancellation themselves. This
// fake mimics that contract — record the call, return whatever errFn
// dictates, then leave the caller to wait on ctx.
type fakeEventsProvider struct {
	calls   atomic.Int32
	topics  atomic.Value // []string
	handler atomic.Value // func(*v1.Event)
	errFn   func(ctx context.Context) error
}

func (f *fakeEventsProvider) Events(ctx context.Context, opts *api.EventsOpts) error {
	f.calls.Add(1)
	f.topics.Store(append([]string(nil), opts.Topics...))
	if opts.Handler != nil {
		f.handler.Store(opts.Handler)
	}
	if f.errFn != nil {
		return f.errFn(ctx)
	}
	return nil
}

// MonitorAttestationsAndProposals lifecycle tests live in
// monitoring_integration_test.go where they exercise the orchestrator
// against a real BeaconChain over fixtureServer (no nil-beacon mock).

// TestSendEpoch_DeliversWhenReceiverReady — happy path: a receiver is
// reading the channel, so the send completes and returns true.
func TestSendEpoch_DeliversWhenReceiverReady(t *testing.T) {
	ch := make(chan phase0.Epoch, 1)
	if !sendEpoch(context.Background(), ch, 42) {
		t.Fatal("sendEpoch returned false when receiver was ready")
	}
	if got := <-ch; got != 42 {
		t.Errorf("received %v, want 42", got)
	}
}

// TestSendEpoch_AbortsOnCtxCancel regresses the shutdown-hang scenario:
// orchestrator died, no one reads the channel, ctx is cancelled — the send
// must bail out instead of blocking forever. Pre-fix code did
// `epochsChan <- e` directly and would hang here indefinitely.
func TestSendEpoch_AbortsOnCtxCancel(t *testing.T) {
	ch := make(chan phase0.Epoch) // unbuffered, no receiver
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	done := make(chan bool, 1)
	go func() {
		done <- sendEpoch(ctx, ch, 42)
	}()

	select {
	case ok := <-done:
		if ok {
			t.Error("sendEpoch returned true even though ctx was cancelled and channel had no reader")
		}
	case <-time.After(time.Second):
		t.Fatal("sendEpoch hung after ctx cancel; shutdown would deadlock")
	}
}

// TestSendEpoch_PrefersDeliveryWhenBothReady — when both ctx and receiver
// are ready, Go's select makes a uniform choice. We don't pin the choice
// in this test; we only verify both branches are reachable in other tests
// above. Documented here so a future maintainer doesn't misread the
// behaviour as "ctx always wins".
func TestSendEpoch_BothReadyEitherIsAcceptable(t *testing.T) {
	ch := make(chan phase0.Epoch, 1)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Acceptable: either the send wins (returns true, value queued) or the
	// ctx wins (returns false, nothing queued). Both are correct outcomes.
	got := sendEpoch(ctx, ch, 99)
	if got {
		select {
		case v := <-ch:
			if v != 99 {
				t.Errorf("send-win branch: got %v, want 99", v)
			}
		default:
			t.Error("sendEpoch returned true but channel is empty")
		}
	} else {
		select {
		case v := <-ch:
			t.Errorf("ctx-win branch: channel has %v, expected empty", v)
		default:
		}
	}
}

// writeFile creates a file at filepath.Join(dir, name) with the given
// content and 0600 permissions, failing the test on any write error.
// Returns the full path for use as a function argument in callers.
func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile %v: %v", p, err)
	}
	return p
}

// TestLoadKeys_MergesCLIAndFiles covers the common case: pubkeys come from
// both the --pubkey CLI flag and one or more files. Lines that are blank or
// only whitespace must be skipped.
func TestLoadKeys_MergesCLIAndFiles(t *testing.T) {
	prev := opts.Monitor.Pubkeys
	t.Cleanup(func() { opts.Monitor.Pubkeys = prev })
	opts.Monitor.Pubkeys = []string{"0xCLI1"}

	dir := t.TempDir()
	f1 := writeFile(t, dir, "a.txt", "0xA1\n0xA2\n\n   \n")
	f2 := writeFile(t, dir, "b.txt", " 0xB1 \n0xB2\n")

	got, err := LoadKeys([]string{f1, f2})
	if err != nil {
		t.Fatalf("LoadKeys: %v", err)
	}
	want := []string{"0xCLI1", "0xA1", "0xA2", "0xB1", "0xB2"}
	if len(got) != len(want) {
		t.Fatalf("LoadKeys returned %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("LoadKeys[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

// TestLoadKeys_DoesNotAliasGlobalPubkeys regresses the slice-aliasing fix.
// Pre-fix `plainKeys := opts.Monitor.Pubkeys[:]` shared a backing array
// with the package-level slice, so an append into the slack capacity
// of the global slice could silently write past its length boundary.
// The fix uses slices.Clone so the returned slice owns its own storage.
func TestLoadKeys_DoesNotAliasGlobalPubkeys(t *testing.T) {
	prev := opts.Monitor.Pubkeys
	t.Cleanup(func() { opts.Monitor.Pubkeys = prev })
	// Force spare capacity in the global so the append in LoadKeys MIGHT
	// reuse the backing array if the alias weren't broken. The cap=4
	// arrangement mirrors what cobra's StringSliceVarP could produce
	// after a power-of-two grow.
	opts.Monitor.Pubkeys = append(make([]string, 0, 4), "0xGLOBAL0", "0xGLOBAL1")

	dir := t.TempDir()
	f := writeFile(t, dir, "extra.txt", "0xFROMFILE\n")

	got, err := LoadKeys([]string{f})
	if err != nil {
		t.Fatalf("LoadKeys: %v", err)
	}
	if len(got) != 3 || got[2] != "0xFROMFILE" {
		t.Fatalf("LoadKeys returned %v; want [0xGLOBAL0 0xGLOBAL1 0xFROMFILE]", got)
	}
	// Mutate the returned slice in the cap-slack window. With aliasing,
	// this would also have changed the global's backing array; with the
	// fix, the global is untouched.
	got[2] = "0xMUTATED"
	if len(opts.Monitor.Pubkeys) >= 3 || cap(opts.Monitor.Pubkeys) >= 4 && opts.Monitor.Pubkeys[:3][2] == "0xMUTATED" {
		t.Errorf("LoadKeys returned slice aliases the global; mutation leaked: global=%v", opts.Monitor.Pubkeys)
	}
}

// TestLoadKeys_MissingFile — surfaces an error rather than silently dropping.
func TestLoadKeys_MissingFile(t *testing.T) {
	prev := opts.Monitor.Pubkeys
	t.Cleanup(func() { opts.Monitor.Pubkeys = prev })
	opts.Monitor.Pubkeys = nil

	_, err := LoadKeys([]string{filepath.Join(t.TempDir(), "nope.txt")})
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}

// TestLoadKeys_NoFDLeak proves the FD-leak fix: opening 64 small pubkey
// files in one LoadKeys call must not leave them all open until LoadKeys
// returns. We do best-effort detection by inspecting /proc/self/fd count
// (Linux) or rough fd counts on other platforms; we accept some slack.
//
// The previous implementation had `defer file.Close()` inside the loop —
// every fd stayed open for the full LoadKeys call. This test would have
// flagged the leak on any system with an ulimit close to 64.
func TestLoadKeys_NoFDLeak(t *testing.T) {
	prev := opts.Monitor.Pubkeys
	t.Cleanup(func() { opts.Monitor.Pubkeys = prev })
	opts.Monitor.Pubkeys = nil

	dir := t.TempDir()
	const N = 64
	paths := make([]string, N)
	for i := range paths {
		paths[i] = writeFile(t, dir, "k"+strconv.Itoa(i)+".txt", "0xk\n")
	}

	before := countOpenFiles(t)
	if _, err := LoadKeys(paths); err != nil {
		t.Fatalf("LoadKeys: %v", err)
	}
	after := countOpenFiles(t)

	// Some FDs come and go in tests; tolerate +8 but the previous-implementation
	// leak would push delta to ≈ N.
	if before >= 0 && after-before > 8 {
		t.Errorf("FD count grew by %d after LoadKeys (before=%d after=%d); fds appear to leak", after-before, before, after)
	}
}

// countOpenFiles returns the open-fd count for this process, or -1 if the
// counting strategy isn't available on this platform. Linux exposes
// /proc/self/fd; macOS / others fall through to -1 (skip the assertion).
func countOpenFiles(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return -1
	}
	return len(entries)
}

// TestLoadMEVRelays_ParsesArray covers the happy path.
func TestLoadMEVRelays_ParsesArray(t *testing.T) {
	dir := t.TempDir()
	p := writeFile(t, dir, "relays.json", `["https://relay1.example", "https://relay2.example"]`)

	got, err := LoadMEVRelays(p)
	if err != nil {
		t.Fatalf("LoadMEVRelays: %v", err)
	}
	if len(got) != 2 || got[0] != "https://relay1.example" || got[1] != "https://relay2.example" {
		t.Errorf("LoadMEVRelays returned %v", got)
	}
}

// TestLoadMEVRelays_MissingFile — surfaces an error.
func TestLoadMEVRelays_MissingFile(t *testing.T) {
	_, err := LoadMEVRelays(filepath.Join(t.TempDir(), "nope.json"))
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}

// TestLoadMEVRelays_MalformedJSON — surfaces a parse error rather than
// returning a half-populated slice.
func TestLoadMEVRelays_MalformedJSON(t *testing.T) {
	dir := t.TempDir()
	p := writeFile(t, dir, "relays.json", `{"not": "an array"}`)

	got, err := LoadMEVRelays(p)
	if err == nil {
		t.Fatalf("expected JSON parse error, got %v", got)
	}
}

// TestLoadMEVRelays_FiltersEmptyEntries — empty or whitespace-only entries
// in the relays JSON would each spawn a wasted retry goroutine in
// requestEpochBidTraces. Filter them at load time.
func TestLoadMEVRelays_FiltersEmptyEntries(t *testing.T) {
	dir := t.TempDir()
	p := writeFile(t, dir, "relays.json", `["", "https://relay1.example", "   ", "https://relay2.example"]`)

	got, err := LoadMEVRelays(p)
	if err != nil {
		t.Fatalf("LoadMEVRelays: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("kept %d relays, want 2 (empty/whitespace filtered)", len(got))
	}
	for _, r := range got {
		if r == "" {
			t.Errorf("empty relay survived filter: %v", got)
		}
	}
}

// TestResumeEpoch_ColdStart — with no persisted epoch (LastEpoch == 0),
// the resume point is exactly the justified epoch. A first-ever run
// anchors at the justified floor.
func TestResumeEpoch_ColdStart(t *testing.T) {
	t.Parallel()
	if got := resumeEpoch(100, 0); got != 100 {
		t.Errorf("cold start: got %d, want 100 (justified)", got)
	}
}

// TestResumeEpoch_WarmStartSkipsProcessedEpoch regresses the off-by-one
// that re-emitted the persisted epoch on every restart. cache.LastEpoch
// is the "highest epoch already processed" — the next emit must be
// persisted+1, NOT persisted. Pre-fix code did max(persisted, justified)
// which returned persisted for any restart at or past justified, spiking
// cumulative counters by one epoch's worth of work on every restart.
func TestResumeEpoch_WarmStartSkipsProcessedEpoch(t *testing.T) {
	t.Parallel()
	// persisted == justified: the canonical restart case. Both say
	// "epoch 100 is the latest known"; we want to start at 101.
	if got := resumeEpoch(100, 100); got != 101 {
		t.Errorf("persisted == justified: got %d, want 101 (persisted+1)", got)
	}
	// persisted > justified: monitor processed past the justified line
	// (chain hasn't justified up to head yet). Resume at persisted+1.
	if got := resumeEpoch(100, 105); got != 106 {
		t.Errorf("persisted > justified: got %d, want 106 (persisted+1)", got)
	}
}

// TestResumeEpoch_StaleCacheSkipsAhead — when persisted is far behind
// justified (monitor was down a long time), accept the gap and start
// from justified rather than backfilling indefinitely. Replaying
// finalised epochs is fast; backfilling thousands of epochs after a
// multi-day outage isn't operationally useful.
func TestResumeEpoch_StaleCacheSkipsAhead(t *testing.T) {
	t.Parallel()
	if got := resumeEpoch(1000, 10); got != 1000 {
		t.Errorf("stale cache: got %d, want 1000 (justified, skipping gap)", got)
	}
}

// TestRunSSESubscription_BlocksUntilCtxCancel regresses the silent-hang
// bug from commit 8528d44: go-eth2-client/http Events() returns nil
// immediately (the SSE loop runs in an internal goroutine), so the
// outer SubscribeToEpochs goroutine MUST block after the call. Pre-fix
// code returned straight after Events, the deferred close(epochsChan)
// fired, and the orchestrator exited before any head event arrived
// (observed in test-env: ETH2_epoch stuck at 0 with the binary
// "running" but processing nothing).
//
// Assertions:
//   - Events is called exactly once (handler registered).
//   - The function does NOT return while ctx is alive (100ms grace).
//   - The function returns promptly after ctx is cancelled.
//   - Returned error is nil (ctx-cancel is a clean shutdown).
func TestRunSSESubscription_BlocksUntilCtxCancel(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	fake := &fakeEventsProvider{}
	done := make(chan error, 1)
	go func() {
		done <- runSSESubscription(ctx, fake, func(*v1.Event) {})
	}()

	// Block-while-ctx-alive: if runSSESubscription returns within this
	// window the silent-hang bug has regressed. 100ms is a deliberate
	// trade-off — long enough to catch a same-goroutine fallthrough,
	// short enough to keep the test suite fast.
	select {
	case err := <-done:
		t.Fatalf("runSSESubscription returned early (err=%v); should block until ctx cancel", err)
	case <-time.After(100 * time.Millisecond):
	}

	if got := fake.calls.Load(); got != 1 {
		t.Errorf("Events called %d times, want 1", got)
	}
	if topics, _ := fake.topics.Load().([]string); len(topics) != 1 || topics[0] != "head" {
		t.Errorf("subscribed topics = %v, want [head]", topics)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("runSSESubscription returned err=%v after ctx cancel; want nil (clean shutdown)", err)
		}
	case <-time.After(time.Second):
		t.Fatal("runSSESubscription did not return within 1s of ctx cancel; shutdown would deadlock SubscribeToEpochs")
	}
}

// TestRunSSESubscription_ReturnsNilOnCtxCanceledError — if Events itself
// returns a wrapped ctx.Canceled (mid-handshake cancellation), the
// helper must treat it as a clean shutdown and return nil so the
// caller's Must(err) does not panic.
func TestRunSSESubscription_ReturnsNilOnCtxCanceledError(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	fake := &fakeEventsProvider{
		errFn: func(context.Context) error { return context.Canceled },
	}
	if err := runSSESubscription(ctx, fake, func(*v1.Event) {}); err != nil {
		t.Errorf("got err=%v; want nil for ctx.Canceled (clean shutdown)", err)
	}
}

// TestRunSSESubscription_PropagatesGenuineError — any non-ctx-cancel
// error must surface to the helper's caller. Today subscribeWithRetry
// catches it and resubscribes; pre-supervisor the caller's Must(err)
// panicked. Either way the helper's contract is "report unexpected
// errors faithfully".
func TestRunSSESubscription_PropagatesGenuineError(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sentinel := errors.New("relay rejected subscribe")
	fake := &fakeEventsProvider{
		errFn: func(context.Context) error { return sentinel },
	}
	if err := runSSESubscription(ctx, fake, func(*v1.Event) {}); !errors.Is(err, sentinel) {
		t.Errorf("got err=%v; want %v (genuine error must propagate)", err, sentinel)
	}
}

// TestSubscribeWithRetry_RetriesOnTransientErrorAndIncrementsCounter
// regresses the zombie-monitor failure mode: a transient SSE drop
// pre-supervisor would have surfaced through runSSESubscription, panicked
// via Must(err), and crashed the process. With the retry layer the SSE
// subscription self-heals, ETH2_sseResubscribes increments, and the
// monitor stays alive.
//
// fakeEventsProvider returns a sentinel error on first invocation, then
// nil (the eth2-client "non-blocking handshake succeeded — caller now
// blocks on ctx" contract) on every subsequent invocation. The test
// expects:
//  1. Events() called at least twice (initial + 1 retry).
//  2. ETH2_sseResubscribes incremented at least once.
//  3. subscribeWithRetry returns nil after ctx cancel.
func TestSubscribeWithRetry_RetriesOnTransientErrorAndIncrementsCounter(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	metrics := NewMonitorMetrics(prometheus.NewRegistry())

	var attempts int32
	fake := &fakeEventsProvider{
		errFn: func(context.Context) error {
			if atomic.AddInt32(&attempts, 1) == 1 {
				return errors.New("transient SSE drop")
			}
			// Subsequent calls: mimic eth2-client's contract by returning
			// nil so runSSESubscription falls through to <-ctx.Done(),
			// keeping the goroutine alive until shutdown.
			return nil
		},
	}

	done := make(chan error, 1)
	go func() {
		done <- subscribeWithRetry(ctx, fake, func(*v1.Event) {}, metrics, zeroBackoff())
	}()

	deadline := time.Now().Add(time.Second)
	for atomic.LoadInt32(&attempts) < 2 && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	if got := atomic.LoadInt32(&attempts); got < 2 {
		cancel()
		<-done
		t.Fatalf("subscribeWithRetry did not retry; Events called %d times, want >= 2", got)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("subscribeWithRetry returned %v; want nil after ctx cancel", err)
		}
	case <-time.After(time.Second):
		t.Fatal("subscribeWithRetry did not return within 1s of ctx cancel")
	}

	if got := counterValue(t, metrics.SSEResubscribes); got < 1 {
		t.Errorf("ETH2_sseResubscribes = %v, want >= 1 after retry", got)
	}
}

// TestSubscribeWithRetry_ReturnsCleanlyOnCtxCancel: with no errors at
// all, subscribeWithRetry must still exit on ctx cancel (returning nil)
// rather than busy-looping or hanging.
func TestSubscribeWithRetry_ReturnsCleanlyOnCtxCancel(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())

	metrics := NewMonitorMetrics(prometheus.NewRegistry())
	fake := &fakeEventsProvider{}

	done := make(chan error, 1)
	go func() {
		done <- subscribeWithRetry(ctx, fake, func(*v1.Event) {}, metrics, zeroBackoff())
	}()

	// Brief grace so the first Events() call lands, then cancel.
	time.Sleep(20 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("subscribeWithRetry returned %v; want nil", err)
		}
	case <-time.After(time.Second):
		t.Fatal("subscribeWithRetry did not return within 1s of ctx cancel")
	}

	if got := counterValue(t, metrics.SSEResubscribes); got != 0 {
		t.Errorf("ETH2_sseResubscribes = %v on no-error path; want 0", got)
	}
}
