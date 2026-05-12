package pkg

import (
	"context"
	"errors"
	"testing"
	"time"

	"eth2-monitor/spec"

	"github.com/attestantio/go-eth2-client/spec/electra"
	"github.com/attestantio/go-eth2-client/spec/phase0"
)

// fakeFetcher records every requested slot and returns scripted responses.
// Scripting is per-slot: each call to GetBlock pops the next response off
// the slot's slice. Once a slot's slice is empty the last response is reused
// (simulates "stable" behaviour after retries succeed).
type fakeFetcher struct {
	responses map[phase0.Slot][]fakeResponse
	calls     map[phase0.Slot]int
}

type fakeResponse struct {
	block *electra.SignedBeaconBlock
	err   error
}

func newFakeFetcher() *fakeFetcher {
	return &fakeFetcher{
		responses: make(map[phase0.Slot][]fakeResponse),
		calls:     make(map[phase0.Slot]int),
	}
}

func (f *fakeFetcher) GetBlock(_ context.Context, slot phase0.Slot) (*electra.SignedBeaconBlock, error) {
	f.calls[slot]++
	seq := f.responses[slot]
	if len(seq) == 0 {
		return nil, nil
	}
	idx := f.calls[slot] - 1
	if idx >= len(seq) {
		idx = len(seq) - 1
	}
	r := seq[idx]
	return r.block, r.err
}

func blockAt(slot phase0.Slot) *electra.SignedBeaconBlock {
	return &electra.SignedBeaconBlock{
		Message: &electra.BeaconBlock{Slot: slot},
	}
}

// TestListEpochBlocks_RetriesTransientError — a single GetBlock failure that
// recovers on the next attempt must NOT result in a missed slot. The
// pre-fix code treated the first error as a missed slot, silently producing
// false missed-proposal reports for transient errors.
func TestListEpochBlocks_RetriesTransientError(t *testing.T) {
	t.Parallel()
	epoch := phase0.Epoch(10)
	low := spec.EpochLowestSlot(epoch)

	ff := newFakeFetcher()
	// All slots succeed first try except `low+5`, which fails once then succeeds.
	ff.responses[low+5] = []fakeResponse{
		{nil, errors.New("transient HTTP 502")},
		{blockAt(low + 5), nil},
	}
	// Make every slot return a block on its first call, except the flaky one.
	for s := low; s <= spec.EpochHighestSlot(epoch)+4; s++ {
		if s == low+5 {
			continue
		}
		ff.responses[s] = []fakeResponse{{blockAt(s), nil}}
	}

	got, err := listEpochBlocks(context.Background(), ff, epoch)
	if err != nil {
		t.Fatalf("listEpochBlocks: %v", err)
	}

	if _, ok := got[low+5]; !ok {
		t.Errorf("transient error caused slot %v to be treated as missed; retries should have recovered", low+5)
	}
	if ff.calls[low+5] != 2 {
		t.Errorf("flaky slot called %d times, want 2 (1 failure + 1 success)", ff.calls[low+5])
	}
}

// TestListEpochBlocks_PersistentErrorTreatedAsMissed — when all retries
// fail, ListEpochBlocks must still continue (epoch processing proceeds) and
// the slot is absent from the returned map. This is the existing
// fault-tolerance contract: a single broken slot must not crash the loop.
func TestListEpochBlocks_PersistentErrorTreatedAsMissed(t *testing.T) {
	t.Parallel()
	epoch := phase0.Epoch(10)
	low := spec.EpochLowestSlot(epoch)
	high := spec.EpochHighestSlot(epoch)

	ff := newFakeFetcher()
	for s := low; s <= high+4; s++ {
		ff.responses[s] = []fakeResponse{{blockAt(s), nil}}
	}
	ff.responses[low+7] = []fakeResponse{{nil, errors.New("persistent")}}

	got, err := listEpochBlocks(context.Background(), ff, epoch)
	if err != nil {
		t.Fatalf("listEpochBlocks: %v", err)
	}
	if _, ok := got[low+7]; ok {
		t.Errorf("persistent error slot %v should be absent (treated as missed)", low+7)
	}
	if _, ok := got[low+6]; !ok {
		t.Errorf("other slots must still be present; got missing %v", low+6)
	}
	if ff.calls[low+7] != 3 {
		t.Errorf("persistently failing slot called %d times, want 3 (maxAttempts)", ff.calls[low+7])
	}
}

// TestListEpochBlocks_MissedSlotNoLog404 — GetBlock translates 404 to
// (nil, nil); fetchBlockWithRetries must short-circuit on the first call
// (no retry, no error log noise).
func TestListEpochBlocks_MissedSlotShortCircuits(t *testing.T) {
	t.Parallel()
	epoch := phase0.Epoch(10)
	low := spec.EpochLowestSlot(epoch)

	ff := newFakeFetcher()
	// All slots return (nil, nil) ⇒ missed
	got, err := listEpochBlocks(context.Background(), ff, epoch)
	if err != nil {
		t.Fatalf("listEpochBlocks: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty result map (all slots missed), got %d entries", len(got))
	}
	if ff.calls[low] != 1 {
		t.Errorf("missed slot was retried (%d calls); 404 must short-circuit", ff.calls[low])
	}
}

// TestFetchBlockWithRetries_CtxCancelStopsBackoff — a cancelled context must
// abort the retry loop instead of sleeping out the full backoff window.
func TestFetchBlockWithRetries_CtxCancelStopsBackoff(t *testing.T) {
	t.Parallel()
	ff := newFakeFetcher()
	ff.responses[7] = []fakeResponse{
		{nil, errors.New("err1")},
		{nil, errors.New("err2")},
		{nil, errors.New("err3")},
	}

	// Cancel almost immediately; the first failure-then-backoff iteration
	// must observe ctx.Done() rather than sleeping the full 200ms.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	_, err := fetchBlockWithRetries(ctx, ff, 7, 3)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected an error on cancelled ctx, got nil")
	}
	if !errors.Is(err, context.Canceled) && err.Error() == "err3" {
		t.Errorf("expected context.Canceled or first underlying error, got %v", err)
	}
	if elapsed > 100*time.Millisecond {
		t.Errorf("retry slept through cancellation (%v); should bail near-immediately", elapsed)
	}
}
