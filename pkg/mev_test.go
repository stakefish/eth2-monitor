package pkg

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"eth2-monitor/spec"

	"github.com/attestantio/go-eth2-client/spec/phase0"
)

// TestExptBackoff_Increasing — first cycle yields delays whose midpoints
// roughly double: base, 2*base, 4*base, 8*base, 16*base. We tolerate jitter
// of up to +base on each step.
func TestExptBackoff_Increasing(t *testing.T) {
	const base = 100 * time.Millisecond
	const maxExp = uint(4)

	var got []time.Duration
	for d := range exptBackoff(base, maxExp) {
		got = append(got, d)
		if len(got) == int(maxExp)+1 {
			break
		}
	}

	if len(got) != int(maxExp)+1 {
		t.Fatalf("yielded %d delays, want %d", len(got), maxExp+1)
	}
	want := []time.Duration{base, 2 * base, 4 * base, 8 * base, 16 * base}
	for i, d := range got {
		// jitter is [0, base) so each delay lives in [want, want+base).
		if d < want[i] || d >= want[i]+base {
			t.Errorf("delay[%d] = %v, want [%v, %v)", i, d, want[i], want[i]+base)
		}
	}
}

// TestExptBackoff_Cycles — once maxExponent+1 yields are consumed, the
// sequence resets to base. Documents the implementation's recovery behaviour.
func TestExptBackoff_Cycles(t *testing.T) {
	const base = 50 * time.Millisecond
	const maxExp = uint(2) // 3 yields per cycle

	var got []time.Duration
	for d := range exptBackoff(base, maxExp) {
		got = append(got, d)
		if len(got) == 6 { // two full cycles
			break
		}
	}

	if got[0] >= 2*base { // first delay must be near base
		t.Errorf("delay[0] = %v, want near %v", got[0], base)
	}
	if got[3] >= 2*base { // first delay of second cycle must reset to base
		t.Errorf("delay[3] = %v, want near %v (cycle reset)", got[3], base)
	}
}

// TestExptBackoff_SubMillisecondBaseDoesNotPanic regresses the rand.Uint()%0
// crash. baseMillis = 0 used to make the next loop iteration panic with
// "integer divide by zero".
func TestExptBackoff_SubMillisecondBaseDoesNotPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("exptBackoff panicked on sub-ms base: %v", r)
		}
	}()
	const base = 500 * time.Microsecond // < 1ms
	seq := exptBackoff(base, 0)
	for d := range seq {
		_ = d
		break
	}
}

// fakeRelay serves canned bidtraces JSON paged by cursor. It also counts
// requests so tests can assert pagination behaviour.
type fakeRelay struct {
	server   *httptest.Server
	traces   []BidTrace // sorted slot ASC; handler returns matching slice descending
	pageSize uint64
	calls    int32
}

func newFakeRelay(t *testing.T, traces []BidTrace, pageSize uint64) *fakeRelay {
	t.Helper()
	r := &fakeRelay{traces: traces, pageSize: pageSize}
	r.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		atomic.AddInt32(&r.calls, 1)
		cursor, _ := strconv.ParseUint(req.URL.Query().Get("cursor"), 10, 64)
		// Filter to traces.Slot <= cursor, return up to pageSize, sorted DESC.
		var out []BidTrace
		for i := len(r.traces) - 1; i >= 0; i-- {
			if r.traces[i].Slot <= cursor {
				out = append(out, r.traces[i])
				if uint64(len(out)) == r.pageSize {
					break
				}
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	}))
	t.Cleanup(r.server.Close)
	return r
}

// TestRequestBidTracesPage_HTTPErrorSurfacesBody — when a relay returns
// non-2xx, the error message must include the response body (or its prefix)
// so operators can tell rate-limit / 502 / 503 cases apart from genuine
// JSON corruption. Pre-fix code surfaced "json: invalid character '<'".
func TestRequestBidTracesPage_HTTPErrorSurfacesBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("<html>502 Bad Gateway</html>"))
	}))
	t.Cleanup(srv.Close)

	client := &http.Client{Timeout: time.Second}
	_, err := requestBidTracesPage(client, srv.URL, phase0.Slot(100), 10)
	if err == nil {
		t.Fatal("expected error on HTTP 502, got nil")
	}
	msg := err.Error()
	if !contains(msg, "502") || !contains(msg, "Bad Gateway") {
		t.Errorf("error %q lacks status code or body excerpt", msg)
	}
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

// TestRequestBidTracesPage_SortOrderCheck — relays must return slots in
// strict descending order. If two adjacent entries violate that, we
// surface an error so a buggy relay doesn't silently mis-aggregate.
func TestRequestBidTracesPage_SortOrderCheck(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Slot 5 then slot 7 — violates descending invariant.
		_ = json.NewEncoder(w).Encode([]BidTrace{
			{Slot: 5}, {Slot: 7},
		})
	}))
	t.Cleanup(srv.Close)

	client := &http.Client{Timeout: time.Second}
	_, err := requestBidTracesPage(client, srv.URL, phase0.Slot(100), 10)
	if err == nil {
		t.Fatal("expected sort-order error, got nil")
	}
}

// TestRequestRelayEpochBidTraces_FiltersToEpoch — only traces whose slot
// falls in [epochLow, epochHigh] are kept; out-of-range traces are
// dropped even if the relay returns them.
func TestRequestRelayEpochBidTraces_FiltersToEpoch(t *testing.T) {
	epoch := phase0.Epoch(10)
	low := uint64(spec.EpochLowestSlot(epoch))
	high := uint64(spec.EpochHighestSlot(epoch))

	traces := []BidTrace{
		{Slot: low - 1, BlockHash: "0xpre"},
		{Slot: low + 4, BlockHash: "0xin1"},
		{Slot: high, BlockHash: "0xin2"},
		{Slot: high + 1, BlockHash: "0xpost"},
	}
	r := newFakeRelay(t, traces, spec.SLOTS_PER_EPOCH)

	got, err := requestRelayEpochBidTraces(2*time.Second, r.server.URL, epoch)
	if err != nil {
		t.Fatalf("requestRelayEpochBidTraces: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("kept %d traces, want 2 (filtered to epoch range)", len(got))
	}
	for _, tr := range got {
		if tr.Slot < low || tr.Slot > high {
			t.Errorf("trace slot %v outside epoch range [%v, %v]", tr.Slot, low, high)
		}
	}
}

// TestRequestRelayEpochBidTraces_NoInfiniteLoopOnLowEpoch is the regression
// test for the uint64 slot underflow. With epoch=0 (epochLowestSlot=0) and
// a relay that never returns a trace at slot 0, the pre-fix code would
// subtract SLOTS_PER_EPOCH from slot=31, wrap to ~maxUint64, and loop forever
// with the relay returning recent traces that the filter discarded.
//
// The defensive break must terminate the loop. We bound the test with a
// short timeout — if the loop is unbounded the test hangs and fails on
// timeout via t.Deadline().
func TestRequestRelayEpochBidTraces_NoInfiniteLoopOnLowEpoch(t *testing.T) {
	var callCount int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&callCount, 1)
		// Always return one trace at a high slot (well above epoch 0's range).
		// Filter will drop it; loop must still terminate.
		_ = json.NewEncoder(w).Encode([]BidTrace{{Slot: 999}})
	}))
	t.Cleanup(srv.Close)

	done := make(chan error, 1)
	go func() {
		_, err := requestRelayEpochBidTraces(time.Second, srv.URL, phase0.Epoch(0))
		done <- err
	}()

	select {
	case <-done:
		// Loop terminated (with or without error) — we just need it to NOT hang.
	case <-time.After(2 * time.Second):
		t.Fatalf("requestRelayEpochBidTraces hung on epoch 0 with high-slot traces; observed %d requests", atomic.LoadInt32(&callCount))
	}
	if got := atomic.LoadInt32(&callCount); got > 5 {
		t.Errorf("relay called %d times; defensive break should cap requests well below this", got)
	}
}

// TestRequestRelayEpochBidTraces_EmptyPageIsError — relays returning an
// empty page mid-pagination surface as errors so callers don't silently
// "succeed" with partial data.
func TestRequestRelayEpochBidTraces_EmptyPageIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("[]"))
	}))
	t.Cleanup(srv.Close)

	_, err := requestRelayEpochBidTraces(time.Second, srv.URL, phase0.Epoch(10))
	if err == nil {
		t.Fatal("expected error on empty page, got nil")
	}
}

// withFloor appends a sentinel trace at epochLow so requestRelayEpochBidTraces's
// pagination terminates after one page. Real relays cover the entire epoch.
func withFloor(traces []BidTrace, epoch phase0.Epoch) []BidTrace {
	out := []BidTrace{{Slot: uint64(spec.EpochLowestSlot(epoch))}}
	out = append(out, traces...)
	return out
}

// TestListBestBids_PicksHighestValuePerSlot — same slot reported by two
// relays with different bid values → keep the higher one.
func TestListBestBids_PicksHighestValuePerSlot(t *testing.T) {
	epoch := phase0.Epoch(10)
	low := uint64(spec.EpochLowestSlot(epoch))

	const pk = "abcdef" // pubkey body (no 0x prefix; ListBestBids prepends)
	const idx = phase0.ValidatorIndex(42)

	cheapTrace := BidTrace{Slot: low + 3, BlockHash: "0xcheap", ProposerPubkey: "0x" + pk, Value: 100}
	richTrace := BidTrace{Slot: low + 3, BlockHash: "0xrich", ProposerPubkey: "0x" + pk, Value: 999}

	relay1 := newFakeRelay(t, withFloor([]BidTrace{cheapTrace}, epoch), spec.SLOTS_PER_EPOCH)
	relay2 := newFakeRelay(t, withFloor([]BidTrace{richTrace}, epoch), spec.SLOTS_PER_EPOCH)

	got, err := ListBestBids(
		context.Background(), 2*time.Second,
		[]string{relay1.server.URL, relay2.server.URL},
		epoch,
		map[phase0.ValidatorIndex]string{idx: pk},
		map[phase0.Slot]phase0.ValidatorIndex{phase0.Slot(low + 3): idx},
	)
	if err != nil {
		t.Fatalf("ListBestBids: %v", err)
	}
	bid, ok := got[phase0.Slot(low+3)]
	if !ok {
		t.Fatalf("no best bid recorded for slot %v", low+3)
	}
	if bid.BlockHash != "0xrich" {
		t.Errorf("best-bid block hash = %q, want %q (higher Value should win)", bid.BlockHash, "0xrich")
	}
}

// TestListBestBids_SkipsUntrackedSlots — bid traces for slots whose
// proposer isn't in our `proposals` map (i.e. not a tracked-validator slot)
// must be discarded, not stored under a different slot/validator.
func TestListBestBids_SkipsUntrackedSlots(t *testing.T) {
	epoch := phase0.Epoch(10)
	low := uint64(spec.EpochLowestSlot(epoch))

	relay := newFakeRelay(t, withFloor([]BidTrace{
		{Slot: low + 5, BlockHash: "0xstale", ProposerPubkey: "0xother", Value: 1},
	}, epoch), spec.SLOTS_PER_EPOCH)

	got, err := ListBestBids(
		context.Background(), 2*time.Second,
		[]string{relay.server.URL},
		epoch,
		map[phase0.ValidatorIndex]string{},      // empty: no tracked pubkeys
		map[phase0.Slot]phase0.ValidatorIndex{}, // empty: no proposals
	)
	if err != nil {
		t.Fatalf("ListBestBids: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected zero best bids, got %d", len(got))
	}
}

// TestListBestBids_PubkeyMismatchSkipped — trace exists for our slot but
// the relay's reported proposer_pubkey doesn't match our tracked validator;
// must skip silently (relay may have stale or wrong data).
func TestListBestBids_PubkeyMismatchSkipped(t *testing.T) {
	epoch := phase0.Epoch(10)
	low := uint64(spec.EpochLowestSlot(epoch))

	const pk = "abcdef"
	const idx = phase0.ValidatorIndex(42)

	relay := newFakeRelay(t, withFloor([]BidTrace{
		// Slot matches but ProposerPubkey doesn't match our tracked pubkey
		{Slot: low + 5, ProposerPubkey: "0xdifferent", Value: 1},
	}, epoch), spec.SLOTS_PER_EPOCH)

	got, err := ListBestBids(
		context.Background(), 2*time.Second,
		[]string{relay.server.URL},
		epoch,
		map[phase0.ValidatorIndex]string{idx: pk},
		map[phase0.Slot]phase0.ValidatorIndex{phase0.Slot(low + 5): idx},
	)
	if err != nil {
		t.Fatalf("ListBestBids: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected zero best bids on pubkey mismatch, got %d", len(got))
	}
}

// Ensure we don't leak fmt for the constant builder. (Compile-time guard.)
var _ = fmt.Sprintf
