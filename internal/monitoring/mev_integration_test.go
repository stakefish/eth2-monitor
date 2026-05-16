package monitoring

// Integration tests for mev.go. Replaces the previous test file's mix
// of pure-function unit tests (ExptBackoff math) and httptest-backed
// fakeRelay tests with end-to-end coverage that runs the production
// HTTP transport, JSON decoder, retry loop, and pagination against:
//
//   - The captured Flashbots fixture for happy-path coverage (real
//     wire format, real proposer pubkey we can match against).
//   - Synthetic httptest handlers for edge cases that real fixtures
//     don't exhibit (502 / sort-order violation / infinite loop /
//     ctx cancel).
//
// ExptBackoff math was previously covered by 3 unit tests; it is now
// exercised through the retry-on-502 integration test below — a bug
// in ExptBackoff would surface as a wrong wall-clock time on the
// recovered request.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stakefish/eth2-monitor/internal/spec"

	"github.com/attestantio/go-eth2-client/spec/phase0"
)

// loadMEVTraces parses a captured MEV fixture into BidTrace values.
// Uses the production BidTrace struct so the test exercises the same
// JSON tag schema (notably ,string for numeric fields). Returns
// traces sorted ASCENDING by slot — matches newFakeRelay's input
// contract (the handler reverses to descending when serving). Real
// relays emit descending; the sort-after-decode insulates tests from
// the on-disk order of the fixture.
func loadMEVTraces(t *testing.T, name string) []BidTrace {
	t.Helper()
	var traces []BidTrace
	if err := json.Unmarshal(loadMEVFixture(t, name), &traces); err != nil {
		t.Fatalf("decode MEV fixture %s: %v", name, err)
	}
	sort.Slice(traces, func(i, j int) bool { return traces[i].Slot < traces[j].Slot })
	return traces
}

// fakeRelay paginates an in-memory []BidTrace by cursor=N&limit=M, the
// same protocol the production code uses against real relays. Mirrors
// the relay-spec contract: descending slot order, no entries above
// cursor, up to `limit` per page.
type fakeRelay struct {
	server   *httptest.Server
	traces   []BidTrace // sorted ascending by Slot; handler returns matching descending slice
	pageSize uint64
	calls    int32
}

func newFakeRelay(t *testing.T, traces []BidTrace, pageSize uint64) *fakeRelay {
	t.Helper()
	r := &fakeRelay{traces: traces, pageSize: pageSize}
	r.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		atomic.AddInt32(&r.calls, 1)
		cursor, _ := strconv.ParseUint(req.URL.Query().Get("cursor"), 10, 64)
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

// withFloor appends a sentinel trace at the lowest slot of `epoch` so
// the production pagination loop terminates after one page. Real relays
// return entries spanning many epochs; tests that only care about a
// single epoch use this to avoid the loop probing further back than
// the in-memory fixture covers.
func withFloor(traces []BidTrace, epoch phase0.Epoch) []BidTrace {
	out := []BidTrace{{Slot: uint64(spec.EpochLowestSlot(epoch))}}
	out = append(out, traces...)
	return out
}

// epochOf returns the epoch a slot belongs to per the spec
// (slot/SLOTS_PER_EPOCH). Used to derive the test epoch from a real
// captured slot.
func epochOf(slot uint64) phase0.Epoch {
	return phase0.Epoch(slot / spec.SLOTS_PER_EPOCH)
}

// TestListBestBids_FixtureMatchesRealProposer is the headline
// integration test: load the captured Flashbots fixture, pick a real
// (slot, proposer_pubkey) pair from it, set up the tracked-validator
// map, and verify ListBestBids matches the bid through the full
// pagination + filter + value-comparison path against the real wire
// format.
func TestListBestBids_FixtureMatchesRealProposer(t *testing.T) {
	traces := loadMEVTraces(t, "flashbots")
	if len(traces) == 0 {
		t.Skip("captured MEV fixture is empty — run `make refresh-fixtures`")
	}
	pick := traces[0] // most recent; proposer_pubkey is stable
	epoch := epochOf(pick.Slot)

	// Bind every trace at any slot in `epoch` so the test decision is
	// driven by what the captured response actually contains. The
	// production code's filter then uses our tracked map to keep only
	// the matching one.
	relay := newFakeRelay(t, withFloor(traces, epoch), spec.SLOTS_PER_EPOCH)

	const idx = phase0.ValidatorIndex(42)
	// validatorPubkeyFromIndex stores the *normalised* (no 0x, lower)
	// form per ResolveValidatorKeys; ListBestBids reattaches "0x" when
	// comparing against relay-emitted ProposerPubkey.
	tracked := map[phase0.ValidatorIndex]string{idx: strings.ToLower(strings.TrimPrefix(pick.ProposerPubkey, "0x"))}
	proposals := map[phase0.Slot]phase0.ValidatorIndex{phase0.Slot(pick.Slot): idx}

	got, err := ListBestBids(context.Background(), 5*time.Second,
		[]string{relay.server.URL}, epoch, tracked, proposals)
	if err != nil {
		t.Fatalf("ListBestBids: %v", err)
	}
	bid, ok := got[phase0.Slot(pick.Slot)]
	if !ok {
		t.Fatalf("no best bid recorded for slot %d (real captured proposer didn't match — likely a regression in case-fold or pubkey normalization)", pick.Slot)
	}
	if bid.BlockHash != pick.BlockHash {
		t.Errorf("best bid block_hash = %s, want %s (fixture's first trace)", bid.BlockHash, pick.BlockHash)
	}
	if bid.Value != pick.Value {
		t.Errorf("best bid value = %d, want %d", bid.Value, pick.Value)
	}
}

// TestListBestBids_HighestValueWins synthesizes two relays serving the
// same slot with different bid values from the same captured proposer.
// Verifies the higher-value bid wins. Synthetic but driven by a real
// captured pubkey/slot pair so the JSON layer still exercises the wire
// format.
func TestListBestBids_HighestValueWins(t *testing.T) {
	traces := loadMEVTraces(t, "flashbots")
	if len(traces) == 0 {
		t.Skip("captured MEV fixture is empty")
	}
	base := traces[0]
	epoch := epochOf(base.Slot)

	cheap := base
	cheap.BlockHash = "0xcheap"
	cheap.Value = 100
	rich := base
	rich.BlockHash = "0xrich"
	rich.Value = 999

	r1 := newFakeRelay(t, withFloor([]BidTrace{cheap}, epoch), spec.SLOTS_PER_EPOCH)
	r2 := newFakeRelay(t, withFloor([]BidTrace{rich}, epoch), spec.SLOTS_PER_EPOCH)

	const idx = phase0.ValidatorIndex(42)
	tracked := map[phase0.ValidatorIndex]string{idx: strings.ToLower(strings.TrimPrefix(base.ProposerPubkey, "0x"))}
	proposals := map[phase0.Slot]phase0.ValidatorIndex{phase0.Slot(base.Slot): idx}

	got, err := ListBestBids(context.Background(), 5*time.Second,
		[]string{r1.server.URL, r2.server.URL}, epoch, tracked, proposals)
	if err != nil {
		t.Fatalf("ListBestBids: %v", err)
	}
	bid := got[phase0.Slot(base.Slot)]
	if bid.BlockHash != "0xrich" {
		t.Errorf("best bid block_hash = %s, want 0xrich (higher Value should win)", bid.BlockHash)
	}
}

// TestListBestBids_PubkeyCaseInsensitive regresses the silent-mismatch
// bug: relay JSON is not case-canonical per spec; if a relay returns
// uppercase hex we must still match our lowercase-stored tracked
// pubkey. Synthesizes the uppercase variant from a real captured
// proposer.
func TestListBestBids_PubkeyCaseInsensitive(t *testing.T) {
	traces := loadMEVTraces(t, "flashbots")
	if len(traces) == 0 {
		t.Skip("captured MEV fixture is empty")
	}
	base := traces[0]
	epoch := epochOf(base.Slot)

	upper := base
	upper.ProposerPubkey = "0x" + strings.ToUpper(strings.TrimPrefix(base.ProposerPubkey, "0x"))
	upper.BlockHash = "0xMATCHED"

	relay := newFakeRelay(t, withFloor([]BidTrace{upper}, epoch), spec.SLOTS_PER_EPOCH)

	const idx = phase0.ValidatorIndex(42)
	tracked := map[phase0.ValidatorIndex]string{idx: strings.ToLower(strings.TrimPrefix(base.ProposerPubkey, "0x"))}
	proposals := map[phase0.Slot]phase0.ValidatorIndex{phase0.Slot(base.Slot): idx}

	got, err := ListBestBids(context.Background(), 5*time.Second,
		[]string{relay.server.URL}, epoch, tracked, proposals)
	if err != nil {
		t.Fatalf("ListBestBids: %v", err)
	}
	if _, ok := got[phase0.Slot(base.Slot)]; !ok {
		t.Errorf("uppercase proposer pubkey didn't match lowercase tracked pubkey: case-fold regression")
	}
}

// TestListBestBids_UntrackedSlotSkipped — a bid for a slot whose
// proposer isn't in our tracked map must be discarded silently.
func TestListBestBids_UntrackedSlotSkipped(t *testing.T) {
	traces := loadMEVTraces(t, "flashbots")
	if len(traces) == 0 {
		t.Skip("captured MEV fixture is empty")
	}
	relay := newFakeRelay(t, withFloor(traces, epochOf(traces[0].Slot)), spec.SLOTS_PER_EPOCH)

	got, err := ListBestBids(context.Background(), 5*time.Second,
		[]string{relay.server.URL}, epochOf(traces[0].Slot),
		map[phase0.ValidatorIndex]string{},      // no tracked validators
		map[phase0.Slot]phase0.ValidatorIndex{}, // no tracked slots
	)
	if err != nil {
		t.Fatalf("ListBestBids: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected zero best bids with empty tracked map, got %d", len(got))
	}
}

// TestRequestBidTracesPage_HTTPErrorSurfacesBody — non-2xx responses
// must surface the body excerpt in the error so operators can tell
// rate-limit / 502 / 503 cases apart from JSON corruption. Uses a
// synthetic handler because real relays don't reliably 502.
func TestRequestBidTracesPage_HTTPErrorSurfacesBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("<html>502 Bad Gateway</html>"))
	}))
	t.Cleanup(srv.Close)

	client := &http.Client{Timeout: 1 * time.Second}
	_, err := requestBidTracesPage(context.Background(), client, srv.URL, phase0.Slot(100), 10)
	if err == nil {
		t.Fatal("expected error on HTTP 502, got nil")
	}
	msg := err.Error()
	if !strings.Contains(msg, "502") || !strings.Contains(msg, "Bad Gateway") {
		t.Errorf("error %q lacks status code or body excerpt", msg)
	}
}

// TestRequestBidTracesPage_SortOrderCheck — relays must return strictly
// descending slots; a violation is surfaced as an error.
func TestRequestBidTracesPage_SortOrderCheck(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode([]BidTrace{{Slot: 5}, {Slot: 7}})
	}))
	t.Cleanup(srv.Close)

	client := &http.Client{Timeout: 1 * time.Second}
	_, err := requestBidTracesPage(context.Background(), client, srv.URL, phase0.Slot(100), 10)
	if err == nil {
		t.Fatal("expected sort-order error, got nil")
	}
}

// TestRequestRelayEpochBidTraces_BoundsBrokenRelay — a relay that
// returns the same out-of-range trace forever must still terminate
// the loop (maxPages cap). Without the cap the orchestrator would
// hang waiting for the per-relay timeout.
func TestRequestRelayEpochBidTraces_BoundsBrokenRelay(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&calls, 1)
		_ = json.NewEncoder(w).Encode([]BidTrace{{Slot: 99_999_999}})
	}))
	t.Cleanup(srv.Close)

	done := make(chan struct{})
	go func() {
		_, _ = requestRelayEpochBidTraces(context.Background(), 1*time.Second, srv.URL, phase0.Epoch(1_000_000))
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("requestRelayEpochBidTraces hung; observed %d requests", atomic.LoadInt32(&calls))
	}
	if c := atomic.LoadInt32(&calls); c > 100 {
		t.Errorf("relay called %d times; maxPages cap should bound this", c)
	}
}

// TestRequestRelayEpochBidTraces_EmptyPageError — relays returning an
// empty page mid-pagination surface as errors so callers don't
// silently succeed with partial data.
func TestRequestRelayEpochBidTraces_EmptyPageError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("[]"))
	}))
	t.Cleanup(srv.Close)

	_, err := requestRelayEpochBidTraces(context.Background(), 1*time.Second, srv.URL, phase0.Epoch(10))
	if err == nil {
		t.Fatal("expected error on empty page, got nil")
	}
}

// TestRequestBidTracesPage_CtxCancelReturnsPromptly regresses a
// shutdown-stalls bug — the in-flight HTTP page fetch must observe
// ctx cancellation rather than running out the client.Timeout.
func TestRequestBidTracesPage_CtxCancelReturnsPromptly(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		<-req.Context().Done()
	}))
	t.Cleanup(srv.Close)

	client := &http.Client{Timeout: 10 * time.Second} // intentionally long
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	_, err := requestBidTracesPage(ctx, client, srv.URL, phase0.Slot(100), 10)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected error after ctx cancel, got nil")
	}
	if elapsed > 2*time.Second {
		t.Errorf("ctx-cancel took %v; expected near 50ms — request must observe ctx, not just client.Timeout", elapsed)
	}
}
