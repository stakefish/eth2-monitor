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

	"github.com/attestantio/go-eth2-client/spec/electra"
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
	// registrations maps a lower-cased 0x pubkey to the JSON body served
	// by /relay/v1/data/validator_registration; unknown pubkeys get the
	// relay-spec HTTP 400 "no registration found". regCalls counts
	// registration requests so tests can assert the lookup is lazy.
	registrations map[string][]byte
	regCalls      int32
	// lateTraces are served only by the per-slot query (?slot=N), never by
	// the cursor-paged epoch sweep: they model a delivery the relay wrote
	// to its data API after the sweep ran (measured lag: 4-10 s after
	// slot start). slotCalls counts per-slot queries.
	lateTraces []BidTrace
	slotCalls  int32
}

func newFakeRelay(t *testing.T, traces []BidTrace, pageSize uint64) *fakeRelay {
	t.Helper()
	r := &fakeRelay{traces: traces, pageSize: pageSize}
	r.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/relay/v1/data/validator_registration" {
			atomic.AddInt32(&r.regCalls, 1)
			body, ok := r.registrations[strings.ToLower(req.URL.Query().Get("pubkey"))]
			if !ok {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"code":400,"message":"no registration found"}`))
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(body)
			return
		}
		if q := req.URL.Query().Get("slot"); q != "" {
			atomic.AddInt32(&r.slotCalls, 1)
			slot, _ := strconv.ParseUint(q, 10, 64)
			out := []BidTrace{}
			for _, tr := range append(append([]BidTrace{}, r.traces...), r.lateTraces...) {
				if tr.Slot == slot {
					out = append(out, tr)
				}
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(out)
			return
		}
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

// loadMEVRegistration parses the captured validator_registration fixture
// (written by fixturegen next to the bid-trace page, for the proposer of
// that page's first trace). Returns the raw body plus the decoded pubkey
// and fee recipient so tests can key the fake relay and assert on the
// real wire values.
func loadMEVRegistration(t *testing.T, relay string) (body []byte, pubkey, feeRecipient string) {
	t.Helper()
	var err error
	if body, err = monitoringFixtures.ReadFile("testdata/mev/" + relay + "_registration.json"); err != nil {
		t.Fatalf("read MEV registration fixture %s: %v (run `make refresh-scenario SCENARIO=mev`)", relay, err)
	}
	var reg struct {
		Message struct {
			FeeRecipient string `json:"fee_recipient"`
			Pubkey       string `json:"pubkey"`
		} `json:"message"`
	}
	if err := json.Unmarshal(body, &reg); err != nil {
		t.Fatalf("decode %s_registration.json: %v", relay, err)
	}
	if reg.Message.Pubkey == "" || reg.Message.FeeRecipient == "" {
		t.Fatalf("%s_registration.json lacks pubkey/fee_recipient — refresh fixtures", relay)
	}
	return body, reg.Message.Pubkey, reg.Message.FeeRecipient
}

// TestLookupRegistration_RegisteredFromFixture — the headline wire-format
// test: the captured flashbots registration served by a fake relay must
// resolve to Registered with the fixture's fee recipient.
func TestLookupRegistration_RegisteredFromFixture(t *testing.T) {
	body, pubkey, feeRecipient := loadMEVRegistration(t, "flashbots")
	relay := newFakeRelay(t, nil, spec.SLOTS_PER_EPOCH)
	relay.registrations = map[string][]byte{strings.ToLower(pubkey): body}

	got := LookupRegistration(context.Background(), 5*time.Second, []string{relay.server.URL}, pubkey)
	if got.Status != RegistrationRegistered {
		t.Fatalf("status = %v, want Registered", got.Status)
	}
	if !strings.EqualFold(got.FeeRecipient, feeRecipient) {
		t.Errorf("fee recipient = %s, want %s (fixture)", got.FeeRecipient, feeRecipient)
	}
}

// TestLookupRegistration_NotFoundWhenEveryRelay400s — a validator no
// configured relay knows (mev-boost never registered it) is NotFound,
// which CheckProposal reports as a broken registration path.
func TestLookupRegistration_NotFoundWhenEveryRelay400s(t *testing.T) {
	r1 := newFakeRelay(t, nil, spec.SLOTS_PER_EPOCH)
	r2 := newFakeRelay(t, nil, spec.SLOTS_PER_EPOCH)
	got := LookupRegistration(context.Background(), 5*time.Second, []string{r1.server.URL, r2.server.URL}, "0x"+strings.Repeat("ab", 48))
	if got.Status != RegistrationNotFound {
		t.Errorf("status = %v, want NotFound when every relay answers 400", got.Status)
	}
}

// TestLookupRegistration_UnknownOnRelayError — a transport/5xx failure
// with no successful relay must NOT be read as "not registered".
func TestLookupRegistration_UnknownOnRelayError(t *testing.T) {
	broken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	t.Cleanup(broken.Close)
	notFound := newFakeRelay(t, nil, spec.SLOTS_PER_EPOCH)
	got := LookupRegistration(context.Background(), 2*time.Second, []string{notFound.server.URL, broken.URL}, "0x"+strings.Repeat("ab", 48))
	if got.Status != RegistrationUnknown {
		t.Errorf("status = %v, want Unknown when a relay errored and none succeeded", got.Status)
	}
}

// registrationBody rewrites the captured registration's fee recipient and
// timestamp so tests can model relays holding different registrations
// for the same key (mev-boost registers with each relay separately, and
// a relay can hold a stale one).
func registrationBody(t *testing.T, feeRecipient string, timestamp uint64) (body []byte, pubkey string) {
	t.Helper()
	raw, pubkey, _ := loadMEVRegistration(t, "flashbots")
	var reg map[string]any
	if err := json.Unmarshal(raw, &reg); err != nil {
		t.Fatalf("decode registration fixture: %v", err)
	}
	msg := reg["message"].(map[string]any)
	msg["fee_recipient"] = feeRecipient
	msg["timestamp"] = strconv.FormatUint(timestamp, 10)
	body, err := json.Marshal(reg)
	if err != nil {
		t.Fatalf("encode registration: %v", err)
	}
	return body, pubkey
}

// TestLookupRegistration_QueriesEveryRelay — every relay is asked (a
// 400 from the first must not stop the sweep); all distinct registered
// fee recipients are kept and the newest registration names FeeRecipient.
func TestLookupRegistration_QueriesEveryRelay(t *testing.T) {
	oldBody, pubkey := registrationBody(t, "0x"+strings.Repeat("aa", 20), 100)
	newBody, _ := registrationBody(t, "0x"+strings.Repeat("bb", 20), 200)
	without := newFakeRelay(t, nil, spec.SLOTS_PER_EPOCH)
	old := newFakeRelay(t, nil, spec.SLOTS_PER_EPOCH)
	old.registrations = map[string][]byte{strings.ToLower(pubkey): oldBody}
	newer := newFakeRelay(t, nil, spec.SLOTS_PER_EPOCH)
	newer.registrations = map[string][]byte{strings.ToLower(pubkey): newBody}

	got := LookupRegistration(context.Background(), 5*time.Second, []string{without.server.URL, old.server.URL, newer.server.URL}, pubkey)
	if got.Status != RegistrationRegistered {
		t.Fatalf("status = %v, want Registered", got.Status)
	}
	if !strings.EqualFold(got.FeeRecipient, "0x"+strings.Repeat("bb", 20)) {
		t.Errorf("FeeRecipient = %s, want the newest registration's (bb…)", got.FeeRecipient)
	}
	if len(got.FeeRecipients) != 2 {
		t.Errorf("FeeRecipients = %v, want both distinct registered recipients", got.FeeRecipients)
	}
	for _, r := range []*fakeRelay{without, old, newer} {
		if n := atomic.LoadInt32(&r.regCalls); n != 1 {
			t.Errorf("relay registration calls = %d, want 1 (every relay queried once)", n)
		}
	}
}

// TestLookupRegistration_RateLimitIsUnknown — a 429 (or any 4xx other
// than 400/404) is not "no registration"; claiming the validator is
// unregistered on a rate limit would be a false alert.
func TestLookupRegistration_RateLimitIsUnknown(t *testing.T) {
	limited := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	t.Cleanup(limited.Close)
	got := LookupRegistration(context.Background(), 2*time.Second, []string{limited.URL, limited.URL}, "0x"+strings.Repeat("ab", 48))
	if got.Status != RegistrationUnknown {
		t.Errorf("status = %v, want Unknown on 429 from every relay", got.Status)
	}
}

// TestConfirmRelayAbsent_FindsLateTrace — a delivery missing from the
// epoch sweep (late data-API write or pagination gap) is found by the
// per-slot query, with the trace's block hash intact for the hash compare.
func TestConfirmRelayAbsent_FindsLateTrace(t *testing.T) {
	traces := loadMEVTraces(t, "flashbots")
	if len(traces) == 0 {
		t.Skip("captured MEV fixture is empty")
	}
	pick := traces[0]
	relay := newFakeRelay(t, nil, spec.SLOTS_PER_EPOCH) // epoch sweep sees nothing
	relay.lateTraces = []BidTrace{pick}

	trace, found := confirmRelayAbsent(context.Background(), 5*time.Second, []string{relay.server.URL}, phase0.Slot(pick.Slot), strings.TrimPrefix(pick.ProposerPubkey, "0x"))
	if !found {
		t.Fatal("late trace not found by the per-slot confirmation")
	}
	if trace.BlockHash != pick.BlockHash {
		t.Errorf("block hash = %s, want %s", trace.BlockHash, pick.BlockHash)
	}
	if n := atomic.LoadInt32(&relay.slotCalls); n != 1 {
		t.Errorf("per-slot calls = %d, want 1", n)
	}
}

// TestConfirmRelayAbsent_IgnoresOtherProposer — a trace for the slot by a
// different proposer (equivocation or relay noise) must not count.
func TestConfirmRelayAbsent_IgnoresOtherProposer(t *testing.T) {
	traces := loadMEVTraces(t, "flashbots")
	if len(traces) == 0 {
		t.Skip("captured MEV fixture is empty")
	}
	pick := traces[0]
	relay := newFakeRelay(t, nil, spec.SLOTS_PER_EPOCH)
	relay.lateTraces = []BidTrace{pick}

	if _, found := confirmRelayAbsent(context.Background(), 5*time.Second, []string{relay.server.URL}, phase0.Slot(pick.Slot), strings.Repeat("ab", 48)); found {
		t.Error("trace by another proposer was accepted as ours")
	}
	none := newFakeRelay(t, nil, spec.SLOTS_PER_EPOCH)
	if _, found := confirmRelayAbsent(context.Background(), 5*time.Second, []string{none.server.URL}, phase0.Slot(pick.Slot), strings.TrimPrefix(pick.ProposerPubkey, "0x")); found {
		t.Error("confirmation found a trace on a relay that delivered nothing")
	}
}

// TestConfirmRelayAbsentProposals_FillsLateBids — the per-epoch helper
// asks the relays only for relay-absent tracked proposals and inserts a
// late trace into bestBids so CheckProposal takes the hash-compare path.
func TestConfirmRelayAbsentProposals_FillsLateBids(t *testing.T) {
	traces := loadMEVTraces(t, "flashbots")
	if len(traces) == 0 {
		t.Skip("captured MEV fixture is empty")
	}
	late := loadCapturedBlock(t) // tracked, no bid in the sweep, delivered late
	idxLate := late.Message.ProposerIndex
	bid := loadCapturedBlock(t) // tracked, bid already known -> no query
	idxBid := idxLate + 1
	bid.Message.ProposerIndex = idxBid
	slotLate, slotBid := phase0.Slot(200), phase0.Slot(201)
	pubkeyLate := strings.Repeat("aa", 48)
	lateTrace := traces[0]
	lateTrace.Slot = uint64(slotLate)
	lateTrace.ProposerPubkey = "0x" + pubkeyLate
	lateTrace.BlockHash = late.Message.Body.ExecutionPayload.BlockHash.String()
	relay := newFakeRelay(t, nil, spec.SLOTS_PER_EPOCH)
	relay.lateTraces = []BidTrace{lateTrace}

	duties := map[phase0.Slot]phase0.ValidatorIndex{slotLate: idxLate, slotBid: idxBid}
	blocks := map[phase0.Slot]*electra.SignedBeaconBlock{slotLate: late, slotBid: bid}
	bids := map[phase0.Slot]BidTrace{slotBid: {Slot: uint64(slotBid), BlockHash: "0xknown"}}
	pubkeys := map[phase0.ValidatorIndex]string{idxLate: pubkeyLate, idxBid: strings.Repeat("bb", 48)}

	confirmRelayAbsentProposals(context.Background(), 5*time.Second, []string{relay.server.URL}, duties, blocks, bids, pubkeys)
	got, ok := bids[slotLate]
	if !ok || got.BlockHash != lateTrace.BlockHash {
		t.Fatalf("bestBids[%d] = %+v, want the late trace inserted", slotLate, got)
	}
	if n := atomic.LoadInt32(&relay.slotCalls); n != 1 {
		t.Errorf("per-slot calls = %d, want 1 (only the relay-absent proposal is confirmed)", n)
	}
}

// TestLookupRelayAbsentRegistrations_OnlyRelayAbsentProposals — the
// per-epoch helper must query the relay only for tracked duty slots whose
// block exists, was proposed by the expected validator, and has no bid.
func TestLookupRelayAbsentRegistrations_OnlyRelayAbsentProposals(t *testing.T) {
	body, pubkey, feeRecipient := loadMEVRegistration(t, "flashbots")
	relay := newFakeRelay(t, nil, spec.SLOTS_PER_EPOCH)
	relay.registrations = map[string][]byte{strings.ToLower(pubkey): body}

	absent := loadCapturedBlock(t) // tracked, no bid -> lookup
	idxAbsent := absent.Message.ProposerIndex
	bid := loadCapturedBlock(t) // tracked, has bid -> no lookup
	idxBid := idxAbsent + 1
	bid.Message.ProposerIndex = idxBid
	const idxNoBlock = phase0.ValidatorIndex(999999)  // duty without a block -> no lookup
	const idxMismatch = phase0.ValidatorIndex(999998) // block proposed by someone else -> no lookup
	mismatch := loadCapturedBlock(t)
	builder := loadCapturedBlock(t) // tracked, no bid, but builder-tagged -> never vanilla -> no lookup
	idxBuilder := idxAbsent + 2
	builder.Message.ProposerIndex = idxBuilder
	builder.Message.Body.ExecutionPayload.ExtraData = []byte("BuilderNet")

	slotAbsent, slotBid, slotNoBlock, slotMismatch, slotBuilder := phase0.Slot(100), phase0.Slot(101), phase0.Slot(102), phase0.Slot(103), phase0.Slot(104)
	duties := map[phase0.Slot]phase0.ValidatorIndex{slotAbsent: idxAbsent, slotBid: idxBid, slotNoBlock: idxNoBlock, slotMismatch: idxMismatch, slotBuilder: idxBuilder}
	blocks := map[phase0.Slot]*electra.SignedBeaconBlock{slotAbsent: absent, slotBid: bid, slotMismatch: mismatch, slotBuilder: builder}
	bids := map[phase0.Slot]BidTrace{slotBid: {Slot: uint64(slotBid), BlockHash: "0xdeadbeef"}}
	pubkeys := map[phase0.ValidatorIndex]string{
		idxAbsent:   strings.ToLower(strings.TrimPrefix(pubkey, "0x")),
		idxBid:      strings.Repeat("bb", 48),
		idxNoBlock:  strings.Repeat("cc", 48),
		idxMismatch: strings.Repeat("dd", 48),
		idxBuilder:  strings.Repeat("ee", 48),
	}

	got := lookupRelayAbsentRegistrations(context.Background(), 5*time.Second, []string{relay.server.URL}, duties, blocks, bids, pubkeys)
	if len(got) != 1 {
		t.Fatalf("registrations = %v, want exactly one entry (the relay-absent proposer)", got)
	}
	reg, ok := got[idxAbsent]
	if !ok || reg.Status != RegistrationRegistered || !strings.EqualFold(reg.FeeRecipient, feeRecipient) {
		t.Errorf("registration for relay-absent proposer = %+v, want Registered with %s", reg, feeRecipient)
	}
	if n := atomic.LoadInt32(&relay.regCalls); n != 1 {
		t.Errorf("relay registration calls = %d, want 1 (lazy: only relay-absent tracked proposals)", n)
	}
}
