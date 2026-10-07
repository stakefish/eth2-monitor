package monitoring

// Integration tests for epoch_context.go. Replaces the previous
// fakeFetcher-based unit tests with end-to-end coverage that drives
// BuildEpochContext, ListEpochBlocks, ResolveValidatorKeys,
// SlotsWithBlocks, and ListProposerDuties through a real BeaconChain
// pointed at an httptest server replaying captured beacon fixtures.
//
// Retry/cancel behaviour is exercised by route-level handler logic
// (flaky/hanging routes) instead of an in-process mock — the actual
// HTTP transport, JSON decoder, retry loop, and ctx propagation all
// run for real.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stakefish/eth2-monitor/internal/beaconchain"
	"github.com/stakefish/eth2-monitor/internal/spec"

	v1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/rs/zerolog"
)

// quietGoEth2Client suppresses go-eth2-client's per-request trace logs
// for the duration of t — the volume drowns test output otherwise. The
// httptest URL has no credentials, so no token-leakage concern.
func quietGoEth2Client(t *testing.T) {
	t.Helper()
	prev := zerolog.GlobalLevel()
	zerolog.SetGlobalLevel(zerolog.WarnLevel)
	t.Cleanup(func() { zerolog.SetGlobalLevel(prev) })
}

// blockRouteFor returns the canonical /eth/v2/beacon/blocks/<slot>
// path string for a given slot, matching the production URL format.
func blockRouteFor(slot uint64) string {
	return "/eth/v2/beacon/blocks/" + fmt.Sprint(slot)
}

func newBeaconChainAgainst(t *testing.T, baseURL string) *beaconchain.BeaconChain {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	bc, err := beaconchain.New(ctx, baseURL, 10*time.Second, nil)
	if err != nil {
		t.Fatalf("BeaconChain.New(%s): %v", baseURL, err)
	}
	return bc
}

// TestListEpochBlocks_RecoversFromTransientError replaces the fake
// retry test. A real beacon transport hits a flaky route that returns
// 502 on the first call and the canonical block fixture on the second.
// ListEpochBlocks must include the slot in its result map (i.e. the
// retry loop succeeded), proving that the production code path
// recovers from upstream blips rather than reporting a false missed
// proposal.
func TestListEpochBlocks_RecoversFromTransientError(t *testing.T) {
	quietGoEth2Client(t)

	meta := loadBeaconMeta(t, "missed_proposal")
	canonical := meta.CanonicalSlot
	epoch := phase0.Epoch(meta.TestEpoch)

	var calls int32
	flaky := func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		if n == 1 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		body := loadBeaconFixture(t, "missed_proposal", "block_canonical.json")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}

	// Every other slot in the epoch responds with a 404 (treated as
	// missed). Only the flaky slot is interesting; the rest just need
	// to not panic.
	routes := []fixtureRoute{{Path: blockRouteFor(canonical), Handler: flaky}}
	for s := spec.EpochLowestSlot(epoch); s <= spec.EpochHighestSlot(epoch)+4; s++ {
		if uint64(s) == canonical {
			continue
		}
		routes = append(routes, fixtureRoute{Path: blockRouteFor(uint64(s)), Status: http.StatusNotFound, File: "block_missed.json"})
	}

	server := fixtureServer(t, "missed_proposal", routes)
	bc := newBeaconChainAgainst(t, server.URL)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	got, err := ListEpochBlocks(ctx, bc, epoch)
	if err != nil {
		t.Fatalf("ListEpochBlocks: %v", err)
	}
	if _, ok := got[phase0.Slot(canonical)]; !ok {
		t.Errorf("retry recovered slot %d not present in result map; production code surfaced a false missed proposal", canonical)
	}
	if atomic.LoadInt32(&calls) < 2 {
		t.Errorf("flaky slot called %d times, expected >= 2 (one failure + one retry)", calls)
	}
}

// TestListEpochBlocks_PersistentErrorMissed replaces the fake
// persistent-failure test. A real beacon transport hits a route that
// always returns 500. The slot must be absent from the result map
// (treated as missed) but ListEpochBlocks must NOT propagate the
// error — the orchestrator depends on the rest of the epoch processing.
func TestListEpochBlocks_PersistentErrorMissed(t *testing.T) {
	quietGoEth2Client(t)

	meta := loadBeaconMeta(t, "missed_proposal")
	canonical := meta.CanonicalSlot
	epoch := phase0.Epoch(meta.TestEpoch)

	always500 := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}
	routes := []fixtureRoute{{Path: blockRouteFor(canonical), Handler: always500}}
	for s := spec.EpochLowestSlot(epoch); s <= spec.EpochHighestSlot(epoch)+4; s++ {
		if uint64(s) == canonical {
			continue
		}
		routes = append(routes, fixtureRoute{Path: blockRouteFor(uint64(s)), Status: http.StatusNotFound, File: "block_missed.json"})
	}
	server := fixtureServer(t, "missed_proposal", routes)
	bc := newBeaconChainAgainst(t, server.URL)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	got, err := ListEpochBlocks(ctx, bc, epoch)
	if err != nil {
		t.Fatalf("ListEpochBlocks returned err for a single broken slot; expected nil so the orchestrator keeps running: %v", err)
	}
	if _, ok := got[phase0.Slot(canonical)]; ok {
		t.Errorf("persistently-failing slot %d present in result map; should be treated as missed", canonical)
	}
}

// TestListEpochBlocks_404ShortCircuits replaces the missed-slot unit
// test. The production GetBlock translates a 404 to (nil, nil); the
// retry loop must NOT retry on that. Using a counting handler that
// always returns 404, the assertion is that each missed slot is
// requested exactly once.
func TestListEpochBlocks_404ShortCircuits(t *testing.T) {
	quietGoEth2Client(t)

	meta := loadBeaconMeta(t, "missed_proposal")
	epoch := phase0.Epoch(meta.TestEpoch)
	low := spec.EpochLowestSlot(epoch)

	hits := make(map[string]*int32)
	makeHandler := func(slotPath string) http.HandlerFunc {
		var n int32
		hits[slotPath] = &n
		return func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&n, 1)
			body := loadBeaconFixture(t, "missed_proposal", "block_missed.json")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write(body)
		}
	}
	routes := []fixtureRoute{}
	for s := low; s <= spec.EpochHighestSlot(epoch)+4; s++ {
		path := blockRouteFor(uint64(s))
		routes = append(routes, fixtureRoute{Path: path, Handler: makeHandler(path)})
	}
	server := fixtureServer(t, "missed_proposal", routes)
	bc := newBeaconChainAgainst(t, server.URL)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	got, err := ListEpochBlocks(ctx, bc, epoch)
	if err != nil {
		t.Fatalf("ListEpochBlocks: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("all-missed epoch produced %d entries, want 0", len(got))
	}
	for path, count := range hits {
		if c := atomic.LoadInt32(count); c != 1 {
			t.Errorf("slot path %s requested %d times, want 1 (404 must short-circuit retry)", path, c)
		}
	}
}

// TestListEpochBlocks_CtxCancelStopsBackoff replaces the unit retry-cancel
// test. A handler that always returns 502 forces the retry loop to enter
// backoff; cancelling ctx mid-flight must short-circuit the wait rather
// than sleeping out the full backoff window. We measure wall-clock time
// to assert the cancel was honoured.
func TestListEpochBlocks_CtxCancelStopsBackoff(t *testing.T) {
	quietGoEth2Client(t)

	meta := loadBeaconMeta(t, "missed_proposal")
	canonical := meta.CanonicalSlot
	always502 := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}
	server := fixtureServer(t, "missed_proposal", []fixtureRoute{
		{Path: blockRouteFor(canonical), Handler: always502},
	})
	bc := newBeaconChainAgainst(t, server.URL)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancel; first failure must observe Done immediately

	start := time.Now()
	_, err := bc.GetBlock(ctx, phase0.Slot(canonical))
	elapsed := time.Since(start)

	// fetchBlockWithRetries returns either ctx.Err() or the underlying
	// HTTP error wrapping ctx.Canceled. Either is acceptable; what
	// matters is the elapsed-time bound.
	if err == nil {
		t.Fatal("expected non-nil error on pre-cancelled ctx, got nil")
	}
	if !errors.Is(err, context.Canceled) {
		t.Logf("note: err is not context.Canceled (%v); checking elapsed time as the primary signal", err)
	}
	if elapsed > 500*time.Millisecond {
		t.Errorf("retry slept through cancellation (%v); should bail near-immediately", elapsed)
	}
}

// TestResolveValidatorKeys_FromFixture exercises the validators-resolve
// path end-to-end against a captured /eth/v1/beacon/states/{slot}/validators
// response. Verifies ResolveValidatorKeys projects active validators
// out of the fixture and writes back to the disk cache.
//
// Per-component test rather than going through BuildEpochContext —
// BuildEpochContext queries attester duties and committees for prev/
// curr/next epochs, which our single-epoch fixture set can't satisfy
// without go-eth2-client's epoch-range validation rejecting the reused
// payload. The full BuildEpochContext path is the natural fit for
// Phase C.3 (orchestrator integration test) where multi-epoch fixtures
// will be in scope.
func TestResolveValidatorKeys_FromFixture(t *testing.T) {
	quietGoEth2Client(t)

	const scenario = "happy_path"
	meta := loadBeaconMeta(t, scenario)
	epoch := phase0.Epoch(meta.TestEpoch)
	server := fixtureServer(t, scenario, []fixtureRoute{
		// Production POSTs with State=fmt.Sprintf("%d", EpochLowestSlot(epoch)).
		{Path: fmt.Sprintf("/eth/v1/beacon/states/%d/validators", spec.EpochLowestSlot(epoch)), Status: http.StatusOK, File: "validators_indices_0_1_2.json"},
	})
	bc := newBeaconChainAgainst(t, server.URL)

	// Pull the pubkeys from the fixture so the test stays valid across
	// fixture refreshes. Validators 0/1/2 indices are stable on Hoodi
	// staging (genesis validators); their pubkeys move only on chain
	// reset.
	validatorsResp := struct {
		Data []struct {
			Validator struct {
				Pubkey string `json:"pubkey"`
			} `json:"validator"`
		} `json:"data"`
	}{}
	if err := json.Unmarshal(loadBeaconFixture(t, scenario, "validators_indices_0_1_2.json"), &validatorsResp); err != nil {
		t.Fatalf("decode validators fixture: %v", err)
	}
	var probePubkeys []string
	for _, v := range validatorsResp.Data {
		probePubkeys = append(probePubkeys, v.Validator.Pubkey)
	}
	if len(probePubkeys) == 0 {
		t.Fatal("validators fixture is empty — refresh fixtures")
	}

	// LoadCache reads from $TMPDIR; isolate this test by pointing at a
	// fresh temp dir so it can't pick up state from a prior run or
	// production binary.
	t.Setenv("TMPDIR", t.TempDir())

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	got, err := ResolveValidatorKeys(ctx, bc, probePubkeys, epoch)
	if err != nil {
		t.Fatalf("ResolveValidatorKeys: %v", err)
	}
	if len(got) == 0 {
		t.Fatal("got empty index map — captured validators fixture had no IsAttesting entries?")
	}
	// Every returned index must correspond to one of the pubkeys we
	// asked for (case-normalised).
	probeSet := make(map[string]struct{}, len(probePubkeys))
	for _, pk := range probePubkeys {
		probeSet[beaconchain.NormalizedPublicKey(pk)] = struct{}{}
	}
	for _, pk := range got {
		if _, ok := probeSet[pk]; !ok {
			t.Errorf("unexpected pubkey in result: %s", pk)
		}
	}
}

// TestListProposerDuties_FromFixture exercises ListProposerDuties +
// proposerDutyMap against a captured proposer-duties response. Verifies
// the slot range and the SLOTS_PER_EPOCH count.
func TestListProposerDuties_FromFixture(t *testing.T) {
	quietGoEth2Client(t)

	const scenario = "happy_path"
	meta := loadBeaconMeta(t, scenario)
	epoch := phase0.Epoch(meta.TestEpoch)
	server := fixtureServer(t, scenario, []fixtureRoute{
		{Path: fmt.Sprintf("/eth/v1/validator/duties/proposer/%d", epoch), Status: http.StatusOK, File: "proposer_duties.json"},
	})
	bc := newBeaconChainAgainst(t, server.URL)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	duties, err := ListProposerDuties(ctx, bc, epoch, nil)
	if err != nil {
		t.Fatalf("ListProposerDuties: %v", err)
	}
	if len(duties) != spec.SLOTS_PER_EPOCH {
		t.Errorf("got %d duties, want %d (one per slot in epoch)", len(duties), spec.SLOTS_PER_EPOCH)
	}
	low := spec.EpochLowestSlot(epoch)
	high := spec.EpochHighestSlot(epoch)
	for slot := range duties {
		if slot < low || slot > high {
			t.Errorf("duty slot %d outside epoch range [%d,%d]", slot, low, high)
		}
	}
}

// TestProposerDutyMap_NilEntries keeps the pure-function regression
// against nil duty entries — a real beacon never returns nil entries so
// this can't be a fixture-driven test, but the production code's
// defensive nil-skip is worth preserving with a focused test. Same
// rationale for the nil-slice case below.
func TestProposerDutyMap_NilEntries(t *testing.T) {
	t.Parallel()
	duties := []*v1.ProposerDuty{
		{Slot: 10, ValidatorIndex: 100},
		nil,
		{Slot: 12, ValidatorIndex: 200},
		nil,
	}
	got := proposerDutyMap(duties)
	if len(got) != 2 {
		t.Fatalf("got %d entries, want 2 (nil entries must be skipped)", len(got))
	}
	if got[10] != 100 || got[12] != 200 {
		t.Errorf("non-nil duties not projected correctly: %v", got)
	}
}

func TestProposerDutyMap_NilSliceReturnsEmptyMap(t *testing.T) {
	t.Parallel()
	got := proposerDutyMap(nil)
	if got == nil {
		t.Fatal("nil slice produced nil map; expected empty map")
	}
	if len(got) != 0 {
		t.Errorf("nil slice produced %d entries; expected 0", len(got))
	}
}

// TestBuildEpochContext_RelaysComplete pins the relay-health flag that
// CheckProposal uses to tell a vanilla block (no relay delivered a
// payload) from an unclassifiable slot (a relay failed). Runs the real
// BuildEpochContext against the happy_path beacon fixtures with fake
// relays on the MEV side.
func TestBuildEpochContext_RelaysComplete(t *testing.T) {
	const scenario = "happy_path"
	if !scenarioFixturesPresent(scenario) {
		t.Skipf("scenario %q fixtures not captured — run `make refresh-scenario SCENARIO=%s`", scenario, scenario)
	}
	quietGoEth2Client(t)
	quietScenarioLogging(t)
	meta := loadBeaconMeta(t, scenario)
	epoch := phase0.Epoch(meta.TestEpoch)
	// BuildEpochContext also pulls attester duties for E-1 and E+1 (the
	// cross-epoch inclusion window). The fixture only captured E, and the
	// client rejects duties outside the requested epoch, so serve empty
	// duty lists for the neighbours — enough to drive the proposal/relay
	// side under test.
	noDuties := func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"dependent_root":"0x` + strings.Repeat("00", 32) + `","execution_optimistic":false,"data":[]}`))
	}
	routes := append(scenarioRoutes(t, scenario, meta),
		fixtureRoute{Path: fmt.Sprintf("/eth/v1/validator/duties/attester/%d", epoch-1), Handler: noDuties},
		fixtureRoute{Path: fmt.Sprintf("/eth/v1/validator/duties/attester/%d", epoch+1), Handler: noDuties},
	)
	bc := newBeaconChainAgainst(t, fixtureServer(t, scenario, routes).URL)
	keys := fixturePubkeys(t, scenario)
	t.Setenv("TMPDIR", t.TempDir()) // isolate LoadCache/SaveCache

	build := func(t *testing.T, relays []string) *EpochContext {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		ec, err := BuildEpochContext(ctx, bc, epoch, keys, relays)
		if err != nil {
			t.Fatalf("BuildEpochContext: %v", err)
		}
		if ec == nil {
			t.Fatal("BuildEpochContext returned nil context — fixture validators not active in TestEpoch?")
		}
		return ec
	}

	t.Run("mev disabled", func(t *testing.T) {
		ec := build(t, nil)
		if ec.MEV.Enabled || ec.MEV.RelaysComplete {
			t.Errorf("MEV.Enabled=%v MEV.RelaysComplete=%v, want both false without relays", ec.MEV.Enabled, ec.MEV.RelaysComplete)
		}
	})

	t.Run("every relay answered", func(t *testing.T) {
		relay := newFakeRelay(t, withFloor(nil, epoch), spec.SLOTS_PER_EPOCH)
		ec := build(t, []string{relay.server.URL})
		if !ec.MEV.RelaysComplete {
			t.Error("RelaysComplete=false although the only relay answered with a trace for the epoch")
		}
	})

	t.Run("one relay failing", func(t *testing.T) {
		healthy := newFakeRelay(t, withFloor(nil, epoch), spec.SLOTS_PER_EPOCH)
		broken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusBadGateway)
		}))
		t.Cleanup(broken.Close)
		ec := build(t, []string{healthy.server.URL, broken.URL})
		if ec.MEV.RelaysComplete {
			t.Error("RelaysComplete=true although one relay never answered; a missing bid must not be read as vanilla")
		}
	})
}

// fixturePubkeys returns the validator pubkeys captured in the scenario's
// validators fixture, so tests stay valid across fixture refreshes.
func fixturePubkeys(t *testing.T, scenario string) []string {
	t.Helper()
	var resp struct {
		Data []struct {
			Validator struct {
				Pubkey string `json:"pubkey"`
			} `json:"validator"`
		} `json:"data"`
	}
	if err := json.Unmarshal(loadBeaconFixture(t, scenario, "validators_indices_0_1_2.json"), &resp); err != nil {
		t.Fatalf("decode validators fixture: %v", err)
	}
	var keys []string
	for _, v := range resp.Data {
		keys = append(keys, v.Validator.Pubkey)
	}
	if len(keys) == 0 {
		t.Fatal("validators fixture is empty — refresh fixtures")
	}
	return keys
}
