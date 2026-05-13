package monitoring

// Scenario: happy_path
// Validates the canonical-proposal detection path end-to-end through
// real captured beacon bytes. Asserts BOTH:
//   - Monitoring metric: TotalCanonicalProposals increments by 1.
//   - BeaconAPI metric: a (/eth/v2/beacon/blocks/{block_id}, GET, 2xx)
//     counter+histogram increment is recorded for the canonical fetch.
//
// Drives CheckProposal directly rather than the orchestrator — the
// orchestrator end-to-end path is exercised by monitoring_integration_test.go.
// Per-scenario tests are focused on the specific detection function
// each scenario's metric pivots on.

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/attestantio/go-eth2-client/spec/electra"
	"github.com/attestantio/go-eth2-client/spec/phase0"
)

func TestScenarioHappyPath(t *testing.T) {
	rig := newScenarioRig(t, "happy_path")

	// Take a snapshot of the canonical-block-fetch label tuple BEFORE
	// the test action. go-eth2-client's startup probes have already
	// populated other endpoints' counters by this point, but the
	// per-block path is untouched until we call GetBlock.
	blockKey := beaconAPILabelKey{
		endpoint:    "/eth/v2/beacon/blocks/{block_id}",
		method:      http.MethodGet,
		statusClass: "2xx",
	}
	before := snapshotBeaconAPI(t, rig.metrics, blockKey)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	block, err := rig.bc.GetBlock(ctx, phase0.Slot(rig.meta.CanonicalSlot))
	if err != nil {
		t.Fatalf("GetBlock(canonical=%d): %v", rig.meta.CanonicalSlot, err)
	}
	if block == nil {
		t.Fatalf("GetBlock(canonical=%d) returned nil block", rig.meta.CanonicalSlot)
	}

	// Drive the proposal-detection path. CheckProposal increments
	// TotalCanonicalProposals when the proposer matches the expected
	// duty for the slot.
	pubkeys := map[phase0.ValidatorIndex]string{block.Message.ProposerIndex: "tracked"}
	ok := CheckProposal(block, block.Message.Slot, block.Message.ProposerIndex, nil, false, pubkeys, phase0.Epoch(rig.meta.TestEpoch), rig.metrics)
	if !ok {
		t.Fatal("CheckProposal returned false for canonical happy-path block")
	}

	// Layer 1: monitoring metric — exactly 1 canonical proposal counted.
	requireMonitorCounter(t, rig.metrics.TotalCanonicalProposals, 1, "TotalCanonicalProposals")
	// And no failure-mode counters should have fired.
	requireMonitorCounter(t, rig.metrics.TotalProposedEmptyBlocks, 0, "TotalProposedEmptyBlocks")
	requireMonitorCounter(t, rig.metrics.TotalVanillaBlocks, 0, "TotalVanillaBlocks")
	requireMonitorCounter(t, rig.metrics.TotalMissingBidTraces, 0, "TotalMissingBidTraces")

	// Layer 2: BeaconAPI metric — at least one 2xx GET on
	// /eth/v2/beacon/blocks/{block_id} (the templated endpoint label
	// the instrumentingTransport emits via endpointTemplate).
	assertBeaconAPIDelta(t, rig.metrics, before, blockKey, 1)

	// Sanity: the block we got back must be the expected fork. Schema
	// drift would otherwise surface here before the monitoring path
	// even runs, so this is a useful localised failure point.
	if _, ok := any(block).(*electra.SignedBeaconBlock); !ok {
		t.Errorf("GetBlock returned %T, want *electra.SignedBeaconBlock", block)
	}

	// Ensure no "other"-labeled traffic leaked — this is the same
	// invariant the live e2e test guards (the monitor's URLs must
	// every one match an endpointTemplate case, never the "other"
	// catch-all).
	assertNoOtherLabel(t, rig.metrics)

	// Make sure the captured block JSON is the same shape the parsed
	// version reports, anchoring the slot to meta so the test stays
	// green across fixture refreshes.
	var env struct {
		Data *electra.SignedBeaconBlock `json:"data"`
	}
	if err := json.Unmarshal(loadBeaconFixture(t, "happy_path", "block_canonical.json"), &env); err != nil {
		t.Fatalf("decode block_canonical.json: %v", err)
	}
	if env.Data == nil {
		t.Fatal("block_canonical.json has nil .data — refresh fixtures")
	}
	if uint64(env.Data.Message.Slot) != rig.meta.CanonicalSlot {
		t.Errorf("fixture slot = %d, meta.CanonicalSlot = %d", env.Data.Message.Slot, rig.meta.CanonicalSlot)
	}
}
