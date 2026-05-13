package monitoring

// Scenario: empty_block
// Validates the empty-block detection path. The captured anchor block
// has no execution-layer value (no EL transactions, no blobs, no
// post-Pectra ExecutionRequests). Asserts:
//
//   - Monitoring metric: CheckProposal increments TotalProposedEmptyBlocks
//     and pins LastProposedEmptyBlockSlot.
//   - BeaconAPI metric: 2xx GET on /eth/v2/beacon/blocks/{block_id}.

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/attestantio/go-eth2-client/spec/phase0"
)

func TestScenarioEmptyBlock(t *testing.T) {
	rig := newScenarioRig(t, "empty_block")
	if rig.meta.EmptyBlockSlot == 0 {
		t.Skip("empty_block/meta.json missing EmptyBlockSlot — refresh fixtures during a low-traffic window")
	}

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
	if block == nil || block.Message == nil || block.Message.Body == nil {
		t.Fatal("GetBlock returned nil block / message / body for empty-block anchor")
	}

	// Sanity check: the captured block actually classifies as empty.
	if !isBlockEmpty(block.Message.Body) {
		t.Fatalf("captured block at slot %d does not classify as empty — fixture predicate captured wrong block", block.Message.Slot)
	}

	// Drive CheckProposal. For an empty block the duty IS fulfilled
	// (the block exists) — CheckProposal returns true and stacks the
	// empty-block metric on top of the canonical-proposal metric.
	pubkeys := map[phase0.ValidatorIndex]string{block.Message.ProposerIndex: "tracked"}
	ok := CheckProposal(block, block.Message.Slot, block.Message.ProposerIndex, nil, false, pubkeys, phase0.Epoch(rig.meta.TestEpoch), rig.metrics)
	if !ok {
		t.Fatal("CheckProposal returned false for an empty (but canonically proposed) block — duty IS fulfilled even when empty")
	}

	// Layer 1: monitoring metric — exactly one empty block recorded,
	// and one canonical proposal alongside.
	requireMonitorCounter(t, rig.metrics.TotalProposedEmptyBlocks, 1, "TotalProposedEmptyBlocks")
	requireMonitorCounter(t, rig.metrics.TotalCanonicalProposals, 1, "TotalCanonicalProposals")
	if got := gaugeValue(t, rig.metrics.LastProposedEmptyBlockSlot); got != float64(block.Message.Slot) {
		t.Errorf("LastProposedEmptyBlockSlot = %v, want %v", got, block.Message.Slot)
	}

	// Layer 2: BeaconAPI metric — the GetBlock landed on the templated
	// endpoint label with 2xx classification.
	assertBeaconAPIDelta(t, rig.metrics, before, blockKey, 1)
	assertNoOtherLabel(t, rig.metrics)
}
