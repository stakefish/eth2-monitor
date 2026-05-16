package monitoring

// Scenario: missed_proposal
// Validates the missed-proposal detection path end-to-end through real
// captured beacon bytes. The captured fixture has a real 404 envelope
// at the gap slot. Asserts:
//
//   - Monitoring metric: TotalMissedProposals increments by 1 when
//     FinalizeMissedProposals runs over the gap slot's duty.
//   - BeaconAPI metric: a (/eth/v2/beacon/blocks/{block_id}, GET, 4xx)
//     counter+histogram increment is recorded for the 404 fetch.
//
// This guards the production observability contract: every monitor
// "missed proposal" report must be backed by a real 4xx response on
// the corresponding beacon endpoint, visible to Prometheus operators
// without needing to correlate against missed-proposal Slack alerts.

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/attestantio/go-eth2-client/spec/phase0"
)

func TestScenarioMissedProposal(t *testing.T) {
	rig := newScenarioRig(t, "missed_proposal")
	if !rig.meta.HasMissed || rig.meta.MissedSlot == 0 {
		t.Skip("missed_proposal/meta.json missing HasMissed=true or MissedSlot — refresh fixtures")
	}

	blockKey4xx := beaconAPILabelKey{
		endpoint:    "/eth/v2/beacon/blocks/{block_id}",
		method:      http.MethodGet,
		statusClass: "4xx",
	}
	before4xx := snapshotBeaconAPI(t, rig.metrics, blockKey4xx)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Production code path: GetBlock for the gap slot translates 404
	// to (nil, nil); the orchestrator leaves that slot in the
	// unfulfilled-duties map and FinalizeMissedProposals reports it.
	block, err := rig.bc.GetBlock(ctx, phase0.Slot(rig.meta.MissedSlot))
	if err != nil {
		t.Fatalf("GetBlock(missed=%d): unexpected err %v (production translates 404 to nil err)", rig.meta.MissedSlot, err)
	}
	if block != nil {
		t.Fatalf("GetBlock(missed=%d) returned non-nil block; the captured 404 fixture should produce a nil block", rig.meta.MissedSlot)
	}

	// Drive the missed-proposal detection. Simulate the orchestrator
	// state: this slot's proposer duty was never fulfilled, so it
	// remains in unfulfilledProposerDuties. Validator 42 is a
	// placeholder — the real proposer doesn't matter for the metric.
	unfulfilled := map[phase0.Slot]phase0.ValidatorIndex{
		phase0.Slot(rig.meta.MissedSlot): 42,
	}
	pubkeys := map[phase0.ValidatorIndex]string{42: "tracked"}
	FinalizeMissedProposals(unfulfilled, pubkeys, phase0.Epoch(rig.meta.TestEpoch), rig.metrics)

	// Layer 1: monitoring metric — exactly 1 missed proposal recorded.
	requireMonitorCounter(t, rig.metrics.TotalMissedProposals, 1, "TotalMissedProposals")
	// Last* gauges should pin to the missed slot + its validator.
	if got := gaugeValue(t, rig.metrics.LastMissedProposalSlot); got != float64(rig.meta.MissedSlot) {
		t.Errorf("LastMissedProposalSlot = %v, want %v", got, rig.meta.MissedSlot)
	}
	if got := gaugeValue(t, rig.metrics.LastMissedProposalValidator); got != 42 {
		t.Errorf("LastMissedProposalValidator = %v, want 42", got)
	}

	// Layer 2: BeaconAPI metric — the 404 fetch must have landed on
	// the templated endpoint label with statusClass="4xx". This is the
	// critical regression guard: a refactor that breaks the 4xx
	// classification (e.g. checking resp.StatusCode == 200 instead of
	// /100 == 2) would silently flip these into "2xx" and the operator
	// would lose the "block not found" signal.
	assertBeaconAPIDelta(t, rig.metrics, before4xx, blockKey4xx, 1)
	assertNoOtherLabel(t, rig.metrics)
}
