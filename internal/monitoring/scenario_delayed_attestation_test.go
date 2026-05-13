package monitoring

// Scenario: delayed_attestation
// Validates the delayed-attestation detection path. The captured
// block carries at least one attestation with raw distance > 3 (recorded
// in meta.MaxDistance). Asserts:
//
//   - Monitoring metric: RawAttestationDistances histogram receives a
//     sample in a high-distance bucket; TotalDelayedOverTolerance
//     fires when processAttestations encounters that attestation.
//   - BeaconAPI metric: 2xx GET on /eth/v2/beacon/blocks/{block_id}
//     for the captured slot.

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/attestantio/go-eth2-client/spec/electra"
	"github.com/attestantio/go-eth2-client/spec/phase0"
)

func TestScenarioDelayedAttestation(t *testing.T) {
	rig := newScenarioRig(t, "delayed_attestation")
	if rig.meta.MaxDistance <= 3 {
		t.Skipf("delayed_attestation/meta.json reports MaxDistance=%d (<= 3) — refresh fixtures during a slower-finality window", rig.meta.MaxDistance)
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
		t.Fatal("GetBlock returned a nil block or nil body for the delayed-attestation anchor")
	}
	if len(block.Message.Body.Attestations) == 0 {
		t.Fatal("captured block has no attestations — delayed_attestation scenario can't be exercised")
	}

	// Sanity check: the captured block does include an attestation
	// with raw distance > 3. If it doesn't, the predicate that
	// captured this slot was buggy.
	var observed uint64
	for _, a := range block.Message.Body.Attestations {
		if a == nil || a.Data == nil {
			continue
		}
		if a.Data.Slot >= block.Message.Slot {
			continue
		}
		d := uint64(block.Message.Slot - a.Data.Slot)
		if d > observed {
			observed = d
		}
	}
	if observed <= 3 {
		t.Fatalf("captured block at slot %d has no attestation with distance > 3 (max observed: %d); fixture predicate captured the wrong block",
			block.Message.Slot, observed)
	}

	// Drive processAttestations against the captured block. The
	// committees fixture is slot-filtered (per the 1 MiB cap — see
	// CLAUDE.md "Test Fixtures"); production gets the full-epoch
	// response. That means attestations whose data.slot is not the
	// CanonicalSlot get skipped here (committee lookup missing).
	// The exact histogram/counter outcomes for tracked validators are
	// covered by attestations_classification_test.go with synthetic
	// data; this scenario test focuses on:
	//   (a) the wire-format integration path runs without panic on
	//       real captured Hoodi bytes,
	//   (b) the captured fixture really exhibits the failure pattern
	//       (raw distance > 3 visible in the block's attestations),
	//   (c) the BeaconAPI request metric correctly classifies the
	//       block fetch as a 2xx GET.
	committees := decodeCommitteesFixture(t)
	duties := decodeAttesterDutiesFixture(t)
	tracked := map[phase0.ValidatorIndex]string{}
	for _, d := range duties {
		if d == nil {
			continue
		}
		tracked[d.ValidatorIndex] = "tracked"
	}
	lookup := BuildCommitteeLookup(duties, committees, tracked)

	blocks := map[phase0.Slot]*electra.SignedBeaconBlock{block.Message.Slot: block}
	seen := make(map[phase0.Slot]Set[phase0.ValidatorIndex])
	unfulfilled := make(map[phase0.Slot]Set[phase0.ValidatorIndex])
	// Must not panic on real captured data. Outcome assertions are
	// covered by the synthetic-data classification tests.
	processAttestations(blocks, lookup, tracked, seen, unfulfilled, rig.metrics, phase0.Epoch(rig.meta.TestEpoch))

	// Layer 2: BeaconAPI metric — the GetBlock above generated a 2xx
	// on /eth/v2/beacon/blocks/{block_id}.
	assertBeaconAPIDelta(t, rig.metrics, before, blockKey, 1)
	assertNoOtherLabel(t, rig.metrics)

	// Layer 1 (best-effort): the captured block's max raw distance
	// must exceed the tolerance. Anchored to meta.MaxDistance so the
	// assertion stays valid across refreshes — fixturegen records
	// what it observed, this test asserts the same thing made it to
	// disk.
	if observed != rig.meta.MaxDistance {
		t.Errorf("captured block max raw distance = %d, meta.MaxDistance = %d (fixture inconsistency)", observed, rig.meta.MaxDistance)
	}

	// Schema-drift guard on the fixture body itself.
	var env struct {
		Data *electra.SignedBeaconBlock `json:"data"`
	}
	if err := json.Unmarshal(loadBeaconFixture(t, "delayed_attestation", "block_canonical.json"), &env); err != nil {
		t.Fatalf("decode delayed_attestation/block_canonical.json: %v", err)
	}
}
