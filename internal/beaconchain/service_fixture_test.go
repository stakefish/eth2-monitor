package beaconchain

// Offline counterpart to service_e2e_test.go's GetBlock subtests.
// Replays captured fixtures (canonical block + 404 missed-slot envelope)
// through a local httptest server pointed at by a real BeaconChain. This
// keeps GetBlock's success and 4xx code paths unit-testable without a
// live beacon endpoint and without the e2e build tag.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/rs/zerolog"
	"github.com/stakefish/eth2-monitor/internal/spec"
)

func TestGetBlock_FixtureCanonicalAndMissed(t *testing.T) {
	// Quiet go-eth2-client's per-request trace logs — same rationale as
	// service_e2e_test.go. The httptest server URL contains no
	// credentials, but the trace volume drowns test output.
	prevLevel := zerolog.GlobalLevel()
	zerolog.SetGlobalLevel(zerolog.WarnLevel)
	t.Cleanup(func() { zerolog.SetGlobalLevel(prevLevel) })

	// GetBlock has two production paths (canonical 200 + missed 404).
	// missed_proposal/ is the only scenario that bundles both, so this
	// test always loads from there.
	const scenario = "missed_proposal"
	meta := loadMeta(t, scenario)
	if !meta.HasMissed {
		t.Skip("missed_proposal/meta.json HasMissed=false — run `make refresh-scenario SCENARIO=missed_proposal` against an endpoint with a missed slot in the search window")
	}

	server := fixtureServer(t, scenario, []fixtureRoute{
		{Path: fmt.Sprintf("/eth/v2/beacon/blocks/%d", meta.CanonicalSlot), Status: 200, File: "block_canonical.json"},
		{Path: fmt.Sprintf("/eth/v2/beacon/blocks/%d", meta.MissedSlot), Status: 404, File: "block_missed.json"},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	bc, err := New(ctx, server.URL, 10*time.Second, nil)
	if err != nil {
		t.Fatalf("New(fixtureServer): %v", err)
	}

	t.Run("canonical_returns_block", func(t *testing.T) {
		block, err := bc.GetBlock(ctx, phase0.Slot(meta.CanonicalSlot))
		if err != nil {
			t.Fatalf("GetBlock(canonical=%d): %v", meta.CanonicalSlot, err)
		}
		if block == nil {
			t.Fatalf("GetBlock(canonical=%d) returned nil block", meta.CanonicalSlot)
		}
		if uint64(block.Message.Slot) != meta.CanonicalSlot {
			t.Errorf("block.Message.Slot = %d, want %d", block.Message.Slot, meta.CanonicalSlot)
		}
		if block.Message.Body == nil {
			t.Fatal("block body is nil — Caplin compat layer or go-eth2-client parser failed")
		}
	})

	t.Run("missed_returns_nil_nil", func(t *testing.T) {
		// Production GetBlock translates beacon 404 into (nil, nil).
		// Replaying the captured 404 envelope must produce the same
		// outcome — that's the contract every caller (orchestrator,
		// epoch_context.ListEpochBlocks, etc.) depends on.
		block, err := bc.GetBlock(ctx, phase0.Slot(meta.MissedSlot))
		if err != nil {
			t.Fatalf("GetBlock(missed=%d): unexpected err %v (production code translates 404 to nil err)", meta.MissedSlot, err)
		}
		if block != nil {
			t.Fatalf("GetBlock(missed=%d) returned non-nil block; expected nil", meta.MissedSlot)
		}
	})
}

// TestGetValidatorIndexes_ProbeForwardOnMissedFirstSlot covers the
// Caplin-specific behaviour where /eth/v1/beacon/states/{slot}/validators
// returns 404 ("block not found N") when slot N is missed. Production
// must walk forward through the epoch's slots until a canonical slot
// resolves; otherwise the orchestrator panics at each epoch whose first
// slot was missed (see staging incident 2026-05-13). The validator set
// is stable within an epoch, so any canonical slot answers the same
// question.
func TestGetValidatorIndexes_ProbeForwardOnMissedFirstSlot(t *testing.T) {
	prevLevel := zerolog.GlobalLevel()
	zerolog.SetGlobalLevel(zerolog.WarnLevel)
	t.Cleanup(func() { zerolog.SetGlobalLevel(prevLevel) })

	const epoch phase0.Epoch = 1000
	missedSlot := spec.EpochLowestSlot(epoch)   // 32000 — first slot of epoch; we 404 this
	canonicalSlot := missedSlot + 1             // 32001 — answers the validators query
	respBody := loadFixture(t, "happy_path", "validators_indices_0_1_2.json")

	// Pull the pubkey at index 0 out of the fixture so the test stays
	// resilient to fixture refreshes (validator at index 0 changes per
	// chain, but the response shape is stable).
	var parsed struct {
		Data []struct {
			Index     string `json:"index"`
			Validator struct {
				PublicKey string `json:"pubkey"`
			} `json:"validator"`
		} `json:"data"`
	}
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		t.Fatalf("parse validators fixture: %v", err)
	}
	if len(parsed.Data) == 0 {
		t.Fatalf("validators fixture has no entries")
	}
	// Query all pubkeys the fixture covers — production panics if the
	// response carries more validators than requested (defensive check
	// against an upstream returning the wrong shape).
	wantPubkeys := make([]string, len(parsed.Data))
	for i, v := range parsed.Data {
		wantPubkeys[i] = NormalizedPublicKey(v.Validator.PublicKey)
	}

	server := fixtureServer(t, "happy_path", []fixtureRoute{
		{
			Path: fmt.Sprintf("/eth/v1/beacon/states/%d/validators", missedSlot),
			Handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusNotFound)
				_, _ = fmt.Fprintf(w, `{"code":404,"message":"block not found %d"}`, missedSlot)
			},
		},
		{
			Path:   fmt.Sprintf("/eth/v1/beacon/states/%d/validators", canonicalSlot),
			Status: http.StatusOK,
			File:   "validators_indices_0_1_2.json",
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	bc, err := New(ctx, server.URL, 10*time.Second, nil)
	if err != nil {
		t.Fatalf("New(fixtureServer): %v", err)
	}

	got, err := bc.GetValidatorIndexes(ctx, wantPubkeys, epoch)
	if err != nil {
		t.Fatalf("GetValidatorIndexes after first-slot 404: %v", err)
	}
	if len(got) != len(wantPubkeys) {
		t.Fatalf("expected %d resolved pubkeys, got %d (probe-forward likely didn't trigger)", len(wantPubkeys), len(got))
	}
	// First fixture pubkey is validator index 0; verify the round-trip.
	if idx, ok := got[wantPubkeys[0]]; !ok || idx != 0 {
		t.Errorf("pubkey %s mapped to index %d (ok=%v); want 0", wantPubkeys[0], idx, ok)
	}
}
