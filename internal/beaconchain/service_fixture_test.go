package beaconchain

// Offline counterpart to service_e2e_test.go's GetBlock subtests.
// Replays captured fixtures (canonical block + 404 missed-slot envelope)
// through a local httptest server pointed at by a real BeaconChain. This
// keeps GetBlock's success and 4xx code paths unit-testable without a
// live beacon endpoint and without the e2e build tag.

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/rs/zerolog"
)

func TestGetBlock_FixtureCanonicalAndMissed(t *testing.T) {
	// Quiet go-eth2-client's per-request trace logs — same rationale as
	// service_e2e_test.go. The httptest server URL contains no
	// credentials, but the trace volume drowns test output.
	prevLevel := zerolog.GlobalLevel()
	zerolog.SetGlobalLevel(zerolog.WarnLevel)
	t.Cleanup(func() { zerolog.SetGlobalLevel(prevLevel) })

	meta := loadMeta(t)
	if !meta.HasMissed {
		t.Skip("captured fixtures don't include a missed slot — run `make refresh-fixtures` against an endpoint with a missed slot in the search window")
	}

	server := fixtureServer(t, []fixtureRoute{
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
