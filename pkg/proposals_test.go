package pkg

import (
	"testing"

	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/deneb"
	"github.com/attestantio/go-eth2-client/spec/electra"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/prometheus/client_golang/prometheus"
)

// emptyBody returns a BeaconBlockBody whose ExecutionPayload exists but has
// no transactions/blobs/exec-requests. isBlockEmpty must classify this as
// empty.
func emptyBody() *electra.BeaconBlockBody {
	return &electra.BeaconBlockBody{
		ExecutionPayload: &deneb.ExecutionPayload{},
	}
}

// nonEmptyBody returns a body with a single transaction so isBlockEmpty
// returns false and CheckProposal's MEV branch reaches the bid-trace check.
func nonEmptyBody() *electra.BeaconBlockBody {
	return &electra.BeaconBlockBody{
		ExecutionPayload: &deneb.ExecutionPayload{
			Transactions: []bellatrix.Transaction{[]byte{0x01}},
		},
	}
}

func TestIsBlockEmpty(t *testing.T) {
	cases := []struct {
		name string
		body *electra.BeaconBlockBody
		want bool
	}{
		{
			name: "all_zero",
			body: &electra.BeaconBlockBody{
				ExecutionPayload: &deneb.ExecutionPayload{},
			},
			want: true,
		},
		{
			name: "has_transactions",
			body: &electra.BeaconBlockBody{
				ExecutionPayload: &deneb.ExecutionPayload{
					Transactions: []bellatrix.Transaction{[]byte{0xab}},
				},
			},
			want: false,
		},
		{
			name: "has_blob_commitments",
			body: &electra.BeaconBlockBody{
				ExecutionPayload:   &deneb.ExecutionPayload{},
				BlobKZGCommitments: []deneb.KZGCommitment{{}},
			},
			want: false,
		},
		{
			name: "has_exec_request_deposits",
			body: &electra.BeaconBlockBody{
				ExecutionPayload: &deneb.ExecutionPayload{},
				ExecutionRequests: &electra.ExecutionRequests{
					Deposits: []*electra.DepositRequest{{}},
				},
			},
			want: false,
		},
		{
			name: "has_exec_request_withdrawals",
			body: &electra.BeaconBlockBody{
				ExecutionPayload: &deneb.ExecutionPayload{},
				ExecutionRequests: &electra.ExecutionRequests{
					Withdrawals: []*electra.WithdrawalRequest{{}},
				},
			},
			want: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isBlockEmpty(tc.body); got != tc.want {
				t.Errorf("isBlockEmpty = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestCheckProposal_EmptyBlock — MEV disabled; empty body. Empty-block metrics fire,
// canonical-proposal counter fires, no MEV-side counters touched.
func TestCheckProposal_EmptyBlock(t *testing.T) {
	const (
		validator = phase0.ValidatorIndex(42)
		slot      = phase0.Slot(100)
	)
	block := &electra.SignedBeaconBlock{
		Message: &electra.BeaconBlock{
			Slot:          slot,
			ProposerIndex: validator,
			Body:          emptyBody(),
		},
	}
	pubkeys := map[phase0.ValidatorIndex]string{validator: "pk"}
	m := NewMonitorMetrics(prometheus.NewRegistry())

	if ok := CheckProposal(block, slot, validator, nil, false, pubkeys, 3, m); !ok {
		t.Fatalf("CheckProposal returned false, want true on canonical empty block")
	}
	if got := counterValue(t, m.TotalCanonicalProposals); got != 1 {
		t.Errorf("TotalCanonicalProposals = %v, want 1", got)
	}
	if got := counterValue(t, m.TotalProposedEmptyBlocks); got != 1 {
		t.Errorf("TotalProposedEmptyBlocks = %v, want 1", got)
	}
	if got := gaugeValue(t, m.LastProposedEmptyBlockSlot); got != float64(slot) {
		t.Errorf("LastProposedEmptyBlockSlot = %v, want %v", got, slot)
	}
	if got := counterValue(t, m.TotalMissingBidTraces); got != 0 {
		t.Errorf("TotalMissingBidTraces = %v, want 0 (MEV disabled)", got)
	}
	if got := counterValue(t, m.TotalVanillaBlocks); got != 0 {
		t.Errorf("TotalVanillaBlocks = %v, want 0", got)
	}
}

// TestCheckProposal_MissingBidTrace — MEV enabled, no bid for this slot.
// Distinct from the hash-mismatch vanilla case; classified as a relay-side
// reporting gap.
func TestCheckProposal_MissingBidTrace(t *testing.T) {
	const (
		validator = phase0.ValidatorIndex(42)
		slot      = phase0.Slot(100)
	)
	block := &electra.SignedBeaconBlock{
		Message: &electra.BeaconBlock{
			Slot:          slot,
			ProposerIndex: validator,
			Body:          nonEmptyBody(),
		},
	}
	pubkeys := map[phase0.ValidatorIndex]string{validator: "pk"}
	bestBids := map[phase0.Slot]BidTrace{} // empty: no bid for this slot
	m := NewMonitorMetrics(prometheus.NewRegistry())

	if ok := CheckProposal(block, slot, validator, bestBids, true, pubkeys, 3, m); !ok {
		t.Fatalf("CheckProposal returned false, want true")
	}
	if got := counterValue(t, m.TotalCanonicalProposals); got != 1 {
		t.Errorf("TotalCanonicalProposals = %v, want 1", got)
	}
	if got := counterValue(t, m.TotalMissingBidTraces); got != 1 {
		t.Errorf("TotalMissingBidTraces = %v, want 1", got)
	}
	if got := counterValue(t, m.TotalVanillaBlocks); got != 0 {
		t.Errorf("TotalVanillaBlocks = %v, want 0 (missing-bid is NOT a vanilla)", got)
	}
	if got := counterValue(t, m.TotalProposedEmptyBlocks); got != 0 {
		t.Errorf("TotalProposedEmptyBlocks = %v, want 0", got)
	}
}

// TestCheckProposal_VanillaHashMismatch — MEV enabled, bid present, hash differs.
// All four vanilla-side metrics fire.
func TestCheckProposal_VanillaHashMismatch(t *testing.T) {
	const (
		validator = phase0.ValidatorIndex(42)
		slot      = phase0.Slot(100)
	)
	executionHash := phase0.Hash32{0xaa}
	block := &electra.SignedBeaconBlock{
		Message: &electra.BeaconBlock{
			Slot:          slot,
			ProposerIndex: validator,
			Body: &electra.BeaconBlockBody{
				ExecutionPayload: &deneb.ExecutionPayload{
					BlockHash:    executionHash,
					Transactions: []bellatrix.Transaction{[]byte{0x01}},
				},
			},
		},
	}
	pubkeys := map[phase0.ValidatorIndex]string{validator: "pk"}
	differentHash := phase0.Hash32{0xbb}
	bestBids := map[phase0.Slot]BidTrace{
		slot: {BlockHash: differentHash.String()},
	}
	m := NewMonitorMetrics(prometheus.NewRegistry())

	if ok := CheckProposal(block, slot, validator, bestBids, true, pubkeys, 3, m); !ok {
		t.Fatalf("CheckProposal returned false, want true")
	}
	if got := counterValue(t, m.TotalCanonicalProposals); got != 1 {
		t.Errorf("TotalCanonicalProposals = %v, want 1", got)
	}
	if got := counterValue(t, m.TotalVanillaBlocks); got != 1 {
		t.Errorf("TotalVanillaBlocks = %v, want 1", got)
	}
	if got := gaugeValue(t, m.LastVanillaBlockSlot); got != float64(slot) {
		t.Errorf("LastVanillaBlockSlot = %v, want %v", got, slot)
	}
	if got := gaugeValue(t, m.LastVanillaBlockValidator); got != float64(validator) {
		t.Errorf("LastVanillaBlockValidator = %v, want %v", got, validator)
	}
	if got := counterValue(t, m.TotalMissingBidTraces); got != 0 {
		t.Errorf("TotalMissingBidTraces = %v, want 0 (this is hash mismatch, not missing bid)", got)
	}
}

// TestCheckProposal_OptimalMEV — MEV enabled, bid present, hash matches.
// Only TotalCanonicalProposals fires.
func TestCheckProposal_OptimalMEV(t *testing.T) {
	const (
		validator = phase0.ValidatorIndex(42)
		slot      = phase0.Slot(100)
	)
	executionHash := phase0.Hash32{0xcc}
	block := &electra.SignedBeaconBlock{
		Message: &electra.BeaconBlock{
			Slot:          slot,
			ProposerIndex: validator,
			Body: &electra.BeaconBlockBody{
				ExecutionPayload: &deneb.ExecutionPayload{
					BlockHash:    executionHash,
					Transactions: []bellatrix.Transaction{[]byte{0x01}},
				},
			},
		},
	}
	pubkeys := map[phase0.ValidatorIndex]string{validator: "pk"}
	bestBids := map[phase0.Slot]BidTrace{
		slot: {BlockHash: executionHash.String()},
	}
	m := NewMonitorMetrics(prometheus.NewRegistry())

	if ok := CheckProposal(block, slot, validator, bestBids, true, pubkeys, 3, m); !ok {
		t.Fatalf("CheckProposal returned false, want true")
	}
	if got := counterValue(t, m.TotalCanonicalProposals); got != 1 {
		t.Errorf("TotalCanonicalProposals = %v, want 1", got)
	}
	if got := counterValue(t, m.TotalProposedEmptyBlocks); got != 0 {
		t.Errorf("TotalProposedEmptyBlocks = %v, want 0", got)
	}
	if got := counterValue(t, m.TotalVanillaBlocks); got != 0 {
		t.Errorf("TotalVanillaBlocks = %v, want 0", got)
	}
	if got := counterValue(t, m.TotalMissingBidTraces); got != 0 {
		t.Errorf("TotalMissingBidTraces = %v, want 0", got)
	}
}

// TestCheckProposal_EmptyBlockAndMissingBid is the regression trap for the
// fall-through behavior: an empty block on a MEV-enabled run with no bid trace
// must fire BOTH the empty-block metrics AND TotalMissingBidTraces. A future
// switch-style refactor that picks one branch per call would break this.
func TestCheckProposal_EmptyBlockAndMissingBid(t *testing.T) {
	const (
		validator = phase0.ValidatorIndex(42)
		slot      = phase0.Slot(100)
	)
	block := &electra.SignedBeaconBlock{
		Message: &electra.BeaconBlock{
			Slot:          slot,
			ProposerIndex: validator,
			Body:          emptyBody(), // empty body...
		},
	}
	pubkeys := map[phase0.ValidatorIndex]string{validator: "pk"}
	bestBids := map[phase0.Slot]BidTrace{} // ...AND no bid trace
	m := NewMonitorMetrics(prometheus.NewRegistry())

	if ok := CheckProposal(block, slot, validator, bestBids, true, pubkeys, 3, m); !ok {
		t.Fatalf("CheckProposal returned false, want true")
	}
	if got := counterValue(t, m.TotalCanonicalProposals); got != 1 {
		t.Errorf("TotalCanonicalProposals = %v, want 1", got)
	}
	if got := counterValue(t, m.TotalProposedEmptyBlocks); got != 1 {
		t.Errorf("TotalProposedEmptyBlocks = %v, want 1 (empty branch must fire)", got)
	}
	if got := counterValue(t, m.TotalMissingBidTraces); got != 1 {
		t.Errorf("TotalMissingBidTraces = %v, want 1 (missing-bid branch must also fire — fall-through preserved)", got)
	}
}

// TestIsBlockEmpty_NilExecutionPayload regresses the nil-deref. A
// non-conforming JSON response could leave ExecutionPayload nil; the
// previous code panicked on body.ExecutionPayload.Transactions.
func TestIsBlockEmpty_NilExecutionPayload(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("isBlockEmpty panicked on nil ExecutionPayload: %v", r)
		}
	}()
	body := &electra.BeaconBlockBody{ExecutionPayload: nil}
	if !isBlockEmpty(body) {
		t.Error("nil ExecutionPayload should classify as empty")
	}
}

// TestCheckProposal_NilExecutionPayloadOnMEVRun regresses the second
// nil-deref site: with MEV enabled and a nil ExecutionPayload, the previous
// code crashed reading BlockHash. We now record TotalMissingBidTraces and
// return true so the orchestrator continues.
func TestCheckProposal_NilExecutionPayloadOnMEVRun(t *testing.T) {
	const (
		validator = phase0.ValidatorIndex(42)
		slot      = phase0.Slot(100)
	)
	block := &electra.SignedBeaconBlock{
		Message: &electra.BeaconBlock{
			Slot:          slot,
			ProposerIndex: validator,
			Body:          &electra.BeaconBlockBody{ExecutionPayload: nil},
		},
	}
	pubkeys := map[phase0.ValidatorIndex]string{validator: "pk"}
	m := NewMonitorMetrics(prometheus.NewRegistry())

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("CheckProposal panicked on nil ExecutionPayload: %v", r)
		}
	}()
	if ok := CheckProposal(block, slot, validator, map[phase0.Slot]BidTrace{}, true, pubkeys, 3, m); !ok {
		t.Fatal("CheckProposal returned false; should still return true so orchestrator counts proposal as canonical")
	}
	if got := counterValue(t, m.TotalMissingBidTraces); got != 1 {
		t.Errorf("TotalMissingBidTraces = %v, want 1 (nil payload should bump the missing-bid counter)", got)
	}
}

// TestCheckProposal_ProposerMismatch — block at this slot was proposed by a
// different validator than the duty assigned. CheckProposal must return false
// (so the caller leaves the duty in unfulfilledProposerDuties, where
// FinalizeMissedProposals will later count it as missed) and must NOT
// increment any of its own metrics, regardless of body contents.
func TestCheckProposal_ProposerMismatch(t *testing.T) {
	const (
		expected = phase0.ValidatorIndex(42)
		actual   = phase0.ValidatorIndex(99)
		slot     = phase0.Slot(100)
	)
	block := &electra.SignedBeaconBlock{
		Message: &electra.BeaconBlock{
			Slot:          slot,
			ProposerIndex: actual, // mismatch
			Body:          emptyBody(),
		},
	}
	pubkeys := map[phase0.ValidatorIndex]string{expected: "pk-expected", actual: "pk-actual"}
	m := NewMonitorMetrics(prometheus.NewRegistry())

	if ok := CheckProposal(block, slot, expected, nil, false, pubkeys, 3, m); ok {
		t.Fatalf("CheckProposal returned true, want false on proposer mismatch")
	}
	if got := counterValue(t, m.TotalCanonicalProposals); got != 0 {
		t.Errorf("TotalCanonicalProposals = %v, want 0 (mismatch must short-circuit before counting)", got)
	}
	if got := counterValue(t, m.TotalProposedEmptyBlocks); got != 0 {
		t.Errorf("TotalProposedEmptyBlocks = %v, want 0 (mismatch must short-circuit before reading body)", got)
	}
	if got := counterValue(t, m.TotalMissedProposals); got != 0 {
		t.Errorf("TotalMissedProposals = %v, want 0 (CheckProposal does not write this metric; FinalizeMissedProposals does)", got)
	}
}

// TestFinalizeMissedProposals — 3 unsorted unfulfilled duties at slots 100, 50, 200.
// Counter increments by 3; Last* gauges settle on slot 200 (the highest, by
// slices.Sorted's ascending order).
func TestFinalizeMissedProposals(t *testing.T) {
	const (
		v50  = phase0.ValidatorIndex(1)
		v100 = phase0.ValidatorIndex(2)
		v200 = phase0.ValidatorIndex(3)
	)
	unfulfilled := map[phase0.Slot]phase0.ValidatorIndex{
		100: v100,
		50:  v50,
		200: v200,
	}
	pubkeys := map[phase0.ValidatorIndex]string{v50: "pk50", v100: "pk100", v200: "pk200"}
	m := NewMonitorMetrics(prometheus.NewRegistry())

	FinalizeMissedProposals(unfulfilled, pubkeys, m)

	if got := counterValue(t, m.TotalMissedProposals); got != 3 {
		t.Errorf("TotalMissedProposals = %v, want 3", got)
	}
	if got := gaugeValue(t, m.LastMissedProposalSlot); got != 200 {
		t.Errorf("LastMissedProposalSlot = %v, want 200 (highest slot wins under ascending sort)", got)
	}
	if got := gaugeValue(t, m.LastMissedProposalValidator); got != float64(v200) {
		t.Errorf("LastMissedProposalValidator = %v, want %v", got, v200)
	}
}
