package monitoring

// Integration tests for proposals.go (CheckProposal, isBlockEmpty,
// FinalizeMissedProposals). Replaces the previous tests' inline
// hand-constructed *electra.SignedBeaconBlock literals with a baseline
// parsed from the captured block_canonical.json fixture, with targeted
// in-Go mutations to drive the empty / vanilla / case-mismatch
// scenarios.
//
// Defensive nil-safety tests still use minimal inline blocks — those
// regressions are about pointer-deref discipline, not classification
// against realistic data, and a captured block doesn't have nil
// pointers to test against.

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/attestantio/go-eth2-client/spec/deneb"
	"github.com/attestantio/go-eth2-client/spec/electra"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/prometheus/client_golang/prometheus"
)

// loadCapturedBlock parses block_canonical.json into a fresh
// *electra.SignedBeaconBlock. Returns a deep-decoded value each call
// so test mutations don't leak between tests via shared pointers.
func loadCapturedBlock(t *testing.T) *electra.SignedBeaconBlock {
	t.Helper()
	body := loadBeaconFixture(t, "happy_path", "block_canonical.json")
	var env struct {
		Version string                     `json:"version"`
		Data    *electra.SignedBeaconBlock `json:"data"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("decode block_canonical.json: %v", err)
	}
	if env.Data == nil {
		t.Fatal("captured block has nil .data — refresh fixtures")
	}
	return env.Data
}

// emptyBodyFrom returns a copy of `body` with execution payload
// transactions, blob commitments, and execution_requests all zeroed —
// the shape isBlockEmpty classifies as empty. Used by tests that need
// an empty-block scenario derived from a real captured block (so the
// surrounding Body fields are realistic).
func emptyBodyFrom(body *electra.BeaconBlockBody) *electra.BeaconBlockBody {
	cp := *body
	if cp.ExecutionPayload != nil {
		ep := *cp.ExecutionPayload
		ep.Transactions = nil
		cp.ExecutionPayload = &ep
	}
	cp.BlobKZGCommitments = nil
	if cp.ExecutionRequests != nil {
		er := *cp.ExecutionRequests
		er.Deposits = nil
		er.Withdrawals = nil
		er.Consolidations = nil
		cp.ExecutionRequests = &er
	}
	return &cp
}

// counterIs is a small assertion helper to keep individual test bodies
// terse — these tests touch ~5 metric assertions each.
func counterIs(t *testing.T, c prometheus.Counter, want float64, label string) {
	t.Helper()
	if got := counterValue(t, c); got != want {
		t.Errorf("%s = %v, want %v", label, got, want)
	}
}

func TestIsBlockEmpty_FromFixture(t *testing.T) {
	body := loadCapturedBlock(t).Message.Body
	if isBlockEmpty(body) {
		t.Fatal("captured block classified as empty — the fixture must have transactions / blobs / requests for the rest of the suite to be meaningful")
	}
}

func TestIsBlockEmpty_StrippedFixture(t *testing.T) {
	body := emptyBodyFrom(loadCapturedBlock(t).Message.Body)
	if !isBlockEmpty(body) {
		t.Error("stripped body still classified as non-empty — emptyBodyFrom missed a path or isBlockEmpty regressed")
	}
}

// TestIsBlockEmpty_OnlyDeposits documents the post-Pectra behaviour:
// a body with only ExecutionRequests.Deposits is non-empty.
func TestIsBlockEmpty_OnlyDeposits(t *testing.T) {
	body := emptyBodyFrom(loadCapturedBlock(t).Message.Body)
	body.ExecutionRequests = &electra.ExecutionRequests{
		Deposits: []*electra.DepositRequest{{}},
	}
	if isBlockEmpty(body) {
		t.Error("body with ExecutionRequests.Deposits classified as empty — must count as proposer-valuable")
	}
}

func TestIsBlockEmpty_OnlyBlobs(t *testing.T) {
	body := emptyBodyFrom(loadCapturedBlock(t).Message.Body)
	body.BlobKZGCommitments = []deneb.KZGCommitment{{}}
	if isBlockEmpty(body) {
		t.Error("body with BlobKZGCommitments classified as empty — blobs earn the proposer the blob base fee")
	}
}

// TestIsBlockEmpty_NilBody / NilExecutionPayload — defensive paths.
// The captured block doesn't have nil pointers to test against;
// minimal inline construction is the right tool for these.
func TestIsBlockEmpty_NilBody(t *testing.T) {
	if !isBlockEmpty(nil) {
		t.Error("nil body must classify as empty (defensive)")
	}
}

func TestIsBlockEmpty_NilExecutionPayload(t *testing.T) {
	if !isBlockEmpty(&electra.BeaconBlockBody{}) {
		t.Error("body with nil ExecutionPayload must classify as empty (defensive)")
	}
}

// proposalCase bundles the fixed inputs every CheckProposal test needs
// so each subtest only spells out what it changes. epoch / validator /
// pubkeys are stable; what varies is the block, bid map, and mevEnabled.
type proposalCase struct {
	block        *electra.SignedBeaconBlock
	slot         phase0.Slot
	expectedIdx  phase0.ValidatorIndex
	bestBids     map[phase0.Slot]BidTrace
	mevEnabled   bool
}

func runCheckProposal(t *testing.T, c proposalCase) (returned bool, m *MonitorMetrics) {
	t.Helper()
	m = NewMonitorMetrics(prometheus.NewRegistry())
	pubkeys := map[phase0.ValidatorIndex]string{c.expectedIdx: "abcdef"}
	returned = CheckProposal(c.block, c.slot, c.expectedIdx, c.bestBids, c.mevEnabled, pubkeys, phase0.Epoch(uint64(c.slot)/32), m)
	return returned, m
}

func TestCheckProposal_CanonicalNonEmpty(t *testing.T) {
	block := loadCapturedBlock(t)
	c := proposalCase{
		block: block,
		slot:  block.Message.Slot,
		expectedIdx: block.Message.ProposerIndex,
	}
	ok, m := runCheckProposal(t, c)
	if !ok {
		t.Fatal("captured canonical block returned false from CheckProposal — should be true (duty fulfilled)")
	}
	counterIs(t, m.TotalCanonicalProposals, 1, "TotalCanonicalProposals")
	counterIs(t, m.TotalProposedEmptyBlocks, 0, "TotalProposedEmptyBlocks")
	counterIs(t, m.TotalMissingBidTraces, 0, "TotalMissingBidTraces")
	counterIs(t, m.TotalVanillaBlocks, 0, "TotalVanillaBlocks")
}

func TestCheckProposal_EmptyBlockFromFixture(t *testing.T) {
	block := loadCapturedBlock(t)
	block.Message.Body = emptyBodyFrom(block.Message.Body)
	c := proposalCase{
		block:       block,
		slot:        block.Message.Slot,
		expectedIdx: block.Message.ProposerIndex,
	}
	ok, m := runCheckProposal(t, c)
	if !ok {
		t.Fatal("empty proposal still counts as fulfilled (duty was met); got false")
	}
	counterIs(t, m.TotalProposedEmptyBlocks, 1, "TotalProposedEmptyBlocks")
}

func TestCheckProposal_MEVMissingBidTrace(t *testing.T) {
	block := loadCapturedBlock(t)
	c := proposalCase{
		block:       block,
		slot:        block.Message.Slot,
		expectedIdx: block.Message.ProposerIndex,
		bestBids:    map[phase0.Slot]BidTrace{}, // no relay returned a trace
		mevEnabled:  true,
	}
	_, m := runCheckProposal(t, c)
	counterIs(t, m.TotalMissingBidTraces, 1, "TotalMissingBidTraces")
	counterIs(t, m.TotalVanillaBlocks, 0, "TotalVanillaBlocks (must NOT count missing-bid as vanilla)")
}

func TestCheckProposal_MEVHashMismatchVanilla(t *testing.T) {
	block := loadCapturedBlock(t)
	wrongHash := "0x" + strings.Repeat("ab", 32) // arbitrary 32-byte hex
	c := proposalCase{
		block:       block,
		slot:        block.Message.Slot,
		expectedIdx: block.Message.ProposerIndex,
		bestBids: map[phase0.Slot]BidTrace{
			block.Message.Slot: {Slot: uint64(block.Message.Slot), BlockHash: wrongHash, Value: 1},
		},
		mevEnabled: true,
	}
	_, m := runCheckProposal(t, c)
	counterIs(t, m.TotalVanillaBlocks, 1, "TotalVanillaBlocks")
	counterIs(t, m.TotalMissingBidTraces, 0, "TotalMissingBidTraces")
}

func TestCheckProposal_MEVOptimalMatch(t *testing.T) {
	block := loadCapturedBlock(t)
	matchHash := block.Message.Body.ExecutionPayload.BlockHash.String()
	c := proposalCase{
		block:       block,
		slot:        block.Message.Slot,
		expectedIdx: block.Message.ProposerIndex,
		bestBids: map[phase0.Slot]BidTrace{
			block.Message.Slot: {Slot: uint64(block.Message.Slot), BlockHash: matchHash, Value: 1},
		},
		mevEnabled: true,
	}
	_, m := runCheckProposal(t, c)
	counterIs(t, m.TotalCanonicalProposals, 1, "TotalCanonicalProposals")
	counterIs(t, m.TotalVanillaBlocks, 0, "TotalVanillaBlocks (matched hash must NOT count vanilla)")
	counterIs(t, m.TotalMissingBidTraces, 0, "TotalMissingBidTraces")
}

// TestCheckProposal_HashMatchCaseInsensitive regresses the
// silent-mismatch bug: relay JSON is not case-canonical per spec; an
// uppercase relay-emitted hash must still match the lowercase
// canonical form from the block payload.
func TestCheckProposal_HashMatchCaseInsensitive(t *testing.T) {
	block := loadCapturedBlock(t)
	matchHash := strings.ToUpper(block.Message.Body.ExecutionPayload.BlockHash.String())
	c := proposalCase{
		block:       block,
		slot:        block.Message.Slot,
		expectedIdx: block.Message.ProposerIndex,
		bestBids: map[phase0.Slot]BidTrace{
			block.Message.Slot: {Slot: uint64(block.Message.Slot), BlockHash: matchHash, Value: 1},
		},
		mevEnabled: true,
	}
	_, m := runCheckProposal(t, c)
	counterIs(t, m.TotalVanillaBlocks, 0, "TotalVanillaBlocks (case-fold match must NOT count vanilla)")
}

func TestCheckProposal_NilBlock(t *testing.T) {
	c := proposalCase{block: nil, slot: 100, expectedIdx: 42}
	ok, m := runCheckProposal(t, c)
	if ok {
		t.Error("nil block returned true; expected false (treat as missed)")
	}
	counterIs(t, m.TotalCanonicalProposals, 0, "TotalCanonicalProposals")
}

func TestCheckProposal_NilMessageOrBody(t *testing.T) {
	cases := []struct {
		name  string
		block *electra.SignedBeaconBlock
	}{
		{"nil_message", &electra.SignedBeaconBlock{Message: nil}},
		{"nil_body", &electra.SignedBeaconBlock{Message: &electra.BeaconBlock{Slot: 1, ProposerIndex: 42, Body: nil}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ok, m := runCheckProposal(t, proposalCase{block: tc.block, slot: 1, expectedIdx: 42})
			if ok {
				t.Errorf("%s returned true; expected false", tc.name)
			}
			counterIs(t, m.TotalCanonicalProposals, 0, "TotalCanonicalProposals")
		})
	}
}

func TestCheckProposal_ProposerMismatch(t *testing.T) {
	block := loadCapturedBlock(t)
	wrong := block.Message.ProposerIndex + 1 // any other validator
	c := proposalCase{
		block:       block,
		slot:        block.Message.Slot,
		expectedIdx: wrong,
	}
	ok, m := runCheckProposal(t, c)
	if ok {
		t.Error("proposer-mismatch returned true; expected false (orchestrator must leave slot in unfulfilled)")
	}
	counterIs(t, m.TotalCanonicalProposals, 0, "TotalCanonicalProposals (mismatched proposer must NOT count)")
}

func TestCheckProposal_NilExecutionPayloadOnMEVRun(t *testing.T) {
	block := loadCapturedBlock(t)
	block.Message.Body.ExecutionPayload = nil
	c := proposalCase{
		block:       block,
		slot:        block.Message.Slot,
		expectedIdx: block.Message.ProposerIndex,
		bestBids:    map[phase0.Slot]BidTrace{},
		mevEnabled:  true,
	}
	ok, _ := runCheckProposal(t, c)
	if !ok {
		t.Fatal("nil ExecutionPayload + MEV enabled returned false; expected true (duty fulfilled, just missing-bid)")
	}
}

// TestFinalizeMissedProposals exercises the leftover-map drain. No
// block fixture needed — the function operates on a slot→validator
// map only, so synthesis is the right tool.
func TestFinalizeMissedProposals(t *testing.T) {
	m := NewMonitorMetrics(prometheus.NewRegistry())
	unfulfilled := map[phase0.Slot]phase0.ValidatorIndex{
		100: 1,
		102: 2,
		101: 3,
	}
	pubkeys := map[phase0.ValidatorIndex]string{1: "a", 2: "b", 3: "c"}
	FinalizeMissedProposals(unfulfilled, pubkeys, phase0.Epoch(3), m)
	counterIs(t, m.TotalMissedProposals, 3, "TotalMissedProposals")
	// Iteration is sorted ascending so the Last* gauges settle on slot=102 / validator=2.
	if got := gaugeValue(t, m.LastMissedProposalSlot); got != 102 {
		t.Errorf("LastMissedProposalSlot = %v, want 102 (highest slot from sorted iteration)", got)
	}
	if got := gaugeValue(t, m.LastMissedProposalValidator); got != 2 {
		t.Errorf("LastMissedProposalValidator = %v, want 2", got)
	}
}
