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
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stakefish/eth2-monitor/internal/opts"

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
	block          *electra.SignedBeaconBlock
	slot           phase0.Slot
	expectedIdx    phase0.ValidatorIndex
	bestBids       map[phase0.Slot]BidTrace
	mevEnabled     bool
	relaysComplete bool // every configured relay answered with traces for the epoch
	registrations  map[phase0.ValidatorIndex]Registration
}

func runCheckProposal(t *testing.T, c proposalCase) (returned bool, m *MonitorMetrics) {
	t.Helper()
	m = NewMonitorMetrics(prometheus.NewRegistry())
	pubkeys := map[phase0.ValidatorIndex]string{c.expectedIdx: "abcdef"}
	mev := MEVContext{Enabled: c.mevEnabled, RelaysComplete: c.relaysComplete, BestBids: c.bestBids, Registrations: c.registrations}
	returned = CheckProposal(c.block, c.slot, c.expectedIdx, mev, pubkeys, phase0.Epoch(uint64(c.slot)/32), m)
	return returned, m
}

func TestCheckProposal_CanonicalNonEmpty(t *testing.T) {
	block := loadCapturedBlock(t)
	c := proposalCase{
		block:       block,
		slot:        block.Message.Slot,
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

// TestCheckProposal_NoTraceRelaysIncompleteIsMissingBid — a
// builder-tagged block with no trace while at least one relay failed
// (or returned nothing for the epoch) cannot be classified: the failed
// relay most likely delivered it. Stays in TotalMissingBidTraces, no
// vanilla or builder-block report.
func TestCheckProposal_NoTraceRelaysIncompleteIsMissingBid(t *testing.T) {
	posted := captureSlack(t)
	block := loadCapturedBlock(t)
	block.Message.Body.ExecutionPayload.ExtraData = []byte("Titan (titanbuilder.xyz)")
	c := proposalCase{
		block:          block,
		slot:           block.Message.Slot,
		expectedIdx:    block.Message.ProposerIndex,
		bestBids:       map[phase0.Slot]BidTrace{}, // no relay returned a trace
		mevEnabled:     true,
		relaysComplete: false,
	}
	_, m := runCheckProposal(t, c)
	counterIs(t, m.TotalMissingBidTraces, 1, "TotalMissingBidTraces")
	counterIs(t, m.TotalVanillaBlocks, 0, "TotalVanillaBlocks (must NOT count an unclassifiable slot as vanilla)")
	counterIs(t, m.TotalRelayAbsentBuilderBlocks, 0, "TotalRelayAbsentBuilderBlocks (relay failure is not list drift)")
	if len(*posted) != 0 {
		t.Errorf("unclassifiable slot must not reach Slack, got %v", *posted)
	}
}

// TestCheckProposal_NoTraceRelaysIncomplete_ClientDefaultIsVanilla — a
// slow or failing relay must not hide a real vanilla block: with
// client-default extra_data the on-chain evidence decides, and the report
// notes the incomplete sweep.
func TestCheckProposal_NoTraceRelaysIncomplete_ClientDefaultIsVanilla(t *testing.T) {
	posted := captureSlack(t)
	block := loadCapturedBlock(t) // erigon extra_data
	c := relayAbsentCase(block, nil)
	c.relaysComplete = false
	_, m := runCheckProposal(t, c)
	counterIs(t, m.TotalVanillaBlocks, 1, "TotalVanillaBlocks")
	counterIs(t, m.TotalMissingBidTraces, 0, "TotalMissingBidTraces")
	if len(*posted) != 1 || !strings.Contains(strings.ToLower((*posted)[0]), "sweep incomplete") {
		t.Errorf("want one vanilla report noting the incomplete relay sweep, got %v", *posted)
	}
}

// TestCheckProposal_NoTraceRelaysCompleteIsVanilla — every relay
// answered with traces for the epoch and none delivered a payload for
// our slot: that is a locally built (vanilla) block. Verified on
// mainnet slots 15174684 / 15177504 (no relay trace, EL-client
// extra_data, proposer's own fee recipient).
func TestCheckProposal_NoTraceRelaysCompleteIsVanilla(t *testing.T) {
	block := loadCapturedBlock(t)
	c := proposalCase{
		block:          block,
		slot:           block.Message.Slot,
		expectedIdx:    block.Message.ProposerIndex,
		bestBids:       map[phase0.Slot]BidTrace{},
		mevEnabled:     true,
		relaysComplete: true,
	}
	_, m := runCheckProposal(t, c)
	counterIs(t, m.TotalVanillaBlocks, 1, "TotalVanillaBlocks")
	counterIs(t, m.TotalMissingBidTraces, 0, "TotalMissingBidTraces (relays were healthy; this is not a relay gap)")
	if got := gaugeValue(t, m.LastVanillaBlockSlot); got != float64(block.Message.Slot) {
		t.Errorf("LastVanillaBlockSlot = %v, want %v", got, block.Message.Slot)
	}
	if got := gaugeValue(t, m.LastVanillaBlockValidator); got != float64(block.Message.ProposerIndex) {
		t.Errorf("LastVanillaBlockValidator = %v, want %v", got, block.Message.ProposerIndex)
	}
}

// TestCheckProposal_VanillaReportCarriesEvidence — the Slack message
// for a vanilla block must carry the on-chain evidence a human uses to
// confirm the classification and, for SSV clusters, to identify the
// leader operator: graffiti, execution extra_data and fee recipient.
// Expected values come from the captured hoodi fixture block.
// captureSlack points opts.SlackURL at a fake webhook for the duration
// of the test and returns the posted bodies (appended as they arrive).
func captureSlack(t *testing.T) *[]string {
	t.Helper()
	posted := &[]string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		*posted = append(*posted, string(b))
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	prev := opts.SlackURL
	t.Cleanup(func() { opts.SlackURL = prev })
	opts.SlackURL = srv.URL
	return posted
}

// relayAbsentCase is the shared shape of the cross-check tests: MEV on,
// every relay answered, no bid for the slot.
func relayAbsentCase(block *electra.SignedBeaconBlock, regs map[phase0.ValidatorIndex]Registration) proposalCase {
	return proposalCase{
		block:          block,
		slot:           block.Message.Slot,
		expectedIdx:    block.Message.ProposerIndex,
		bestBids:       map[phase0.Slot]BidTrace{},
		mevEnabled:     true,
		relaysComplete: true,
		registrations:  regs,
	}
}

// TestCheckProposal_RelayAbsent_RegisteredMatching_IsVanilla — the fixture
// block is a real locally built hoodi block (erigon extra_data, proposer's
// own fee recipient). With a registration equal to the block's fee
// recipient it is a confirmed vanilla block.
func TestCheckProposal_RelayAbsent_RegisteredMatching_IsVanilla(t *testing.T) {
	block := loadCapturedBlock(t)
	regs := map[phase0.ValidatorIndex]Registration{block.Message.ProposerIndex: {
		Status: RegistrationRegistered, FeeRecipient: block.Message.Body.ExecutionPayload.FeeRecipient.String(),
	}}
	_, m := runCheckProposal(t, relayAbsentCase(block, regs))
	counterIs(t, m.TotalVanillaBlocks, 1, "TotalVanillaBlocks")
	counterIs(t, m.TotalRelayAbsentBuilderBlocks, 0, "TotalRelayAbsentBuilderBlocks")
	counterIs(t, m.TotalMissingBidTraces, 0, "TotalMissingBidTraces")
}

// TestCheckProposal_RelayAbsent_BuilderTagged_IsNotVanilla — a builder tag
// in extra_data means a builder made the block even though no configured
// relay delivered it (relay missing from --mev-relays or a direct deal).
func TestCheckProposal_RelayAbsent_BuilderTagged_IsNotVanilla(t *testing.T) {
	posted := captureSlack(t)
	block := loadCapturedBlock(t)
	block.Message.Body.ExecutionPayload.ExtraData = []byte("Titan (titanbuilder.xyz)")
	regs := map[phase0.ValidatorIndex]Registration{block.Message.ProposerIndex: {
		Status: RegistrationRegistered, FeeRecipient: block.Message.Body.ExecutionPayload.FeeRecipient.String(),
	}}
	_, m := runCheckProposal(t, relayAbsentCase(block, regs))
	counterIs(t, m.TotalRelayAbsentBuilderBlocks, 1, "TotalRelayAbsentBuilderBlocks")
	counterIs(t, m.TotalVanillaBlocks, 0, "TotalVanillaBlocks (builder-tagged block must NOT count as vanilla)")
	counterIs(t, m.TotalMissingBidTraces, 0, "TotalMissingBidTraces")
	if len(*posted) != 1 || !strings.Contains(strings.ToLower((*posted)[0]), "titan (titanbuilder.xyz)") || !strings.Contains(strings.ToLower((*posted)[0]), "mev-relays") {
		t.Errorf("want one Slack report naming the builder tag and the relay list, got %v", *posted)
	}
}

// TestCheckProposal_RelayAbsent_NotRegistered_ReportsIt — vanilla, and the
// report must say the validator is not registered with any relay.
func TestCheckProposal_RelayAbsent_NotRegistered_ReportsIt(t *testing.T) {
	posted := captureSlack(t)
	block := loadCapturedBlock(t)
	regs := map[phase0.ValidatorIndex]Registration{block.Message.ProposerIndex: {Status: RegistrationNotFound}}
	_, m := runCheckProposal(t, relayAbsentCase(block, regs))
	counterIs(t, m.TotalVanillaBlocks, 1, "TotalVanillaBlocks")
	if len(*posted) != 1 || !strings.Contains(strings.ToLower((*posted)[0]), "not registered") {
		t.Errorf("want one Slack report mentioning 'not registered', got %v", *posted)
	}
}

// TestCheckProposal_RelayAbsent_FeeRecipientMismatch_ReportsIt — vanilla,
// and the report must flag that the local EL paid a different address
// than the one registered with the relays.
func TestCheckProposal_RelayAbsent_FeeRecipientMismatch_ReportsIt(t *testing.T) {
	posted := captureSlack(t)
	block := loadCapturedBlock(t)
	regs := map[phase0.ValidatorIndex]Registration{block.Message.ProposerIndex: {
		Status: RegistrationRegistered, FeeRecipient: "0x" + strings.Repeat("11", 20),
	}}
	_, m := runCheckProposal(t, relayAbsentCase(block, regs))
	counterIs(t, m.TotalVanillaBlocks, 1, "TotalVanillaBlocks")
	if len(*posted) != 1 || !strings.Contains(strings.ToLower((*posted)[0]), "differs") || !strings.Contains(strings.ToLower((*posted)[0]), "0x"+strings.Repeat("11", 20)) {
		t.Errorf("want one Slack report saying the fee recipient differs from the registered one, got %v", *posted)
	}
}

// TestCheckProposal_RelayAbsent_AnyRegisteredRecipientMatches — relays can
// hold different registrations for one key (one of them stale); the
// block matching ANY of them is a correctly configured local build, so
// the report must not claim the fee recipient differs.
func TestCheckProposal_RelayAbsent_AnyRegisteredRecipientMatches(t *testing.T) {
	posted := captureSlack(t)
	block := loadCapturedBlock(t)
	blockFee := block.Message.Body.ExecutionPayload.FeeRecipient.String()
	regs := map[phase0.ValidatorIndex]Registration{block.Message.ProposerIndex: {
		Status:        RegistrationRegistered,
		FeeRecipient:  "0x" + strings.Repeat("11", 20), // newest registration, stale elsewhere
		FeeRecipients: []string{"0x" + strings.Repeat("11", 20), blockFee},
	}}
	_, m := runCheckProposal(t, relayAbsentCase(block, regs))
	counterIs(t, m.TotalVanillaBlocks, 1, "TotalVanillaBlocks")
	if len(*posted) != 1 || strings.Contains(strings.ToLower((*posted)[0]), "differs") {
		t.Errorf("block fee recipient matches one registration; report must not say 'differs': %v", *posted)
	}
}

// TestCheckProposal_RelayAbsent_RegistrationUnknown_IsVanilla — a failed
// lookup (or no lookup at all) must not block the vanilla report.
func TestCheckProposal_RelayAbsent_RegistrationUnknown_IsVanilla(t *testing.T) {
	block := loadCapturedBlock(t)
	regs := map[phase0.ValidatorIndex]Registration{block.Message.ProposerIndex: {Status: RegistrationUnknown}}
	_, m := runCheckProposal(t, relayAbsentCase(block, regs))
	counterIs(t, m.TotalVanillaBlocks, 1, "TotalVanillaBlocks")
	counterIs(t, m.TotalRelayAbsentBuilderBlocks, 0, "TotalRelayAbsentBuilderBlocks")
}

// TestIsClientDefaultExtraData pins the split observed on 636 mainnet
// blocks (Oct 2026): relay-delivered blocks always carried a builder tag,
// locally built ones an EL client tag or nothing.
func TestIsClientDefaultExtraData(t *testing.T) {
	gethRLP := []byte{0xd8, 0x83, 0x01, 0x0f, 0x0a, 0x84, 'g', 'e', 't', 'h', 0x88, 'g', 'o', '1', '.', '2', '6', '.', '4', 0x85, 'l', 'i', 'n', 'u', 'x'}
	for _, tc := range []struct {
		in   []byte
		want bool
	}{
		{nil, true},
		{[]byte("Nethermind v1.39.3"), true},
		{[]byte("besu 26.8.1"), true},
		{[]byte("reth/v2.4.1/linux"), true},
		{[]byte("erigon-3.5.2-8a829d21"), true},
		{gethRLP, true},
		{[]byte("ethrex 24.0.0"), true},
		{[]byte("Titan (titanbuilder.xyz)"), false},
		{[]byte("BuilderNet"), false},
		{[]byte("✨ Quasar (quasar.win) ✨"), false},
		{[]byte("beaverbuild.org"), false},
	} {
		if got := isClientDefaultExtraData(tc.in); got != tc.want {
			t.Errorf("isClientDefaultExtraData(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestCheckProposal_VanillaReportCarriesEvidence(t *testing.T) {
	posted := captureSlack(t)

	block := loadCapturedBlock(t)
	c := proposalCase{
		block:          block,
		slot:           block.Message.Slot,
		expectedIdx:    block.Message.ProposerIndex,
		bestBids:       map[phase0.Slot]BidTrace{},
		mevEnabled:     true,
		relaysComplete: true,
	}
	runCheckProposal(t, c)

	if len(*posted) != 1 {
		t.Fatalf("expected exactly one Slack report for a vanilla block, got %d: %v", len(*posted), *posted)
	}
	for _, want := range []string{
		"vanilla",
		"Erigon-Nimbus-C9",          // graffiti of the fixture block
		"erigon-3.5.0-dev-24537869", // execution payload extra_data
		"0x71b981b8aeade9af6363ab9a2b8dc9b70bf3c8c6", // execution payload fee_recipient
	} {
		if !strings.Contains(strings.ToLower((*posted)[0]), strings.ToLower(want)) {
			t.Errorf("Slack report lacks %q: %s", want, (*posted)[0])
		}
	}
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
