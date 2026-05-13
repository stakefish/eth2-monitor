// fixturegen captures raw HTTP/SSE responses from a real beacon endpoint
// and writes them under internal/beaconchain/testdata/ for use by offline
// integration tests. Uses net/http directly (not go-eth2-client) so the
// captured bytes are exactly what the wire delivers — including any
// client-specific quirks (Caplin amount/index, future schema drift).
//
// Capture strategy: instead of walking historical slots (which hits
// Caplin's slow state-reconstruction path on Hoodi staging), each
// scenario subscribes to /eth/v1/events?topics=head and processes
// fresh head events as they arrive. Every block fetched during the
// wait is recorded into the scenario directory as block_<slot>.json,
// so the test fixture set ends up densely populated with real blocks
// rather than holding just one anchor block per scenario.
//
// One invocation captures one scenario, selected by `--scenario=<name>`:
//
//   _shared              - go-eth2-client startup probes + SSE excerpt
//   happy_path           - first canonical head observed; full epoch context
//   missed_proposal      - detected via slot gap in head stream; 404 envelope
//                          captured for the missed slot
//   empty_block          - first head whose block has no execution-payload
//                          value (no EL txns, no blobs, no exec requests)
//   delayed_attestation  - first head whose block carries an attestation
//                          with raw distance > 3
//   cross_epoch_attestation - first head whose block carries any
//                          attestation from a strictly earlier epoch
//   mev                  - one page of bid traces from each public mainnet
//                          relay; written under internal/monitoring/testdata/mev/
//
// Run via `make refresh-fixtures` (loops over all scenarios) or
// `make refresh-scenario SCENARIO=<name>` for a single scenario.
//
//   - The endpoint is sourced from $BEACON_CHAIN_API or test-env/.env.
//   - The full endpoint URL (which on staging carries a bearer token in
//     the path) is NEVER written to disk. Captured response bodies are
//     pure beacon-API JSON and contain no upstream identifiers.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	envKey            = "BEACON_CHAIN_API"
	dotenvPath        = "test-env/.env"
	requestTimeout    = 30 * time.Second
	slotsPerEpoch     = 32
	beaconRoot        = "internal/beaconchain/testdata/beacon"
	defaultChain      = "hoodi"
	mevOutDir         = "internal/monitoring/testdata/mev"
	mevMetaPath       = "internal/monitoring/testdata/meta.json"
	mevPageLimit      = 32      // matches what production code requests (SLOTS_PER_EPOCH)
	maxFixtureBytes   = 1 << 20 // 1 MiB safety cap
	generatorVersion  = "3"     // bumped: layout = scenario subdirs, capture flow = head-stream
	sharedScenario    = "_shared"
	mevScenario       = "mev"

	// defaultScenarioTimeout bounds the total wall time a head-stream
	// scenario will wait for a matching head. Heads arrive every ~12s;
	// 10 minutes is ≈50 slots of opportunity, comfortable for
	// predicates that hit on most blocks (cross-epoch, delayed-att
	// near a testnet incident), often-insufficient for empty_block on
	// a busy testnet (Hoodi staging routinely runs 10 min with no
	// empty block). The `--timeout` flag overrides this when an
	// operator wants to camp on a rare scenario.
	defaultScenarioTimeout = 10 * time.Minute

	// blockFetchRetryDelay is the short pause before the second attempt
	// when the upstream returns 404 right after announcing a head — head
	// announcements sometimes outpace block-availability on the read side.
	blockFetchRetryDelay = 500 * time.Millisecond
)

var mevRelays = []struct {
	name string
	url  string
}{
	{name: "flashbots", url: "https://boost-relay.flashbots.net"},
	{name: "ultrasound", url: "https://relay.ultrasound.money"},
}

// meta is the union of fields any scenario may write. omitempty keeps
// per-scenario files small. Deliberately omits any endpoint identifier
// (no host, no URL): the source beacon is configurable and committing
// it would expose which upstream the project uses for fixtures.
type meta struct {
	Scenario          string    `json:"scenario"`
	Chain             string    `json:"chain,omitempty"`
	FinalizedEpoch    uint64    `json:"finalized_epoch,omitempty"`
	TestEpoch         uint64    `json:"test_epoch,omitempty"`
	CanonicalSlot     uint64    `json:"canonical_slot,omitempty"`
	MissedSlot        uint64    `json:"missed_slot,omitempty"`
	HasMissed         bool      `json:"has_missed,omitempty"`
	EmptyBlockSlot    uint64    `json:"empty_block_slot,omitempty"`
	DelayedBlockSlot  uint64    `json:"delayed_block_slot,omitempty"`
	MaxDistance       uint64    `json:"max_distance,omitempty"`
	PrevEpoch         uint64    `json:"prev_epoch,omitempty"`
	PrevCanonicalSlot uint64    `json:"prev_canonical_slot,omitempty"`
	CapturedSlots     []uint64  `json:"captured_slots,omitempty"`
	CapturedAt        time.Time `json:"captured_at"`
	GeneratorVersion  string    `json:"generator_version"`
}

type mevMeta struct {
	RelaysCaptured []string  `json:"relays_captured"`
	CursorSlot     uint64    `json:"cursor_slot"`
	PageLimit      uint64    `json:"page_limit"`
	CapturedAt     time.Time `json:"captured_at"`
}

// scenarioPredicate is called for each new head event's block. Returns
// (matched, scenarioMeta) — when matched is true, the captured block
// becomes the canonical anchor and scenarioMeta is merged into the
// final meta.json. The state arg carries information accumulated
// across head events (e.g. the previous head slot, used by missed_proposal
// to detect slot gaps).
type scenarioPredicate func(st *scenarioState, slot uint64, b *blockShallow, body []byte) (matched bool, scenarioMeta *meta)

// scenarioState is the mutable accumulator the predicate maintains
// across head events. capturedSlots is the list of slot numbers whose
// fetched blocks have already been written to outDir/block_<slot>.json.
type scenarioState struct {
	prevHeadSlot  uint64
	capturedSlots []uint64
	outDir        string
	ctx           context.Context
	base          string
}

// beaconScenario describes everything fixturegen needs to capture a
// head-stream-driven beacon scenario.
type beaconScenario struct {
	name      string
	predicate scenarioPredicate
	// extra runs after the predicate matches and the epoch context
	// (finality_checkpoints + validators + duties + committees) has been
	// captured. Used for scenarios that need additional fixtures (e.g.
	// cross_epoch_attestation captures a prev-epoch block).
	extra func(ctx context.Context, base, outDir string, anchorSlot, anchorEpoch uint64, m *meta) error
}

var beaconScenarios = map[string]beaconScenario{
	"happy_path": {
		name:      "happy_path",
		predicate: matchAnyCanonical,
	},
	"missed_proposal": {
		name:      "missed_proposal",
		predicate: matchSlotGap,
	},
	"empty_block": {
		name:      "empty_block",
		predicate: matchEmptyBlock,
	},
	"delayed_attestation": {
		name:      "delayed_attestation",
		predicate: matchDelayedAttestation,
	},
	"cross_epoch_attestation": {
		name:      "cross_epoch_attestation",
		predicate: matchCrossEpochAttestation,
		extra:     captureCrossEpochPrevBlock,
	},
}

// scenarioNames returns all scenario names (beacon + special) in a
// stable order for help text and error messages.
func scenarioNames() []string {
	out := []string{sharedScenario, mevScenario}
	for n := range beaconScenarios {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// scenarioTimeout is set by main() from the --timeout flag; the
// head-stream loop reads it. chainName is set similarly from --chain
// and feeds into every scenario output path.
var (
	scenarioTimeout = defaultScenarioTimeout
	chainName       = defaultChain
)

// scenarioRoot returns the beaconchain testdata path for the active
// chain — every captured scenario lives at <beaconRoot>/<chain>/<scenario>/.
func scenarioRoot() string {
	return filepath.Join(beaconRoot, chainName)
}

func main() {
	scenario := flag.String("scenario", "", "scenario to capture (one of: "+strings.Join(scenarioNames(), ", ")+")")
	timeout := flag.Duration("timeout", defaultScenarioTimeout, "max wall time to wait for a matching head event (head-stream scenarios only)")
	chain := flag.String("chain", defaultChain, "chain name; fixtures land in internal/beaconchain/testdata/beacon/<chain>/<scenario>/")
	flag.Parse()

	if *scenario == "" {
		fmt.Fprintf(os.Stderr, "fixturegen: --scenario is required (one of: %s)\n", strings.Join(scenarioNames(), ", "))
		os.Exit(2)
	}
	scenarioTimeout = *timeout
	chainName = strings.TrimSpace(*chain)
	if chainName == "" {
		fmt.Fprintln(os.Stderr, "fixturegen: --chain cannot be empty")
		os.Exit(2)
	}

	if err := run(*scenario); err != nil {
		fmt.Fprintf(os.Stderr, "fixturegen: %v\n", err)
		os.Exit(1)
	}
}

func run(scenario string) error {
	if scenario == mevScenario {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		return captureMEVRelays(ctx)
	}

	endpoint, err := resolveEndpoint()
	if err != nil {
		return err
	}
	base := strings.TrimRight(endpoint, "/")
	fmt.Printf("fixturegen: scenario=%s, capturing from configured BEACON_CHAIN_API\n", scenario)

	if scenario == sharedScenario {
		// _shared only captures the 6 startup probes (no SSE — each
		// per-scenario run captures its own). 1 minute is plenty.
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		return runShared(ctx, base)
	}

	bs, ok := beaconScenarios[scenario]
	if !ok {
		return fmt.Errorf("unknown scenario %q (one of: %s)", scenario, strings.Join(scenarioNames(), ", "))
	}

	ctx, cancel := context.WithTimeout(context.Background(), scenarioTimeout+1*time.Minute)
	defer cancel()
	return runBeaconScenario(ctx, base, bs)
}

// runShared captures the 6 go-eth2-client startup probes into the
// _shared/ subdirectory. These are invariant across scenarios for a
// given chain (BeaconChain.New() probes them on init, and they don't
// change with the failure-detection target). SSE is NOT captured here
// — each per-scenario run tees its own SSE excerpt during the
// head-stream wait, anchored to that scenario's epoch.
func runShared(ctx context.Context, base string) error {
	outDir := filepath.Join(scenarioRoot(), sharedScenario)
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", outDir, err)
	}
	probes := []struct {
		path string
		file string
	}{
		{"/eth/v1/node/syncing", "node_syncing.json"},
		{"/eth/v1/node/version", "node_version.json"},
		{"/eth/v1/config/spec", "config_spec.json"},
		{"/eth/v1/config/deposit_contract", "config_deposit_contract.json"},
		{"/eth/v1/config/fork_schedule", "config_fork_schedule.json"},
		{"/eth/v1/beacon/genesis", "beacon_genesis.json"},
	}
	for _, p := range probes {
		if _, err := captureToFile(ctx, base, http.MethodGet, p.path, nil, outDir, p.file, 200); err != nil {
			return fmt.Errorf("capture probe %s: %w", p.path, err)
		}
	}
	return nil
}

// runBeaconScenario implements the head-stream-driven capture flow.
// Subscribes to /eth/v1/events?topics=head, fetches each new block,
// saves it as block_<slot>.json in outDir, and runs the scenario
// predicate. On match: copies the matching block to block_canonical.json,
// captures the surrounding epoch context, runs scenario-specific extras,
// and writes meta.json.
func runBeaconScenario(ctx context.Context, base string, bs beaconScenario) error {
	outDir := filepath.Join(scenarioRoot(), bs.name)
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", outDir, err)
	}

	st := &scenarioState{
		outDir: outDir,
		ctx:    ctx,
		base:   base,
	}

	slots := make(chan uint64, 8)
	sseErrCh := make(chan error, 1)
	streamCtx, streamCancel := context.WithCancel(ctx)
	defer streamCancel()

	// Tee the SSE bytes into outDir/events_head.sse as we read them,
	// capped at maxFixtureBytes. Each scenario ends up with its own
	// head transcript anchored to its captured slot range — useful for
	// SSE-replay tests that want to drive epoch detection against the
	// same chain conditions the scenario captured.
	ssePath := filepath.Join(outDir, "events_head.sse")
	sseFile, err := os.Create(ssePath)
	if err != nil {
		return fmt.Errorf("create %s: %w", ssePath, err)
	}
	defer func() {
		if cerr := sseFile.Close(); cerr != nil {
			fmt.Printf("fixturegen: WARN close %s: %v\n", ssePath, cerr)
		}
	}()
	sseSink := &cappedWriter{w: sseFile, cap: maxFixtureBytes}

	go func() {
		sseErrCh <- streamHeadSlots(streamCtx, base, slots, sseSink)
	}()

	scenarioDeadline := time.NewTimer(scenarioTimeout)
	defer scenarioDeadline.Stop()

	fmt.Printf("fixturegen: %s waiting up to %s for a matching head event\n", bs.name, scenarioTimeout)

	for {
		select {
		case <-scenarioDeadline.C:
			return fmt.Errorf("scenario %s: timed out after %s with no matching head event (captured %d block(s) along the way: %v)",
				bs.name, scenarioTimeout, len(st.capturedSlots), st.capturedSlots)
		case <-ctx.Done():
			return ctx.Err()
		case err := <-sseErrCh:
			if err == nil {
				return fmt.Errorf("scenario %s: SSE stream closed before match (captured %d block(s): %v)",
					bs.name, len(st.capturedSlots), st.capturedSlots)
			}
			return fmt.Errorf("scenario %s: SSE stream error: %w", bs.name, err)
		case slot, ok := <-slots:
			if !ok {
				return fmt.Errorf("scenario %s: SSE channel closed unexpectedly", bs.name)
			}
			// Skip duplicates / regressions / pre-stream stale events.
			if slot <= st.prevHeadSlot {
				continue
			}
			body, b, err := fetchAndRecordBlock(ctx, base, outDir, slot)
			if err != nil {
				// fetchAndRecordBlock already logged; advance prevHeadSlot
				// so a later predicate check doesn't run against a missing
				// block as a "previous" anchor.
				st.prevHeadSlot = slot
				continue
			}
			st.capturedSlots = append(st.capturedSlots, slot)

			matched, scenMeta := bs.predicate(st, slot, b, body)
			st.prevHeadSlot = slot
			if !matched {
				continue
			}

			anchorSlot := b.Slot
			anchorEpoch := anchorSlot / slotsPerEpoch
			fmt.Printf("fixturegen: %s predicate matched at slot %d (epoch %d)\n", bs.name, anchorSlot, anchorEpoch)

			// Write the matched block as block_canonical.json (existing
			// test contract). Keep the per-slot copy too — tests that
			// need surrounding blocks load them via block_<slot>.json.
			if err := os.WriteFile(filepath.Join(outDir, "block_canonical.json"), body, 0o644); err != nil {
				return fmt.Errorf("write block_canonical.json: %w", err)
			}
			fmt.Printf("fixturegen: wrote %s (mirror of block_%d.json)\n", filepath.Join(outDir, "block_canonical.json"), anchorSlot)

			// Capture the epoch context: finality_checkpoints +
			// validators + proposer/attester duties + committees,
			// anchored to the matched slot's epoch.
			finalizedEpoch, err := captureEpochContext(ctx, base, outDir, anchorEpoch, anchorSlot)
			if err != nil {
				return fmt.Errorf("capture epoch context: %w", err)
			}

			if bs.extra != nil {
				if err := bs.extra(ctx, base, outDir, anchorSlot, anchorEpoch, scenMeta); err != nil {
					return fmt.Errorf("scenario extra: %w", err)
				}
			}

			if scenMeta == nil {
				scenMeta = &meta{}
			}
			scenMeta.Scenario = bs.name
			scenMeta.Chain = chainName
			scenMeta.FinalizedEpoch = finalizedEpoch
			scenMeta.TestEpoch = anchorEpoch
			scenMeta.CanonicalSlot = anchorSlot
			scenMeta.CapturedSlots = append([]uint64(nil), st.capturedSlots...)
			scenMeta.CapturedAt = time.Now().UTC()
			scenMeta.GeneratorVersion = generatorVersion
			if err := writeMeta(filepath.Join(outDir, "meta.json"), scenMeta); err != nil {
				return err
			}
			fmt.Println("fixturegen: done")
			return nil
		}
	}
}

// fetchAndRecordBlock fetches /eth/v2/beacon/blocks/<slot>, writes the
// body to outDir/block_<slot>.json, and returns the body + parsed
// shallow view. Retries once after a short pause if the first fetch
// returns a non-200 (head announcements can outpace block availability).
func fetchAndRecordBlock(ctx context.Context, base, outDir string, slot uint64) ([]byte, *blockShallow, error) {
	path := fmt.Sprintf("/eth/v2/beacon/blocks/%d", slot)
	fname := fmt.Sprintf("block_%d.json", slot)
	body, err := captureToFile(ctx, base, http.MethodGet, path, nil, outDir, fname, 200)
	if err != nil {
		fmt.Printf("fixturegen: WARN first fetch slot=%d failed: %v; retrying after %s\n", slot, err, blockFetchRetryDelay)
		select {
		case <-time.After(blockFetchRetryDelay):
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		}
		body, err = captureToFile(ctx, base, http.MethodGet, path, nil, outDir, fname, 200)
		if err != nil {
			fmt.Printf("fixturegen: WARN slot=%d still failing after retry: %v\n", slot, err)
			return nil, nil, err
		}
	}
	b, err := parseBlockShallow(body)
	if err != nil {
		fmt.Printf("fixturegen: WARN parse slot=%d: %v\n", slot, err)
		return body, nil, err
	}
	return body, b, nil
}

// captureEpochContext fetches and writes the shared per-epoch fixture
// set (finality_checkpoints + validators + proposer/attester duties +
// committees, slot-filtered to anchorSlot). Returns the finalized
// epoch reported by finality_checkpoints so meta can record it.
func captureEpochContext(ctx context.Context, base, outDir string, testEpoch, anchorSlot uint64) (uint64, error) {
	finalityBody, err := captureToFile(ctx, base, http.MethodGet, "/eth/v1/beacon/states/head/finality_checkpoints", nil, outDir, "finality_checkpoints.json", 200)
	if err != nil {
		return 0, fmt.Errorf("capture finality_checkpoints: %w", err)
	}
	finalizedEpoch, err := parseFinalizedEpoch(finalityBody)
	if err != nil {
		return 0, fmt.Errorf("parse finalized epoch: %w", err)
	}
	validatorsBody := []byte(`{"ids":["0","1","2"],"statuses":[]}`)
	if _, err := captureToFile(ctx, base, http.MethodPost, "/eth/v1/beacon/states/head/validators", bytes.NewReader(validatorsBody), outDir, "validators_indices_0_1_2.json", 200); err != nil {
		return 0, fmt.Errorf("capture validators: %w", err)
	}
	if _, err := captureToFile(ctx, base, http.MethodGet, fmt.Sprintf("/eth/v1/validator/duties/proposer/%d", testEpoch), nil, outDir, "proposer_duties.json", 200); err != nil {
		return 0, fmt.Errorf("capture proposer_duties: %w", err)
	}
	attesterBody := []byte(`["0","1","2"]`)
	if _, err := captureToFile(ctx, base, http.MethodPost, fmt.Sprintf("/eth/v1/validator/duties/attester/%d", testEpoch), bytes.NewReader(attesterBody), outDir, "attester_duties.json", 200); err != nil {
		return 0, fmt.Errorf("capture attester_duties: %w", err)
	}
	if _, err := captureToFile(ctx, base, http.MethodGet, fmt.Sprintf("/eth/v1/beacon/states/head/committees?epoch=%d&slot=%d", testEpoch, anchorSlot), nil, outDir, "committees.json", 200); err != nil {
		return 0, fmt.Errorf("capture committees: %w", err)
	}
	return finalizedEpoch, nil
}

// matchAnyCanonical matches the first canonical block we see. Used by
// happy_path — no failure-mode predicate, just anchor on whatever
// block lands next.
func matchAnyCanonical(_ *scenarioState, _ uint64, _ *blockShallow, _ []byte) (bool, *meta) {
	return true, &meta{}
}

// matchSlotGap matches when the new head's slot jumps past
// prevHeadSlot+1, meaning slots in between were missed. Captures a
// 404 envelope for the first missed slot and stops. The captured
// gap-slot fixture is written as both block_<gapSlot>.json (404) and
// block_missed.json (for the existing test contract).
func matchSlotGap(st *scenarioState, slot uint64, _ *blockShallow, _ []byte) (bool, *meta) {
	if st.prevHeadSlot == 0 || slot <= st.prevHeadSlot+1 {
		return false, nil
	}
	missedSlot := st.prevHeadSlot + 1
	missedBody, err := captureExpectedStatus(st.ctx, st.base, http.MethodGet, fmt.Sprintf("/eth/v2/beacon/blocks/%d", missedSlot), nil, 404)
	if err != nil {
		fmt.Printf("fixturegen: WARN missed-slot 404 capture for slot=%d failed: %v; continuing\n", missedSlot, err)
		return false, nil
	}
	// Save as both block_<slot>.json (per-slot record) and
	// block_missed.json (existing test contract).
	if err := os.WriteFile(filepath.Join(st.outDir, fmt.Sprintf("block_%d.json", missedSlot)), missedBody, 0o644); err != nil {
		fmt.Printf("fixturegen: WARN write block_%d.json: %v\n", missedSlot, err)
		return false, nil
	}
	if err := os.WriteFile(filepath.Join(st.outDir, "block_missed.json"), missedBody, 0o644); err != nil {
		fmt.Printf("fixturegen: WARN write block_missed.json: %v\n", err)
		return false, nil
	}
	st.capturedSlots = append(st.capturedSlots, missedSlot)
	fmt.Printf("fixturegen: captured 404 envelope for missed slot %d (gap between heads %d and %d)\n",
		missedSlot, st.prevHeadSlot, slot)
	return true, &meta{MissedSlot: missedSlot, HasMissed: true}
}

// matchEmptyBlock matches blocks with no execution-layer value
// (mirrors monitoring/proposals.go's isBlockEmpty).
func matchEmptyBlock(_ *scenarioState, _ uint64, b *blockShallow, _ []byte) (bool, *meta) {
	if b == nil || !blockIsEmpty(b) {
		return false, nil
	}
	return true, &meta{EmptyBlockSlot: b.Slot}
}

// matchDelayedAttestation matches blocks whose attestations include any
// with raw distance > 3 (block.slot - att.data.slot > 3).
func matchDelayedAttestation(_ *scenarioState, _ uint64, b *blockShallow, _ []byte) (bool, *meta) {
	if b == nil {
		return false, nil
	}
	var maxDist uint64
	for _, a := range b.Attestations {
		if a.DataSlot >= b.Slot {
			continue
		}
		d := b.Slot - a.DataSlot
		if d > maxDist {
			maxDist = d
		}
	}
	if maxDist <= 3 {
		return false, nil
	}
	return true, &meta{DelayedBlockSlot: b.Slot, MaxDistance: maxDist}
}

// matchCrossEpochAttestation matches blocks whose attestations include
// any with att.data.slot in a strictly earlier epoch than block.slot.
func matchCrossEpochAttestation(_ *scenarioState, _ uint64, b *blockShallow, _ []byte) (bool, *meta) {
	if b == nil {
		return false, nil
	}
	blockEpoch := b.Slot / slotsPerEpoch
	for _, a := range b.Attestations {
		ae := a.DataSlot / slotsPerEpoch
		if ae < blockEpoch {
			return true, &meta{PrevEpoch: ae}
		}
	}
	return false, nil
}

// captureCrossEpochPrevBlock captures a canonical block from the
// previous epoch as block_prev.json. Called by cross_epoch_attestation
// after the main predicate matches. The prev-epoch slot is derived from
// the anchored block's earliest cross-epoch attestation. Falls back to
// scanning forward from epoch-first-slot if the attestation's data.slot
// doesn't have a canonical block.
func captureCrossEpochPrevBlock(ctx context.Context, base, outDir string, anchorSlot, anchorEpoch uint64, m *meta) error {
	if m.PrevEpoch == 0 {
		return fmt.Errorf("cross_epoch_attestation: prev epoch not recorded by predicate")
	}
	prevSlot := uint64(0)
	first := m.PrevEpoch * slotsPerEpoch
	for slot := first; slot < first+slotsPerEpoch; slot++ {
		_, code, err := probe(ctx, base, fmt.Sprintf("/eth/v2/beacon/blocks/%d", slot))
		if err != nil {
			fmt.Printf("fixturegen: WARN probe prev epoch slot=%d: %v; continuing\n", slot, err)
			continue
		}
		if code == 200 {
			prevSlot = slot
			break
		}
	}
	if prevSlot == 0 {
		return fmt.Errorf("no canonical block in prev epoch %d (recent enough that the upstream should still have it)", m.PrevEpoch)
	}
	body, err := captureToFile(ctx, base, http.MethodGet, fmt.Sprintf("/eth/v2/beacon/blocks/%d", prevSlot), nil, outDir, fmt.Sprintf("block_%d.json", prevSlot), 200)
	if err != nil {
		return fmt.Errorf("capture prev-epoch block at slot=%d: %w", prevSlot, err)
	}
	if err := os.WriteFile(filepath.Join(outDir, "block_prev.json"), body, 0o644); err != nil {
		return fmt.Errorf("write block_prev.json: %w", err)
	}
	fmt.Printf("fixturegen: wrote %s (mirror of block_%d.json)\n", filepath.Join(outDir, "block_prev.json"), prevSlot)
	m.PrevCanonicalSlot = prevSlot
	return nil
}

// streamHeadSlots reads /eth/v1/events?topics=head and yields slot
// numbers as they arrive. Closes slots when the stream ends or ctx is
// cancelled. If sseSink is non-nil, every byte read from the stream
// is also forwarded to it (caller decides whether to disk-write,
// buffer, or discard once a per-scenario cap is hit). The slot
// parsing is intentionally minimal — beacon events include other
// fields (block, state, etc.) that fixturegen ignores.
func streamHeadSlots(ctx context.Context, base string, slots chan<- uint64, sseSink io.Writer) error {
	defer close(slots)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/eth/v1/events?topics=head", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "text/event-stream")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("events: status %d", resp.StatusCode)
	}
	var src io.Reader = resp.Body
	if sseSink != nil {
		src = io.TeeReader(resp.Body, sseSink)
	}
	scanner := bufio.NewScanner(src)
	scanner.Buffer(make([]byte, 64*1024), 1<<20)
	var event, data string
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "event: "):
			event = strings.TrimPrefix(line, "event: ")
		case strings.HasPrefix(line, "data: "):
			data = strings.TrimPrefix(line, "data: ")
		case line == "":
			if event == "head" && data != "" {
				var hd struct {
					Slot string `json:"slot"`
				}
				if json.Unmarshal([]byte(data), &hd) == nil {
					var s uint64
					if _, err := fmt.Sscanf(hd.Slot, "%d", &s); err == nil && s > 0 {
						select {
						case slots <- s:
						case <-ctx.Done():
							return nil
						}
					}
				}
			}
			event, data = "", ""
		}
	}
	return scanner.Err()
}

// resolveEndpoint mirrors loadE2EEndpoint in service_e2e_test.go: env
// var first, then a BEACON_CHAIN_API= line in test-env/.env.
func resolveEndpoint() (string, error) {
	if v := strings.TrimSpace(os.Getenv(envKey)); v != "" {
		return v, nil
	}
	f, err := os.Open(dotenvPath)
	if err != nil {
		return "", fmt.Errorf("$%s unset and %s unreadable: %w", envKey, dotenvPath, err)
	}
	defer func() { _ = f.Close() }()
	prefix := envKey + "="
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if v, ok := strings.CutPrefix(line, prefix); ok {
			return strings.TrimSpace(v), nil
		}
	}
	return "", fmt.Errorf("$%s unset and %s did not contain %s", envKey, dotenvPath, prefix)
}

// captureToFile issues a request, writes the body to outDir/name, and
// returns the body bytes for any in-process parsing. expectedStatus is
// asserted (mismatch is an error) so a silent gateway rewrite doesn't
// pollute the fixture set.
func captureToFile(ctx context.Context, base, method, path string, body io.Reader, outDir, name string, expectedStatus int) ([]byte, error) {
	b, err := captureExpectedStatus(ctx, base, method, path, body, expectedStatus)
	if err != nil {
		return nil, err
	}
	dst := filepath.Join(outDir, name)
	if err := os.WriteFile(dst, b, 0o644); err != nil {
		return nil, fmt.Errorf("write %s: %w", dst, err)
	}
	fmt.Printf("fixturegen: wrote %s (%d bytes, status %d)\n", dst, len(b), expectedStatus)
	return b, nil
}

// captureExpectedStatus is captureToFile without the disk write — for
// callers that want to inspect the body before deciding where to write.
func captureExpectedStatus(ctx context.Context, base, method, path string, body io.Reader, expectedStatus int) ([]byte, error) {
	rc, code, err := doRequest(ctx, base, method, path, body)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rc.Close() }()
	b, err := io.ReadAll(io.LimitReader(rc, maxFixtureBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	if len(b) > maxFixtureBytes {
		return nil, fmt.Errorf("response body exceeds %d bytes (got %d) — refuse to commit oversized fixture",
			maxFixtureBytes, len(b))
	}
	if code != expectedStatus {
		return nil, fmt.Errorf("%s %s: status %d, expected %d (body: %s)",
			method, path, code, expectedStatus, truncate(string(b), 200))
	}
	return b, nil
}

// captureMEVRelays captures one page of bid traces from each public
// mainnet relay. Output goes into internal/monitoring/testdata/mev/.
// One relay's failure doesn't stop the others.
func captureMEVRelays(ctx context.Context) error {
	if err := os.MkdirAll(mevOutDir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", mevOutDir, err)
	}
	captured := make([]string, 0, len(mevRelays))
	var firstSlot uint64
	for _, r := range mevRelays {
		body, code, err := mevRelayPage(ctx, r.url, 0, mevPageLimit)
		if err != nil {
			fmt.Printf("fixturegen: WARN MEV relay %s capture failed: %v\n", r.name, err)
			continue
		}
		if code != 200 {
			fmt.Printf("fixturegen: WARN MEV relay %s returned status %d (body excerpt: %s)\n", r.name, code, truncate(string(body), 200))
			continue
		}
		if len(body) > maxFixtureBytes {
			fmt.Printf("fixturegen: WARN MEV relay %s response %d bytes exceeds %d cap; skipping\n", r.name, len(body), maxFixtureBytes)
			continue
		}
		if isEmptyJSONArray(body) {
			fmt.Printf("fixturegen: WARN MEV relay %s returned empty array; skipping fixture\n", r.name)
			continue
		}
		dst := filepath.Join(mevOutDir, r.name+"_bidtraces.json")
		if err := os.WriteFile(dst, body, 0o644); err != nil {
			return fmt.Errorf("write %s: %w", dst, err)
		}
		fmt.Printf("fixturegen: wrote %s (%d bytes, status %d)\n", dst, len(body), code)
		captured = append(captured, r.name)
		if firstSlot == 0 {
			if s, ok := firstBidTraceSlot(body); ok {
				firstSlot = s
			}
		}
	}
	if len(captured) == 0 {
		return fmt.Errorf("no MEV relays captured (all failed)")
	}
	mm := mevMeta{
		RelaysCaptured: captured,
		CursorSlot:     firstSlot,
		PageLimit:      mevPageLimit,
		CapturedAt:     time.Now().UTC(),
	}
	b, err := json.MarshalIndent(mm, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(mevMetaPath, append(b, '\n'), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", mevMetaPath, err)
	}
	fmt.Printf("fixturegen: wrote %s\n", mevMetaPath)
	return nil
}

func mevRelayPage(ctx context.Context, baseurl string, cursor, limit uint64) ([]byte, int, error) {
	subCtx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	url := fmt.Sprintf("%s/relay/v1/data/bidtraces/proposer_payload_delivered?cursor=%d&limit=%d", baseurl, cursor, limit)
	req, err := http.NewRequestWithContext(subCtx, http.MethodGet, url, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxFixtureBytes+1))
	if err != nil {
		return nil, resp.StatusCode, err
	}
	return body, resp.StatusCode, nil
}

func isEmptyJSONArray(body []byte) bool {
	var arr []json.RawMessage
	if err := json.Unmarshal(body, &arr); err != nil {
		return false
	}
	return len(arr) == 0
}

func firstBidTraceSlot(body []byte) (uint64, bool) {
	var traces []struct {
		Slot string `json:"slot"`
	}
	if err := json.Unmarshal(body, &traces); err != nil || len(traces) == 0 {
		return 0, false
	}
	var n uint64
	if _, err := fmt.Sscanf(traces[0].Slot, "%d", &n); err != nil {
		return 0, false
	}
	return n, true
}

// cappedWriter forwards writes to an underlying writer up to cap
// bytes, then silently discards further input (reporting them as
// "written" so an io.TeeReader doesn't see a short-write error and
// terminate the downstream consumer prematurely). Used to bound the
// per-scenario events_head.sse size at maxFixtureBytes regardless of
// how long the head-stream wait runs.
type cappedWriter struct {
	w   io.Writer
	cap int
	n   int
}

func (cw *cappedWriter) Write(p []byte) (int, error) {
	if cw.n >= cw.cap {
		return len(p), nil
	}
	remaining := cw.cap - cw.n
	if len(p) > remaining {
		p = p[:remaining]
	}
	n, err := cw.w.Write(p)
	cw.n += n
	if n < len(p) && err == nil {
		// Underlying writer truncated — claim full to satisfy TeeReader.
		return len(p), nil
	}
	return n, err
}

// blockShallow is a minimal subset of the block envelope sufficient for
// scenario selection without pulling go-eth2-client into this tool.
type blockShallow struct {
	Slot                uint64
	ProposerIndex       uint64
	HasExecutionPayload bool
	NumTransactions     int
	NumBlobs            int
	NumDeposits         int
	NumWithdrawals      int
	NumConsolidations   int
	Attestations        []attestationShallow
}

type attestationShallow struct {
	DataSlot uint64
}

func parseBlockShallow(body []byte) (*blockShallow, error) {
	var env struct {
		Data struct {
			Message struct {
				Slot          string `json:"slot"`
				ProposerIndex string `json:"proposer_index"`
				Body          struct {
					ExecutionPayload *struct {
						Transactions []string `json:"transactions"`
					} `json:"execution_payload"`
					BlobKZGCommitments []string `json:"blob_kzg_commitments"`
					ExecutionRequests  *struct {
						Deposits       []json.RawMessage `json:"deposits"`
						Withdrawals    []json.RawMessage `json:"withdrawals"`
						Consolidations []json.RawMessage `json:"consolidations"`
					} `json:"execution_requests"`
					Attestations []struct {
						Data struct {
							Slot string `json:"slot"`
						} `json:"data"`
					} `json:"attestations"`
				} `json:"body"`
			} `json:"message"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, fmt.Errorf("decode block envelope: %w", err)
	}
	var slot uint64
	if _, err := fmt.Sscanf(env.Data.Message.Slot, "%d", &slot); err != nil {
		return nil, fmt.Errorf("parse slot %q: %w", env.Data.Message.Slot, err)
	}
	var proposer uint64
	_, _ = fmt.Sscanf(env.Data.Message.ProposerIndex, "%d", &proposer)
	b := &blockShallow{
		Slot:                slot,
		ProposerIndex:       proposer,
		HasExecutionPayload: env.Data.Message.Body.ExecutionPayload != nil,
		NumBlobs:            len(env.Data.Message.Body.BlobKZGCommitments),
	}
	if env.Data.Message.Body.ExecutionPayload != nil {
		b.NumTransactions = len(env.Data.Message.Body.ExecutionPayload.Transactions)
	}
	if env.Data.Message.Body.ExecutionRequests != nil {
		b.NumDeposits = len(env.Data.Message.Body.ExecutionRequests.Deposits)
		b.NumWithdrawals = len(env.Data.Message.Body.ExecutionRequests.Withdrawals)
		b.NumConsolidations = len(env.Data.Message.Body.ExecutionRequests.Consolidations)
	}
	for _, a := range env.Data.Message.Body.Attestations {
		var ds uint64
		_, _ = fmt.Sscanf(a.Data.Slot, "%d", &ds)
		b.Attestations = append(b.Attestations, attestationShallow{DataSlot: ds})
	}
	return b, nil
}

// blockIsEmpty mirrors monitoring/proposals.go's isBlockEmpty: a block
// is "empty" if it has no execution-layer transactions, no blobs, and
// no post-Pectra execution requests of any kind.
func blockIsEmpty(b *blockShallow) bool {
	if b == nil {
		return false
	}
	return b.NumTransactions == 0 &&
		b.NumBlobs == 0 &&
		b.NumDeposits == 0 &&
		b.NumWithdrawals == 0 &&
		b.NumConsolidations == 0
}

// probe is a one-shot GET that returns (body, status, err). Used by
// captureCrossEpochPrevBlock to scan an epoch for its first canonical
// slot. Errors from probe are treated by callers as "skip this slot".
func probe(ctx context.Context, base, path string) ([]byte, int, error) {
	rc, code, err := doRequest(ctx, base, http.MethodGet, path, nil)
	if err != nil {
		return nil, code, err
	}
	defer func() { _ = rc.Close() }()
	body, err := io.ReadAll(io.LimitReader(rc, maxFixtureBytes+1))
	if err != nil {
		return nil, code, err
	}
	return body, code, nil
}

// doRequest is a thin wrapper that returns body, status code, error.
func doRequest(ctx context.Context, base, method, path string, body io.Reader) (io.ReadCloser, int, error) {
	subCtx, cancel := context.WithTimeout(ctx, requestTimeout)
	req, err := http.NewRequestWithContext(subCtx, method, base+path, body)
	if err != nil {
		cancel()
		return nil, 0, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		cancel()
		return nil, 0, err
	}
	return &cancelOnClose{ReadCloser: resp.Body, cancel: cancel}, resp.StatusCode, nil
}

type cancelOnClose struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (c *cancelOnClose) Close() error {
	defer c.cancel()
	return c.ReadCloser.Close()
}

func parseFinalizedEpoch(body []byte) (uint64, error) {
	var resp struct {
		Data struct {
			Finalized struct {
				Epoch string `json:"epoch"`
			} `json:"finalized"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return 0, err
	}
	if resp.Data.Finalized.Epoch == "" {
		return 0, errors.New("no data.finalized.epoch in response")
	}
	var n uint64
	if _, err := fmt.Sscanf(resp.Data.Finalized.Epoch, "%d", &n); err != nil {
		return 0, fmt.Errorf("parse epoch %q: %w", resp.Data.Finalized.Epoch, err)
	}
	return n, nil
}

func writeMeta(path string, m *meta) error {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(path, append(b, '\n'), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	fmt.Printf("fixturegen: wrote %s\n", path)
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
