//go:build e2e

package monitoring

// TestMonitorCorrectnessAgainstBeaconchaInE2E exercises the orchestrator's
// per-epoch delegates against a live Hoodi beacon endpoint and cross-checks
// every per-(validator, slot) decision against beaconcha.in V2 — the
// authoritative third-party explorer record.
//
// The endpoints are sourced, in order:
//   1. $BEACON_CHAIN_API   / $BEACONCHAIN_API_KEY
//   2. matching prefixes in ../../test-env/.env
//   3. t.Skip (so a fresh checkout without a .env exits cleanly).
//
// Run via `make test-e2e`. Honours the Hobbyist plan's 1 req/s ceiling on
// every beaconcha.in call (~30s of HTTP work per run).
//
// Authoritative-field convention (see docs/MONITOR_CORRECTNESS_REPORT.md):
//   - "monitor distance" is shifted AND missed-slot-adjusted
//   - beaconcha.in's `inclusion_delay_without_missed_block` matches that
//   - beaconcha.in's `inclusion_delay` is the RAW form (counts missed
//     intermediate slots) and would produce false FAILs if compared.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stakefish/eth2-monitor/internal/beaconchain"
	"github.com/stakefish/eth2-monitor/internal/opts"
	"github.com/stakefish/eth2-monitor/internal/spec"

	v1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog"
)

const (
	e2eMonBeaconEnvKey     = "BEACON_CHAIN_API"
	e2eMonAPIKeyEnvKey     = "BEACONCHAIN_API_KEY"
	e2eMonDotenvPath       = "../../test-env/.env"
	e2eMonHTTPTimeout      = 30 * time.Second
	e2eMonTestTimeout      = 5 * time.Minute
	e2eMonExplorerBase     = "https://beaconcha.in/api"
	e2eMonExplorerChain    = "hoodi"
	e2eMonFinalitySafety   = 3  // epochs back from /epoch/finalized
	e2eMonMonitoredSetSize = 10 // fits in one V2 page (cap=10)
	// 1.5s spacing comfortably covers the 1 req/s Hobbyist ceiling even
	// when two adjacent calls straddle a wall-clock-second boundary
	// (server rate limit is enforced per literal second, not per rolling
	// window). 1.1s tripped 429 in early development.
	e2eMonAPISpacing = 1500 * time.Millisecond
	// On a 429, sleep this long and retry once. Hobbyist budget is
	// 1 req/s, so a 2s sleep guarantees at least one fresh budget tick.
	e2eMon429Backoff = 2 * time.Second
)

// loadE2EMonVar reads VAR from env or from BEACONCHAIN_API_KEY=… style line
// in ../../test-env/.env. Skips the test on absence — same pattern as
// internal/beaconchain/service_e2e_test.go::loadE2EEndpoint.
func loadE2EMonVar(t *testing.T, key string) string {
	t.Helper()
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	f, err := os.Open(e2eMonDotenvPath)
	if err != nil {
		t.Skipf("e2e: $%s unset and %s unreadable: %v", key, e2eMonDotenvPath, err)
	}
	defer func() { _ = f.Close() }()
	prefix := key + "="
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if v, ok := strings.CutPrefix(line, prefix); ok {
			// Strip surrounding quotes that operators sometimes wrap secrets in.
			v = strings.TrimSpace(v)
			v = strings.Trim(v, `"'`)
			if v == "" {
				t.Skipf("e2e: %s present in %s but blank", key, e2eMonDotenvPath)
			}
			return v
		}
	}
	t.Skipf("e2e: %s not found in %s", key, e2eMonDotenvPath)
	return ""
}

// hostOnly redacts URLs that may carry a bearer token in the path.
func hostOnly(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return "<unparseable>"
	}
	return u.Host
}

// beaconchaClient is a paced HTTP wrapper around beaconcha.in V1 and V2.
// All calls block at least e2eMonAPISpacing apart so the 1 req/s Hobbyist
// ceiling is honoured even when callers iterate over many slots.
type beaconchaClient struct {
	apiKey  string
	chain   string
	spacing time.Duration
	http    *http.Client
	last    time.Time
}

func newBeaconchaClient(apiKey, chain string, spacing time.Duration) *beaconchaClient {
	return &beaconchaClient{
		apiKey:  apiKey,
		chain:   chain,
		spacing: spacing,
		http:    &http.Client{Timeout: 30 * time.Second},
	}
}

// pace blocks until at least spacing has elapsed since the previous request.
func (c *beaconchaClient) pace(ctx context.Context) error {
	if c.last.IsZero() {
		c.last = time.Now()
		return nil
	}
	wait := c.spacing - time.Since(c.last)
	if wait > 0 {
		timer := time.NewTimer(wait)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
		}
	}
	c.last = time.Now()
	return nil
}

// v1Get performs a paced GET against the network-specific subdomain
// (e.g. https://hoodi.beaconcha.in/api/v1/...). Retries once on 429.
func (c *beaconchaClient) v1Get(ctx context.Context, path string) (json.RawMessage, int, error) {
	url := fmt.Sprintf("https://%s.beaconcha.in/api/v1%s", c.chain, path)
	build := func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
		return req, nil
	}
	return c.doPacedWithRetry(ctx, build)
}

// v2Post performs a paced POST against the unified V2 endpoint at
// https://beaconcha.in/api/v2/ethereum/<resource> with chain injected
// into the JSON body. Retries once on 429.
func (c *beaconchaClient) v2Post(ctx context.Context, resource string, body map[string]any) (json.RawMessage, int, error) {
	body["chain"] = c.chain
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, 0, err
	}
	url := e2eMonExplorerBase + "/v2/ethereum" + resource
	build := func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
		req.Header.Set("Content-Type", "application/json")
		return req, nil
	}
	return c.doPacedWithRetry(ctx, build)
}

// doPacedWithRetry runs build() through the HTTP client honouring c.spacing,
// and retries exactly once on HTTP 429 after sleeping e2eMon429Backoff.
// build() is a factory because http.Request.Body must be re-readable on retry
// (the byte-reader we pass for v2Post is fine to share, but using a fresh
// request avoids any in-flight client mutation surprises).
func (c *beaconchaClient) doPacedWithRetry(ctx context.Context, build func() (*http.Request, error)) (json.RawMessage, int, error) {
	for attempt := 0; attempt < 2; attempt++ {
		if err := c.pace(ctx); err != nil {
			return nil, 0, err
		}
		req, err := build()
		if err != nil {
			return nil, 0, err
		}
		resp, err := c.http.Do(req)
		if err != nil {
			return nil, 0, err
		}
		raw, readErr := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if readErr != nil {
			return nil, resp.StatusCode, readErr
		}
		if resp.StatusCode != http.StatusTooManyRequests {
			return raw, resp.StatusCode, nil
		}
		// 429: sleep the backoff then retry once. On second 429 fall
		// through and return the body so the caller can decide.
		if attempt == 1 {
			return raw, resp.StatusCode, nil
		}
		timer := time.NewTimer(e2eMon429Backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return raw, resp.StatusCode, ctx.Err()
		case <-timer.C:
		}
	}
	return nil, 0, fmt.Errorf("unreachable")
}

// latestFinalizedEpoch reads V1 /epoch/finalized — beaconcha.in's most
// recent fully-finalized epoch. Used to anchor the target epoch with a
// safety margin so V2 calls (which are finality-gated) never 404.
func (c *beaconchaClient) latestFinalizedEpoch(ctx context.Context, t *testing.T) phase0.Epoch {
	t.Helper()
	raw, status, err := c.v1Get(ctx, "/epoch/finalized")
	if err != nil || status != http.StatusOK {
		t.Fatalf("v1 /epoch/finalized: status=%d err=%v body=%s", status, err, string(raw))
	}
	var env struct {
		Status string `json:"status"`
		Data   struct {
			Epoch     uint64 `json:"epoch"`
			Finalized bool   `json:"finalized"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("v1 /epoch/finalized: unmarshal: %v body=%s", err, string(raw))
	}
	if !env.Data.Finalized {
		t.Skipf("v1 /epoch/finalized: returned non-finalized epoch %d", env.Data.Epoch)
	}
	return phase0.Epoch(env.Data.Epoch)
}

// proposersInEpoch returns up to 32 proposer indices for an epoch via
// V1 /epoch/{e}/slots. Each row carries a `proposer` field.
func (c *beaconchaClient) proposersInEpoch(ctx context.Context, t *testing.T, epoch phase0.Epoch) []phase0.ValidatorIndex {
	t.Helper()
	raw, status, err := c.v1Get(ctx, fmt.Sprintf("/epoch/%d/slots", epoch))
	if err != nil || status != http.StatusOK {
		t.Fatalf("v1 /epoch/%d/slots: status=%d err=%v", epoch, status, err)
	}
	var env struct {
		Data []struct {
			Slot     uint64 `json:"slot"`
			Status   string `json:"status"`
			Proposer uint64 `json:"proposer"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("v1 /epoch/%d/slots: unmarshal: %v", epoch, err)
	}
	out := make([]phase0.ValidatorIndex, 0, len(env.Data))
	for _, row := range env.Data {
		// Only collect proposers from slots that were actually proposed —
		// missed-slot proposers also appear in the list, but they're not
		// guaranteed to have been online for attestation duties later, so
		// excluding them keeps the monitored set on the "fully-active"
		// side of the validator status spectrum.
		if row.Status == "1" {
			out = append(out, phase0.ValidatorIndex(row.Proposer))
		}
	}
	return out
}

// resolveIndicesToPubkeys returns the 0x-prefixed BLS public keys for the
// given validator indices via V2 /validators (batched, ≤100 per call).
func (c *beaconchaClient) resolveIndicesToPubkeys(ctx context.Context, t *testing.T, indices []phase0.ValidatorIndex) []string {
	t.Helper()
	// phase0.ValidatorIndex marshals as a JSON STRING via its custom
	// MarshalJSON; the V2 explorer rejects strings here and requires
	// raw integers (or 0x-prefixed pubkey hex). Convert to []uint64.
	body := map[string]any{
		"validator": map[string]any{
			"validator_identifiers": indicesToUint64(indices),
		},
	}
	raw, status, err := c.v2Post(ctx, "/validators", body)
	if err != nil || status != http.StatusOK {
		t.Fatalf("v2 /validators: status=%d err=%v body=%s", status, err, string(raw))
	}
	var env struct {
		Data []struct {
			Validator struct {
				Index     uint64 `json:"index"`
				PublicKey string `json:"public_key"`
			} `json:"validator"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("v2 /validators: unmarshal: %v", err)
	}
	out := make([]string, 0, len(env.Data))
	for _, row := range env.Data {
		out = append(out, row.Validator.PublicKey)
	}
	return out
}

// attestationTruth is one row of beaconcha.in's V2 /slot/attestation-duties
// reply, restricted to the fields this test compares against monitor state.
type attestationTruth struct {
	Index             phase0.ValidatorIndex
	Slot              phase0.Slot
	Missed            bool
	InclusionSlot     phase0.Slot
	DistanceCanonical int // inclusion_delay_without_missed_block (THE ground truth)
	DistanceRaw       int // inclusion_delay (counts missed intermediate slots)
}

// fetchAttestationTruth queries V2 /slot/attestation-duties for every
// (slot, monitoredValidators-at-that-slot) tuple in duties. One call per
// distinct attesterslot; the validator filter is always ≤10 entries
// because beaconcha.in's V2 page_size caps at 10 (silently truncates
// otherwise — see docs/BEACONCHAIN_API_STUDY.md).
func (c *beaconchaClient) fetchAttestationTruth(
	ctx context.Context,
	t *testing.T,
	duties []*v1.AttesterDuty,
	monitored map[phase0.ValidatorIndex]bool,
	currentEpoch phase0.Epoch,
) []attestationTruth {
	t.Helper()
	// Group duties by slot, keep only current-epoch monitored validators.
	bySlot := make(map[phase0.Slot][]phase0.ValidatorIndex)
	for _, d := range duties {
		if d == nil {
			continue
		}
		if spec.EpochFromSlot(d.Slot) != currentEpoch {
			continue
		}
		if !monitored[d.ValidatorIndex] {
			continue
		}
		bySlot[d.Slot] = append(bySlot[d.Slot], d.ValidatorIndex)
	}

	var out []attestationTruth
	// Sort slots for deterministic call order (easier to diagnose failures
	// from CI logs).
	slots := slices.Sorted(maps.Keys(bySlot))
	for _, slot := range slots {
		ids := bySlot[slot]
		// page_size cap at 10 — paginate if we ever exceed.
		for start := 0; start < len(ids); start += 10 {
			end := start + 10
			if end > len(ids) {
				end = len(ids)
			}
			chunk := ids[start:end]
			body := map[string]any{
				"slot": map[string]any{"number": uint64(slot)},
				"validator": map[string]any{
					// See resolveIndicesToPubkeys: phase0.ValidatorIndex
					// emits JSON strings; V2 explorer expects integers.
					"validator_identifiers": indicesToUint64(chunk),
				},
				"page_size": 10,
			}
			raw, status, err := c.v2Post(ctx, "/slot/attestation-duties", body)
			if status == http.StatusNotFound {
				// "requested slot N is greater than latest finalized slot M"
				// — explorer lagged past our safety margin. Skip gracefully.
				t.Skipf("v2 /slot/attestation-duties slot=%d: indexer lagged (%s)", slot, string(raw))
			}
			if err != nil || status != http.StatusOK {
				t.Fatalf("v2 /slot/attestation-duties slot=%d: status=%d err=%v body=%s", slot, status, err, string(raw))
			}
			var env struct {
				Data []struct {
					Validator struct {
						Index uint64 `json:"index"`
					} `json:"validator"`
					Status                          string `json:"status"`
					InclusionSlot                   uint64 `json:"inclusion_slot"`
					InclusionDelay                  int    `json:"inclusion_delay"`
					InclusionDelayWithoutMissedBlk  int    `json:"inclusion_delay_without_missed_block"`
				} `json:"data"`
			}
			if err := json.Unmarshal(raw, &env); err != nil {
				t.Fatalf("v2 /slot/attestation-duties slot=%d: unmarshal: %v", slot, err)
			}
			for _, row := range env.Data {
				out = append(out, attestationTruth{
					Index:             phase0.ValidatorIndex(row.Validator.Index),
					Slot:              slot,
					Missed:            row.Status == "missed",
					InclusionSlot:     phase0.Slot(row.InclusionSlot),
					DistanceCanonical: row.InclusionDelayWithoutMissedBlk,
					DistanceRaw:       row.InclusionDelay,
				})
			}
		}
	}
	return out
}

// proposalTruth is the per-slot proposal outcome from V1 /slot/{n}.
type proposalTruth struct {
	Slot   phase0.Slot
	Status string // "1" = proposed, "0" = missed
}

// fetchProposalTruth queries V1 /slot/{n} for each given slot.
func (c *beaconchaClient) fetchProposalTruth(ctx context.Context, t *testing.T, slots []phase0.Slot) []proposalTruth {
	t.Helper()
	out := make([]proposalTruth, 0, len(slots))
	for _, slot := range slots {
		raw, status, err := c.v1Get(ctx, fmt.Sprintf("/slot/%d", slot))
		if err != nil {
			t.Fatalf("v1 /slot/%d: err=%v", slot, err)
		}
		// V1 returns HTTP 400 with "could not retrieve db results" for genuinely
		// missed slots — treat as "missed", consistent with the monitor's view.
		if status == http.StatusBadRequest {
			out = append(out, proposalTruth{Slot: slot, Status: "0"})
			continue
		}
		if status != http.StatusOK {
			t.Fatalf("v1 /slot/%d: unexpected status %d body=%s", slot, status, string(raw))
		}
		var env struct {
			Data struct {
				Status string `json:"status"`
			} `json:"data"`
		}
		if err := json.Unmarshal(raw, &env); err != nil {
			t.Fatalf("v1 /slot/%d: unmarshal: %v", slot, err)
		}
		out = append(out, proposalTruth{Slot: slot, Status: env.Data.Status})
	}
	return out
}

// cloneUnfulfilled deep-copies the unfulfilled-duties map so the test can
// snapshot it before FinalizeMissedAttestations mutates it.
func cloneUnfulfilled(src map[phase0.Slot]Set[phase0.ValidatorIndex]) map[phase0.Slot]Set[phase0.ValidatorIndex] {
	dst := make(map[phase0.Slot]Set[phase0.ValidatorIndex], len(src))
	for slot, s := range src {
		cp := NewSet[phase0.ValidatorIndex]()
		for v := range s.Elems() {
			cp.Add(v)
		}
		dst[slot] = cp
	}
	return dst
}

// mergeCommitteeLookups returns a slot→committee map combining a and b.
// Entries from a take precedence on overlap; for our use case a (epoch E)
// and b (epoch E+1) describe disjoint slot ranges, so precedence is moot.
func mergeCommitteeLookups(a, b map[phase0.Slot]map[phase0.CommitteeIndex]*CommitteeInfo) map[phase0.Slot]map[phase0.CommitteeIndex]*CommitteeInfo {
	out := make(map[phase0.Slot]map[phase0.CommitteeIndex]*CommitteeInfo, len(a)+len(b))
	for slot, byIdx := range a {
		out[slot] = make(map[phase0.CommitteeIndex]*CommitteeInfo, len(byIdx))
		for idx, info := range byIdx {
			out[slot][idx] = info
		}
	}
	for slot, byIdx := range b {
		if out[slot] == nil {
			out[slot] = make(map[phase0.CommitteeIndex]*CommitteeInfo, len(byIdx))
		}
		for idx, info := range byIdx {
			if _, exists := out[slot][idx]; !exists {
				out[slot][idx] = info
			}
		}
	}
	return out
}

func TestMonitorCorrectnessAgainstBeaconchaInE2E(t *testing.T) {
	// go-eth2-client trace-level logging echoes request URLs that may carry a
	// bearer token in the path. Quiet the global level so a CI log capture
	// can't leak the secret.
	prevLevel := zerolog.GlobalLevel()
	zerolog.SetGlobalLevel(zerolog.WarnLevel)
	t.Cleanup(func() { zerolog.SetGlobalLevel(prevLevel) })

	beaconURL := loadE2EMonVar(t, e2eMonBeaconEnvKey)
	apiKey := loadE2EMonVar(t, e2eMonAPIKeyEnvKey)
	t.Logf("e2e: beacon host=%s explorer chain=%s", hostOnly(beaconURL), e2eMonExplorerChain)

	// Slack POSTs and the on-disk validator-index cache would persist outside
	// the test sandbox; suppress / redirect both.
	prevSlack := opts.SlackURL
	t.Cleanup(func() { opts.SlackURL = prevSlack })
	opts.SlackURL = ""
	withTempCachePath(t)

	ctx, cancel := context.WithTimeout(context.Background(), e2eMonTestTimeout)
	defer cancel()

	reg := prometheus.NewRegistry()
	metrics := NewMonitorMetrics(reg)
	bc, err := beaconchain.New(ctx, beaconURL, e2eMonHTTPTimeout, metrics.BeaconRequestMetrics())
	if err != nil {
		t.Fatalf("beaconchain.New(host=%s): %v", hostOnly(beaconURL), err)
	}

	explorer := newBeaconchaClient(apiKey, e2eMonExplorerChain, e2eMonAPISpacing)

	// === Phase 1: pick a target epoch with a safety margin past finalized ===
	finalized := explorer.latestFinalizedEpoch(ctx, t)
	if finalized < e2eMonFinalitySafety+1 {
		t.Skipf("e2e: chain too young — finalized epoch %d < safety margin %d", finalized, e2eMonFinalitySafety)
	}
	targetEpoch := finalized - e2eMonFinalitySafety
	t.Logf("e2e: targetEpoch=%d (finalized=%d, safety=%d)", targetEpoch, finalized, e2eMonFinalitySafety)

	// === Phase 2: pick a monitored set of validators known active in E ===
	// Proposers of E are guaranteed active in E (they were assigned a duty);
	// using them gives us a 10-validator set with both an attestation and a
	// proposal duty in the target epoch.
	proposers := explorer.proposersInEpoch(ctx, t, targetEpoch)
	if len(proposers) < e2eMonMonitoredSetSize {
		t.Skipf("e2e: epoch %d has %d successful proposers (<%d) — not enough sample", targetEpoch, len(proposers), e2eMonMonitoredSetSize)
	}
	pickedIndices := proposers[:e2eMonMonitoredSetSize]
	monitoredKeys := explorer.resolveIndicesToPubkeys(ctx, t, pickedIndices)
	if len(monitoredKeys) < e2eMonMonitoredSetSize {
		t.Skipf("e2e: only %d/%d pubkeys resolved", len(monitoredKeys), e2eMonMonitoredSetSize)
	}
	t.Logf("e2e: monitoredKeys=%d picked from proposers of epoch %d", len(monitoredKeys), targetEpoch)

	// === Phase 3: drive the orchestrator's per-epoch delegates ===
	// BuildEpochContext(E) fetches duties for [E-1, E, E+1] and blocks for
	// [low(E), high(E)+4]; we additionally fetch E+1 so late inclusions
	// across the full 32-slot window land in our scan range.
	ecE, err := BuildEpochContext(ctx, bc, targetEpoch, monitoredKeys, nil /* no MEV */)
	if err != nil {
		t.Fatalf("BuildEpochContext(E=%d): %v", targetEpoch, err)
	}
	if ecE == nil {
		t.Skip("e2e: no monitored validators active in target epoch")
	}
	ecNext, err := BuildEpochContext(ctx, bc, targetEpoch+1, monitoredKeys, nil)
	if err != nil {
		t.Fatalf("BuildEpochContext(E+1=%d): %v", targetEpoch+1, err)
	}
	if ecNext == nil {
		t.Skip("e2e: no monitored validators active in E+1 — should be impossible given E was active")
	}

	// Build the monitor's monitored-set index map for filtering below.
	monitored := make(map[phase0.ValidatorIndex]bool, len(ecE.ValidatorPubkeyFromIndex))
	for idx := range ecE.ValidatorPubkeyFromIndex {
		monitored[idx] = true
	}

	// Capture the original proposer duties BEFORE the CheckProposal loop
	// deletes successful entries — needed for the proposal-side ground-truth
	// fetch later.
	originalProposerDuties := make(map[phase0.Slot]phase0.ValidatorIndex, len(ecE.ProposerDuties))
	for slot, v := range ecE.ProposerDuties {
		originalProposerDuties[slot] = v
	}

	// Seed unfulfilled with E's duties only (current-epoch slots; the
	// prev/next-epoch duties exist in ec.AttesterDuties only to anchor the
	// committee lookup).
	unfulfilled := make(map[phase0.Slot]Set[phase0.ValidatorIndex])
	seen := make(map[phase0.Slot]Set[phase0.ValidatorIndex])
	for _, duty := range ecE.AttesterDuties {
		if duty == nil {
			continue
		}
		if spec.EpochFromSlot(duty.Slot) != targetEpoch {
			continue
		}
		if _, ok := unfulfilled[duty.Slot]; !ok {
			unfulfilled[duty.Slot] = NewSet[phase0.ValidatorIndex]()
		}
		unfulfilled[duty.Slot].Add(duty.ValidatorIndex)
	}

	// Combined committee lookup covering E-1, E, E+1, E+2 so attestations
	// in either epoch's blocks can be resolved regardless of which slot they
	// reference.
	combinedLookup := mergeCommitteeLookups(ecE.CommitteeLookup, ecNext.CommitteeLookup)

	// Process E's blocks (with built-in 4-slot lookahead from
	// ListEpochBlocks) THEN E+1's blocks (full 32 slots). Seen+unfulfilled
	// are persistent across both calls — duplicate observations in the
	// 4-slot overlap are deduped exactly as the orchestrator handles them.
	processAttestations(ecE.Blocks, combinedLookup, ecE.ValidatorPubkeyFromIndex, unfulfilled, seen, metrics, targetEpoch)
	processAttestations(ecNext.Blocks, combinedLookup, ecE.ValidatorPubkeyFromIndex, unfulfilled, seen, metrics, targetEpoch)

	// Snapshot before finalize so the per-duty assertion can compare
	// "did the explorer say missed?" against the monitor's pre-finalize
	// unfulfilled state.
	unfulfilledSnapshot := cloneUnfulfilled(unfulfilled)

	// Finalize as the orchestrator would at iteration E+1: cutoff =
	// EpochHighestSlot(E). Any unfulfilled entry at slot ≤ cutoff fires
	// "did not attest" + bumps TotalMissedAttestations.
	FinalizeMissedAttestations(unfulfilled, spec.EpochHighestSlot(targetEpoch), ecE.ValidatorPubkeyFromIndex, targetEpoch, metrics)

	// Proposal phase — mirrors monitoring.go:429-443.
	for _, slot := range slices.Sorted(maps.Keys(ecE.Blocks)) {
		block := ecE.Blocks[slot]
		expected, ok := ecE.ProposerDuties[slot]
		if !ok {
			continue
		}
		if CheckProposal(block, slot, expected, ecE.BestBids, ecE.MEVEnabled, ecE.ValidatorPubkeyFromIndex, targetEpoch, metrics) {
			delete(ecE.ProposerDuties, slot)
		}
	}
	FinalizeMissedProposals(ecE.ProposerDuties, ecE.ValidatorPubkeyFromIndex, targetEpoch, metrics)

	// === Phase 4: fetch beaconcha.in ground truth + cross-check ===
	truth := explorer.fetchAttestationTruth(ctx, t, ecE.AttesterDuties, monitored, targetEpoch)
	if len(truth) == 0 {
		t.Fatalf("e2e: explorer returned no attestation truth rows for %d duties", len(ecE.AttesterDuties))
	}

	expectedMissed := 0
	expectedServed := 0
	for _, row := range truth {
		if row.Missed {
			expectedMissed++
			// Monitor should agree: pre-finalize, this duty must be in
			// unfulfilled[row.Slot]. (After finalize the map entry is
			// gone — that's why we snapshotted.)
			s := unfulfilledSnapshot[row.Slot]
			if s == nil || !s.Contains(row.Index) {
				t.Errorf("explorer: V%d missed slot %d; monitor's unfulfilledSnapshot does not contain it (slots present: %v)",
					row.Index, row.Slot, slotsOf(unfulfilledSnapshot))
			}
		} else {
			expectedServed++
			// Monitor should NOT have it in unfulfilled.
			s := unfulfilledSnapshot[row.Slot]
			if s != nil && s.Contains(row.Index) {
				t.Errorf("explorer: V%d attested slot %d (incl_slot=%d, canon_dist=%d); monitor still has it in unfulfilled",
					row.Index, row.Slot, row.InclusionSlot, row.DistanceCanonical)
			}
		}
	}

	// Aggregate counter assertion — scope-aligned because the test's
	// FinalizeMissedAttestations call uses cutoff `EpochHighestSlot(E)`,
	// so every increment of TotalMissedAttestations corresponds to a
	// monitored E duty unobserved across both iterations' scan windows.
	// That same set is what the explorer reports as `status:"missed"`
	// for the same (validator, slot) tuples.
	if got, want := counterValue(t, metrics.TotalMissedAttestations), float64(expectedMissed); got != want {
		t.Errorf("TotalMissedAttestations: monitor=%v explorer=%v", got, want)
	}

	// NOT asserted: TotalCanonicalAttestations / TotalDelayedOverTolerance
	// / CanonicalAttestationDistances buckets. These counters increment
	// for *every* observed (validator, attested-slot) tuple, regardless
	// of which epoch the attested slot belongs to. The two
	// processAttestations calls above scan blocks in [low(E), high(E)+4]
	// and [low(E+1), high(E+1)+4], so the monitor's values cover
	// attestations from [E-1, E+1+lookahead]; this test's explorer truth
	// is filtered to E's duties only. Asserting equality would require
	// fetching explorer truth for E-1 and E+1 too — out of scope for a
	// single-run test that already exercises the per-duty correctness
	// of the missed/served decision. The distance histogram itself is
	// exercised by fixture-backed scenario_delayed_attestation_test.go.

	// === Phase 5: proposal cross-check ===
	// originalProposerDuties has exactly len(monitoredKeys) entries
	// (we picked monitored from epoch E's proposers). For each slot, V1
	// /slot/{n} returns proposed (status=1) or missed (HTTP 400 or status=0).
	proposalSlots := slices.Sorted(maps.Keys(originalProposerDuties))
	proposalTruthRows := explorer.fetchProposalTruth(ctx, t, proposalSlots)
	expectedServedProposals := 0
	expectedMissedProposals := 0
	for _, row := range proposalTruthRows {
		if row.Status == "1" {
			expectedServedProposals++
		} else {
			expectedMissedProposals++
		}
	}
	if got, want := counterValue(t, metrics.TotalCanonicalProposals), float64(expectedServedProposals); got != want {
		t.Errorf("TotalCanonicalProposals: monitor=%v explorer=%v", got, want)
	}
	if got, want := counterValue(t, metrics.TotalMissedProposals), float64(expectedMissedProposals); got != want {
		t.Errorf("TotalMissedProposals: monitor=%v explorer=%v", got, want)
	}

	t.Logf("e2e: PASS targetEpoch=%d duties=%d (served=%d missed=%d) proposals=%d (served=%d missed=%d)",
		targetEpoch, len(truth), expectedServed, expectedMissed,
		len(proposalTruthRows), expectedServedProposals, expectedMissedProposals)
}

// indicesToUint64 unwraps the custom-marshalling phase0.ValidatorIndex
// type back to plain uint64s so the V2 explorer schema accepts them
// (it rejects string-encoded indices).
func indicesToUint64(in []phase0.ValidatorIndex) []uint64 {
	out := make([]uint64, len(in))
	for i, v := range in {
		out[i] = uint64(v)
	}
	return out
}

// slotsOf is a small helper for diagnostic messages — returns the
// sorted slot keys of an unfulfilled map.
func slotsOf(m map[phase0.Slot]Set[phase0.ValidatorIndex]) []string {
	slots := slices.Sorted(maps.Keys(m))
	out := make([]string, 0, len(slots))
	for _, s := range slots {
		out = append(out, strconv.FormatUint(uint64(s), 10))
	}
	return out
}
