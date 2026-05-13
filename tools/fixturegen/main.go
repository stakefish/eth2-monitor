// fixturegen captures raw HTTP/SSE responses from a real beacon endpoint
// and writes them under internal/beaconchain/testdata/ for use by offline
// unit tests. It deliberately uses net/http directly (not go-eth2-client)
// so the captured bytes are exactly what the wire delivers — including
// any client-specific quirks (Caplin amount/index, future schema drift).
//
// Run via `make refresh-fixtures` from the repo root.
//
//   - The endpoint is sourced from $BEACON_CHAIN_API or test-env/.env.
//   - The full endpoint URL (which on staging carries a bearer token in
//     the path) is NEVER written to disk. Only the host portion lands
//     in meta.json. The captured response bodies themselves are pure
//     beacon-API JSON and contain no upstream credentials.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	envKey            = "BEACON_CHAIN_API"
	dotenvPath        = "test-env/.env"
	requestTimeout    = 30 * time.Second
	sseDuration       = 30 * time.Second
	epochSearchWindow = 64
	beaconOutDir      = "internal/beaconchain/testdata/beacon"
	metaPath          = "internal/beaconchain/testdata/meta.json"
	maxFixtureBytes   = 1 << 20 // 1 MiB safety cap
	generatorVersion  = "1"
)

// meta records what the captured fixtures are anchored to so tests can
// assert against the right slot/epoch numbers without hard-coding them.
// Deliberately omits any endpoint-identifying field (no host, no URL):
// the source beacon is configurable and committing it would expose which
// upstream the project uses for fixtures. The fixture bodies themselves
// are pure beacon-API JSON and likewise contain no upstream identifiers.
type meta struct {
	FinalizedEpoch   uint64    `json:"finalized_epoch"`
	TestEpoch        uint64    `json:"test_epoch"`
	CanonicalSlot    uint64    `json:"canonical_slot"`
	MissedSlot       uint64    `json:"missed_slot,omitempty"`
	HasMissed        bool      `json:"has_missed"`
	CapturedAt       time.Time `json:"captured_at"`
	GeneratorVersion string    `json:"generator_version"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "fixturegen: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	endpoint, err := resolveEndpoint()
	if err != nil {
		return err
	}
	base := strings.TrimRight(endpoint, "/")
	// Intentionally don't log the host or full URL — output may end up
	// in CI logs or pasted into PRs. The chosen test epoch / slots
	// printed below are the only context needed to diagnose a capture.
	fmt.Println("fixturegen: capturing from configured BEACON_CHAIN_API endpoint")

	if err := os.MkdirAll(beaconOutDir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", beaconOutDir, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	// 0. Startup probes — go-eth2-client.New() calls these on init to
	//    confirm the upstream is alive and to populate its internal
	//    chain-config cache. Captured so the fixture-backed unit tests
	//    can stand up a real BeaconChain against a fake server without
	//    those probes 404'ing.
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
		if _, err := capture(ctx, base, http.MethodGet, p.path, nil, p.file, 200); err != nil {
			return fmt.Errorf("capture probe %s: %w", p.path, err)
		}
	}

	// 1. finality_checkpoints — also gives us the finalized epoch we
	//    need for stable-epoch selection. Capture it first because the
	//    epoch we report later in meta.json must match the file we just
	//    wrote.
	finalityBody, err := capture(ctx, base, http.MethodGet, "/eth/v1/beacon/states/head/finality_checkpoints", nil, "finality_checkpoints.json", 200)
	if err != nil {
		return fmt.Errorf("capture finality_checkpoints: %w", err)
	}
	finalizedEpoch, err := parseFinalizedEpoch(finalityBody)
	if err != nil {
		return fmt.Errorf("parse finalized epoch: %w", err)
	}
	fmt.Printf("fixturegen: finalized epoch = %d\n", finalizedEpoch)

	testEpoch, canonicalSlot, missedSlot, hasMissed, err := findStableEpoch(ctx, base, finalizedEpoch)
	if err != nil {
		return fmt.Errorf("find stable epoch: %w", err)
	}
	fmt.Printf("fixturegen: testEpoch=%d canonicalSlot=%d missedSlot=%d hasMissed=%v\n",
		testEpoch, canonicalSlot, missedSlot, hasMissed)

	// 2. validators (POST with indices [0,1,2]) — production uses the
	//    POST form when its index/pubkey list is large; even for 3
	//    entries we follow the same path so the fixture matches what
	//    the monitor sees in real traffic. State="head" keeps the
	//    fixture stable across epoch rotations.
	validatorsBody := []byte(`{"ids":["0","1","2"],"statuses":[]}`)
	if _, err := capture(ctx, base, http.MethodPost, "/eth/v1/beacon/states/head/validators", bytes.NewReader(validatorsBody), "validators_indices_0_1_2.json", 200); err != nil {
		return fmt.Errorf("capture validators: %w", err)
	}

	// 3. canonical block.
	if _, err := capture(ctx, base, http.MethodGet, fmt.Sprintf("/eth/v2/beacon/blocks/%d", canonicalSlot), nil, "block_canonical.json", 200); err != nil {
		return fmt.Errorf("capture block_canonical: %w", err)
	}

	// 4. missed block (404). Skip if no missed slot in window — without
	//    a real 404 from upstream, fabricating one would defeat the
	//    "fixture matches real wire" property.
	if hasMissed {
		if _, err := capture(ctx, base, http.MethodGet, fmt.Sprintf("/eth/v2/beacon/blocks/%d", missedSlot), nil, "block_missed.json", 404); err != nil {
			return fmt.Errorf("capture block_missed: %w", err)
		}
	} else {
		fmt.Println("fixturegen: WARN no missed slot found in search window; skipping block_missed.json")
	}

	// 5. proposer duties.
	if _, err := capture(ctx, base, http.MethodGet, fmt.Sprintf("/eth/v1/validator/duties/proposer/%d", testEpoch), nil, "proposer_duties.json", 200); err != nil {
		return fmt.Errorf("capture proposer_duties: %w", err)
	}

	// 6. attester duties (POST with indices array body — beacon spec).
	attesterBody := []byte(`["0","1","2"]`)
	if _, err := capture(ctx, base, http.MethodPost, fmt.Sprintf("/eth/v1/validator/duties/attester/%d", testEpoch), bytes.NewReader(attesterBody), "attester_duties.json", 200); err != nil {
		return fmt.Errorf("capture attester_duties: %w", err)
	}

	// 7. committees. Filtered to a single slot — the unfiltered
	//    response on Hoodi staging is >1 MiB (the full validator set
	//    expanded across all committees in the epoch). The wire
	//    shape is identical between the filtered and unfiltered form,
	//    so a unit test parsing the slot-filtered fixture exercises
	//    the same JSON-decoding path as the production
	//    GetCommitteeLengths call.
	if _, err := capture(ctx, base, http.MethodGet, fmt.Sprintf("/eth/v1/beacon/states/head/committees?epoch=%d&slot=%d", testEpoch, canonicalSlot), nil, "committees.json", 200); err != nil {
		return fmt.Errorf("capture committees: %w", err)
	}

	// 8. SSE events stream.
	if err := captureSSE(ctx, base); err != nil {
		// SSE is best-effort — some gateways (e.g. cached ones) don't
		// stream reliably. Don't fail the whole run; just warn.
		fmt.Printf("fixturegen: WARN events SSE capture failed: %v\n", err)
	}

	// meta.json — capture context for diagnosability. Deliberately
	// excludes any endpoint identifier (see meta struct doc).
	if err := writeMeta(meta{
		FinalizedEpoch:   finalizedEpoch,
		TestEpoch:        testEpoch,
		CanonicalSlot:    canonicalSlot,
		MissedSlot:       missedSlot,
		HasMissed:        hasMissed,
		CapturedAt:       time.Now().UTC(),
		GeneratorVersion: generatorVersion,
	}); err != nil {
		return fmt.Errorf("write meta: %w", err)
	}

	fmt.Println("fixturegen: done")
	return nil
}

// resolveEndpoint mirrors the loadE2EEndpoint helper in
// internal/beaconchain/service_e2e_test.go: env var first, then a
// BEACON_CHAIN_API= line in test-env/.env. Kept inline rather than
// imported because the e2e test is build-tag-gated and this binary is not.
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

// capture issues a single request, writes the body verbatim to outDir/name,
// and returns the body bytes for any in-process parsing the caller needs.
// expectedStatus is asserted (mismatch is an error) so a silent gateway
// rewrite (e.g. a 200 page where we expected a 404) doesn't pollute the
// fixture set.
func capture(ctx context.Context, base, method, path string, body io.Reader, name string, expectedStatus int) ([]byte, error) {
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
	dst := filepath.Join(beaconOutDir, name)
	if err := os.WriteFile(dst, b, 0o644); err != nil {
		return nil, fmt.Errorf("write %s: %w", dst, err)
	}
	fmt.Printf("fixturegen: wrote %s (%d bytes, status %d)\n", dst, len(b), code)
	return b, nil
}

// captureSSE opens the events stream and copies up to sseDuration of bytes
// to events_head.sse. The fixture is a verbatim transcript of what the
// upstream sent — line endings, blank lines, and event boundaries
// preserved so a fixture-replay test sees the same byte stream the
// production monitor sees.
func captureSSE(ctx context.Context, base string) error {
	dst := filepath.Join(beaconOutDir, "events_head.sse")
	subCtx, cancel := context.WithTimeout(ctx, sseDuration+5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(subCtx, http.MethodGet, base+"/eth/v1/events?topics=head", nil)
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

	// Cap the read by both byte size and wall time. SSE streams indefinitely;
	// we only want a representative excerpt.
	deadline := time.Now().Add(sseDuration)
	var buf bytes.Buffer
	chunk := make([]byte, 4096)
	for time.Now().Before(deadline) && buf.Len() <= maxFixtureBytes {
		// Set a per-read deadline so a quiet stream doesn't block us
		// past the wall-time deadline. We fall back to ctx-based
		// cancellation via subCtx.
		if dl, ok := subCtx.Deadline(); ok && time.Now().After(dl) {
			break
		}
		n, err := resp.Body.Read(chunk)
		if n > 0 {
			buf.Write(chunk[:n])
		}
		if err != nil {
			if err == io.EOF {
				break
			}
			// Network blip or context cancel — stop cleanly with what we have.
			break
		}
	}
	if buf.Len() == 0 {
		return fmt.Errorf("captured 0 bytes (stream silent for %s)", sseDuration)
	}
	if err := os.WriteFile(dst, buf.Bytes(), 0o644); err != nil {
		return err
	}
	fmt.Printf("fixturegen: wrote %s (%d bytes)\n", dst, buf.Len())
	return nil
}

// findStableEpoch picks an epoch that has both a canonical block at its
// first slot (so a /eth/v2/beacon/blocks/{slot} fixture can use that slot)
// and ideally a missed slot somewhere inside (so the 404 fixture has a
// real source). Walks backward from finalized-1 over up to
// epochSearchWindow epochs.
func findStableEpoch(ctx context.Context, base string, finalized uint64) (testEpoch, canonicalSlot, missedSlot uint64, hasMissed bool, err error) {
	const slotsPerEpoch = 32
	if finalized < 2 {
		return 0, 0, 0, false, fmt.Errorf("finalized epoch %d too low", finalized)
	}
	var fallbackEpoch, fallbackSlot uint64
	for cand := finalized - 1; cand+epochSearchWindow > finalized && cand > 0; cand-- {
		first := cand * slotsPerEpoch
		_, code, err := doRequest(ctx, base, http.MethodGet, fmt.Sprintf("/eth/v2/beacon/blocks/%d", first), nil)
		if err != nil && code == 0 {
			return 0, 0, 0, false, fmt.Errorf("probe block(slot=%d): %w", first, err)
		}
		if code != 200 {
			continue // probably a missed first slot; skip the epoch entirely
		}
		if fallbackEpoch == 0 {
			fallbackEpoch, fallbackSlot = cand, first
		}
		// Scan the rest of the epoch for a 404.
		for slot := first + 1; slot < first+slotsPerEpoch; slot++ {
			_, sc, err := doRequest(ctx, base, http.MethodGet, fmt.Sprintf("/eth/v2/beacon/blocks/%d", slot), nil)
			if err != nil && sc == 0 {
				return 0, 0, 0, false, fmt.Errorf("scan block(slot=%d): %w", slot, err)
			}
			if sc == 404 {
				return cand, first, slot, true, nil
			}
		}
	}
	if fallbackEpoch == 0 {
		return 0, 0, 0, false, fmt.Errorf("no canonical block at any first-slot within %d epochs of finalized %d",
			epochSearchWindow, finalized)
	}
	return fallbackEpoch, fallbackSlot, 0, false, nil
}

// doRequest is a thin wrapper that returns body, status code, error. The
// body Closer is the caller's responsibility unless an error is returned.
// For probe requests where we only want the status code, the caller can
// drain and close.
func doRequest(ctx context.Context, base, method, path string, body io.Reader) (io.ReadCloser, int, error) {
	subCtx, cancel := context.WithTimeout(ctx, requestTimeout)
	// We can't defer cancel here because we're returning the body; the
	// caller's Close will drop the response and the underlying transport
	// will release resources. Pin cancel to the body close.
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

// parseFinalizedEpoch extracts data.finalized.epoch from the
// finality_checkpoints response. Uses a minimal struct rather than
// go-eth2-client to keep this tool dependency-free of the wider project.
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
		return 0, fmt.Errorf("no data.finalized.epoch in response")
	}
	var n uint64
	if _, err := fmt.Sscanf(resp.Data.Finalized.Epoch, "%d", &n); err != nil {
		return 0, fmt.Errorf("parse epoch %q: %w", resp.Data.Finalized.Epoch, err)
	}
	return n, nil
}

func writeMeta(m meta) error {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(metaPath), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(metaPath, append(b, '\n'), 0o644); err != nil {
		return err
	}
	fmt.Printf("fixturegen: wrote %s\n", metaPath)
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
