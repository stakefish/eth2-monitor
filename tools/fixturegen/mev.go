package main

// MEV relay fixture capture (`--scenario=mev`): one page of bid traces per
// public mainnet relay plus the validator_registration of the page's first
// proposer, written under internal/monitoring/testdata/mev/ with a
// meta.json that records the cursor slot and page limit the monitoring
// tests replay against.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

const (
	mevOutDir    = "internal/monitoring/testdata/mev"
	mevMetaPath  = "internal/monitoring/testdata/meta.json"
	mevPageLimit = 32 // matches what production code requests (SLOTS_PER_EPOCH)
)

var mevRelays = []struct {
	name string
	url  string
}{
	{name: "flashbots", url: "https://boost-relay.flashbots.net"},
	{name: "ultrasound", url: "https://relay.ultrasound.money"},
}

type mevMeta struct {
	RelaysCaptured []string `json:"relays_captured"`
	CursorSlot     uint64   `json:"cursor_slot"`
	PageLimit      uint64   `json:"page_limit"`
	// RegistrationPubkey is the proposer of the first captured trace,
	// whose validator_registration was captured as <relay>_registration.json.
	RegistrationPubkey string    `json:"registration_pubkey,omitempty"`
	CapturedAt         time.Time `json:"captured_at"`
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
	var registrationPubkey string
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
		// Capture the registration of the page's first proposer so the
		// registration-lookup tests run against a real wire response for
		// a pubkey that also appears in the bid-trace fixture.
		pk, ok := firstBidTraceProposer(body)
		if !ok {
			continue
		}
		regBody, regCode, err := mevRelayRegistration(ctx, r.url, pk)
		if err != nil || regCode != 200 || len(regBody) > maxFixtureBytes {
			fmt.Printf("fixturegen: WARN MEV relay %s registration capture failed (status %d, err %v); skipping\n", r.name, regCode, err)
			continue
		}
		regDst := filepath.Join(mevOutDir, r.name+"_registration.json")
		if err := os.WriteFile(regDst, regBody, 0o644); err != nil {
			return fmt.Errorf("write %s: %w", regDst, err)
		}
		fmt.Printf("fixturegen: wrote %s (%d bytes, status %d)\n", regDst, len(regBody), regCode)
		if registrationPubkey == "" {
			registrationPubkey = pk
		}
	}
	if len(captured) == 0 {
		return fmt.Errorf("no MEV relays captured (all failed)")
	}
	mm := mevMeta{
		RelaysCaptured:     captured,
		CursorSlot:         firstSlot,
		PageLimit:          mevPageLimit,
		RegistrationPubkey: registrationPubkey,
		CapturedAt:         time.Now().UTC(),
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
	return mevRelayGet(ctx, fmt.Sprintf("%s/relay/v1/data/bidtraces/proposer_payload_delivered?cursor=%d&limit=%d", baseurl, cursor, limit))
}

// mevRelayRegistration fetches the relay's validator_registration record
// for pubkey (raw body + status; 400 means the relay has none).
func mevRelayRegistration(ctx context.Context, baseurl, pubkey string) ([]byte, int, error) {
	return mevRelayGet(ctx, fmt.Sprintf("%s/relay/v1/data/validator_registration?pubkey=%s", baseurl, pubkey))
}

// firstBidTraceProposer returns the proposer_pubkey of the first (most
// recent) trace in a proposer_payload_delivered page.
func firstBidTraceProposer(body []byte) (string, bool) {
	var traces []struct {
		ProposerPubkey string `json:"proposer_pubkey"`
	}
	if err := json.Unmarshal(body, &traces); err != nil || len(traces) == 0 || traces[0].ProposerPubkey == "" {
		return "", false
	}
	return traces[0].ProposerPubkey, true
}

func mevRelayGet(ctx context.Context, url string) ([]byte, int, error) {
	subCtx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
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
