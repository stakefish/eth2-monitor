package monitoring

// Integration tests for attestations.go. The full classification
// edge-case coverage stays in attestations_classification_test.go
// (synthetic data — see header comment there for rationale). This
// file proves the production code paths *accept and process* real
// captured beacon data without schema or pointer-deref regressions:
//
//   - BuildCommitteeLookup runs against the real captured
//     committees.json + attester_duties.json fixtures.
//   - Real Attestation values pulled from block_canonical.json's
//     body.attestations[] survive a round-trip through processAttestations
//     without panicking the orchestrator.
//
// The classification *outcome* (canonical vs. missed vs. dedup) is
// not asserted here — that requires constructing committee+duty
// scenarios that the captured single-slot fixture set can't satisfy.
// The classification tests cover those; this test covers the wire-
// format integration that the synthetic tests don't.

import (
	"encoding/json"
	"testing"

	v1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec/electra"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/prometheus/client_golang/prometheus"
)

// TestBuildCommitteeLookup_FromFixtures runs the builder against the
// captured /eth/v1/beacon/states/head/committees + attester_duties
// responses. Verifies the result has at least one slot populated
// from committees and that tracked-validator overlays land in the
// right (slot, committee, position) cells.
func TestBuildCommitteeLookup_FromFixtures(t *testing.T) {
	committees := decodeCommitteesFixture(t)
	duties := decodeAttesterDutiesFixture(t)

	tracked := map[phase0.ValidatorIndex]string{}
	for _, d := range duties {
		tracked[d.ValidatorIndex] = "tracked"
	}

	lookup := BuildCommitteeLookup(duties, committees, tracked)
	if len(lookup) == 0 {
		t.Fatal("BuildCommitteeLookup returned empty result; committees fixture had no slots?")
	}

	// At least one tracked duty's (slot, committee, position) entry
	// must point to its validator index. Walks duties (small list) and
	// asserts the lookup has the entry populated.
	for _, d := range duties {
		if d == nil {
			continue
		}
		entry := lookup[d.Slot][d.CommitteeIndex]
		if entry == nil {
			// Duty's committee may not be in committeeLengths if the
			// captured committees fixture is slot-filtered; the builder
			// then synthesises the entry from duty.CommitteeLength. Re-
			// check the lookup directly for that case.
			t.Errorf("lookup missing entry for slot=%d committee=%d (tracked validator %d)", d.Slot, d.CommitteeIndex, d.ValidatorIndex)
			continue
		}
		if got, ok := entry.Validators[d.ValidatorCommitteeIndex]; !ok {
			t.Errorf("lookup entry slot=%d committee=%d position=%d not populated for validator %d", d.Slot, d.CommitteeIndex, d.ValidatorCommitteeIndex, d.ValidatorIndex)
		} else if got != d.ValidatorIndex {
			t.Errorf("lookup entry slot=%d committee=%d position=%d = validator %d, want %d", d.Slot, d.CommitteeIndex, d.ValidatorCommitteeIndex, got, d.ValidatorIndex)
		}
	}
}

// TestProcessAttestations_AcceptsRealAttestations passes the
// captured block (containing real Attestation values in body.attestations[])
// through processAttestations as the orchestrator would. The assertion
// is "did not panic" and "metric counters are intact" — not the
// specific classification outcome (which depends on whose duties
// happen to land in the captured slot, and the captured single-slot
// fixture set won't have a matching tracked-validator scenario).
func TestProcessAttestations_AcceptsRealAttestations(t *testing.T) {
	block := loadCapturedBlock(t)
	if block.Message == nil || block.Message.Body == nil {
		t.Fatal("captured block has nil message/body")
	}
	if len(block.Message.Body.Attestations) == 0 {
		t.Skip("captured block has no attestations — refresh fixtures from a busier slot")
	}

	committees := decodeCommitteesFixture(t)
	duties := decodeAttesterDutiesFixture(t)
	tracked := map[phase0.ValidatorIndex]string{}
	for _, d := range duties {
		tracked[d.ValidatorIndex] = "tracked"
	}
	lookup := BuildCommitteeLookup(duties, committees, tracked)

	m := NewMonitorMetrics(prometheus.NewRegistry())
	blocks := map[phase0.Slot]*electra.SignedBeaconBlock{block.Message.Slot: block}
	seen := make(map[phase0.Slot]Set[phase0.ValidatorIndex])
	unfulfilled := make(map[phase0.Slot]Set[phase0.ValidatorIndex])

	// processAttestations is tolerant of missing-from-lookup committees
	// (just doesn't credit anyone). What we're testing is the wire-
	// format AggregationBits / CommitteeBits flow through without
	// panicking, and that the dedup map machinery is intact.
	processAttestations(blocks, lookup, tracked, seen, unfulfilled, m, phase0.Epoch(uint64(block.Message.Slot)/32))

	// Soft assertions: counters must be non-negative (they always are
	// — the assertion is that processAttestations completed without
	// panic and the metric registry is intact).
	if got := counterValue(t, m.TotalCanonicalAttestations); got < 0 {
		t.Errorf("TotalCanonicalAttestations = %v (impossible negative)", got)
	}
	if got := counterValue(t, m.DuplicateAttestationsSkipped); got < 0 {
		t.Errorf("DuplicateAttestationsSkipped = %v (impossible negative)", got)
	}
}

// decodeCommitteesFixture loads /eth/v1/beacon/states/head/committees
// (slot-filtered per fixturegen) into the committeeLengths shape
// BuildCommitteeLookup expects: map[Slot]map[CommitteeIndex]uint64
// (size, computed from len(validators) per spec).
func decodeCommitteesFixture(t *testing.T) map[phase0.Slot]map[phase0.CommitteeIndex]uint64 {
	t.Helper()
	body := loadBeaconFixture(t, "happy_path", "committees.json")
	var resp struct {
		Data []struct {
			Slot       string   `json:"slot"`
			Index      string   `json:"index"`
			Validators []string `json:"validators"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("decode committees.json: %v", err)
	}
	out := make(map[phase0.Slot]map[phase0.CommitteeIndex]uint64, len(resp.Data))
	for _, c := range resp.Data {
		var slot uint64
		if _, err := scanUint(c.Slot, &slot); err != nil {
			t.Fatalf("parse committee slot %q: %v", c.Slot, err)
		}
		var idx uint64
		if _, err := scanUint(c.Index, &idx); err != nil {
			t.Fatalf("parse committee index %q: %v", c.Index, err)
		}
		s := phase0.Slot(slot)
		i := phase0.CommitteeIndex(idx)
		if out[s] == nil {
			out[s] = make(map[phase0.CommitteeIndex]uint64)
		}
		out[s][i] = uint64(len(c.Validators))
	}
	return out
}

// decodeAttesterDutiesFixture loads attester_duties.json into the
// []*v1.AttesterDuty slice BuildCommitteeLookup expects.
func decodeAttesterDutiesFixture(t *testing.T) []*v1.AttesterDuty {
	t.Helper()
	body := loadBeaconFixture(t, "happy_path", "attester_duties.json")
	// Beacon API envelope: {"dependent_root":..., "execution_optimistic":..., "data":[...duties...]}
	var resp struct {
		Data []*v1.AttesterDuty `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("decode attester_duties.json: %v", err)
	}
	return resp.Data
}

// scanUint is a thin Sscanf wrapper. Avoids strconv noise in the
// fixture loaders.
func scanUint(s string, dst *uint64) (int, error) {
	var n int
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, &scanErr{s: s}
		}
		*dst = *dst*10 + uint64(c-'0')
		n++
	}
	if n == 0 {
		return 0, &scanErr{s: s}
	}
	return n, nil
}

type scanErr struct{ s string }

func (e *scanErr) Error() string { return "scanUint: bad input " + e.s }
