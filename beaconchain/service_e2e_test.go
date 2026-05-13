//go:build e2e

package beaconchain

// Tests in this file hit a real beacon node and are gated by the `e2e`
// build tag so they are invisible to default `go test ./...` (and to CI,
// which has neither the endpoint nor its token).
//
// The endpoint is sourced, in order:
//   1. $BEACON_CHAIN_API
//   2. BEACON_CHAIN_API= line in ../test-env/.env
//   3. t.Skip (so a fresh checkout without an .env exits cleanly)
//
// Run via `make test-e2e`.

import (
	"bufio"
	"context"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"eth2-monitor/spec"

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/api"
	"github.com/attestantio/go-eth2-client/spec/electra"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/rs/zerolog"
)

const (
	e2eEnvKey      = "BEACON_CHAIN_API"
	e2eDotenvPath  = "../test-env/.env"
	e2eReqTimeout  = 30 * time.Second
	e2eTestTimeout = 2 * time.Minute
)

func loadE2EEndpoint(t *testing.T) string {
	t.Helper()
	if v := strings.TrimSpace(os.Getenv(e2eEnvKey)); v != "" {
		return v
	}
	f, err := os.Open(e2eDotenvPath)
	if err != nil {
		t.Skipf("e2e endpoint not configured: $%s unset and %s unreadable: %v", e2eEnvKey, e2eDotenvPath, err)
	}
	defer f.Close()
	prefix := e2eEnvKey + "="
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if v, ok := strings.CutPrefix(line, prefix); ok {
			return strings.TrimSpace(v)
		}
	}
	t.Skipf("e2e endpoint not configured: %s not found in %s", e2eEnvKey, e2eDotenvPath)
	return ""
}

// endpointHost extracts host only — the URL path may carry a bearer token
// that should not appear in logs.
func endpointHost(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return "<unparseable>"
	}
	return u.Host
}

func TestBeaconChain_E2E(t *testing.T) {
	// go-eth2-client logs every request URL (which includes the token in
	// the path) at trace level. Suppress that for the duration of the test
	// so failures aren't drowned out and so no token shows up in CI logs
	// if someone runs this with $BEACON_CHAIN_API set in a pipeline.
	prevLevel := zerolog.GlobalLevel()
	zerolog.SetGlobalLevel(zerolog.WarnLevel)
	t.Cleanup(func() { zerolog.SetGlobalLevel(prevLevel) })

	endpoint := loadE2EEndpoint(t)
	host := endpointHost(endpoint)
	t.Logf("e2e: beacon endpoint host=%s", host)

	ctx, cancel := context.WithTimeout(context.Background(), e2eTestTimeout)
	defer cancel()

	bc, err := New(ctx, endpoint, e2eReqTimeout, nil)
	if err != nil {
		t.Fatalf("New(host=%s): %v", host, err)
	}

	// Anchor every subtest to a finalized epoch so duty/committee lookups
	// don't race the chain tip.
	finProvider, ok := bc.Service().(eth2client.FinalityProvider)
	if !ok {
		t.Fatalf("service does not implement FinalityProvider")
	}
	finCtx, finCancel := context.WithTimeout(ctx, e2eReqTimeout)
	defer finCancel()
	finResp, err := finProvider.Finality(finCtx, &api.FinalityOpts{State: "head"})
	if err != nil {
		t.Fatalf("Finality(host=%s): %v", host, err)
	}
	if finResp == nil || finResp.Data == nil || finResp.Data.Finalized == nil {
		t.Fatalf("Finality(host=%s): nil response data", host)
	}
	if finResp.Data.Finalized.Epoch < 2 {
		t.Fatalf("finalized epoch (%d) too low to choose a stable test epoch", finResp.Data.Finalized.Epoch)
	}
	// Production `GetValidatorIndexes` uses EpochLowestSlot(epoch) as the
	// state ID, and Caplin returns 404 for slot-id queries pointing at a
	// missed slot (it resolves slot→block first). Walk backward from
	// finalized-1 to find an epoch whose first slot has a canonical block,
	// so the roundtrip subtest doesn't flake on epoch-boundary skips.
	const epochSearchWindow = 32
	var testEpoch phase0.Epoch
	for cand := finResp.Data.Finalized.Epoch - 1; cand+epochSearchWindow > finResp.Data.Finalized.Epoch && cand > 0; cand-- {
		probeCtx, probeCancel := context.WithTimeout(ctx, e2eReqTimeout)
		b, err := bc.GetBlock(probeCtx, spec.EpochLowestSlot(cand))
		probeCancel()
		if err != nil {
			t.Fatalf("probe GetBlock(slot=%d): %v", spec.EpochLowestSlot(cand), err)
		}
		if b != nil {
			testEpoch = cand
			break
		}
	}
	if testEpoch == 0 {
		t.Fatalf("no canonical block at any epoch-first-slot within %d epochs of finalized %d",
			epochSearchWindow, finResp.Data.Finalized.Epoch)
	}
	t.Logf("e2e: finalizedEpoch=%d testEpoch=%d", finResp.Data.Finalized.Epoch, testEpoch)

	epochFirstSlot := spec.EpochLowestSlot(testEpoch)
	epochLastSlot := spec.EpochHighestSlot(testEpoch)

	// Discover real validator pubkeys at indices [0..2] from head state, so
	// we can round-trip them through GetValidatorIndexes without any
	// hardcoded testnet-specific data.
	var probePubkeys []string
	t.Run("validators_at_low_indices", func(t *testing.T) {
		provider := bc.Service().(eth2client.ValidatorsProvider)
		subCtx, c := context.WithTimeout(ctx, e2eReqTimeout)
		defer c()
		resp, err := provider.Validators(subCtx, &api.ValidatorsOpts{
			State:   "head",
			Indices: []phase0.ValidatorIndex{0, 1, 2},
		})
		if err != nil {
			t.Fatalf("Validators(head, [0,1,2]): %v", err)
		}
		if len(resp.Data) == 0 {
			t.Fatalf("no validators returned for indices [0,1,2]")
		}
		for _, v := range resp.Data {
			probePubkeys = append(probePubkeys, NormalizedPublicKey(v.Validator.PublicKey.String()))
		}
	})

	t.Run("get_validator_indexes_roundtrip", func(t *testing.T) {
		if len(probePubkeys) == 0 {
			t.Skip("no probe pubkeys available")
		}
		subCtx, c := context.WithTimeout(ctx, e2eReqTimeout)
		defer c()
		result, err := bc.GetValidatorIndexes(subCtx, probePubkeys, testEpoch)
		if err != nil {
			t.Fatalf("GetValidatorIndexes: %v", err)
		}
		if len(result) == 0 {
			t.Fatalf("empty index map for %d probe pubkeys", len(probePubkeys))
		}
		probeSet := make(map[string]struct{}, len(probePubkeys))
		for _, pk := range probePubkeys {
			probeSet[pk] = struct{}{}
		}
		for pk, idx := range result {
			if _, ok := probeSet[pk]; !ok {
				t.Errorf("unexpected pubkey in result: %s", pk)
			}
			if idx > 2 {
				t.Errorf("pubkey %s mapped to unexpected index %d (asked for [0,1,2])", pk, idx)
			}
		}
	})

	t.Run("get_proposer_duties", func(t *testing.T) {
		subCtx, c := context.WithTimeout(ctx, e2eReqTimeout)
		defer c()
		duties, err := bc.GetProposerDuties(subCtx, testEpoch, nil)
		if err != nil {
			t.Fatalf("GetProposerDuties(epoch=%d): %v", testEpoch, err)
		}
		if len(duties) != spec.SLOTS_PER_EPOCH {
			t.Errorf("expected %d duties, got %d", spec.SLOTS_PER_EPOCH, len(duties))
		}
		for _, d := range duties {
			if d == nil {
				t.Error("nil duty entry")
				continue
			}
			if d.Slot < epochFirstSlot || d.Slot > epochLastSlot {
				t.Errorf("duty slot %d outside epoch range [%d,%d]", d.Slot, epochFirstSlot, epochLastSlot)
			}
		}
	})

	t.Run("get_attester_duties", func(t *testing.T) {
		subCtx, c := context.WithTimeout(ctx, e2eReqTimeout)
		defer c()
		duties, err := bc.GetAttesterDuties(subCtx, testEpoch, []phase0.ValidatorIndex{0, 1, 2})
		if err != nil {
			t.Fatalf("GetAttesterDuties: %v", err)
		}
		if len(duties) == 0 {
			t.Fatalf("no attester duties for indices [0,1,2] at epoch %d", testEpoch)
		}
		for _, d := range duties {
			if d == nil {
				t.Error("nil duty entry")
				continue
			}
			if d.Slot < epochFirstSlot || d.Slot > epochLastSlot {
				t.Errorf("attester duty slot %d outside epoch range [%d,%d]", d.Slot, epochFirstSlot, epochLastSlot)
			}
			if d.ValidatorIndex > 2 {
				t.Errorf("unexpected validator index %d in attester duty", d.ValidatorIndex)
			}
		}
	})

	t.Run("get_committee_lengths", func(t *testing.T) {
		subCtx, c := context.WithTimeout(ctx, e2eReqTimeout)
		defer c()
		lengths, err := bc.GetCommitteeLengths(subCtx, testEpoch)
		if err != nil {
			t.Fatalf("GetCommitteeLengths: %v", err)
		}
		if len(lengths) == 0 {
			t.Fatal("empty committee lengths map")
		}
		for slot, byIdx := range lengths {
			if slot < epochFirstSlot || slot > epochLastSlot {
				t.Errorf("slot %d outside epoch range [%d,%d]", slot, epochFirstSlot, epochLastSlot)
			}
			if len(byIdx) == 0 {
				t.Errorf("slot %d has no committees", slot)
			}
			for idx, length := range byIdx {
				if length == 0 {
					t.Errorf("committee (slot=%d idx=%d) reports zero length", slot, idx)
				}
			}
		}
	})

	t.Run("get_block_caplin_compat", func(t *testing.T) {
		// Walk forward through the epoch to find a canonical block. Missed
		// slots are normal (especially on testnets); only fail if no block
		// exists in the whole epoch.
		var (
			block     *electra.SignedBeaconBlock
			foundSlot phase0.Slot
		)
		for slot := epochFirstSlot; slot <= epochLastSlot; slot++ {
			subCtx, c := context.WithTimeout(ctx, e2eReqTimeout)
			b, err := bc.GetBlock(subCtx, slot)
			c()
			if err != nil {
				t.Fatalf("GetBlock(slot=%d): %v", slot, err)
			}
			if b != nil {
				block, foundSlot = b, slot
				break
			}
		}
		if block == nil {
			t.Fatalf("no canonical block in epoch %d (slots %d..%d)", testEpoch, epochFirstSlot, epochLastSlot)
		}
		t.Logf("e2e: block at slot=%d proposer=%d", foundSlot, block.Message.ProposerIndex)
		// The Caplin amount/index quoting fix only succeeds if the response
		// deserialized — which it did, since we have a non-nil block. The
		// remaining checks are sanity on the payload shape.
		if block.Message.Slot != foundSlot {
			t.Errorf("payload slot %d != requested slot %d", block.Message.Slot, foundSlot)
		}
		if block.Message.Body == nil {
			t.Fatal("block body is nil")
		}
	})
}
