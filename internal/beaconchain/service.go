package beaconchain

import (
	"context"
	"encoding/hex"
	"errors"
	"github.com/stakefish/eth2-monitor/internal/spec"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/api"
	apiv1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2http "github.com/attestantio/go-eth2-client/http"
	"github.com/attestantio/go-eth2-client/spec/electra"
	"github.com/attestantio/go-eth2-client/spec/phase0"
)

func newInstrumentedHTTPClient(timeout time.Duration, m *RequestMetrics) *http.Client {
	base := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   timeout,
			KeepAlive: 30 * time.Second,
			DualStack: true,
		}).DialContext,
		MaxIdleConns:        64,
		MaxConnsPerHost:     64,
		MaxIdleConnsPerHost: 64,
		IdleConnTimeout:     600 * time.Second,
	}
	var transport http.RoundTripper = base
	if m != nil {
		transport = &instrumentingTransport{base: transport, m: m}
	}
	return &http.Client{Transport: transport}
}

type BeaconChain struct {
	service eth2client.Service
	timeout time.Duration
}

func New(ctx context.Context, address string, timeout time.Duration, m *RequestMetrics) (*BeaconChain, error) {
	service, err := eth2http.New(ctx,
		eth2http.WithAddress(address),
		eth2http.WithTimeout(time.Minute),
		eth2http.WithHTTPClient(newInstrumentedHTTPClient(time.Minute, m)),
	)

	if err != nil {
		return nil, err
	}

	result := &BeaconChain{
		service: service,
		timeout: timeout,
	}

	return result, nil
}

func (beacon *BeaconChain) Service() eth2client.Service {
	return beacon.service
}

func NormalizedPublicKey(pubkey string) string {
	if !strings.HasPrefix(pubkey, "0x") {
		panic(fmt.Sprintf("Public key did not have the expected 0x prefix: %v", pubkey))
	}
	pubkey = strings.TrimPrefix(pubkey, "0x")
	pubkey = strings.ToLower(pubkey)
	return pubkey
}

func (beacon *BeaconChain) GetValidatorIndexes(ctx context.Context, pubkeys []string, epoch phase0.Epoch) (map[string]phase0.ValidatorIndex, error) {
	provider := beacon.service.(eth2client.ValidatorsProvider)

	blspubkeys := make([]phase0.BLSPubKey, len(pubkeys))
	for i, strkey := range pubkeys {
		binkey, err := hex.DecodeString(strkey)
		if err != nil {
			return nil, err
		}
		blspubkeys[i] = phase0.BLSPubKey(binkey)
	}

	// Caplin resolves a slot state_id by finding the block AT that slot,
	// so a missed slot returns `404 block not found`. The active-validator
	// set is stable within an epoch, so any canonical slot of `epoch`
	// answers the same question. Walk forward from the epoch's first slot
	// until we either hit a canonical slot or exhaust the epoch.
	var (
		resp      *api.Response[map[phase0.ValidatorIndex]*apiv1.Validator]
		probedErr error
	)
	for slot := spec.EpochLowestSlot(epoch); slot <= spec.EpochHighestSlot(epoch); slot++ {
		r, err := provider.Validators(ctx, &api.ValidatorsOpts{
			State:   fmt.Sprintf("%d", slot),
			PubKeys: blspubkeys,
		})
		if err == nil {
			resp = r
			break
		}
		var apiErr *api.Error
		if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusNotFound {
			return nil, err
		}
		probedErr = err
	}
	if resp == nil {
		return nil, fmt.Errorf("no canonical slot in epoch %d (every slot 404'd): %w", epoch, probedErr)
	}
	if len(resp.Data) > len(pubkeys) {
		panic(fmt.Sprintf("Expected at most %v validator in Beacon API response, got %v", len(pubkeys), len(resp.Data)))
	}

	result := map[string]phase0.ValidatorIndex{}
	for index, validator := range resp.Data {
		// IsAttesting excludes active_slashed (a slashed validator has no
		// further attestation/proposal duties even though it's still
		// "active" by the epoch-bound is_active_validator definition).
		if validator.Status.IsAttesting() {
			// Includes the leading 0x
			key := validator.Validator.PublicKey.String()
			key = NormalizedPublicKey(key)
			result[key] = index
		}
	}
	return result, nil
}

// Get block payload
func (beacon *BeaconChain) GetBlock(ctx context.Context, slot phase0.Slot) (*electra.SignedBeaconBlock, error) {
	provider := beacon.Service().(eth2client.SignedBeaconBlockProvider)

	resp, err := provider.SignedBeaconBlock(ctx, &api.SignedBeaconBlockOpts{
		Block: fmt.Sprintf("%v", slot),
	})

	if err != nil {
		// 404 means the slot was missed (no canonical block exists). The
		// previous `resp == nil` check after this block was dead code —
		// go-eth2-client returns (nil, *api.Error{404}), never (nil, nil).
		var apiErr *api.Error
		if errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusNotFound {
			return nil, nil
		}
		return nil, err
	}

	// Fulu uses the same electra.SignedBeaconBlock structure
	if resp.Data.Fulu == nil {
		return nil, fmt.Errorf("unsupported block version at slot %v: Fulu block not found (expected Fusaka)", slot)
	}

	return resp.Data.Fulu, nil
}

func (beacon *BeaconChain) GetProposerDuties(ctx context.Context, epoch phase0.Epoch, indices []phase0.ValidatorIndex) ([]*apiv1.ProposerDuty, error) {
	provider := beacon.service.(eth2client.ProposerDutiesProvider)
	resp, err := provider.ProposerDuties(ctx, &api.ProposerDutiesOpts{
		Epoch:   epoch,
		Indices: indices,
	})
	if err != nil {
		return nil, err
	}
	return resp.Data, err
}

func (beacon *BeaconChain) GetAttesterDuties(ctx context.Context, epoch phase0.Epoch, indices []phase0.ValidatorIndex) ([]*apiv1.AttesterDuty, error) {
	provider := beacon.service.(eth2client.AttesterDutiesProvider)
	resp, err := provider.AttesterDuties(ctx, &api.AttesterDutiesOpts{
		Epoch:   epoch,
		Indices: indices,
	})
	if err != nil {
		return nil, err
	}
	return resp.Data, err
}

// GetCommitteeLengths returns the size of every beacon committee in the
// given epoch, keyed by slot and committee index. It is used to compute
// correct AggregationBits offsets in EIP-7549 attestations that span
// committees with no tracked validators (where AttesterDuties alone don't
// give us the length).
func (beacon *BeaconChain) GetCommitteeLengths(ctx context.Context, epoch phase0.Epoch) (map[phase0.Slot]map[phase0.CommitteeIndex]uint64, error) {
	provider := beacon.service.(eth2client.BeaconCommitteesProvider)
	e := epoch
	// Use "head" rather than a slot-id state: the slot at the start of the
	// requested epoch may not exist yet (future epoch lookahead) or may have
	// been pruned. "head" is always valid; combined with Epoch=e the node
	// computes committees for the target epoch using the appropriate state.
	resp, err := provider.BeaconCommittees(ctx, &api.BeaconCommitteesOpts{
		State: "head",
		Epoch: &e,
	})
	if err != nil {
		return nil, err
	}

	result := make(map[phase0.Slot]map[phase0.CommitteeIndex]uint64)
	for _, c := range resp.Data {
		if result[c.Slot] == nil {
			result[c.Slot] = make(map[phase0.CommitteeIndex]uint64)
		}
		result[c.Slot][c.Index] = uint64(len(c.Validators))
	}
	return result, nil
}

