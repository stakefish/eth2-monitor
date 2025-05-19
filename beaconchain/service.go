package beaconchain

import (
	"context"
	"encoding/hex"
	"eth2-monitor/spec"
	"fmt"
	"strings"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/api"
	apiv1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2http "github.com/attestantio/go-eth2-client/http"
	"github.com/attestantio/go-eth2-client/spec/electra"
	"github.com/attestantio/go-eth2-client/spec/phase0"
)

type BeaconChain struct {
	service eth2client.Service
	timeout time.Duration
}

func New(ctx context.Context, address string, timeout time.Duration) (*BeaconChain, error) {
	service, err := eth2http.New(ctx, eth2http.WithAddress(address), eth2http.WithTimeout(time.Minute))

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

	resp, err := provider.Validators(ctx, &api.ValidatorsOpts{
		State:   fmt.Sprintf("%d", spec.EpochLowestSlot(epoch)),
		PubKeys: blspubkeys,
	})
	if err != nil {
		return nil, err
	}
	if len(resp.Data) > len(pubkeys) {
		panic(fmt.Sprintf("Expected at most %v validator in Beacon API response, got %v", len(pubkeys), len(resp.Data)))
	}

	result := map[string]phase0.ValidatorIndex{}
	for index, validator := range resp.Data {
		if validator.Status == apiv1.ValidatorStateActiveOngoing || validator.Status == apiv1.ValidatorStateActiveExiting || validator.Status == apiv1.ValidatorStateActiveSlashed {
			// Includes the leading 0x
			key := validator.Validator.PublicKey.String()
			key = NormalizedPublicKey(key)
			result[key] = index
		}
	}
	return result, nil
}

// Resolve slot number to a block
func (beacon *BeaconChain) GetBlockHeader(ctx context.Context, slot phase0.Slot) (*apiv1.BeaconBlockHeader, error) {
	provider := beacon.Service().(eth2client.BeaconBlockHeadersProvider)

	resp, err := provider.BeaconBlockHeader(ctx, &api.BeaconBlockHeaderOpts{
		Block: fmt.Sprintf("%v", slot),
	})

	if err != nil {
		return nil, err
	}

	if resp == nil {
		// Missed slot
		return nil, nil
	}

	return resp.Data, err
}

// Get block payload
func (beacon *BeaconChain) GetBlock(ctx context.Context, slot phase0.Slot) (*electra.SignedBeaconBlock, error) {
	provider := beacon.Service().(eth2client.SignedBeaconBlockProvider)

	resp, err := provider.SignedBeaconBlock(ctx, &api.SignedBeaconBlockOpts{
		Block: fmt.Sprintf("%v", slot),
	})

	if err != nil {
		return nil, err
	}

	if resp == nil {
		// Missed slot
		return nil, nil
	}

	return resp.Data.Electra, err
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

func (beacon *BeaconChain) GetBeaconCommitees(ctx context.Context, epoch phase0.Epoch) ([]*apiv1.BeaconCommittee, error) {
	provider := beacon.service.(eth2client.BeaconCommitteesProvider)
	resp, err := provider.BeaconCommittees(ctx, &api.BeaconCommitteesOpts{
		State: fmt.Sprintf("%d", spec.EpochLowestSlot(epoch)),
		Epoch: &epoch,
	})
	if err != nil {
		return nil, err
	}
	return resp.Data, err
}
