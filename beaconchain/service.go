package beaconchain

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/api"
	apiv1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2http "github.com/attestantio/go-eth2-client/http"
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

func (beacon *BeaconChain) GetValidatorIndexes(ctx context.Context, pubkeys []string) (map[string]phase0.ValidatorIndex, error) {
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
		State:   "justified",
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
		// Includes the leading 0x
		key := validator.Validator.PublicKey.String()
		key = NormalizedPublicKey(key)
		result[key] = index
	}
	return result, nil
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

func (beacon *BeaconChain) GetBeaconCommitees(ctx context.Context, epoch phase0.Epoch) ([]*apiv1.BeaconCommittee, error) {
	provider := beacon.service.(eth2client.BeaconCommitteesProvider)
	resp, err := provider.BeaconCommittees(ctx, &api.BeaconCommitteesOpts{
		State: "justified",
		Epoch: &epoch,
	})
	if err != nil {
		return nil, err
	}
	return resp.Data, err
}

func (beacon *BeaconChain) getValidatorBalance(ctx context.Context, validator phase0.ValidatorIndex, slot phase0.Slot) (*phase0.Gwei, error) {
	provider := beacon.service.(eth2client.ValidatorBalancesProvider)
	resp, err := provider.ValidatorBalances(ctx, &api.ValidatorBalancesOpts{
		State:   fmt.Sprintf("%d", slot),
		Indices: []phase0.ValidatorIndex{validator},
	})
	if err != nil {
		return nil, err
	}
	if len(resp.Data) == 0 {
		return nil, nil
	}
	if len(resp.Data) > 1 {
		panic(fmt.Sprintf("Expected at most 1 validator in Beacon API response, got %v", len(resp.Data)))
	}
	for _, balance := range resp.Data {
		return &balance, nil
	}
	panic("unreachable")
}

func (beacon *BeaconChain) GetValidatorBalanceDiff(ctx context.Context, validator phase0.ValidatorIndex, earlierSlot phase0.Slot, laterSlot phase0.Slot) (*int64, error) {
	earlierBalance, err := beacon.getValidatorBalance(ctx, validator, earlierSlot)
	if err != nil {
		return nil, err
	}

	laterBalance, err := beacon.getValidatorBalance(ctx, validator, laterSlot)
	if err != nil {
		return nil, err
	}

	balance := int64(*laterBalance) - int64(*earlierBalance)
	return &balance, nil
}
