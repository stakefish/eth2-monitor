package prysmgrpc

import (
	"context"
	"eth2-monitor/spec"

	"github.com/pkg/errors"
	eth2types "github.com/prysmaticlabs/eth2-types"
	ethpb "github.com/prysmaticlabs/prysm/v2/proto/prysm/v1alpha1"
)

func (s *Service) GetValidatorIndex(pubkey []byte) (spec.ValidatorIndex, error) {
	conn := ethpb.NewBeaconNodeValidatorClient(s.conn)

	req := &ethpb.ValidatorIndexRequest{
		PublicKey: pubkey,
	}

	opCtx, cancel := context.WithTimeout(s.ctx, s.timeout)
	resp, err := conn.ValidatorIndex(opCtx, req)
	cancel()
	if err != nil {
		return ^spec.ValidatorIndex(0), err
	}

	return spec.ValidatorIndex(resp.Index), nil
}

func (s *Service) GetValidatorBalances(index spec.ValidatorIndex, epochs []spec.Epoch) (map[spec.Epoch]spec.Gwei, error) {
	conn := ethpb.NewBeaconChainClient(s.Connection())
	result := make(map[spec.Epoch]spec.Gwei)

	for _, epoch := range epochs {
		req := &ethpb.ListValidatorBalancesRequest{
			QueryFilter: &ethpb.ListValidatorBalancesRequest_Epoch{Epoch: eth2types.Epoch(epoch)},
			Indices:     []eth2types.ValidatorIndex{eth2types.ValidatorIndex(index)},
		}

		for {
			opCtx, cancel := context.WithTimeout(s.ctx, s.timeout)
			resp, err := conn.ListValidatorBalances(opCtx, req)
			cancel()
			if err != nil {
				return nil, errors.Wrap(err, "rpc call ListValidatorBalances failed")
			}

			for _, balance := range resp.Balances {
				result[epoch] = balance.Balance
			}

			req.PageToken = resp.NextPageToken
			if req.PageToken == "" {
				break
			}
		}
	}

	return result, nil
}
