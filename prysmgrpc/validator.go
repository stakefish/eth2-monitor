package prysmgrpc

import (
	"context"
	"eth2-monitor/spec"

	"github.com/pkg/errors"
	primitives "github.com/prysmaticlabs/prysm/v4/consensus-types/primitives"
	ethpb "github.com/prysmaticlabs/prysm/v4/proto/prysm/v1alpha1"
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
			QueryFilter: &ethpb.ListValidatorBalancesRequest_Epoch{Epoch: primitives.Epoch(epoch)},
			Indices:     []primitives.ValidatorIndex{primitives.ValidatorIndex(index)},
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
