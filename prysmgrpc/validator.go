package prysmgrpc

import (
	"context"
	"eth2-monitor/spec"

	"github.com/pkg/errors"
	primitives "github.com/prysmaticlabs/prysm/v5/consensus-types/primitives"
	ethpb "github.com/prysmaticlabs/prysm/v5/proto/prysm/v1alpha1"
)

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
