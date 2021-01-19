package prysmgrpc

import (
	"context"

	"github.com/gogo/protobuf/types"
	"github.com/pkg/errors"
	ethpb "github.com/prysmaticlabs/ethereumapis/eth/v1alpha1"
)

func (s *Service) GetChainHead() (*ethpb.ChainHead, error) {
	conn := ethpb.NewBeaconChainClient(s.conn)

	opCtx, cancel := context.WithTimeout(s.ctx, s.timeout)
	resp, err := conn.GetChainHead(opCtx, &types.Empty{})
	cancel()
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain current head")
	}

	return resp, nil
}

func (s *Service) StreamChainHead() (ethpb.BeaconChain_StreamChainHeadClient, error) {
	conn := ethpb.NewBeaconChainClient(s.conn)

	stream, err := conn.StreamChainHead(s.ctx, &types.Empty{})
	if err != nil {
		return nil, err
	}

	return stream, nil
}
