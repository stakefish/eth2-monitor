package prysmgrpc

import (
	"context"

	empty "github.com/golang/protobuf/ptypes/empty"
	"github.com/pkg/errors"
	ethpb "github.com/prysmaticlabs/prysm/v2/proto/prysm/v1alpha1"
)

func (s *Service) GetChainHead() (*ethpb.ChainHead, error) {
	conn := ethpb.NewBeaconChainClient(s.conn)

	opCtx, cancel := context.WithTimeout(s.ctx, s.timeout)
	resp, err := conn.GetChainHead(opCtx, &empty.Empty{})
	cancel()
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain current head")
	}

	return resp, nil
}

func (s *Service) StreamChainHead() (ethpb.BeaconChain_StreamChainHeadClient, error) {
	conn := ethpb.NewBeaconChainClient(s.conn)

	stream, err := conn.StreamChainHead(s.ctx, &empty.Empty{})
	if err != nil {
		return nil, err
	}

	return stream, nil
}

func (s *Service) GetGenesis() (*ethpb.Genesis, error) {
	conn := ethpb.NewNodeClient(s.Connection())

	opCtx, cancel := context.WithTimeout(s.ctx, s.timeout)
	resp, err := conn.GetGenesis(opCtx, &empty.Empty{})
	cancel()
	if err != nil {
		return nil, errors.Wrap(err, "rpc call GetGenesis failed")
	}

	return resp, nil
}
