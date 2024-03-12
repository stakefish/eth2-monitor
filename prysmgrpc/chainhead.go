package prysmgrpc

import (
	"context"

	"github.com/pkg/errors"
	ethpb "github.com/prysmaticlabs/prysm/v5/proto/prysm/v1alpha1"
	empty "google.golang.org/protobuf/types/known/emptypb"
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
