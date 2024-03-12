package prysmgrpc

import (
	"context"
	"time"

	"github.com/pkg/errors"
	ethpb "github.com/prysmaticlabs/prysm/v5/proto/prysm/v1alpha1"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc"
	empty "google.golang.org/protobuf/types/known/emptypb"
)

// Service is an Ethereum 2 client service.
type Service struct {
	// Hold the initializing context to allow for streams to use it.
	ctx context.Context
	// Client connection.
	conn    *grpc.ClientConn
	address string
	timeout time.Duration

	maxPageSize int32
}

// New creates a new Ethereum 2 client service, connecting with Prysm GRPC.
func New(ctx context.Context, params ...Parameter) (*Service, error) {
	parameters, err := parseAndCheckParameters(params...)
	if err != nil {
		return nil, errors.Wrap(err, "problem with parameters")
	}

	grpcOpts := []grpc.DialOption{
		// Maximum receive value 128 MB
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(128 * 1024 * 1024)),
		grpc.WithInsecure(),
	}

	dialCtx, cancel := context.WithTimeout(ctx, parameters.timeout)
	defer cancel()
	conn, err := grpc.DialContext(dialCtx, parameters.address, grpcOpts...)
	if err != nil {
		return nil, errors.Wrap(err, "failed to dial connection")
	}

	s := &Service{
		ctx:         ctx,
		conn:        conn,
		address:     parameters.address,
		timeout:     parameters.timeout,
		maxPageSize: 250, // Prysm default.
	}

	// Obtain the node version to confirm the connection is good.
	if _, err := s.NodeVersion(ctx); err != nil {
		return nil, errors.Wrap(err, "failed to confirm node connection")
	}

	// Close the service on context done.
	go func(s *Service) {
		<-ctx.Done()
		log.Trace().Msg("context done; closing connection")
		s.close()
	}(s)

	return s, nil
}

// Address provides the address for the connection.
func (s *Service) Address() string {
	return s.address
}

func (s *Service) Connection() *grpc.ClientConn {
	return s.conn
}

func (s *Service) Timeout() time.Duration {
	return s.timeout
}

// Close the service, freeing up resources.
func (s *Service) close() {
	if err := s.conn.Close(); err != nil {
		log.Warn().Err(err).Msg("Failed to close connection")
	}
}

// NodeVersion returns a free-text string with the node version.
func (s *Service) NodeVersion(ctx context.Context) (string, error) {
	conn := ethpb.NewNodeClient(s.conn)
	opCtx, cancel := context.WithTimeout(ctx, s.timeout)
	version, err := conn.GetVersion(opCtx, &empty.Empty{})
	cancel()
	if err != nil {
		return "", errors.Wrap(err, "failed to obtain node version")
	}
	return version.Version, nil
}
