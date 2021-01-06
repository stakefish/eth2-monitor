package prysmgrpc

import (
	"context"
	"sync"
	"time"

	"eth2-monitor/spec"

	"github.com/gogo/protobuf/types"
	"github.com/pkg/errors"
	ethpb "github.com/prysmaticlabs/ethereumapis/eth/v1alpha1"
	"github.com/rs/zerolog"
	zerologger "github.com/rs/zerolog/log"
	"google.golang.org/grpc"
)

// log is a service-wide logger.
var log zerolog.Logger

// Service is an Ethereum 2 client service.
type Service struct {
	// Hold the initialising context to allow for streams to use it.
	ctx context.Context
	// Client connection.
	conn    *grpc.ClientConn
	address string
	timeout time.Duration

	maxPageSize int32

	ChainHeadChan           chan *ethpb.ChainHead
	DutiesChan              chan *ethpb.DutiesResponse_Duty
	IndexedAttestationsChan chan *ethpb.IndexedAttestation
	SignedBlocksChan        chan *ethpb.SignedBeaconBlock

	// The standard API commonly uses validator indices, and the prysm API commonly uses public keys.
	// We keep a mapping of index to public keys to avoid repeated lookups.
	indexMap   map[spec.ValidatorIndex]spec.BLSPubKey
	indexMapMu sync.RWMutex
}

// New creates a new Ethereum 2 client service, connecting with Prysm GRPC.
func New(ctx context.Context, params ...Parameter) (*Service, error) {
	parameters, err := parseAndCheckParameters(params...)
	if err != nil {
		return nil, errors.Wrap(err, "problem with parameters")
	}

	// Set logging.
	log = zerologger.With().Str("service", "client").Str("impl", "prysmgrpc").Logger()
	if parameters.logLevel != log.GetLevel() {
		log = log.Level(parameters.logLevel)
	}

	grpcOpts := []grpc.DialOption{
		grpc.WithInsecure(),
		// Maximum receive value 128 MB
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(128 * 1024 * 1024)),
	}

	dialCtx, cancel := context.WithTimeout(ctx, parameters.timeout)
	defer cancel()
	conn, err := grpc.DialContext(dialCtx, parameters.address, grpcOpts...)
	if err != nil {
		return nil, errors.Wrap(err, "failed to dial connection")
	}

	s := &Service{
		ChainHeadChan:           make(chan *ethpb.ChainHead),
		DutiesChan:              make(chan *ethpb.DutiesResponse_Duty),
		IndexedAttestationsChan: make(chan *ethpb.IndexedAttestation),
		SignedBlocksChan:        make(chan *ethpb.SignedBeaconBlock),
		ctx:                     ctx,
		conn:                    conn,
		address:                 parameters.address,
		timeout:                 parameters.timeout,
		maxPageSize:             250, // Prysm default.
		indexMap:                make(map[spec.ValidatorIndex]spec.BLSPubKey),
	}

	// Obtain the node version to confirm the connection is good.
	if _, err := s.NodeVersion(ctx); err != nil {
		return nil, errors.Wrap(err, "failed to confirm node connection")
	}

	// Close the service on context done.
	go func(s *Service) {
		<-ctx.Done()
		log.Trace().Msg("Context done; closing connection")
		s.close()
	}(s)

	return s, nil
}

// Name provides the name of the service.
func (s *Service) Name() string {
	return "Prysm (gRPC)"
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
	version, err := conn.GetVersion(opCtx, &types.Empty{})
	cancel()
	if err != nil {
		return "", errors.Wrap(err, "failed to obtain node version")
	}
	return version.Version, nil
}
