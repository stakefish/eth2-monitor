package beaconchain

import (
	"context"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	eth2http "github.com/attestantio/go-eth2-client/http"
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

func (beacon *BeaconChain) Timeout() time.Duration {
	return beacon.timeout
}
