package monitoring

import (
	"context"
	"fmt"

	"github.com/stakefish/eth2-monitor/internal/beaconchain"

	"github.com/rs/zerolog/log"
)

// beaconchainHostByChain maps the `CONFIG_NAME` returned by
// /eth/v1/config/spec to the matching beaconcha.in subdomain. The
// dashboard reads this via the ETH2_info gauge to render chain-aware
// validator deep-links. Unknown chains fall back to `<chain>.beaconcha.in`
// at the call site so new testnets still get a plausible URL.
var beaconchainHostByChain = map[string]string{
	"mainnet": "beaconcha.in",
	"hoodi":   "hoodi.beaconcha.in",
}

// beaconchainHostFor returns the beaconcha.in subdomain for the given chain
// name. Pure function; broken out so it can be unit tested without a beacon.
func beaconchainHostFor(chain string) string {
	if host, ok := beaconchainHostByChain[chain]; ok {
		return host
	}
	return chain + ".beaconcha.in"
}

// RegisterChainInfo reads CONFIG_NAME from the beacon's /eth/v1/config/spec
// response and emits ETH2_info{chain, beaconchain_host} = 1. Called once at
// startup so the Grafana dashboard's beaconchain_host template variable can
// resolve to the right block-explorer subdomain.
//
// Returns the resolved (chain, host) for logging convenience. On any error
// (spec fetch, missing CONFIG_NAME, wrong type) returns the error without
// touching the gauge — the caller logs and continues; the dashboard simply
// shows no candidate hosts in the template variable.
func RegisterChainInfo(ctx context.Context, beacon *beaconchain.BeaconChain, m *MonitorMetrics) (chain, host string, err error) {
	spec, err := beacon.Spec(ctx)
	if err != nil {
		return "", "", fmt.Errorf("beacon.Spec: %w", err)
	}
	raw, ok := spec["CONFIG_NAME"]
	if !ok {
		return "", "", fmt.Errorf("CONFIG_NAME missing from spec response")
	}
	chain, ok = raw.(string)
	if !ok {
		return "", "", fmt.Errorf("CONFIG_NAME has unexpected type %T (want string)", raw)
	}
	host = beaconchainHostFor(chain)
	m.Info.WithLabelValues(chain, host).Set(1)
	log.Info().Str("chain", chain).Str("beaconchain_host", host).Msg("chain identified")
	return chain, host, nil
}
