# CLAUDE.md -- eth2-monitor

## Project Overview

Ethereum 2.0 validator performance monitor built by stakefish. Tracks attestation and proposal performance for a set of validator public keys by querying a Beacon Chain API node, reporting issues via Slack webhooks and exposing Prometheus metrics.

## Tech Stack

- **Language:** Go 1.23
- **CLI Framework:** Cobra (`github.com/spf13/cobra`)
- **Beacon Chain Client:** `github.com/attestantio/go-eth2-client` v0.27.1 (HTTP transport)
- **Logging:** zerolog (`github.com/rs/zerolog`)
- **Metrics:** Prometheus (`github.com/prometheus/client_golang`)
- **Error Wrapping:** `github.com/pkg/errors`
- **Concurrency:** `golang.org/x/sync` (errgroup)
- **Dependencies:** vendored (`vendor/`)

## Codebase Structure

```
main.go              -- Entry point, zerolog init, calls cmd.Execute()
cmd/
  root.go            -- Cobra root command, "monitor" and "version" subcommands
  opts/opts.go       -- Global CLI flag variables (package-level vars)
beaconchain/
  service.go         -- BeaconChain wrapper around go-eth2-client (HTTP)
  service_test.go    -- Table-driven tests with mock block provider
spec/
  consts.go          -- SLOTS_PER_EPOCH=32, SECONDS_PER_SLOT=12
  routines.go        -- Epoch/Slot conversion helpers
pkg/
  monitoring.go      -- Core monitoring loop: epoch subscription, attestation/proposal checks
  reporting.go       -- Slack webhook + log reporting (Report/Info helpers)
  mev.go             -- MEV relay bid trace fetching (concurrent, paginated)
  cache.go           -- Disk-backed JSON cache for validator index lookups
  set.go             -- Generic Set[E comparable] collection
  profiling.go       -- Measure() timing utility
  utilities.go       -- Must() panic-on-error helper
test-env/
  docker-compose.yml -- Full local stack: eth2-monitor + Prometheus + Grafana
  grafana/           -- Pre-provisioned dashboards and datasources
docs/
  BEACON_API_USAGE.md  -- Detailed beacon API endpoint reference
  ERIGON_CAPLIN_COMPATIBILITY.md -- Erigon Caplin compatibility notes
  METRICS.md           -- Prometheus metrics documentation
  ETHEREUM_HARDFORK_TIMELINE.md -- Ethereum hard fork timeline reference
  attestant/           -- Attestant research articles (attestation effectiveness, MEV, etc.)
Dockerfile           -- Multi-stage: golang:alpine builder -> alpine runtime, non-root user
Makefile             -- Targets: `all` -> `build` -> `eth2-monitor`; output: bin/eth2-monitor (with git version ldflags)
.tool-versions       -- Go version pinning (golang 1.23.6)
.github/workflows/   -- GitHub Actions CI (build, lint, Docker publish)
.gitlab-ci.yml       -- Legacy GitLab CI config
```

## Build & Run Commands

```bash
# Build
make build                    # -> bin/eth2-monitor

# Run
bin/eth2-monitor monitor --beacon-chain-api http://localhost:3500 -k 0xPUBKEY...

# Test
go test ./...

# Test environment (Docker Compose with Prometheus + Grafana)
cd test-env && docker compose up --build
```

## CLI Flags

**Global:**
- `--beacon-chain-api` (default: `localhost:3500`) -- Beacon Chain REST API
- `--beacon-node` (default: `localhost:4000`) -- Prysm GRPC (legacy)
- `--metrics-port` (default: `1337`) -- Prometheus metrics port
- `--log-level` / `-l` (default: `info`)
- `--slack-url` / `--slack-username` -- Slack webhook notifications

**Monitor command:**
- `-k` / `--pubkey` -- Validator BLS public keys (repeatable)
- `--mev-relays` -- Path to MEV relay list JSON file
- `--replay-epoch` -- Replay specific epoch(s) for debugging
- `--since-epoch` -- Start monitoring from a given epoch
- `--print-successful` -- Log successful attestations

## Beacon Chain API Endpoints Used

1. `POST /eth/v1/beacon/states/{state}/validators` -- Resolve pubkeys to validator indices
2. `GET /eth/v1/beacon/headers/{block_id}` -- Check slot proposed/missed
3. `GET /eth/v2/beacon/blocks/{block_id}` -- Fetch full signed blocks (Fulu/Fusaka fork)
4. `GET /eth/v1/validator/duties/proposer/{epoch}` -- Proposer duties
5. `POST /eth/v1/validator/duties/attester/{epoch}` -- Attester duties
6. `GET /eth/v1/beacon/states/{state}/committees` -- Committee compositions
7. `GET /eth/v1/beacon/states/{state}/finality_checkpoints` -- Justified epoch seed
8. `GET /eth/v1/events?topics=head` -- SSE head events for epoch detection

## Prometheus Metrics (namespace: ETH2)

| Metric | Type | Description |
|--------|------|-------------|
| `ETH2_epoch` | Gauge | Current justified epoch |
| `ETH2_totalMissedProposals` | Counter | Missed block proposals |
| `ETH2_totalServedProposals` | Counter | Canonical proposals |
| `ETH2_totalMissedAttestations` | Counter | Missed attestations |
| `ETH2_totalServedAttestations` | Counter | Canonical attestations |
| `ETH2_totalDelayedAttestationsOverTolerance` | Counter | Attestations with inclusion distance > 2 |
| `ETH2_canonicalAttestationDistances` | Histogram | Inclusion distance distribution (buckets 1-32) |
| `ETH2_totalProposedEmptyBlocks` | Counter | Blocks with zero transactions |
| `ETH2_totalVanillaBlocks` | Counter | Blocks not matching MEV relay bids |
| `ETH2_lastMissedProposalSlot` | Gauge | Last missed proposal slot |
| `ETH2_lastMissedProposalValidatorIndex` | Gauge | Last missed proposal validator |
| `ETH2_lastProposedEmptyBlockSlot` | Gauge | Last empty block slot |
| `ETH2_lastVanillaBlockSlot` | Gauge | Last vanilla block slot |
| `ETH2_lastVanillaBlockValidator` | Gauge | Last vanilla block validator |

## Code Conventions

- **Constants:** SCREAMING_SNAKE_CASE (project convention, not standard Go)
- **Error handling:** `pkg.Must(err)` panics with stack trace for fatal errors; standard `(value, error)` returns for API calls
- **Logging:** zerolog with `Msgf()` printf-style (not structured fields); Trace for per-slot, Debug for per-epoch, Warn for user-facing reports
- **Reporting:** `pkg.Report()` and `pkg.Info()` log + send to Slack webhook
- **Config:** Global mutable vars in `cmd/opts` package (not dependency-injected)
- **Go features:** Generics (Set[E]), Go 1.23 iterators (iter.Seq, slices.Chunk)
- **Testing:** Table-driven tests with mock interfaces
- **Fork target:** GetBlock expects Fulu/Fusaka fork blocks only; returns `*electra.SignedBeaconBlock` because Fulu reuses the Electra block structure in go-eth2-client

## CI

- **Linting:** golangci-lint v1.60 via GitHub Actions (`golangci-lint.yml`, runs on PRs)
- **Build:** Multi-arch build via GitHub Actions (`main.yml`, runs on push/PR)
- **Release:** Auto-publishes binaries + Docker image to GHCR on git tags (`softprops/action-gh-release` + `docker/build-push-action`)
- **Known bug:** `main.yml` line 52 loops `arm64 arm64` instead of `amd64 arm64` -- only builds arm64, skips amd64
- No automated test runner in CI -- run `go test ./...` locally

## Gotchas

- **GetBlock fails on pre-Fusaka slots** -- returns error `"unsupported block version"` for any slot before the Fulu fork
- **Validator cache has 8-hour TTL** -- `pkg/cache.go` uses disk-backed JSON; stale cache can cause missed validators after key rotation
- **vendor/ is tracked despite .gitignore** -- the gitignore has `/vendor/` but the directory was force-added; run `go mod vendor` after dependency changes
- **Attestation tracking is memory-sensitive** -- was reworked 3 times to fix OOM (PR #20); be careful adding per-validator state
- **Prometheus counter names must be unique** -- duplicate registration panics at startup (happened with `total_canonical_attestations_counter` in PR #26)
- **Dead code in `cmd/opts/opts.go`** -- `Slashings` struct and `Monitor.DistanceTolerance`/`UseAbsoluteDistance` fields are unused; no CLI flags wired, no code references. Legacy/future placeholders.
- **Test/impl mismatch in GetBlock** -- `beaconchain/service_test.go` has an "electra block" test case expecting success, but `service.go` only handles Fulu blocks; this test fails against current code

## Architecture

The monitor runs two goroutines communicating via an epoch channel:
1. **SubscribeToEpochs** -- Listens to beacon head SSE events, detects epoch boundaries, sends epoch numbers
2. **MonitorAttestationsAndProposals** -- Per epoch: resolves validator keys, fetches duties/blocks/bids, checks attestation inclusion distances, detects missed/empty/vanilla proposals, reports and records metrics
