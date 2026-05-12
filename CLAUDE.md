# CLAUDE.md -- eth2-monitor

## Project Overview

Ethereum 2.0 validator performance monitor built by stakefish. Tracks attestation and proposal performance for a set of validator public keys by querying a Beacon Chain API node, reporting issues via Slack webhooks and exposing Prometheus metrics.

## Tech Stack

- **Language:** Go 1.25 (go.mod: 1.25.10; `.tool-versions`: 1.25.8; CI: 1.25.x)
- **CLI Framework:** Cobra (`github.com/spf13/cobra`)
- **Beacon Chain Client:** `github.com/attestantio/go-eth2-client` v0.28.1 (HTTP transport)
- **Logging:** zerolog (`github.com/rs/zerolog`)
- **Metrics:** Prometheus (`github.com/prometheus/client_golang`)
- **Error Wrapping:** `github.com/pkg/errors`
- **Concurrency:** `golang.org/x/sync` (errgroup)
- **Dependencies:** Go modules; `vendor/` is gitignored and not tracked. Dockerfile uses `go mod download` (module cache); local `go build` will use `vendor/` if you've run `go mod vendor`.

## Codebase Structure

```
main.go              -- Entry point, zerolog init, calls cmd.Execute()
cmd/
  root.go            -- Cobra root command, "monitor" and "version" subcommands
  opts/opts.go       -- Global CLI flag variables (package-level vars)
beaconchain/
  service.go         -- BeaconChain wrapper around go-eth2-client (HTTP)
  caplin_compat.go   -- HTTP transport that rewrites unquoted amount/index JSON fields in Caplin block responses
  metrics.go         -- Beacon API request CounterVec/HistogramVec instrumentation
  *_test.go          -- Tests for service + caplin compat + API metrics
spec/
  consts.go          -- SLOTS_PER_EPOCH=32, SECONDS_PER_SLOT=12
  routines.go        -- Epoch/Slot conversion helpers
pkg/
  monitoring.go        -- Orchestrator loop + SubscribeToEpochs + LoadKeys/LoadMEVRelays
  epoch_context.go     -- Per-epoch state fetch: EpochContext + BuildEpochContext + ResolveValidatorKeys + ListProposerDuties / ListEpochBlocks + SlotsWithBlocks
  attestations.go      -- Attestation-issue detection: processAttestations + BuildCommitteeLookup + PruneSeenAttestations + FinalizeMissedAttestations + CommitteeInfo
  proposals.go         -- Proposal-issue detection: isBlockEmpty + CheckProposal + FinalizeMissedProposals
  metrics.go           -- MonitorMetrics struct + NewMonitorMetrics(reg) factory; all Prometheus metrics
  reporting.go         -- Slack webhook + log reporting (Report/Info helpers)
  mev.go               -- MEV relay bid trace fetching (concurrent, paginated)
  cache.go             -- Disk-backed JSON cache for validator index lookups
  set.go               -- Generic Set[E comparable] collection
  profiling.go         -- Measure() timing utility
  utilities.go         -- Must() panic-on-error helper
  attestations_test.go -- Tests for processAttestations, BuildCommitteeLookup, FinalizeMissedAttestations, PruneSeenAttestations
  proposals_test.go    -- Tests for isBlockEmpty, CheckProposal, FinalizeMissedProposals
  test_helpers_test.go -- Shared test helpers (counterValue, gaugeValue, histogramSampleCount, buildSingleValidatorAttestation)
test-env/
  docker-compose.yml -- Full local stack: eth2-monitor + Prometheus + Grafana
  grafana/           -- Pre-provisioned dashboards and datasources
docs/                -- Onboarding reference (BEACON_API_USAGE, ERIGON_CAPLIN_COMPATIBILITY,
                       ETHEREUM_HARDFORK_TIMELINE, METRICS, attestant/ research notes).
                       Untracked in git but checked-out locally; useful for context.
Dockerfile           -- Multi-stage: golang:alpine builder -> alpine runtime, non-root user
Makefile             -- Targets: `all` -> `build` -> `eth2-monitor`; output: bin/eth2-monitor (with git version ldflags)
.tool-versions       -- Go version pinning (golang 1.25.8)
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

## Debugging Workflows

```bash
# Re-run a single past epoch with full per-slot detail (epochs must be processed
# in order; see "Attestation dedup requires consecutive epoch processing" below)
bin/eth2-monitor monitor --replay-epoch 12345 --print-successful -l trace \
  --beacon-chain-api http://localhost:3500 -k 0xPUBKEY...

# Resume from a specific epoch (e.g. after a long downtime)
bin/eth2-monitor monitor --since-epoch 12000 ...
```

## CLI Flags

**Global:**
- `--beacon-chain-api` (default: `localhost:3500`) -- Beacon Chain REST API
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
2. `GET /eth/v2/beacon/blocks/{block_id}` -- Fetch full signed blocks (Fulu/Fusaka fork)
3. `GET /eth/v1/validator/duties/proposer/{epoch}` -- Proposer duties
4. `POST /eth/v1/validator/duties/attester/{epoch}` -- Attester duties (fetched for prev/curr/next epoch; also builds committee lookup)
5. `GET /eth/v1/beacon/states/{state}/committees` -- Backfills committee sizes for committees with no tracked validators (`GetCommitteeLengths` in `beaconchain/service.go`)
6. `GET /eth/v1/beacon/states/{state}/finality_checkpoints` -- Justified epoch seed
7. `GET /eth/v1/events?topics=head` -- SSE head events for epoch detection

## Prometheus Metrics (namespace: ETH2)

| Metric | Type | Description |
|--------|------|-------------|
| `ETH2_epoch` | Gauge | Most recently processed epoch (the just-ended one from the SSE head stream; typically `head_epoch - 1`, NOT the justified epoch despite the historical name) |
| `ETH2_totalMissedProposals` | Counter | Missed block proposals |
| `ETH2_totalServedProposals` | Counter | Canonical proposals |
| `ETH2_totalMissedAttestations` | Counter | Missed attestations |
| `ETH2_totalServedAttestations` | Counter | Canonical attestations |
| `ETH2_totalDelayedAttestationsOverTolerance` | Counter | Attestations whose shifted inclusion distance exceeds 2 (i.e. spec-distance > 3, included at attestedSlot+4 or later after missed-slot adjustment) |
| `ETH2_canonicalAttestationDistances` | Histogram | Inclusion distance distribution after missed-slot adjustment. Distance is shifted: 0 = optimal (included at attestedSlot+1); Attestant's spec-distance = this + 1. Linear buckets 1..32 (so distance 0 lands in the ≤1 bucket). |
| `ETH2_totalProposedEmptyBlocks` | Counter | Blocks with no execution-layer payload of value to the proposer (no EL transactions, no blobs, no post-Pectra exec requests) |
| `ETH2_totalVanillaBlocks` | Counter | Blocks not matching MEV relay bids (hash mismatch case) |
| `ETH2_totalMissingBidTraces` | Counter | Proposed blocks where no tracked MEV relay returned any bid trace (distinct from the hash-mismatch case in `totalVanillaBlocks`) |
| `ETH2_lastMissedProposalSlot` | Gauge | Last missed proposal slot |
| `ETH2_lastMissedProposalValidatorIndex` | Gauge | Last missed proposal validator |
| `ETH2_lastProposedEmptyBlockSlot` | Gauge | Last empty block slot |
| `ETH2_lastVanillaBlockSlot` | Gauge | Last vanilla block slot |
| `ETH2_lastVanillaBlockValidator` | Gauge | Last vanilla block validator |
| `ETH2_duplicateAttestationsSkipped` | Counter | Attestations skipped due to (validator, slot) dedup |
| `ETH2_rawAttestationDistances` | Histogram | Raw attestation distances before the missed-slot adjustment (same shifted numbering as canonicalAttestationDistances; 0 = optimal). Linear buckets 1..32. |
| `ETH2_missedSlotsInEpoch` | Gauge | Missed slots in the most recently processed epoch (stays at the previous value during ctx-cancel / soft-skip iterations) |
| `ETH2_crossEpochAttestations` | Counter | Attestations included in a different epoch than attested |
| `ETH2_beaconAPIRequestsTotal` | CounterVec | Beacon API requests by `endpoint`, `method`, `status_class` (2xx/3xx/4xx/5xx/error) |
| `ETH2_beaconAPIRequestDurationSeconds` | HistogramVec | Beacon API request latency by `endpoint`, `method` (DefBuckets) |

## Code Conventions

- **Constants:** SCREAMING_SNAKE_CASE (project convention, not standard Go)
- **Error handling:** `pkg.Must(err)` panics with stack trace for genuinely-fatal errors (beacon-API contract violations at startup, unrecoverable beacon errors mid-epoch); standard `(value, error)` returns for API calls. `ctx.Canceled` / `context.DeadlineExceeded` are detected explicitly in `SubscribeToEpochs` and `MonitorAttestationsAndProposals` and returned cleanly rather than panicked through Must.
- **Logging:** zerolog. `Msgf()` printf-style is the dominant form for Report/Info paths; recent additions use structured-field form (`Uint64("slot", ...).Msg(...)`) for error logs that operators grep against. Trace for per-slot, Debug for per-epoch, Warn for user-facing reports, Error for invariant violations.
- **Reporting:** `pkg.Report()` and `pkg.Info()` log + send to Slack webhook
- **Config:** Global mutable vars in `cmd/opts` package (not dependency-injected)
- **Go features:** Generics (Set[E]), Go iterators (iter.Seq, slices.Chunk)
- **Testing:** Table-driven tests with mock interfaces
- **Fork target:** GetBlock expects Fulu/Fusaka fork blocks only; returns `*electra.SignedBeaconBlock` because Fulu reuses the Electra block structure in go-eth2-client

## CI

- **Linting:** golangci-lint `v2.12.2` (pinned in `golangci-lint.yml:27`) via `golangci/golangci-lint-action@v8`, runs on PRs
- **Tests:** `test` job in `main.yml` runs `go test ./...`; `build` depends on it so a failing test blocks the release
- **Build:** Multi-arch (amd64 + arm64; linux/darwin/freebsd/windows) via `main.yml`, runs on push/PR
- **Release:** Auto-publishes binaries + Docker image to GHCR on git tags (`softprops/action-gh-release` + `docker/build-push-action`)

## Gotchas

- **GetBlock fails on pre-Fusaka slots** -- returns error `"unsupported block version"` for any slot before the Fulu fork
- **Validator cache has a 30-minute TTL** -- `pkg/cache.go` persists the `Validators` map plus `LastEpoch` to disk JSON (`$TMPDIR/stakefish-eth2-monitor-cache.json`). `CachedIndex.At` is consulted by `ResolveValidatorKeys` to refresh entries older than 30 minutes; `VALIDATOR_INDEX_INVALID` sentinel entries are also TTL-bounded so a newly-active validator becomes visible within the window. On restart `LastEpoch` gates skip-ahead so cumulative counters don't double-count re-processed epochs. Writes use atomic tmpfile + fsync + rename + dir-fsync for crash durability. Delete the file to force a clean run.
- **Caplin `amount`/`index` JSON quoting** -- `beaconchain/caplin_compat.go` installs an HTTP transport that rewrites *only* the `"amount":N` and `"index":N` fields (regex `unquotedNumericField`) on `/eth/v2/beacon/blocks/` JSON responses. Other Caplin endpoints, other unquoted uint64 fields (e.g. anything under `solid/`), and SSZ responses are untouched -- those still need a fix upstream in go-eth2-client.
- **Slashed validators silently excluded from monitoring** -- `GetValidatorIndexes` filters via `IsAttesting()`, which is false for `active_slashed` *and* for any post-exit state. Once a key is slashed it never reappears in duties or reports (slashed and exited are both filtered) -- surprising during incident response when "where is validator X?" has no log line.
- **Attestation dedup requires consecutive epoch processing** -- `processAttestations` keys `seenAttestations` on `(validator, slot)` and the cross-epoch lookahead window assumes E and E+1 are processed in order. Skipping an epoch (SSE jump, replay-epoch gap) produces false missed-attestation reports.
- **`vendor/` is not in git** -- `.gitignore` has `/vendor/` and the directory is genuinely untracked (`git ls-files vendor/` is empty). After a fresh clone vendor/ is absent; `go build` falls back to the module cache. Run `go mod vendor` only if you want a vendored local build. Older docs/comments that imply vendor/ is checked in are stale.
- **Attestation tracking is memory-sensitive** -- was reworked 3 times to fix OOM (PR #20); be careful adding per-validator state
- **Prometheus counter names must be unique** -- duplicate registration panics at startup (happened with `total_canonical_attestations_counter` in PR #26)
- **`CheckProposal` returns false on proposer-index mismatch** -- when the block at a duty slot was proposed by an unexpected validator, `CheckProposal` short-circuits and returns false; the orchestrator MUST leave that slot in `ec.ProposerDuties` so `FinalizeMissedProposals` later reports it as missed. A naïve unconditional `delete(ec.ProposerDuties, slot)` after the call silently swallows the report (regression-trapped by `TestCheckProposal_ProposerMismatch`).

## Architecture

The monitor runs two goroutines communicating via an epoch channel:
1. **SubscribeToEpochs** -- Listens to beacon head SSE events, detects epoch boundaries, sends epoch numbers
2. **MonitorAttestationsAndProposals** -- Slim orchestrator. Per epoch: `PruneSeenAttestations` → `BuildEpochContext` (single call that fetches validator keys, attester/proposer duties, committee lengths, blocks, and MEV bids) → seed `unfulfilledAttesterDuties` for current epoch → `processAttestations` → `FinalizeMissedAttestations` (E-1 cutoff) → walk blocks calling `CheckProposal` per slot → `FinalizeMissedProposals` → `SaveCache`. Each per-concern delegate owns one issue class (attestation vs proposal vs lifecycle) so tests can drive them in isolation.

Metrics are encapsulated in `MonitorMetrics` struct (`pkg/metrics.go`), created via `NewMonitorMetrics(reg)` which accepts a `prometheus.Registerer` — production uses `DefaultRegisterer`, tests use isolated registries.
