# CLAUDE.md -- eth2-monitor

## Project Overview

Ethereum 2.0 validator performance monitor built by stakefish. Tracks attestation and proposal performance for a set of validator public keys by querying a Beacon Chain API node, reporting issues via Slack webhooks and exposing Prometheus metrics.

## Tech Stack

- **Language:** Go 1.25 (go.mod: 1.25.10; `.tool-versions`: 1.25.10; CI: `'1.25'` in `golangci-lint.yml`, `1.25.x` in `main.yml`)
- **CLI Framework:** Cobra (`github.com/spf13/cobra`)
- **Beacon Chain Client:** `github.com/attestantio/go-eth2-client` v0.28.1 — redirected via `replace` directive in `go.mod` to `github.com/stakefish/go-eth2-client@feat/erigon-caplin-support` (commit `781f0c7f`) for native Caplin JSON tolerance. Imports stay as `github.com/attestantio/go-eth2-client/...`; the fork keeps the upstream module path. Revert by dropping the replace directive when upstream absorbs the fix.
- **Logging:** zerolog (`github.com/rs/zerolog`)
- **Metrics:** Prometheus (`github.com/prometheus/client_golang`)
- **Error Wrapping:** `github.com/pkg/errors`
- **Concurrency:** `golang.org/x/sync` (errgroup)
- **Dependencies:** Go modules; `vendor/` is gitignored and not tracked. Dockerfile uses `go mod download` (module cache); local `go build` will use `vendor/` if you've run `go mod vendor`.

## Codebase Structure

Module path: `github.com/stakefish/eth2-monitor`. Layout follows golang-standards/project-layout (pragmatic application — `Dockerfile` and `test-env/` stay at the root).

```
cmd/
  eth2-monitor/
    main.go              -- Entry point, zerolog init, calls cli.Execute()
internal/
  cli/
    root.go              -- Cobra root command, "monitor" and "version" subcommands (package cli)
  opts/
    opts.go              -- Global CLI flag variables (package-level vars)
  beaconchain/
    service.go                          -- BeaconChain wrapper around go-eth2-client (HTTP); builds the metrics-instrumented http.Client via newInstrumentedHTTPClient
    metrics.go                          -- Beacon API request CounterVec/HistogramVec instrumentation; defines instrumentingTransport
    caplin_parse_test.go                -- json.Unmarshal block_canonical.json into electra.SignedBeaconBlock (regression guard that the forked go-eth2-client still tolerates Caplin's bare-number JSON natively)
    service_fixture_test.go             -- Offline GetBlock canonical+missed via fixtureServer (no live endpoint)
    metrics_e2e_test.go                 -- Live-fire metric-detection coverage for the 7 monitor endpoints (build tag: `e2e`)
    service_e2e_test.go                 -- Live-fire tests covering each BeaconChain wrapper method (GetValidatorIndexes, GetBlock, GetProposerDuties, GetAttesterDuties, GetCommitteeLengths) against the staging endpoint (build tag: `e2e`)
    testdata_test.go                    -- embed.FS + loadFixture(scenario,name)/loadSharedFixture/loadMeta(scenario)/fixtureServer(scenario,routes) helpers; `defaultChain = "hoodi"`
    testdata/
      beacon/
        hoodi/                          -- all fixtures captured against Hoodi staging (the chain configured in test-env/.env)
          _shared/                      -- go-eth2-client startup probes (invariant across scenarios for a given chain)
          happy_path/                   -- canonical block + duties + committees + events_head.sse + per-scenario meta.json
          missed_proposal/              -- same as happy_path PLUS a real 404 envelope for a missed slot inside the test epoch
          empty_block/                  -- block_canonical is structurally empty (no EL txns / no blobs / no Pectra exec requests)
          delayed_attestation/          -- block_canonical carries an attestation with raw distance > 3
          cross_epoch_attestation/      -- block_canonical (epoch E+1) carries an attestation from epoch E; also has block_prev.json
                                        -- each beacon scenario also captures its own events_head.sse (head transcript tee'd during the head-stream wait)
                                        -- all refreshed via `make refresh-fixtures` (loops scenarios; honours `CHAIN=<name>`) or `make refresh-scenario SCENARIO=<name>`
  spec/
    consts.go          -- SLOTS_PER_EPOCH=32, SECONDS_PER_SLOT=12
    routines.go        -- Epoch/Slot conversion helpers
  monitoring/
    doc.go                                   -- Package-level overview (entry points + flow)
    monitoring.go                            -- Orchestrator loop + SubscribeToEpochs (wrapped in subscribeWithRetry) + LoadKeys/LoadMEVRelays
    supervisor.go                            -- ctx-aware restart loop (`Supervise`; backs off using `ExptBackoff` from `mev.go`); wraps the orchestrator pair from cli/root.go so an unexpected goroutine exit no longer zombifies the process
    supervisor_test.go                       -- Supervise lifecycle tests (ctx cancellation, restart-on-unexpected-return, backoff draining)
    epoch_context.go                         -- Per-epoch state fetch: EpochContext + BuildEpochContext + ResolveValidatorKeys + ListProposerDuties / ListEpochBlocks + SlotsWithBlocks
    attestations.go                          -- Attestation-issue detection: processAttestations + BuildCommitteeLookup + PruneSeenAttestations + FinalizeMissedAttestations + CommitteeInfo
    proposals.go                             -- Proposal-issue detection: isBlockEmpty + CheckProposal + FinalizeMissedProposals
    metrics.go                               -- MonitorMetrics struct + NewMonitorMetrics(reg) factory; all Prometheus metrics
    reporting.go                             -- Slack webhook + log reporting (Report/Info helpers)
    mev.go                                   -- MEV relay bid trace fetching (concurrent, paginated)
    cache.go                                 -- Disk-backed JSON cache for validator index lookups
    set.go                                   -- Generic Set[E comparable] collection
    profiling.go                             -- Measure() timing utility
    utilities.go                             -- Must() panic-on-error helper
    epoch_context_integration_test.go        -- Real-BeaconChain-against-fixtureServer tests for BuildEpochContext / ResolveValidatorKeys / ListProposerDuties / ListEpochBlocks (incl. retry/cancel)
    mev_integration_test.go                  -- ListBestBids against fakeRelay backed by captured Flashbots fixture + synthetic edge-case handlers
    monitoring_integration_test.go           -- Orchestrator lifecycle + SubscribeToEpochs end-to-end through SSE-fixture replay
    monitoring_helpers_test.go               -- sendEpoch / LoadKeys / LoadMEVRelays / ResumeEpoch / runSSESubscription tests (no beacon I/O to fixture)
    proposals_integration_test.go            -- CheckProposal / isBlockEmpty / FinalizeMissedProposals on captured block + in-Go mutations for empty/MEV/vanilla
    attestations_integration_test.go         -- BuildCommitteeLookup + processAttestations against captured fixtures (wire-format integration)
    attestations_classification_test.go      -- Synthetic classification edge cases (cross-epoch dedup, AggregationBits offset drift) — see header comment for why these stay synthetic
    cache_integration_test.go                -- Disk-backed cache round-trip / merge / atomic write tests (uses t.TempDir)
    reporting_integration_test.go            -- Report/Info via httptest fake Slack server
    scenario_helpers_test.go                 -- newScenarioRig + snapshotBeaconAPI/assertBeaconAPIDelta helpers shared by scenario_*_test.go
    scenario_happy_path_test.go              -- canonical-proposal detection: CheckProposal + 2xx BeaconAPI label assertion
    scenario_missed_proposal_test.go         -- missed-proposal detection: 404 GetBlock + FinalizeMissedProposals + 4xx BeaconAPI label
    scenario_empty_block_test.go             -- empty-block detection: CheckProposal on no-EL-value block + TotalProposedEmptyBlocks
    scenario_delayed_attestation_test.go     -- captured block with raw att distance > 3 + processAttestations wire-format integration
    scenario_cross_epoch_attestation_test.go -- captured cross-epoch block + prev-epoch block + cross-epoch wire-format integration
    correctness_e2e_test.go                  -- Live-fire correctness E2E (build tag: `e2e`). Drives BuildEpochContext + processAttestations + FinalizeMissedAttestations + CheckProposal + FinalizeMissedProposals against the staging Hoodi beacon endpoint, then cross-checks every per-(validator, slot) decision against beaconcha.in V2 `/slot/attestation-duties`. Reads BEACON_CHAIN_API and BEACONCHAIN_API_KEY (from env or test-env/.env); t.Skip on either missing or on explorer indexer lag. Compares monitor distance against `inclusion_delay_without_missed_block` (canonical / missed-slot-adjusted), NOT `inclusion_delay` (raw).
    test_helpers_test.go                     -- Shared helpers (counterValue, gaugeValue, histogramSampleCount, buildSingleValidatorAttestation)
    testdata_test.go                         -- Cross-package os.ReadFile loaders + fixtureServer helper + embed.FS for testdata/mev
    testdata/
      meta.json                              -- captured MEV cursor slot + relays captured (no endpoint info)
      mev/                                   -- captured MEV relay bid-trace JSON (refreshed via `make refresh-scenario SCENARIO=mev`)
test-env/
  docker-compose.yml -- Full local stack: eth2-monitor + Prometheus + Grafana
  grafana/           -- Pre-provisioned dashboards and datasources
Dockerfile           -- Multi-stage: golang:alpine builder -> alpine runtime, non-root user; builds ./cmd/eth2-monitor
Makefile             -- Targets: `build` (default), `lint`, `test` (= `go test -cover ./...`), `test-e2e` (build tag `e2e` against ./internal/beaconchain/... + ./internal/monitoring/...), `refresh-fixtures` (loop every scenario), `refresh-scenario SCENARIO=<name>` (single scenario); output: bin/eth2-monitor with git version ldflags
tools/
  fixturegen/        -- `go run ./tools/fixturegen --scenario=<name> [--chain=<name>]` captures one scenario at a time. Subscribes to /eth/v1/events?topics=head on $BEACON_CHAIN_API and tails new heads waiting for one whose block matches the scenario predicate (empty / delayed att / cross-epoch att / slot gap); EVERY block fetched during the wait is recorded as block_<slot>.json so each scenario directory ends up densely populated with real beacon JSON, not just one anchor block. Output path: internal/beaconchain/testdata/beacon/<chain>/<scenario>/ (default chain: hoodi). See top-of-file doc comment for the scenario list.
.tool-versions       -- Go version pinning (golang 1.25.10)
.github/workflows/   -- GitHub Actions CI: `main.yml` (test + multi-arch build + Docker publish on tag), `golangci-lint.yml` (lint + coverage on PR)
.gitlab-ci.yml       -- Legacy GitLab CI config
```

## Build & Run Commands

```bash
# Build
make build                    # -> bin/eth2-monitor

# Run
bin/eth2-monitor monitor --beacon-chain-api http://localhost:3500 -k 0xPUBKEY...

# Test
go test ./...                 # or `make test` for `go test -cover ./...`

# Lint (matches CI; assumes golangci-lint is on $PATH)
make lint

# End-to-end tests against the staging Hoodi endpoint (build tag: `e2e`).
# Reads BEACON_CHAIN_API (always) and BEACONCHAIN_API_KEY (correctness_e2e_test.go only)
# from env or test-env/.env. Tests t.Skip cleanly when either is unset, so this
# can run on a fresh checkout without setup.
make test-e2e

# Regenerate every scenario's testdata/ bundle from the configured
# BEACON_CHAIN_API endpoint. Head-stream-driven capture; each scenario
# waits up to ~10 minutes for a matching head event, so a full
# refresh-fixtures run can take 30-60 minutes on a normal-finality
# testnet. Refresh a single scenario instead during development:
make refresh-fixtures                              # all scenarios sequentially
make refresh-scenario SCENARIO=missed_proposal     # single scenario

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
5. `GET /eth/v1/beacon/states/{state}/committees` -- Backfills committee sizes for committees with no tracked validators (`GetCommitteeLengths` in `internal/beaconchain/service.go`)
6. `GET /eth/v1/beacon/states/{state}/finality_checkpoints` -- Justified epoch seed
7. `GET /eth/v1/events?topics=head` -- SSE head events for epoch detection

## Prometheus Metrics (namespace: ETH2)

| Metric | Type | Description |
|--------|------|-------------|
| `ETH2_epoch` | Gauge | Most recently processed epoch (the just-ended one from the SSE head stream; typically `head_epoch - 1`, NOT the justified epoch despite the historical name) |
| `ETH2_totalMissedProposals` | Counter | Missed block proposals |
| `ETH2_totalServedProposals` | Counter | Canonical proposals |
| `ETH2_totalMissedAttestations` | CounterVec | Missed attestations. Labels: `validator_index`, `pubkey` (0x-prefixed lowercase hex). |
| `ETH2_totalServedAttestations` | CounterVec | Canonical attestations. Labels: `validator_index`, `pubkey`. |
| `ETH2_totalDelayedAttestationsOverTolerance` | CounterVec | Attestations whose shifted inclusion distance exceeds 2 (i.e. spec-distance > 3, included at attestedSlot+4 or later after missed-slot adjustment). Labels: `validator_index`, `pubkey`. |
| `ETH2_canonicalAttestationDistances` | Histogram | Inclusion distance distribution after missed-slot adjustment. Distance is shifted: 0 = optimal (included at attestedSlot+1); Attestant's spec-distance = this + 1. Linear buckets 1..32 (so distance 0 lands in the ≤1 bucket). |
| `ETH2_totalProposedEmptyBlocks` | Counter | Blocks with no execution-layer payload of value to the proposer (no EL transactions, no blobs, no post-Pectra exec requests) |
| `ETH2_totalVanillaBlocks` | Counter | Blocks not matching MEV relay bids (hash mismatch case) |
| `ETH2_totalMissingBidTraces` | Counter | Proposed blocks where no tracked MEV relay returned any bid trace (distinct from the hash-mismatch case in `totalVanillaBlocks`) |
| `ETH2_lastMissedProposalSlot` | Gauge | Last missed proposal slot |
| `ETH2_lastMissedProposalValidatorIndex` | Gauge | Last missed proposal validator |
| `ETH2_lastProposedEmptyBlockSlot` | Gauge | Last empty block slot |
| `ETH2_lastVanillaBlockSlot` | Gauge | Last vanilla block slot |
| `ETH2_lastVanillaBlockValidator` | Gauge | Last vanilla block validator |
| `ETH2_duplicateAttestationsSkipped` | CounterVec | Attestations skipped due to (validator, slot) dedup. Labels: `validator_index`, `pubkey`. |
| `ETH2_rawAttestationDistances` | Histogram | Raw attestation distances before the missed-slot adjustment (same shifted numbering as canonicalAttestationDistances; 0 = optimal). Linear buckets 1..32. |
| `ETH2_missedSlotsInEpoch` | Gauge | Missed slots in the most recently processed epoch (stays at the previous value during ctx-cancel / soft-skip iterations) |
| `ETH2_crossEpochAttestations` | CounterVec | Attestations included in a different epoch than attested. Labels: `validator_index`, `pubkey`. |
| `ETH2_beaconAPIRequestsTotal` | CounterVec | Beacon API requests by `endpoint`, `method`, `status_class` (2xx/3xx/4xx/5xx/error) |
| `ETH2_beaconAPIRequestDurationSeconds` | HistogramVec | Beacon API request latency by `endpoint`, `method` (DefBuckets) |

## Code Conventions

- **Constants:** SCREAMING_SNAKE_CASE (project convention, not standard Go)
- **Error handling:** `monitoring.Must(err)` panics with stack trace for genuinely-fatal errors (beacon-API contract violations at startup, unrecoverable beacon errors mid-epoch); standard `(value, error)` returns for API calls. `ctx.Canceled` / `context.DeadlineExceeded` are detected explicitly in `SubscribeToEpochs` and `MonitorAttestationsAndProposals` and returned cleanly rather than panicked through Must.
- **Logging:** zerolog. `Report()` / `Info()` accept printf-style format strings (`Report("missed slot %v", s)`) and internally `fmt.Sprintf` + `.Msg()` to a single zerolog event. Direct call sites predominantly use the structured-field form (`Uint64("slot", ...).Msg(...)`) for error/debug logs that operators grep against; raw `.Msgf(...)` is rare (3 production call sites, vs 40+ `.Msg(...)`). Trace for per-slot, Debug for per-epoch, Warn for user-facing reports, Error for invariant violations.
- **Reporting:** `monitoring.Report()` and `monitoring.Info()` log + send to Slack webhook
- **Config:** Global mutable vars in `internal/opts` package (not dependency-injected)
- **Go features:** Generics (Set[E]), Go iterators (iter.Seq, slices.Chunk)
- **Testing:** Fixture-backed integration tests are the default — production code runs against an httptest server replaying captured beacon JSON / SSE / MEV-relay responses. Only narrow classification edge cases (cross-epoch dedup in `attestations_classification_test.go`) and pure helpers (`monitoring_helpers_test.go`) stay as inline-data unit tests. See **Test Fixtures** below.
- **Fork target:** GetBlock expects Fulu/Fusaka fork blocks only; returns `*electra.SignedBeaconBlock` because Fulu reuses the Electra block structure in go-eth2-client

## Test Fixtures

Wire-format fixtures live under `internal/beaconchain/testdata/beacon/<chain>/` (beacon API + SSE; currently only `hoodi/`) and `internal/monitoring/testdata/mev/` (MEV relay bid traces, chain-agnostic since fixturegen pulls public mainnet relays). Beacon fixtures are **organized into per-scenario subdirectories under the chain** so each validator-failure-detection path gets its own self-contained bundle:

| Scenario | Beacon-API fingerprint | Monitoring metric exercised |
|---|---|---|
| `_shared` | go-eth2-client startup probes — invariant across scenarios for a given chain | (auto-registered by `fixtureServer`) |
| `happy_path` | canonical block + on-time attestations at a stable test epoch; also captures `events_head.sse` (head transcript tee'd during the head-stream wait) | `TotalCanonicalProposals` |
| `missed_proposal` | head-stream slot gap captured as a real 404 envelope | `TotalMissedProposals` + `LastMissedProposal*` |
| `empty_block` | first head whose block has no EL transactions / blobs / Pectra exec requests. Captured opportunistically — Hoodi often goes 10+ min with every block carrying EL value, so the bundle may be absent on a fresh clone; `scenario_empty_block_test.go` `t.Skip`s when `EmptyBlockSlot==0`. | `TotalProposedEmptyBlocks` + `LastProposedEmptyBlockSlot` |
| `delayed_attestation` | first head whose block carries an attestation with raw distance > 3 | `TotalDelayedOverTolerance` + `RawAttestationDistances` (>3 bucket) |
| `cross_epoch_attestation` | first head whose block carries an attestation from a strictly earlier epoch; bundle also includes `block_prev.json` for the prev-epoch canonical block | `CrossEpochAttestations` |
| `mev` | one page of `proposer_payload_delivered` from each public mainnet relay (Flashbots, ultrasound) | MEV side; written under `internal/monitoring/testdata/mev/` |

Captures are produced by `tools/fixturegen/main.go --scenario=<name> [--chain=<name>]`. Capture flow (for beacon scenarios) **subscribes to `/eth/v1/events?topics=head`** on the configured `BEACON_CHAIN_API` endpoint and tails new head events. Each new block is fetched + recorded as `block_<slot>.json` in the scenario directory; the scenario predicate runs on each block until it matches, at which point the matched block is also mirrored as `block_canonical.json` and the per-epoch context (finality, validators, duties, committees) is captured. **Every block fetched during the wait stays on disk**, so each scenario subdirectory ends up with a dense set of real beacon JSON. Each scenario directory carries its own `meta.json` recording the chain + anchor slot/epoch + `captured_slots[]` (and scenario-specific extras: `missed_slot`, `empty_block_slot`, `max_distance`, `prev_epoch`/`prev_canonical_slot`).

Make targets:

```bash
make refresh-fixtures                            # loop every scenario (chain=hoodi); can take 30-60 min
make refresh-scenario SCENARIO=missed_proposal   # single scenario (chain=hoodi)
make refresh-fixtures CHAIN=sepolia              # capture against a different chain — fixtures land under testdata/beacon/sepolia/
go run ./tools/fixturegen --scenario=empty_block --timeout=30m   # override the default 10-min wait for rare scenarios
```

Loading helpers (`defaultChain = "hoodi"` in `internal/beaconchain/testdata_test.go`; `defaultBeaconChain = "hoodi"` in `internal/monitoring/testdata_test.go` — both promoted to parameters when a second chain is added):
- `internal/beaconchain/testdata_test.go` provides `loadMeta(t, scenario)`, `loadFixture(t, scenario, name)` (embed.FS, `all:testdata/beacon` so `_shared/` is included), `loadSharedFixture(t, name)`, and `fixtureServer(t, scenario, routes)` (auto-registers `_shared/` startup probes + caller routes; routes can be a static fixture or a custom `Handler` for flaky/cancel/error injection).
- `internal/monitoring/testdata_test.go` provides `loadBeaconMeta(t, scenario)`, `loadBeaconFixture(t, scenario, name)`, `loadSharedBeaconFixture(t, name)`, and `loadMEVFixture(t, name)` via cross-package `os.ReadFile("../beaconchain/testdata/beacon/<chain>/<scenario>/...")`.
- `internal/monitoring/scenario_helpers_test.go` provides `newScenarioRig(t, scenario)` which wires up `fixtureServer` + isolated `RequestMetrics` + `MonitorMetrics` + a real `BeaconChain`, ready for scenario tests to call.

Tests anchor assertions to scenario `meta.json` (`HasMissed`, `CanonicalSlot`, `EmptyBlockSlot`, `MaxDistance`, etc.) rather than hard-coded slot numbers so they stay green across refresh runs. The `_shared` scenario has no `meta.json` — its files are chain-invariant.

`meta.json` records the scenario name + anchor fields + `captured_at` + `generator_version` and **deliberately excludes any endpoint identifier** (no host, no URL) so committed fixtures don't disclose which upstream the project fixtures from. Captured response bodies are pure beacon-API JSON and likewise contain no upstream identifiers. The 1 MiB per-fixture cap rejects oversized captures; `committees.json` is slot-filtered (`?slot=…`) because the unfiltered response exceeds the cap on networks with large validator sets — production code path fetches full-epoch committees, so the slot-filtered fixture covers only the canonical anchor slot. Scenario tests that drive `processAttestations` against the captured fixture will see `attestation references committee with no lookup entry; skipping` warnings for attestations referencing other slots (the integration test asserts wire-format integrity + BeaconAPI metric labels; outcome assertions for the monitoring counters live in `attestations_classification_test.go` with synthesised committees).

Most monitoring/beaconchain tests are now fixture-backed integration tests (see Codebase Structure for the full list). The exceptions:
- `attestations_classification_test.go` — synthesised edge cases (cross-epoch dedup, AggregationBits offset drift) whose specific (validator, slot, committee) tuples can't be reproduced from a single captured block.
- `monitoring_helpers_test.go` — pure file/goroutine helpers (sendEpoch, LoadKeys, LoadMEVRelays, ResumeEpoch, runSSESubscription) with no beacon I/O to fixture.

**go-eth2-client SSE caveat (production observability gap):** `eth2http.WithHTTPClient` does NOT route SSE traffic through the configured transport — `Events()` doesn't increment the production beacon-API request counter. The `events_template_strips_query` subtest in `metrics_e2e_test.go` side-channels a direct `http.Client.Do` against the events URL via the same `instrumentingTransport` to keep fixture-based detection coverage for that endpoint.

## CI

- **Linting:** golangci-lint `v2.12.2` (pinned in `golangci-lint.yml:27`) via `golangci/golangci-lint-action@v8`, runs on PRs
- **Coverage:** `coverage` job in `golangci-lint.yml` runs `go test -cover ./...` on PRs; per-package coverage prints to the job log (no artifact, no third-party service). The `e2e`-tagged tests are excluded — they need a beacon endpoint that CI doesn't have.
- **Tests:** `test` job in `main.yml` runs `go test ./...`; `build` depends on it so a failing test blocks the release
- **Build:** Multi-arch (amd64 + arm64; linux/darwin/freebsd/windows) via `main.yml`, runs on push/PR
- **Release:** Auto-publishes binaries + Docker image to GHCR on git tags (`softprops/action-gh-release` + `docker/build-push-action`)

## Gotchas

- **GetBlock fails on pre-Fusaka slots** -- returns error `"unsupported block version"` for any slot before the Fulu fork
- **Validator cache has a 30-minute TTL** -- `internal/monitoring/cache.go` persists the `Validators` map plus `LastEpoch` to disk JSON (`$TMPDIR/stakefish-eth2-monitor-cache.json`). `CachedIndex.At` is consulted by `ResolveValidatorKeys` to refresh entries older than 30 minutes; `VALIDATOR_INDEX_INVALID` sentinel entries are also TTL-bounded so a newly-active validator becomes visible within the window. On restart `LastEpoch` gates skip-ahead so cumulative counters don't double-count re-processed epochs. Writes use atomic tmpfile + fsync + rename + dir-fsync for crash durability. Delete the file to force a clean run.
- **Caplin returns 404 on slot-ID state queries for missed slots** -- `/eth/v1/beacon/states/{slot}/validators` 404s with `block not found N` when slot N was missed; Caplin resolves a slot state_id by walking to the block AT that slot. `GetValidatorIndexes` walks forward through the epoch's slots (validator set is stable within an epoch) until one resolves, capping at the epoch's last slot. The e2e test (`get_validator_indexes_roundtrip`) and the fixture-backed regression test (`TestGetValidatorIndexes_ProbeForwardOnMissedFirstSlot`) both lock this in. Found via staging crash 2026-05-13: epoch 94898's first slot (3036736) was missed and the monitor panicked at `Must(BuildEpochContext)` before the fix.
- **Slashed validators silently excluded from monitoring** -- `GetValidatorIndexes` filters via `IsAttesting()`, which is false for `active_slashed` *and* for any post-exit state. Once a key is slashed it never reappears in duties or reports (slashed and exited are both filtered) -- surprising during incident response when "where is validator X?" has no log line.
- **Attestation dedup requires consecutive epoch processing** -- `processAttestations` keys `seenAttestations` on `(validator, slot)` and the cross-epoch lookahead window assumes E and E+1 are processed in order. Skipping an epoch (SSE jump, replay-epoch gap) produces false missed-attestation reports.
- **`vendor/` is not in git** -- `.gitignore` has `/vendor/` and the directory is genuinely untracked (`git ls-files vendor/` is empty). After a fresh clone vendor/ is absent; `go build` falls back to the module cache. Run `go mod vendor` only if you want a vendored local build. Older docs/comments that imply vendor/ is checked in are stale.
- **Attestation tracking is memory-sensitive** -- was reworked 3 times to fix OOM (PR #20); be careful adding per-validator state
- **Prometheus counter names must be unique** -- duplicate registration panics at startup (happened with `total_canonical_attestations_counter` in PR #26)
- **CounterVec children must be pre-warmed** -- `prometheus.CounterVec` emits NO time series for label-value combos that have never been touched by `WithLabelValues(...)`. With the per-validator labels (`validator_index`, `pubkey`), a healthy cluster with zero missed attestations would scrape with `ETH2_totalMissedAttestations` completely absent, and Grafana renders "No data" for `sum(rate(...))` instead of `0`. `(*MonitorMetrics).PrewarmValidators` is called per epoch (`internal/monitoring/monitoring.go` right after `BuildEpochContext`) to poke `WithLabelValues` on every per-validator counter for every tracked validator, materialising zero-valued children for the scrape. When adding a new per-validator counter, extend `PrewarmValidators` in `internal/monitoring/metrics.go` so the zero-data invariant holds. (The 2 distance histograms intentionally stay label-free — at 10k validators the per-validator histogram cardinality (~680k series) dwarfed the operational value, so they were dropped back to scalar `prometheus.Histogram` which always emit zero-bucketed series on register.)
- **Chain identity exposed via `ETH2_info` gauge** -- `(*MonitorMetrics).Info` is a static value=1 `GaugeVec` with labels `{chain, beaconchain_host}`, populated once at startup by `monitoring.RegisterChainInfo` (called from `internal/cli/root.go` right after `beaconchain.New` succeeds). The mapping from `CONFIG_NAME` to beaconcha.in subdomain lives in `internal/monitoring/chain.go` (`beaconchainHostByChain`). Unknown chains fall back to `<chain>.beaconcha.in`. The Grafana dashboard reads this via the hidden `beaconchain_host` template variable so validator deep-links in the Problematic Validators table point at the correct block-explorer host. To add a new chain, just extend `beaconchainHostByChain` — no dashboard changes needed.
- **`CheckProposal` returns false on proposer-index mismatch** -- when the block at a duty slot was proposed by an unexpected validator, `CheckProposal` short-circuits and returns false; the orchestrator MUST leave that slot in `ec.ProposerDuties` so `FinalizeMissedProposals` later reports it as missed. A naïve unconditional `delete(ec.ProposerDuties, slot)` after the call silently swallows the report (regression-trapped by `TestCheckProposal_ProposerMismatch`).
- **Scenario captures depend on live testnet behaviour** -- `tools/fixturegen --scenario=<name>` tails `/eth/v1/events?topics=head` and waits up to 10 min (`--timeout` overrides) for a matching head event. `empty_block` may not find a match during high-traffic windows (Hoodi staging routinely runs 10 min with every block carrying EL value); the operator gets an actionable timeout error and the corresponding scenario test cleanly `Skip`s when the fixture is missing. Re-run during quieter periods or extend with `--timeout=30m`.
- **Capture against a non-Hoodi chain must set `--chain=<name>`** -- the default is `hoodi`, which writes into `testdata/beacon/hoodi/<scenario>/`. Capturing against a different chain WITHOUT overriding `--chain` collides into Hoodi's fixture set. The Make wrapper threads `CHAIN=<name>` through (`make refresh-fixtures CHAIN=sepolia`).
- **fixturegen first-fetch 404s are normal** -- head announcements occasionally outpace block availability on the beacon's read side; fixturegen retries once after 500ms and logs `WARN first fetch slot=N failed: status 404`. Both the retry success and the warn line are expected.

## Architecture

The monitor runs under a `monitoring.Supervise(ctx, runOnce, backoff)` restart loop (`internal/cli/root.go:137`). `Supervise` re-runs `runOnce` whenever it returns while ctx is still live, sleeping the next value from an `ExptBackoff` between attempts; only ctx cancellation breaks the loop. This was added to fix the "stale `/metrics` + no new epochs" zombie state where an unexpected inner goroutine return cascaded through the shared ctx and left the process serving stale metrics with no epoch progress (see `internal/monitoring/supervisor.go` header).

Inside one `runOnce` iteration, two goroutines communicate via an epoch channel:
1. **SubscribeToEpochs** -- Listens to beacon head SSE events, detects epoch boundaries, sends epoch numbers. The SSE call itself is wrapped by `subscribeWithRetry` (`internal/monitoring/monitoring.go:180`) with its own `ExptBackoff`, so a single dropped connection retries in place rather than propagating out to `Supervise`.
2. **MonitorAttestationsAndProposals** -- Slim orchestrator. Per epoch: `PruneSeenAttestations` → `BuildEpochContext` (single call that fetches validator keys, attester/proposer duties, committee lengths, blocks, and MEV bids) → seed `unfulfilledAttesterDuties` for current epoch → `processAttestations` → `FinalizeMissedAttestations` (E-1 cutoff) → walk blocks calling `CheckProposal` per slot → `FinalizeMissedProposals` → `SaveCache`. Each per-concern delegate owns one issue class (attestation vs proposal vs lifecycle) so tests can drive them in isolation.

Metrics are encapsulated in `MonitorMetrics` struct (`internal/monitoring/metrics.go`), created via `NewMonitorMetrics(reg)` which accepts a `prometheus.Registerer` — production uses `DefaultRegisterer`, tests use isolated registries.
