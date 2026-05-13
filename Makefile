VERSION = $(shell git describe --tags --abbrev=8 2>/dev/null)

LDFLAGS += -X github.com/stakefish/eth2-monitor/internal/cli.version=${VERSION}

.PHONY: all build eth2-monitor lint test test-e2e refresh-fixtures refresh-scenario
all: build

build: eth2-monitor

eth2-monitor:
	-@mkdir -p bin
	-@rm -f bin/$@
	go build -ldflags '$(LDFLAGS)' -o bin/$@ ./cmd/eth2-monitor

lint:
	golangci-lint run ./...

test:
	go test -cover ./...

test-e2e:
	go test -tags=e2e -count=1 -timeout=2m ./internal/beaconchain/...

# Scenarios captured by tools/fixturegen. Each scenario gets its own
# subdirectory under internal/beaconchain/testdata/beacon/<chain>/<scenario>/
# (plus internal/monitoring/testdata/mev/ for the chain-agnostic mev
# scenario). The head-stream-driven capture flow waits for live head
# events on the configured BEACON_CHAIN_API endpoint — see
# tools/fixturegen/main.go.
SCENARIOS = _shared happy_path missed_proposal empty_block delayed_attestation cross_epoch_attestation mev

# CHAIN selects the chain subdirectory under testdata/beacon/. Defaults
# to hoodi (the chain configured in test-env/.env). Set explicitly to
# capture against a different network:
#   make refresh-fixtures CHAIN=sepolia
CHAIN ?= hoodi

# Refresh every scenario sequentially. The head-stream selectors each
# wait up to ~10 minutes for a matching head event, so a full
# refresh-fixtures run can take 30-60 minutes on a normal-finality
# testnet. Use refresh-scenario for targeted refreshes during
# development. Reads $BEACON_CHAIN_API or test-env/.env.
refresh-fixtures:
	@for s in $(SCENARIOS); do \
		echo "==> capturing scenario: $$s (chain=$(CHAIN))"; \
		go run ./tools/fixturegen --scenario=$$s --chain=$(CHAIN) || exit 1; \
	done

# Refresh a single scenario. Pass `SCENARIO=<name>` (e.g.
# `make refresh-scenario SCENARIO=missed_proposal`). Honors CHAIN.
refresh-scenario:
	@if [ -z "$(SCENARIO)" ]; then echo "usage: make refresh-scenario SCENARIO=<name> [CHAIN=<chain>]"; exit 2; fi
	go run ./tools/fixturegen --scenario=$(SCENARIO) --chain=$(CHAIN)
