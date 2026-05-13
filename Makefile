VERSION = $(shell git describe --tags --abbrev=8 2>/dev/null)

LDFLAGS += -X github.com/stakefish/eth2-monitor/internal/cli.version=${VERSION}

.PHONY: all build eth2-monitor lint test test-e2e refresh-fixtures
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

# Refresh testdata/ fixtures from the configured BEACON_CHAIN_API endpoint.
# Captures raw HTTP and SSE responses for the 7 endpoints the monitor uses
# so unit tests can run offline against verified on-chain shapes. Reads
# $BEACON_CHAIN_API or test-env/.env. See tools/fixturegen/main.go.
refresh-fixtures:
	go run ./tools/fixturegen
