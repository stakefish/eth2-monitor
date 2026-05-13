VERSION = $(shell git describe --tags --abbrev=8 2>/dev/null)

LDFLAGS += -X eth2-monitor/cmd.version=${VERSION}

.PHONY: all build eth2-monitor lint test test-e2e
all: build

build: eth2-monitor

eth2-monitor:
	-@mkdir -p bin
	-@rm -f bin/$@
	go build -ldflags '$(LDFLAGS)' -o bin/$@ .

lint:
	golangci-lint run ./...

test:
	go test -cover ./...

test-e2e:
	go test -tags=e2e -count=1 -timeout=2m ./beaconchain/...
