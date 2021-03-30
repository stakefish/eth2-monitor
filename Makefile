VERSION = $(shell git describe --tags --abbrev=8 2>/dev/null)

LDFLAGS += -X eth2-monitor/cmd.version=${VERSION}

.PHONY: all build eth2-monitor
all: build

build: eth2-monitor

eth2-monitor:
	-@mkdir -p bin
	-@rm -f bin/$@
	go build -ldflags '$(LDFLAGS)' -o bin/$@ .
