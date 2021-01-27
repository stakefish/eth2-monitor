GIT_COMMIT = $(shell git rev-parse HEAD)
GIT_SHA    = $(shell git rev-parse --short HEAD)
GIT_TAG    = $(shell git describe --tags --abbrev=0 --exact-match 2>/dev/null)
GIT_DIRTY  = $(shell test -n "`git status --porcelain`" && echo "dirty" || echo "clean")

ifdef VERSION
  BINARY_VERSION = $(VERSION)
endif
BINARY_VERSION ?= ${GIT_TAG}

VERSION_METADATA = unreleased
# Clear the "unreleased" string in BuildMetadata
ifneq ($(GIT_TAG),)
  VERSION_METADATA =
endif

LDFLAGS += -X eth2-monitor/cmd.metadata=${VERSION_METADATA}
LDFLAGS += -X eth2-monitor/cmd.gitCommit=${GIT_COMMIT}
LDFLAGS += -X eth2-monitor/cmd.gitTreeState=${GIT_DIRTY}

.PHONY: all build eth2-monitor
all: build

build: eth2-monitor

eth2-monitor:
	-@mkdir -p bin
	-@rm -f bin/$@
	go build -ldflags '$(LDFLAGS)' -o bin/$@ .
