.PHONY: all build eth2-monitor
all: build

build: eth2-monitor

eth2-monitor:
	-@mkdir -p bin
	-@rm bin/$@
	go build -o bin/$@ .
