module eth2-monitor

go 1.19

require (
	github.com/dghubble/go-twitter v0.0.0-20220716041154-837915ec2f79
	github.com/dghubble/oauth1 v0.7.1
	github.com/mattn/go-isatty v0.0.16
	github.com/pkg/errors v0.9.1
	github.com/prometheus/client_golang v1.14.0
	github.com/prysmaticlabs/go-bitfield v0.0.0-20210809151128-385d8c5e3fb7
	github.com/prysmaticlabs/prysm/v4 v4.0.1
	github.com/rs/zerolog v1.27.0
	github.com/spf13/cobra v1.5.0
	golang.org/x/exp v0.0.0-20230206171751-46f607a40771
	google.golang.org/grpc v1.48.0
	google.golang.org/protobuf v1.28.1
)

require (
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/btcsuite/btcd/btcec/v2 v2.3.2 // indirect
	github.com/cenkalti/backoff/v4 v4.1.3 // indirect
	github.com/cespare/xxhash/v2 v2.2.0 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.1.0 // indirect
	github.com/dghubble/sling v1.4.0 // indirect
	github.com/ethereum/go-ethereum v1.11.2 // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/google/go-querystring v1.1.0 // indirect
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.11.2 // indirect
	github.com/inconshreveable/mousetrap v1.0.1 // indirect
	github.com/klauspost/cpuid/v2 v2.2.1 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/matttproud/golang_protobuf_extensions v1.0.4 // indirect
	github.com/minio/sha256-simd v1.0.0 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/prometheus/client_model v0.3.0 // indirect
	github.com/prometheus/common v0.39.0 // indirect
	github.com/prometheus/procfs v0.9.0 // indirect
	github.com/prysmaticlabs/fastssz v0.0.0-20220628131814-351fdcbb9964 // indirect
	github.com/prysmaticlabs/gohashtree v0.0.2-alpha // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/thomaso-mirodin/intmath v0.0.0-20160323211736-5dc6d854e46e // indirect
	golang.org/x/crypto v0.5.0 // indirect
	golang.org/x/net v0.7.0 // indirect
	golang.org/x/sys v0.5.0 // indirect
	golang.org/x/text v0.7.0 // indirect
	google.golang.org/genproto v0.0.0-20220812140447-cec7f5303424 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
)

replace github.com/ferranbt/fastssz => github.com/ferranbt/fastssz v0.0.0-20210526181520-7df50c8568f8

// See: https://github.com/prysmaticlabs/grpc-gateway/issues/2
replace github.com/grpc-ecosystem/grpc-gateway/v2 => github.com/prysmaticlabs/grpc-gateway/v2 v2.3.1-0.20210524202756-cefc26c3f2bf
