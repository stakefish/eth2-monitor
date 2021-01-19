package main

import (
	"context"
	"os"
	"sync"
	"time"

	"eth2-monitor/prysmgrpc"
	"eth2-monitor/spec"

	flags "github.com/jessevdk/go-flags"
	isatty "github.com/mattn/go-isatty"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/rs/zerolog/pkgerrors"
)

var (
	opts struct {
		LogLevel          string       `long:"log-level" default:"info" choice:"error" choice:"warn" choice:"info" choice:"debug" choice:"trace" description:"Log level"`
		ReplayEpoch       []spec.Epoch `long:"replay-epoch" description:"Replay epoch for debug purposes"`
		SinceEpoch        *spec.Epoch  `long:"since-epoch" description:"Replay epochs the specified one"`
		PrintSuccessful   bool         `long:"print-successful" description:"Print successful attestations"`
		DistanceTolerance uint64       `short:"d" default:"2" long:"distance-tolerance" description:"Longest tolerated inclusion slot distance"`

		BeaconNode string `long:"beacon-node" value-name:"HOST:PORT" default:"localhost:4000" description:"Prysm beacon node GRPC address"`

		Pubkeys    []string `short:"k" long:"pubkey" value-name:"PUBKEY" description:"Validator public key"`
		Positional struct {
			PubkeysFiles []string
		} `positional-args:"yes" positional-arg-name:"PUBKEYS_FILE" description:"Files with validator public keys"`
	}

	epochsChan chan spec.Epoch
)

func init() {
	zerolog.ErrorStackMarshaler = pkgerrors.MarshalStack
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	log.Logger = log.Output(zerolog.ConsoleWriter{
		Out:        os.Stdout,
		TimeFormat: time.RFC3339Nano,
		NoColor:    !isatty.IsTerminal(os.Stdout.Fd()),
	})
	epochsChan = make(chan spec.Epoch)
}

func main() {
	if _, err := flags.ParseArgs(&opts, os.Args[1:]); err != nil {
		os.Exit(1)
	}

	logLevel, err := zerolog.ParseLevel(opts.LogLevel)
	Must(err)
	zerolog.SetGlobalLevel(logLevel)

	if len(opts.Positional.PubkeysFiles)+len(opts.Pubkeys) < 1 {
		parser := flags.NewParser(&opts, flags.Default)
		println("Provide validator public keys using -k or by specifing files with public keys")
		println("")
		parser.WriteHelp(os.Stderr)
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s, err := prysmgrpc.New(ctx,
		prysmgrpc.WithAddress(opts.BeaconNode),
		prysmgrpc.WithTimeout(time.Minute))
	Must(err)

	var wg sync.WaitGroup
	wg.Add(2)
	go SubscribeToEpochs(ctx, s, &wg)
	go MonitorAttestationsAndProposals(ctx, s, &wg)
	defer wg.Wait()
}
