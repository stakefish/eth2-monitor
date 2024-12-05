package cmd

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"eth2-monitor/beaconchain"
	"eth2-monitor/cmd/opts"
	"eth2-monitor/pkg"
	"eth2-monitor/spec"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"net/http"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	rootCmd = &cobra.Command{
		Use:   "eth2-monitor",
		Short: "Ethereum 2 performance monitor",
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			if logLevel, err := zerolog.ParseLevel(opts.LogLevel); err != nil {
				fmt.Println(err)
			} else {
				zerolog.SetGlobalLevel(logLevel)
			}
		},
	}

	versionCmd = &cobra.Command{
		Use:   "version",
		Short: "Print the version number of eth2-monitor",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("eth2-monitor %s\n", GetVersion())
		},
	}

	monitorCmd = &cobra.Command{
		Use:   "monitor [-k PUBKEY] [PUBKEY_FILES...]",
		Short: "Monitor attestations and proposals performance",
		Args:  cobra.ArbitraryArgs,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if len(args)+len(opts.Monitor.Pubkeys) < 1 {
				return errors.New("provide validator public keys using -k or by specifying files with public keys")
			}
			return nil
		},
		Run: func(cmd *cobra.Command, args []string) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			beacon, err := beaconchain.New(ctx, opts.BeaconChainAPI, time.Minute)
			pkg.Must(err)

			plainPubkeys, err := pkg.LoadKeys(args)
			pkg.Must(err)
			if len(plainPubkeys) == 0 {
				panic("No validators to monitor")
			}
			log.Info().Msgf("Loaded validator keys: %v", len(plainPubkeys))

			mevRelays := []string{}
			if opts.Monitor.MEVRelaysFilePath != "" {
				mevRelays, err = pkg.LoadMEVRelays(opts.Monitor.MEVRelaysFilePath)
				pkg.Must(err)
				log.Info().Msgf("Loaded MEV relays: %v", len(mevRelays))
			}

			epochsChan := make(chan spec.Epoch)

			var wg sync.WaitGroup
			wg.Add(2)
			go pkg.SubscribeToEpochs(ctx, beacon, &wg, epochsChan)
			go pkg.MonitorAttestationsAndProposals(ctx, beacon, plainPubkeys, mevRelays, &wg, epochsChan)

			//Create Prometheus Metrics Client
			http.Handle("/metrics", promhttp.Handler())
			err = http.ListenAndServe(":"+opts.MetricsPort, nil)
			pkg.Must(err)

			defer wg.Wait() // XXX unreachable -- ListenAndServe() call above blocks
		},
	}

	version = ""
)

// GetVersion returns the semver string of the version
func GetVersion() string {
	return version
}

// Execute executes the root command.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&opts.LogLevel, "log-level", "l", "info", "log level (error, warn, info, debug, trace)")
	rootCmd.PersistentFlags().StringVar(&opts.BeaconNode, "beacon-node", "localhost:4000", "Prysm beacon node GRPC address")
	rootCmd.PersistentFlags().StringVar(&opts.BeaconChainAPI, "beacon-chain-api", "localhost:3500", "Beacon Chain API HTTP address")
	rootCmd.PersistentFlags().StringVar(&opts.MetricsPort, "metrics-port", "1337", "Metrics port to expose metrics for Prometheus")
	rootCmd.PersistentFlags().StringVar(&opts.SlackURL, "slack-url", "", "Slack Webhook URL")
	rootCmd.PersistentFlags().StringVar(&opts.SlackUsername, "slack-username", "", "Slack username")
	rootCmd.PersistentFlags().StringVar(&opts.PushGatewayUrl, "pushgateway-url", "", "Pushgateway URL")
	rootCmd.PersistentFlags().StringVar(&opts.PushGatewayJob, "pushgateway-job", "", "Pushgateway job")

	rootCmd.AddCommand(versionCmd)

	monitorCmd.PersistentFlags().BoolVar(&opts.Monitor.PrintSuccessful, "print-successful", false, "print successful attestations")
	monitorCmd.PersistentFlags().UintSliceVar(&opts.Monitor.ReplayEpoch, "replay-epoch", nil, "replay epoch for debug purposes")
	monitorCmd.PersistentFlags().Uint64Var(&opts.Monitor.SinceEpoch, "since-epoch", ^uint64(0), "replay epochs from the specified one")
	monitorCmd.PersistentFlags().StringSliceVarP(&opts.Monitor.Pubkeys, "pubkey", "k", nil, "validator public key")
	monitorCmd.PersistentFlags().StringVar(&opts.Monitor.MEVRelaysFilePath, "mev-relays", "", "file path containing a one-per-line list of MEV relays to use in monitoring vanilla blocks")
	monitorCmd.PersistentFlags().Lookup("since-epoch").DefValue = "follows justified epoch"
	monitorCmd.PersistentFlags().SortFlags = false
	rootCmd.AddCommand(monitorCmd)
}
