package cmd

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"eth2-monitor/cmd/opts"
	"eth2-monitor/pkg"
	"eth2-monitor/prysmgrpc"

	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
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
				return errors.New("Provide validator public keys using -k or by specifing files with public keys")
			}
			return nil
		},
		Run: func(cmd *cobra.Command, args []string) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			s, err := prysmgrpc.New(ctx,
				prysmgrpc.WithAddress(opts.BeaconNode),
				prysmgrpc.WithTimeout(time.Minute))
			pkg.Must(err)

			plainPubkeys, err := pkg.LoadKeys(args)
			pkg.Must(err)

			var wg sync.WaitGroup
			wg.Add(2)
			go pkg.SubscribeToEpochs(ctx, s, true, &wg)
			go pkg.MonitorAttestationsAndProposals(ctx, s, plainPubkeys, &wg)
			defer wg.Wait()
		},
	}

	slashingsCmd = &cobra.Command{
		Use:   "slashings",
		Short: "Monitor slashings",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			s, err := prysmgrpc.New(ctx,
				prysmgrpc.WithAddress(opts.BeaconNode),
				prysmgrpc.WithTimeout(time.Minute))
			pkg.Must(err)

			var wg sync.WaitGroup
			wg.Add(2)
			go pkg.SubscribeToEpochs(ctx, s, true, &wg)
			go pkg.MonitorSlashings(ctx, s, &wg)
			defer wg.Wait()
		},
	}

	maintenanceCmd = &cobra.Command{
		Use:   "maintenance [-k PUBKEY] [PUBKEY_FILES...]",
		Short: "Shows a possible window for maintenance",
		Args:  cobra.ArbitraryArgs,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if len(args)+len(opts.Monitor.Pubkeys) < 1 {
				return errors.New("Provide validator public keys using -k or by specifing files with public keys")
			}
			return nil
		},
		Run: func(cmd *cobra.Command, args []string) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			s, err := prysmgrpc.New(ctx,
				prysmgrpc.WithAddress(opts.BeaconNode),
				prysmgrpc.WithTimeout(time.Minute))
			pkg.Must(err)

			plainPubkeys, err := pkg.LoadKeys(args)
			pkg.Must(err)

			var wg sync.WaitGroup
			wg.Add(2)
			go pkg.SubscribeToEpochs(ctx, s, false, &wg)
			go pkg.MonitorMaintenanceWindows(ctx, s, plainPubkeys, &wg)
			defer wg.Wait()
		},
	}

	version = ""

	// metadata is extra build time data
	metadata = ""
	// gitCommit is the git sha1
	gitCommit = ""
	// gitTreeState is the state of the git tree
	gitTreeState = ""
)

// GetVersion returns the semver string of the version
func GetVersion() string {
	if metadata == "" {
		return version
	}
	return version + "+" + metadata
}

// Execute executes the root command.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&opts.LogLevel, "log-level", "l", "info", "log level (error, warn, info, debug, trace)")
	rootCmd.PersistentFlags().StringVar(&opts.BeaconNode, "beacon-node", "localhost:4000", "Prysm beacon node GRPC address")
	rootCmd.PersistentFlags().StringVar(&opts.SlackURL, "slack-url", "", "Slack Webhook URL")

	rootCmd.AddCommand(versionCmd)

	monitorCmd.PersistentFlags().BoolVar(&opts.Monitor.PrintSuccessful, "print-successful", false, "print successful attestations")
	monitorCmd.PersistentFlags().UintSliceVar(&opts.Monitor.ReplayEpoch, "replay-epoch", nil, "replay epoch for debug purposes")
	monitorCmd.PersistentFlags().Uint64Var(&opts.Monitor.SinceEpoch, "since-epoch", ^uint64(0), "replay epochs from the specified one")
	monitorCmd.PersistentFlags().Uint64VarP(&opts.Monitor.DistanceTolerance, "distance-tolerance", "d", 2, "longest tolerated inclusion slot distance")
	monitorCmd.PersistentFlags().BoolVar(&opts.Monitor.UseAbsoluteDistance, "use-absolute-distance", false, "use the absolute distance to compare against the tolerance")
	monitorCmd.PersistentFlags().StringSliceVarP(&opts.Monitor.Pubkeys, "pubkey", "k", nil, "validator public key")
	monitorCmd.PersistentFlags().Lookup("since-epoch").DefValue = "follows justified epoch"
	monitorCmd.PersistentFlags().SortFlags = false
	rootCmd.AddCommand(monitorCmd)

	slashingsCmd.PersistentFlags().UintSliceVar(&opts.Monitor.ReplayEpoch, "replay-epoch", nil, "replay epoch for debug purposes")
	slashingsCmd.PersistentFlags().Uint64Var(&opts.Monitor.SinceEpoch, "since-epoch", ^uint64(0), "replay epochs from the specified one")
	slashingsCmd.PersistentFlags().BoolVar(&opts.Slashings.ShowSlashingReward, "show-reward", false, "replay epochs from the specified one")
	slashingsCmd.PersistentFlags().StringVar(&opts.Slashings.TwitterConsumerKey, "twitter-consumer-key", "", "Twitter consumer key")
	slashingsCmd.PersistentFlags().StringVar(&opts.Slashings.TwitterConsumerSecret, "twitter-consumer-secret", "", "Twitter consumer secret")
	slashingsCmd.PersistentFlags().StringVar(&opts.Slashings.TwitterAccessToken, "twitter-access-token", "", "Twitter consumer key")
	slashingsCmd.PersistentFlags().StringVar(&opts.Slashings.TwitterAccessSecret, "twitter-access-secret", "", "Twitter consumer secret")
	slashingsCmd.PersistentFlags().SortFlags = false
	rootCmd.AddCommand(slashingsCmd)

	maintenanceCmd.PersistentFlags().StringSliceVarP(&opts.Monitor.Pubkeys, "pubkey", "k", nil, "validator public key")
	maintenanceCmd.PersistentFlags().UintSliceVar(&opts.Monitor.ReplayEpoch, "replay-epoch", nil, "replay epoch for debug purposes")
	maintenanceCmd.PersistentFlags().Uint64Var(&opts.Monitor.SinceEpoch, "since-epoch", ^uint64(0), "replay epochs from the specified one")
	maintenanceCmd.PersistentFlags().Lookup("since-epoch").DefValue = "follows head epoch"
	maintenanceCmd.PersistentFlags().SortFlags = false
	rootCmd.AddCommand(maintenanceCmd)
}
