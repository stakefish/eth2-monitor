package cli

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"github.com/stakefish/eth2-monitor/internal/beaconchain"
	"github.com/stakefish/eth2-monitor/internal/monitoring"
	"github.com/stakefish/eth2-monitor/internal/opts"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// supervisorBackoffBase / supervisorBackoffMaxExponent shape the wait
// between RunMonitorPair restarts when the inner goroutine pair has
// exited unexpectedly: 1s, 2s, 4s, …, 64s, then resets. Mirrors the
// SSE retry rhythm in monitoring.SubscribeToEpochs.
const (
	supervisorBackoffBase        = time.Second
	supervisorBackoffMaxExponent = 6
	// metricsShutdownTimeout bounds the graceful shutdown of the
	// /metrics HTTP server on real-shutdown signals so a stuck handler
	// can't block process exit indefinitely.
	metricsShutdownTimeout = 5 * time.Second
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
			// rootCtx is signal-aware: SIGINT/SIGTERM (Docker stop, Ctrl-C)
			// cancel it cleanly, which the supervisor uses to distinguish
			// "real shutdown" from "inner goroutine pair returned
			// unexpectedly and should restart". Pre-supervisor the binary
			// had no signal handling at all — Docker SIGTERM was a no-op
			// while http.ListenAndServe blocked the main goroutine.
			rootCtx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()

			metrics := monitoring.NewMonitorMetrics(prometheus.DefaultRegisterer)

			beacon, err := beaconchain.New(rootCtx, opts.BeaconChainAPI, time.Minute, metrics.BeaconRequestMetrics())
			monitoring.Must(err)

			// One-shot: read CONFIG_NAME from /eth/v1/config/spec so the
			// dashboard's beaconchain_host template var can swap the
			// validator-detail URL host between mainnet and the testnets.
			// Non-fatal: an error here just leaves the host variable
			// empty, the rest of the monitor still works.
			if _, _, err := monitoring.RegisterChainInfo(rootCtx, beacon, metrics); err != nil {
				log.Error().Err(err).Msg("RegisterChainInfo failed; dashboard beaconchain_host will be empty")
			}

			plainPubkeys, err := monitoring.LoadKeys(args)
			monitoring.Must(err)
			if len(plainPubkeys) == 0 {
				panic("No validators to monitor")
			}
			log.Info().Msgf("Loaded validator keys: %v", len(plainPubkeys))

			mevRelays := []string{}
			if opts.Monitor.MEVRelaysFilePath != "" {
				mevRelays, err = monitoring.LoadMEVRelays(opts.Monitor.MEVRelaysFilePath)
				monitoring.Must(err)
				log.Info().Msgf("Loaded MEV relays: %v", len(mevRelays))
			}

			// Metrics HTTP server runs in its own goroutine and shuts
			// down gracefully when rootCtx fires. Pre-supervisor the
			// bare http.ListenAndServe blocked the main goroutine
			// forever, which is what kept the process alive as a zombie
			// after both monitor goroutines died.
			metricsMux := http.NewServeMux()
			metricsMux.Handle("/metrics", promhttp.Handler())
			metricsSrv := &http.Server{Addr: ":" + opts.MetricsPort, Handler: metricsMux}
			go func() {
				if err := metricsSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
					log.Error().Err(err).Msg("metrics server stopped with error")
				}
			}()
			defer func() {
				shutdownCtx, cancel := context.WithTimeout(context.Background(), metricsShutdownTimeout)
				defer cancel()
				_ = metricsSrv.Shutdown(shutdownCtx)
			}()

			// Supervisor loop: each iteration spawns the SSE producer +
			// orchestrator goroutine pair against a child ctx and waits
			// for them to exit. An unexpected exit (transient beacon
			// timeout, anything that surfaces as
			// errors.Is(err, ctx.{Canceled,DeadlineExceeded}) inside the
			// orchestrator) leads to restart with exponential backoff;
			// a real shutdown signal causes rootCtx to fire and
			// Supervise returns.
			runOnce := func(runCtx context.Context) error {
				return monitoring.RunMonitorPair(runCtx, beacon, plainPubkeys, mevRelays, metrics)
			}
			err = monitoring.Supervise(rootCtx, runOnce, monitoring.ExptBackoff(supervisorBackoffBase, supervisorBackoffMaxExponent))
			if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
				log.Error().Err(err).Msg("supervisor exited with error")
			}
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
	rootCmd.PersistentFlags().StringVar(&opts.BeaconChainAPI, "beacon-chain-api", "localhost:3500", "Beacon Chain API HTTP address")
	rootCmd.PersistentFlags().StringVar(&opts.MetricsPort, "metrics-port", "1337", "Metrics port to expose metrics for Prometheus")
	rootCmd.PersistentFlags().StringVar(&opts.SlackURL, "slack-url", "", "Slack Webhook URL")
	rootCmd.PersistentFlags().StringVar(&opts.SlackUsername, "slack-username", "", "Slack username")

	rootCmd.AddCommand(versionCmd)

	monitorCmd.PersistentFlags().BoolVar(&opts.Monitor.PrintSuccessful, "print-successful", false, "print successful attestations")
	monitorCmd.PersistentFlags().UintSliceVar(&opts.Monitor.ReplayEpoch, "replay-epoch", nil, "replay epoch for debug purposes")
	monitorCmd.PersistentFlags().Uint64Var(&opts.Monitor.SinceEpoch, "since-epoch", ^uint64(0), "replay epochs from the specified one")
	monitorCmd.PersistentFlags().StringSliceVarP(&opts.Monitor.Pubkeys, "pubkey", "k", nil, "validator public key")
	monitorCmd.PersistentFlags().StringVar(&opts.Monitor.MEVRelaysFilePath, "mev-relays", "", "path to a JSON file containing an array of MEV relay URLs to monitor vanilla blocks against")
	monitorCmd.PersistentFlags().Lookup("since-epoch").DefValue = "follows justified epoch"
	monitorCmd.PersistentFlags().SortFlags = false
	rootCmd.AddCommand(monitorCmd)
}
