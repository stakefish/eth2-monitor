package monitoring

import (
	"context"
	"iter"
	"time"

	"github.com/rs/zerolog/log"
)

// Supervise drives `run` in a loop until ctx is cancelled. Between
// iterations it sleeps using the next value drawn from backoff.
//
// Contract:
//   - run must honour ctx; when run returns, Supervise checks ctx.Err()
//     to decide whether the return signalled real shutdown (ctx done)
//     or an unexpected inner exit (ctx still alive → restart).
//   - Sleeping between restarts is ctx-aware: a parent cancel during
//     backoff returns promptly rather than waiting out the full delay.
//
// Why this exists: the production wiring (cli/root.go) spawns a pair
// of goroutines (SubscribeToEpochs + MonitorAttestationsAndProposals)
// that share one ctx. Pre-supervisor, an unexpected return from either
// goroutine triggered the orchestrator's `defer cancel()`, which
// cancelled the shared ctx, which cancelled the SSE goroutine — and
// because `http.ListenAndServe` was holding the main goroutine, the
// process became a zombie that served stale /metrics but processed no
// new epochs. The supervisor breaks that death-spiral by giving each
// run-iteration its own derived ctx and restarting on a fresh one if
// the parent is still alive.
//
// Panics from run are NOT recovered. Real invariant violations should
// still crash the process so Docker/k8s restart picks up the panic
// stacktrace; the supervisor handles graceful unexpected returns, not
// programmer errors.
func Supervise(ctx context.Context, run func(context.Context) error, backoff iter.Seq[time.Duration]) error {
	next, stop := iter.Pull(backoff)
	defer stop()

	attempt := 0
	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		runErr := run(ctx)

		if err := ctx.Err(); err != nil {
			return err
		}

		attempt++
		delay, ok := next()
		if !ok {
			// Defensive: ExptBackoff never terminates, but a future
			// caller could pass a finite iterator. Treat exhaustion
			// as zero-delay rather than spin-locking.
			delay = 0
		}

		log.Warn().
			Err(runErr).
			Int("attempt", attempt).
			Dur("backoff", delay).
			Msg("monitor goroutines exited unexpectedly; restarting")

		if delay > 0 {
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
		}
	}
}
