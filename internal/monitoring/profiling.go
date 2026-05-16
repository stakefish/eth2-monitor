package monitoring

import (
	"fmt"
	"time"

	"github.com/rs/zerolog/log"
)

// Measure runs handler and emits one Debug log with the elapsed time.
// The log fires from a defer so the timing is captured even when handler
// panics — operators investigating a panic in a wrapped beacon-API call
// keep the "how long was the call running" signal that an unbuffered
// Set-then-log pattern would have dropped.
func Measure(handler func(), title string, args ...interface{}) {
	start := time.Now()
	// Log via defer so the elapsed time is captured even if handler panics —
	// otherwise a panic mid-handler silently drops the timing telemetry just
	// when operators need it most. Defer also fires on early return.
	defer func() {
		log.Debug().Msgf("⏱️ %s took %v", fmt.Sprintf(title, args...), time.Since(start))
	}()
	handler()
}
