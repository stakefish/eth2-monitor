package pkg

import (
	"fmt"
	"time"

	"github.com/rs/zerolog/log"
)

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
