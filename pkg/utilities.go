package pkg

import (
	"github.com/rs/zerolog/log"
)

// Must logs the error with a stack trace at ERROR level and then panics
// with the same error value. Use only for genuinely-fatal conditions —
// e.g. beacon-API contract violations during startup where the process
// has no recovery path. ctx-cancellation errors should be detected
// explicitly by the caller and returned cleanly rather than handed to
// Must (the orchestrator does this in MonitorAttestationsAndProposals).
func Must(err error) {
	if err != nil {
		log.Error().Stack().Err(err).Msg("Fatal error occurred")
		panic(err)
	}
}
