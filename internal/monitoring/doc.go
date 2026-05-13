// Package pkg implements the per-epoch monitoring loop, beacon-API
// interaction helpers, MEV bid integration, and Prometheus metrics
// for the eth2-monitor binary.
//
// # Entry points
//
//   - SubscribeToEpochs: head-event SSE consumer that emits new-epoch
//     signals on a channel.
//   - MonitorAttestationsAndProposals: the orchestrator that processes
//     each epoch (build context → process attestations → check
//     proposals → finalize misses → persist progress).
//
// # Concurrency
//
// The package is single-goroutine internally; cross-goroutine state
// (epochsChan, MonitorMetrics, cacheFilePath) is documented at each
// exposed surface. The orchestrator and SSE consumer run in their own
// goroutines, coordinated via the epochs channel and a shared
// WaitGroup. Both honour ctx cancellation for graceful shutdown.
//
// # Defensive nil handling
//
// Several go-eth2-client types are pointer-keyed at the Go level
// (Message, Body, ExecutionPayload, Data, AttesterDuty, Attestation).
// The package defensively skips entries with nil pointers — these
// shapes shouldn't occur in valid Beacon API responses but the
// defenses prevent orchestrator crashes on malformed JSON from
// non-conforming clients.
package monitoring
