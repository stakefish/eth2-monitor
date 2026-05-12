package pkg

import (
	"context"
	"encoding/json"
	"eth2-monitor/spec"
	"fmt"
	"io"
	"iter"
	"math/rand/v2"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/rs/zerolog/log"
	"golang.org/x/sync/errgroup"
)

// BidTrace mirrors the schema of mev-boost-relay's
// /relay/v1/data/bidtraces/proposer_payload_delivered response entries.
//
// All numeric fields use ,string JSON tags because the relay-api spec
// emits them as quoted decimals (consistent with the broader Beacon API
// convention). Pubkeys and hashes are not case-canonical per spec, so
// comparisons against them in ListBestBids / CheckProposal use
// strings.EqualFold rather than byte equality.
type BidTrace struct {
	Slot                 uint64 `json:"slot,string"`
	ParentHash           string `json:"parent_hash"`
	BlockHash            string `json:"block_hash"`
	BuilderPubkey        string `json:"builder_pubkey"`
	ProposerPubkey       string `json:"proposer_pubkey"`
	ProposerFeeRecipient string `json:"proposer_fee_recipient"`
	GasLimit             uint64 `json:"gas_limit,string"`
	GasUsed              uint64 `json:"gas_used,string"`
	Value                uint64 `json:"value,string"`
}

/*
Sample response:
[

	{
	   "block_hash" : "0x038eacd45f17d198ca1d40a1b9923fd4a93bf17b29c64044ce51fe7725bfb7e6",
	   "block_number" : "20935934",
	   "builder_pubkey" : "0xa32aadb23e45595fe4981114a8230128443fd5407d557dc0c158ab93bc2b88939b5a87a84b6863b0d04a4b5a2447f847",
	   "gas_limit" : "30000000",
	   "gas_used" : "9700082",
	   "num_tx" : "150",
	   "parent_hash" : "0xfe39b1f2c072f60ed0f4f26716f4f20ad792762f4305e1e6aacc9eb0b361033f",
	   "proposer_fee_recipient" : "0xd4DB3D11394FF2b968bA96ba96deFaf281d69412",
	   "proposer_pubkey" : "0xb0b5235d72d49e014fe6171ddb9b6668b30e4140a68178501361791064ac690dbba544c35303687856c4abd6e5a1f9e6",
	   "slot" : "10145666",
	   "value" : "63557422170996168"
	},

]
*/
// requestBidTracesPage fetches one page from baseurl's
// proposer_payload_delivered endpoint using cursor=slot. Validates that
// the returned traces are sorted strictly descending by slot (relay
// contract). Caps body read at 4 MiB to bound memory; surfaces non-2xx
// responses with a body excerpt rather than the cryptic decode error.
func requestBidTracesPage(client *http.Client, baseurl string, slot phase0.Slot, limit uint64) ([]BidTrace, error) {
	var payloads []BidTrace

	url := fmt.Sprintf("%s/relay/v1/data/bidtraces/proposer_payload_delivered?cursor=%d&limit=%d", baseurl, slot, limit)
	log.Debug().Msgf("Calling %v", url)

	resp, err := client.Get(url)

	if err != nil {
		log.Error().Msgf("Error retrieving delivered payloads: %v", err)
		return nil, err
	}

	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode/100 != 2 {
		// Read a short prefix of the body so the error message reflects what
		// the relay actually said (HTML error pages, plaintext "rate limited",
		// etc.) rather than the cryptic "json: invalid character '<'" we'd
		// otherwise get from the decoder below.
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("relay %s returned HTTP %d: %s", baseurl, resp.StatusCode, body)
	}

	// Cap the success-case body too. A misbehaving (or hostile) relay
	// returning gigabytes here would otherwise force json.NewDecoder to
	// allocate unbounded memory. 4 MiB is far above any realistic
	// page-of-32-traces JSON size (each trace is ~500 bytes ⇒ ~16 KiB
	// per page) but still bounded.
	const maxBodyBytes = 4 << 20
	err = json.NewDecoder(io.LimitReader(resp.Body, maxBodyBytes)).Decode(&payloads)

	if err != nil {
		log.Error().Msgf("Error decoding delivered payloads: %v", err)
		return nil, err
	}

	// Bid traces should be returned sorted by the slot number in a decreasing order.
	for i := range payloads {
		if i == 0 {
			continue
		}
		if payloads[i].Slot >= payloads[i-1].Slot {
			return nil, fmt.Errorf("relay returned bid traces in a wrong order: %s", baseurl)
		}
	}

	return payloads, nil
}

// requestRelayEpochBidTraces paginates baseurl's bidtraces endpoint
// until either the page floor reaches epochLowestSlot, the slot cursor
// would underflow (low-epoch / pathological data), or maxPages requests
// have been issued (broken relay returning the same page forever).
// Returns only traces whose slot lies in the requested epoch.
func requestRelayEpochBidTraces(timeout time.Duration, baseurl string, epoch phase0.Epoch) ([]BidTrace, error) {
	var bidtraces []BidTrace

	client := http.Client{
		Timeout: timeout,
	}

	epochHighestSlot := spec.EpochHighestSlot(epoch)
	epochLowestSlot := spec.EpochLowestSlot(epoch)

	// Cap total page requests at a generous-but-bounded value. A normal
	// epoch needs ~1-2 pages; this guard only fires if a misbehaving relay
	// returns the same page regardless of cursor (which would otherwise
	// spin until the per-relay timeout fires). Bigger than any realistic
	// pagination depth, small enough to bound wasted goroutine CPU.
	const maxPages = 64

	slot := epochHighestSlot
	for page := 0; page < maxPages; page++ {
		traces, err := requestBidTracesPage(&client, baseurl, slot, spec.SLOTS_PER_EPOCH)
		if err != nil {
			return nil, err
		}
		if len(traces) == 0 {
			return nil, fmt.Errorf("relay returned no bid traces for epoch %v: %s", epoch, baseurl)
		}

		for _, trace := range traces {
			// We're only interested in bid traces from the requested epoch
			if trace.Slot >= uint64(epochLowestSlot) && trace.Slot <= uint64(epochHighestSlot) {
				bidtraces = append(bidtraces, trace)
			}
		}

		if traces[len(traces)-1].Slot <= uint64(epochLowestSlot) {
			break
		}

		// Defensive break before uint64 underflow: if the relay never
		// returns a trace ≤ epochLowestSlot for a low epoch (or for any
		// epoch where it has gaps near the floor), subtracting
		// SLOTS_PER_EPOCH would wrap to ~maxUint64 and the next page
		// request would loop forever with cursor pointing at recent
		// slots that the filter then drops. Epochs ≥ 1 normally exit
		// via the break above; this guard only fires on pathological
		// data or epoch 0.
		if slot < spec.SLOTS_PER_EPOCH {
			break
		}
		slot -= spec.SLOTS_PER_EPOCH
	}

	return bidtraces, nil
}

// exptBackoff yields an infinite sequence of backoff durations: base,
// 2*base, 4*base, ..., (2^maxExponent)*base, then resets to base and
// cycles. Each yield is offset by [0, base) ms of jitter. Callers should
// break out of the for-range when their work succeeds or context is
// cancelled — the iterator itself never terminates.
//
// Defensive: callers passing base < 1ms get zero-jitter rather than the
// integer-divide-by-zero panic the underlying rand.Uint() % baseMillis
// would otherwise produce.
func exptBackoff(base time.Duration, maxExponent uint) iter.Seq[time.Duration] {
	// baseMillis is the modulus for the jitter draw. Anything less than 1
	// would panic on `rand.Uint() % 0`; clamp so callers that pass sub-ms
	// bases (or someone refactors the call site) get zero-jitter instead
	// of a crash deep in a goroutine.
	baseMillis := uint(base / time.Millisecond)
	if baseMillis < 1 {
		baseMillis = 1
	}
	return func(yield func(time.Duration) bool) {
		step := base
		for {
			for range maxExponent + 1 {
				jitter := time.Duration(rand.Uint()%baseMillis) * time.Millisecond
				delay := step + jitter
				if !yield(delay) {
					return
				}
				step *= 2
			}
			step = base
		}
	}
}

// requestEpochBidTraces fetches one epoch's traces from each relay
// concurrently. Each goroutine has its own per-relay timeout derived
// from ctx, retries via exptBackoff (with a ctx-aware wait between
// attempts), and writes its result under a shared mutex.
//
// Returns the partial result map plus the first error from any failed
// relay. Callers (ListBestBids) should use the partial map and
// separately log the error.
func requestEpochBidTraces(ctx context.Context, timeout time.Duration, relays []string, epoch phase0.Epoch) (map[string][]BidTrace, error) {
	var mu sync.Mutex
	result := make(map[string][]BidTrace)

	var g errgroup.Group
	for _, baseurl := range relays {
		g.Go(func() error {
			// Per-relay timeout: a single slow relay no longer starves
			// the others. The parent ctx still cancels everyone on
			// shutdown.
			relayCtx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()

			var traces []BidTrace
			for delay := range exptBackoff(time.Duration(500)*time.Millisecond, 4) {
				var err error
				traces, err = requestRelayEpochBidTraces(timeout, baseurl, epoch)
				if err == nil {
					break
				}
				log.Error().Msgf("MEV relay request failed: %v", err)
				// Sleep while watching relayCtx so a shutdown / per-relay
				// timeout during backoff is observed immediately rather
				// than after the full ~8s worst-case sleep. NewTimer +
				// Stop avoids leaking the timer when the ctx case wins.
				timer := time.NewTimer(delay)
				select {
				case <-relayCtx.Done():
					timer.Stop()
					// Wrap the underlying ctx error (DeadlineExceeded
					// for the per-relay timeout, Canceled for parent
					// shutdown) so callers can errors.Is against
					// context.Canceled / DeadlineExceeded.
					return fmt.Errorf("relay %s timeout: %w", baseurl, relayCtx.Err())
				case <-timer.C:
				}
			}
			mu.Lock()
			defer mu.Unlock()
			if _, ok := result[baseurl]; ok {
				log.Warn().Msgf("⚠️  Processing the same relay more than once.  Check for duplicates on the relays list")
			}
			result[baseurl] = traces
			return nil
		})
	}

	return result, g.Wait()
}

// ListBestBids fetches bid traces from every relay concurrently and
// returns, per slot, the highest-Value trace whose proposer matches a
// tracked validator. Returns (partial_results, err) on partial failure —
// callers should log the error but use whatever bestBids were assembled.
//
// Slot-membership filtering uses the `proposals` map (which lists our
// tracked validators' duty slots for the epoch). Pubkey matching is
// case-insensitive (relay JSON is not case-canonical per spec; see
// BidTrace doc).
func ListBestBids(ctx context.Context, timeout time.Duration, relays []string, epoch phase0.Epoch, validatorPubkeyFromIndex map[phase0.ValidatorIndex]string, proposals map[phase0.Slot]phase0.ValidatorIndex) (map[phase0.Slot]BidTrace, error) {
	bestBids := make(map[phase0.Slot]BidTrace)

	perRelayBidTraces, err := requestEpochBidTraces(ctx, timeout, relays, epoch)

	// Only keep bid traces whose proposer_pubkey matches any of the tracked validators
	for _, traces := range perRelayBidTraces {
		for _, trace := range traces {
			proposerValidatorIndex, ok := proposals[phase0.Slot(trace.Slot)]
			if !ok {
				continue
			}
			proposerPubkey := validatorPubkeyFromIndex[proposerValidatorIndex]
			// Compare case-insensitively. proposerPubkey is the lowercase
			// canonical form (NormalizedPublicKey), but the relay JSON is
			// not case-canonical per the relay-spec: a relay returning
			// uppercase hex would otherwise silently mismatch every
			// tracked-validator bid and inflate TotalMissingBidTraces.
			if !strings.EqualFold(trace.ProposerPubkey, "0x"+proposerPubkey) {
				continue
			}
			if _, ok := bestBids[phase0.Slot(trace.Slot)]; ok {
				if trace.Value > bestBids[phase0.Slot(trace.Slot)].Value {
					bestBids[phase0.Slot(trace.Slot)] = trace
				}
			} else {
				bestBids[phase0.Slot(trace.Slot)] = trace
			}
		}
	}

	return bestBids, err
}
