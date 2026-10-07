package monitoring

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"iter"
	"math/rand/v2"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/stakefish/eth2-monitor/internal/spec"

	"github.com/attestantio/go-eth2-client/spec/deneb"
	"github.com/attestantio/go-eth2-client/spec/electra"
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
// proposer_payload_delivered endpoint using cursor=slot and validates that
// the returned traces are sorted strictly descending by slot (relay
// contract).
func requestBidTracesPage(ctx context.Context, client *http.Client, baseurl string, slot phase0.Slot, limit uint64) ([]BidTrace, error) {
	var payloads []BidTrace
	url := fmt.Sprintf("%s/relay/v1/data/bidtraces/proposer_payload_delivered?cursor=%d&limit=%d", baseurl, slot, limit)
	if _, err := relayGetJSON(ctx, client, url, &payloads); err != nil {
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
//
// ctx is threaded down to each HTTP page request so a shutdown signal
// aborts an in-flight TCP read immediately. The client.Timeout still
// caps any single request (defence in depth against a hung connection
// that didn't observe ctx).
// relayGetJSON GETs url from a relay data API and decodes the JSON body
// into out. The request carries ctx so a shutdown aborts an in-flight
// read instead of waiting for client.Timeout. A non-2xx response comes
// back as an error with the status and a body excerpt (HTML error pages,
// "rate limited" text) rather than the decoder's cryptic complaint; the
// status lets callers tell a relay's "no such registration" (400/404)
// from a failure. Bodies are capped at 4 MiB so a misbehaving relay
// cannot exhaust memory (a page of 32 traces is ~16 KiB).
func relayGetJSON(ctx context.Context, client *http.Client, url string, out any) (int, error) {
	log.Debug().Str("url", url).Msg("calling relay")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, fmt.Errorf("relay request %s: %w", url, err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return resp.StatusCode, fmt.Errorf("relay %s returned HTTP %d: %s", url, resp.StatusCode, body)
	}
	const maxBodyBytes = 4 << 20
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxBodyBytes)).Decode(out); err != nil {
		return resp.StatusCode, fmt.Errorf("relay %s: decode: %w", url, err)
	}
	return resp.StatusCode, nil
}

func requestRelayEpochBidTraces(ctx context.Context, timeout time.Duration, baseurl string, epoch phase0.Epoch) ([]BidTrace, error) {
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
		traces, err := requestBidTracesPage(ctx, &client, baseurl, slot, spec.SLOTS_PER_EPOCH)
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

// ExptBackoff yields an infinite sequence of backoff durations: base,
// 2*base, 4*base, ..., (2^maxExponent)*base, then resets to base and
// cycles. Each yield is offset by [0, base) ms of jitter. Callers should
// break out of the for-range when their work succeeds or context is
// cancelled — the iterator itself never terminates.
//
// Defensive: callers passing base < 1ms get zero-jitter rather than the
// integer-divide-by-zero panic the underlying rand.Uint() % baseMillis
// would otherwise produce.
func ExptBackoff(base time.Duration, maxExponent uint) iter.Seq[time.Duration] {
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
			for delay := range ExptBackoff(time.Duration(500)*time.Millisecond, 4) {
				var err error
				traces, err = requestRelayEpochBidTraces(relayCtx, timeout, baseurl, epoch)
				if err == nil {
					break
				}
				log.Error().Err(err).Str("relay", baseurl).Msg("MEV relay request failed")
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
				log.Warn().Str("relay", baseurl).Msg("⚠️  Processing the same relay more than once. Check for duplicates on the relays list")
			}
			result[baseurl] = traces
			return nil
		})
	}

	return result, g.Wait()
}

// RegistrationStatus is the outcome of a relay validator_registration
// lookup. The zero value is Unknown so a missing map entry (lookup never
// ran) reads the same as a failed one.
type RegistrationStatus int

const (
	RegistrationUnknown    RegistrationStatus = iota // lookup failed on every relay, or never ran
	RegistrationRegistered                           // at least one relay returned the registration
	RegistrationNotFound                             // every configured relay answered 400/404: mev-boost never registered the key
)

// Registration is a validator's mev-boost registration as the relays see
// it: the fee recipients the validator asked builders to pay. CheckProposal
// compares them with the fee recipient of a relay-absent block to tell a
// correctly configured local build from a misconfigured EL.
type Registration struct {
	Status RegistrationStatus
	// FeeRecipients holds every distinct recipient any configured relay
	// returned for the key, newest registration first. mev-boost registers
	// with each relay separately and a relay can hold a stale one, so a
	// block paying any of them is correctly configured. Empty unless
	// Status is RegistrationRegistered.
	FeeRecipients []string
}

// newest is the recipient of the most recent registration ("" when none).
func (r Registration) newest() string {
	if len(r.FeeRecipients) > 0 {
		return r.FeeRecipients[0]
	}
	return ""
}

// matches reports whether feeRecipient equals any registered recipient.
func (r Registration) matches(feeRecipient string) bool {
	return slices.ContainsFunc(r.FeeRecipients, func(fr string) bool { return strings.EqualFold(fr, feeRecipient) })
}

// newRegistration orders the records newest first and keeps each distinct
// recipient once (ties broken by recipient so the result is deterministic
// regardless of which relay answered first).
func newRegistration(records []registrationRecord) Registration {
	slices.SortFunc(records, func(a, b registrationRecord) int {
		return cmp.Or(cmp.Compare(b.Timestamp, a.Timestamp), strings.Compare(a.FeeRecipient, b.FeeRecipient))
	})
	reg := Registration{Status: RegistrationRegistered}
	for _, rec := range records {
		if !reg.matches(rec.FeeRecipient) {
			reg.FeeRecipients = append(reg.FeeRecipients, rec.FeeRecipient)
		}
	}
	return reg
}

type registrationRecord struct {
	FeeRecipient string
	Timestamp    uint64
}

// requestValidatorRegistration GETs baseurl's validator_registration
// record for pubkey. The HTTP status is returned alongside any error so
// the caller can tell "relay says not registered" (400/404) from a failure.
func requestValidatorRegistration(ctx context.Context, client *http.Client, baseurl, pubkey string) (registrationRecord, int, error) {
	var out struct {
		Message struct {
			FeeRecipient string          `json:"fee_recipient"`
			Timestamp    json.RawMessage `json:"timestamp"` // relays emit a quoted decimal; tolerate a bare number too
		} `json:"message"`
	}
	status, err := relayGetJSON(ctx, client, fmt.Sprintf("%s/relay/v1/data/validator_registration?pubkey=%s", baseurl, pubkey), &out)
	if err != nil {
		return registrationRecord{}, status, err
	}
	if out.Message.FeeRecipient == "" {
		return registrationRecord{}, status, fmt.Errorf("relay %s: registration without fee_recipient", baseurl)
	}
	ts, err := strconv.ParseUint(strings.Trim(string(out.Message.Timestamp), `"`), 10, 64)
	if err != nil {
		return registrationRecord{}, status, fmt.Errorf("relay %s: registration timestamp %s: %w", baseurl, out.Message.Timestamp, err)
	}
	return registrationRecord{FeeRecipient: out.Message.FeeRecipient, Timestamp: ts}, status, nil
}

// requestSlotBidTraces GETs the delivered payloads baseurl recorded for a
// single slot (?slot=N). Unlike the cursor-paged epoch sweep it cannot
// miss a row across a page boundary, and callers run it seconds later,
// after the relay's data API has caught up (measured 4-10 s after slot
// start).
func requestSlotBidTraces(ctx context.Context, client *http.Client, baseurl string, slot phase0.Slot) ([]BidTrace, error) {
	var traces []BidTrace
	_, err := relayGetJSON(ctx, client, fmt.Sprintf("%s/relay/v1/data/bidtraces/proposer_payload_delivered?slot=%d", baseurl, slot), &traces)
	return traces, err
}

// relayClient fans one request out to every configured relay data API in
// parallel, each bounded by timeout, so a slow relay never delays the
// others (a sequential sweep would cost up to len(relays) x timeout).
type relayClient struct {
	relays  []string
	timeout time.Duration
}

// each runs fn against every relay concurrently and waits for all of
// them. fn must synchronise its own writes.
func (c relayClient) each(ctx context.Context, fn func(ctx context.Context, client *http.Client, baseurl string)) {
	client := &http.Client{Timeout: c.timeout}
	var wg sync.WaitGroup
	for _, baseurl := range c.relays {
		wg.Add(1)
		go func() {
			defer wg.Done()
			fn(ctx, client, baseurl)
		}()
	}
	wg.Wait()
}

// LookupRegistration asks every configured relay for pubkey's mev-boost
// registration. Registered when any relay answered 2xx; NotFound only
// when every relay answered 400 or 404 (a 429 or a transport error is
// not evidence of a missing registration); Unknown otherwise.
func (c relayClient) LookupRegistration(ctx context.Context, pubkey string) Registration {
	var mu sync.Mutex
	var records []registrationRecord
	notFound := 0
	c.each(ctx, func(ctx context.Context, client *http.Client, baseurl string) {
		rec, status, err := requestValidatorRegistration(ctx, client, baseurl, pubkey)
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			if status == http.StatusBadRequest || status == http.StatusNotFound {
				notFound++
			}
			log.Debug().Err(err).Str("relay", baseurl).Str("pubkey", pubkey).Msg("validator registration lookup failed")
			return
		}
		log.Debug().Str("relay", baseurl).Str("pubkey", pubkey).Str("feeRecipient", rec.FeeRecipient).Uint64("timestamp", rec.Timestamp).Msg("validator registration found")
		records = append(records, rec)
	})
	switch {
	case len(records) > 0:
		return newRegistration(records)
	case len(c.relays) > 0 && notFound == len(c.relays):
		return Registration{Status: RegistrationNotFound}
	default:
		return Registration{Status: RegistrationUnknown}
	}
}

// confirmRelayAbsent re-asks every relay for one slot and returns the
// highest-value delivered trace whose proposer is pubkey (hex, no 0x).
// This is the last word before any relay-absent verdict: a trace found
// here means a listed relay did deliver the block and the epoch sweep
// simply missed it.
func (c relayClient) confirmRelayAbsent(ctx context.Context, slot phase0.Slot, pubkey string) (BidTrace, bool) {
	var mu sync.Mutex
	var traces []BidTrace
	c.each(ctx, func(ctx context.Context, client *http.Client, baseurl string) {
		got, err := requestSlotBidTraces(ctx, client, baseurl, slot)
		if err != nil {
			log.Debug().Err(err).Str("relay", baseurl).Uint64("slot", uint64(slot)).Msg("per-slot relay confirmation failed")
			return
		}
		mu.Lock()
		traces = append(traces, got...)
		mu.Unlock()
	})
	return bestTraceFor(traces, slot, pubkey)
}

// bestTraceFor returns the highest-value trace in traces that was
// delivered for slot to the proposer pubkey (hex, no 0x). Pubkeys are not
// case-canonical per the relay spec, hence EqualFold.
func bestTraceFor(traces []BidTrace, slot phase0.Slot, pubkey string) (best BidTrace, found bool) {
	for _, trace := range traces {
		if trace.Slot != uint64(slot) || !strings.EqualFold(trace.ProposerPubkey, "0x"+pubkey) {
			continue
		}
		if !found || trace.Value > best.Value {
			best, found = trace, true
		}
	}
	return best, found
}

// relayAbsentProposals returns the tracked duty slots CheckProposal would
// treat as relay-absent: the block exists, its proposer is the expected
// validator, and no relay bid matched the slot.
func relayAbsentProposals(
	proposerDuties map[phase0.Slot]phase0.ValidatorIndex,
	blocks map[phase0.Slot]*electra.SignedBeaconBlock,
	bestBids map[phase0.Slot]BidTrace,
) map[phase0.Slot]phase0.ValidatorIndex {
	out := make(map[phase0.Slot]phase0.ValidatorIndex)
	for slot, idx := range proposerDuties {
		block := blocks[slot]
		if block == nil || block.Message == nil || block.Message.ProposerIndex != idx {
			continue
		}
		if _, ok := bestBids[slot]; ok {
			continue
		}
		out[slot] = idx
	}
	return out
}

// executionPayload is a nil-safe accessor for the block's execution payload.
func executionPayload(block *electra.SignedBeaconBlock) *deneb.ExecutionPayload {
	if block == nil || block.Message == nil || block.Message.Body == nil {
		return nil
	}
	return block.Message.Body.ExecutionPayload
}

// resolveRelayAbsent settles every tracked proposal the epoch sweep left
// without a trace. Each is re-asked from every relay by slot (a late
// data-API write or a page boundary can hide a delivery) and a trace found
// that way goes into bestBids, so CheckProposal takes the hash-compare
// path. For the proposals that classifyProposal still calls vanilla the
// mev-boost registration is fetched, once per validator, so the relays see
// one request per vanilla candidate rather than one per validator. Cost:
// one parallel relay round per relay-absent proposal, a rare event.
func (c relayClient) resolveRelayAbsent(
	ctx context.Context,
	proposerDuties map[phase0.Slot]phase0.ValidatorIndex,
	blocks map[phase0.Slot]*electra.SignedBeaconBlock,
	bestBids map[phase0.Slot]BidTrace,
	pubkeyFromIndex map[phase0.ValidatorIndex]string,
	relaysComplete bool,
) map[phase0.ValidatorIndex]Registration {
	registrations := make(map[phase0.ValidatorIndex]Registration)
	for slot, idx := range relayAbsentProposals(proposerDuties, blocks, bestBids) {
		pubkey, ok := pubkeyFromIndex[idx]
		if !ok {
			continue
		}
		if trace, found := c.confirmRelayAbsent(ctx, slot, pubkey); found {
			log.Info().
				Uint64("slot", uint64(slot)).
				Uint64("validator", uint64(idx)).
				Str("blockHash", trace.BlockHash).
				Msg("relay delivery found by per-slot confirmation; the epoch sweep had missed it")
			bestBids[slot] = trace
			continue
		}
		if classifyProposal(executionPayload(blocks[slot]), nil, relaysComplete) != verdictVanilla {
			continue
		}
		if _, done := registrations[idx]; done {
			continue
		}
		registrations[idx] = c.LookupRegistration(ctx, "0x"+pubkey)
	}
	return registrations
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

	var traces []BidTrace
	for _, relayTraces := range perRelayBidTraces {
		traces = append(traces, relayTraces...)
	}
	for slot, proposerValidatorIndex := range proposals {
		if best, ok := bestTraceFor(traces, slot, validatorPubkeyFromIndex[proposerValidatorIndex]); ok {
			bestBids[slot] = best
		}
	}

	return bestBids, err
}
