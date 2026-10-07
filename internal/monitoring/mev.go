package monitoring

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"iter"
	"math/rand/v2"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/stakefish/eth2-monitor/internal/spec"

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
// proposer_payload_delivered endpoint using cursor=slot. Validates that
// the returned traces are sorted strictly descending by slot (relay
// contract). Caps body read at 4 MiB to bound memory; surfaces non-2xx
// responses with a body excerpt rather than the cryptic decode error.
//
// Honours ctx cancellation: the GET is built with NewRequestWithContext
// so a shutdown signal aborts the in-flight TCP read immediately rather
// than waiting for the client.Timeout to fire. Without this, ListBestBids
// at shutdown would block up to client.Timeout (typically 4s) per
// in-flight relay even though the surrounding errgroup goroutine has
// already lost its sleep race to ctx.Done.
func requestBidTracesPage(ctx context.Context, client *http.Client, baseurl string, slot phase0.Slot, limit uint64) ([]BidTrace, error) {
	var payloads []BidTrace

	url := fmt.Sprintf("%s/relay/v1/data/bidtraces/proposer_payload_delivered?cursor=%d&limit=%d", baseurl, slot, limit)
	log.Debug().Str("url", url).Msg("calling relay")

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		// NewRequestWithContext only fails on a malformed URL or method;
		// surface so a future caller passing junk gets a clean error
		// rather than a panic deep in net/http.
		return nil, fmt.Errorf("relay %s: build request: %w", baseurl, err)
	}
	resp, err := client.Do(req)

	if err != nil {
		log.Error().Err(err).Str("relay", baseurl).Msg("error retrieving delivered payloads")
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
		log.Error().Err(err).Str("relay", baseurl).Msg("error decoding delivered payloads")
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
	RegistrationNotFound                             // every configured relay answered 4xx: mev-boost never registered the key
)

func (s RegistrationStatus) String() string {
	switch s {
	case RegistrationRegistered:
		return "registered"
	case RegistrationNotFound:
		return "not_found"
	default:
		return "unknown"
	}
}

// Registration is a validator's mev-boost registration as the relays see
// it: the fee recipient the validator asked builders to pay. CheckProposal
// compares it with the fee recipient of a relay-absent block to tell a
// correctly configured local build from a misconfigured EL. mev-boost
// registers with each relay separately and a relay can hold a stale
// registration, so every distinct recipient any relay holds is kept.
type Registration struct {
	Status RegistrationStatus
	// FeeRecipient comes from the newest registration (by message.timestamp);
	// 0x-prefixed hex as the relay returned it, not case-canonical.
	FeeRecipient string
	// FeeRecipients lists every distinct recipient any configured relay
	// holds for the key, newest first is NOT guaranteed; compare with matches.
	FeeRecipients []string
}

// matches reports whether feeRecipient equals any registered recipient.
func (r Registration) matches(feeRecipient string) bool {
	for _, fr := range r.FeeRecipients {
		if strings.EqualFold(fr, feeRecipient) {
			return true
		}
	}
	return len(r.FeeRecipients) == 0 && strings.EqualFold(r.FeeRecipient, feeRecipient)
}

type registrationRecord struct {
	FeeRecipient string
	Timestamp    uint64
}

// requestValidatorRegistration GETs baseurl's validator_registration
// endpoint for pubkey. Returns the registered fee recipient and
// registration timestamp on 2xx; on any other status the status code is
// returned alongside the error so the caller can tell "relay says not
// registered" (400/404) from a failure.
func requestValidatorRegistration(ctx context.Context, client *http.Client, baseurl, pubkey string) (registrationRecord, int, error) {
	url := fmt.Sprintf("%s/relay/v1/data/validator_registration?pubkey=%s", baseurl, pubkey)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return registrationRecord{}, 0, fmt.Errorf("relay %s: build request: %w", baseurl, err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return registrationRecord{}, 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return registrationRecord{}, resp.StatusCode, fmt.Errorf("relay %s returned HTTP %d: %s", baseurl, resp.StatusCode, body)
	}
	var out struct {
		Message struct {
			FeeRecipient string          `json:"fee_recipient"`
			Timestamp    json.RawMessage `json:"timestamp"` // relays emit a quoted decimal; tolerate a bare number too
		} `json:"message"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&out); err != nil {
		return registrationRecord{}, resp.StatusCode, fmt.Errorf("relay %s: decode registration: %w", baseurl, err)
	}
	if out.Message.FeeRecipient == "" {
		return registrationRecord{}, resp.StatusCode, fmt.Errorf("relay %s: registration without fee_recipient", baseurl)
	}
	ts, _ := strconv.ParseUint(strings.Trim(string(out.Message.Timestamp), `"`), 10, 64)
	return registrationRecord{FeeRecipient: out.Message.FeeRecipient, Timestamp: ts}, resp.StatusCode, nil
}

// LookupRegistration asks every configured relay for pubkey's mev-boost
// registration. Registered when any relay answered 2xx (FeeRecipient =
// newest registration, FeeRecipients = every distinct recipient seen);
// NotFound only when every relay answered 400 or 404 (a 429 or a
// transport error is not evidence of a missing registration); Unknown
// otherwise. Sequential and uncached: callers only invoke it for vanilla
// candidates, which are rare events.
func LookupRegistration(ctx context.Context, timeout time.Duration, relays []string, pubkey string) Registration {
	client := http.Client{Timeout: timeout}
	reg := Registration{Status: RegistrationUnknown}
	notFound := 0
	var newest uint64
	for _, baseurl := range relays {
		rec, status, err := requestValidatorRegistration(ctx, &client, baseurl, pubkey)
		if err != nil {
			if status == http.StatusBadRequest || status == http.StatusNotFound {
				notFound++
			}
			log.Debug().Err(err).Str("relay", baseurl).Str("pubkey", pubkey).Msg("validator registration lookup failed")
			continue
		}
		log.Debug().Str("relay", baseurl).Str("pubkey", pubkey).Str("feeRecipient", rec.FeeRecipient).Uint64("timestamp", rec.Timestamp).Msg("validator registration found")
		if reg.Status != RegistrationRegistered || rec.Timestamp > newest {
			reg.FeeRecipient = rec.FeeRecipient
			newest = rec.Timestamp
		}
		reg.Status = RegistrationRegistered
		if !reg.matches(rec.FeeRecipient) || len(reg.FeeRecipients) == 0 {
			reg.FeeRecipients = append(reg.FeeRecipients, rec.FeeRecipient)
		}
	}
	if reg.Status != RegistrationRegistered && len(relays) > 0 && notFound == len(relays) {
		reg.Status = RegistrationNotFound
	}
	return reg
}

// requestSlotBidTraces GETs the delivered payloads baseurl recorded for a
// single slot (?slot=N). Unlike the cursor-paged epoch sweep it cannot
// miss a row across a page boundary, and callers run it seconds later,
// after the relay's data API has caught up (measured 4-10 s after slot
// start).
func requestSlotBidTraces(ctx context.Context, client *http.Client, baseurl string, slot phase0.Slot) ([]BidTrace, error) {
	url := fmt.Sprintf("%s/relay/v1/data/bidtraces/proposer_payload_delivered?slot=%d", baseurl, slot)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("relay %s: build request: %w", baseurl, err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("relay %s returned HTTP %d: %s", baseurl, resp.StatusCode, body)
	}
	var traces []BidTrace
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&traces); err != nil {
		return nil, fmt.Errorf("relay %s: decode slot traces: %w", baseurl, err)
	}
	return traces, nil
}

// confirmRelayAbsent re-asks every relay for one slot and returns the
// highest-value delivered trace whose proposer is pubkey (normalised, no
// 0x). This is the last word before any relay-absent verdict: a trace
// found here means a listed relay did deliver the block and the epoch
// sweep simply missed it.
func confirmRelayAbsent(ctx context.Context, timeout time.Duration, relays []string, slot phase0.Slot, pubkey string) (BidTrace, bool) {
	client := http.Client{Timeout: timeout}
	var best BidTrace
	found := false
	for _, baseurl := range relays {
		traces, err := requestSlotBidTraces(ctx, &client, baseurl, slot)
		if err != nil {
			log.Debug().Err(err).Str("relay", baseurl).Uint64("slot", uint64(slot)).Msg("per-slot relay confirmation failed")
			continue
		}
		for _, trace := range traces {
			if trace.Slot != uint64(slot) || !strings.EqualFold(trace.ProposerPubkey, "0x"+pubkey) {
				continue
			}
			if !found || trace.Value > best.Value {
				best = trace
				found = true
			}
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

// confirmRelayAbsentProposals runs confirmRelayAbsent for every
// relay-absent tracked proposal and inserts any trace it finds into
// bestBids, so CheckProposal takes the ordinary hash-compare path instead
// of a vanilla or relay-drift verdict. Cost: len(relays) quick requests
// per relay-absent proposal, a rare event.
func confirmRelayAbsentProposals(
	ctx context.Context,
	timeout time.Duration,
	relays []string,
	proposerDuties map[phase0.Slot]phase0.ValidatorIndex,
	blocks map[phase0.Slot]*electra.SignedBeaconBlock,
	bestBids map[phase0.Slot]BidTrace,
	pubkeyFromIndex map[phase0.ValidatorIndex]string,
) {
	for slot, idx := range relayAbsentProposals(proposerDuties, blocks, bestBids) {
		pubkey, ok := pubkeyFromIndex[idx]
		if !ok {
			continue
		}
		if trace, found := confirmRelayAbsent(ctx, timeout, relays, slot, pubkey); found {
			log.Info().
				Uint64("slot", uint64(slot)).
				Uint64("validator", uint64(idx)).
				Str("blockHash", trace.BlockHash).
				Msg("relay delivery found by per-slot confirmation; the epoch sweep had missed it")
			bestBids[slot] = trace
		}
	}
}

// lookupRelayAbsentRegistrations resolves registrations for exactly the
// tracked duty slots CheckProposal will report as vanilla: the block
// exists, its proposer is the expected validator, no relay bid matched
// the slot, and extra_data is a client default (builder-tagged blocks
// are never vanilla, so their registration is irrelevant). Everything
// else is skipped so the relay sees one request per vanilla candidate,
// never one per validator.
func lookupRelayAbsentRegistrations(
	ctx context.Context,
	timeout time.Duration,
	relays []string,
	proposerDuties map[phase0.Slot]phase0.ValidatorIndex,
	blocks map[phase0.Slot]*electra.SignedBeaconBlock,
	bestBids map[phase0.Slot]BidTrace,
	pubkeyFromIndex map[phase0.ValidatorIndex]string,
) map[phase0.ValidatorIndex]Registration {
	out := make(map[phase0.ValidatorIndex]Registration)
	for slot, idx := range relayAbsentProposals(proposerDuties, blocks, bestBids) {
		block := blocks[slot]
		if block.Message.Body == nil || block.Message.Body.ExecutionPayload == nil ||
			!isClientDefaultExtraData(block.Message.Body.ExecutionPayload.ExtraData) {
			continue
		}
		if _, done := out[idx]; done {
			continue
		}
		pubkey, ok := pubkeyFromIndex[idx]
		if !ok {
			continue
		}
		out[idx] = LookupRegistration(ctx, timeout, relays, "0x"+pubkey)
	}
	return out
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
