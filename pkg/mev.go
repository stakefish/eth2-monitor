package pkg

import (
	"context"
	"encoding/json"
	"eth2-monitor/spec"
	"fmt"
	"iter"
	"math/rand/v2"
	"net/http"
	"sync"
	"time"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/rs/zerolog/log"
	"golang.org/x/sync/errgroup"
)

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
func requestBidTracesPage(client *http.Client, baseurl string, slot uint64, limit uint64) ([]BidTrace, error) {
	var payloads []BidTrace

	url := fmt.Sprintf("%s/relay/v1/data/bidtraces/proposer_payload_delivered?cursor=%d&limit=%d", baseurl, slot, limit)
	log.Debug().Msgf("Calling %v", url)

	resp, err := client.Get(url)

	if err != nil {
		log.Error().Msgf("Error retrieving delivered payloads: %v", err)
		return nil, err
	}

	defer resp.Body.Close()

	err = json.NewDecoder(resp.Body).Decode(&payloads)

	if err != nil {
		log.Error().Msgf("Error decoding delivered payloads: %v", err)
		return nil, err
	}

	// Bid traces should be returned sorted by the slot number in a decreasing order.
	for i, _ := range payloads {
		if i == 0 {
			continue
		}
		if payloads[i].Slot >= payloads[i-1].Slot {
			return nil, fmt.Errorf("Relay returned bid traces in a wrong order: %s", baseurl)
		}
	}

	return payloads, nil
}

func requestRelayEpochBidTraces(timeout time.Duration, baseurl string, epoch spec.Epoch) ([]BidTrace, error) {
	var bidtraces []BidTrace

	client := http.Client{
		Timeout: timeout,
	}

	epochHighestSlot := ((epoch + 1) * spec.SLOTS_PER_EPOCH) - 1
	epochLowestSlot := epoch * spec.SLOTS_PER_EPOCH

	slot := epochHighestSlot
	for {
		page, err := requestBidTracesPage(&client, baseurl, slot, spec.SLOTS_PER_EPOCH)
		if err != nil {
			return nil, err
		}
		if len(page) == 0 {
			return nil, fmt.Errorf("Relay returned no bid traces for epoch %v: %s", epoch, baseurl)
		}

		for _, trace := range page {
			// We're only interested in bid traces from the requested epoch
			if trace.Slot >= epochLowestSlot && trace.Slot <= epochHighestSlot {
				bidtraces = append(bidtraces, trace)
			}
		}

		if page[len(page)-1].Slot <= epochLowestSlot {
			break
		}

		slot -= spec.SLOTS_PER_EPOCH
	}

	return bidtraces, nil
}

func exptBackoff(base time.Duration, maxExponent uint) iter.Seq[time.Duration] {
	baseMillis := uint(base / time.Millisecond)
	return func(yield func(time.Duration) bool) {
		step := base
		for {
			for _ = range maxExponent + 1 {
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

func requestEpochBidTraces(ctx context.Context, timeout time.Duration, relays []string, epoch uint64) (map[string][]BidTrace, error) {
	var mu sync.Mutex
	result := make(map[string][]BidTrace)

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var g errgroup.Group
	for _, baseurl := range relays {
		g.Go(func() error {
			var traces []BidTrace
			for delay := range exptBackoff(time.Duration(500)*time.Millisecond, 4) {
				var err error
				traces, err = requestRelayEpochBidTraces(timeout, baseurl, epoch)
				if err == nil {
					break
				}
				log.Error().Msgf("MEV relay request failed: %v", err)
				select {
				case <-ctx.Done():
					return fmt.Errorf("timeout")
				default:
					time.Sleep(delay)
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

func ListBestBids(ctx context.Context, timeout time.Duration, relays []string, epoch uint64, validatorPubkeyFromIndex map[phase0.ValidatorIndex]string, proposals map[spec.Slot]phase0.ValidatorIndex) (map[spec.Slot]BidTrace, error) {
	bestBids := make(map[spec.Slot]BidTrace)

	perRelayBidTraces, err := requestEpochBidTraces(ctx, timeout, relays, epoch)

	// Only keep bid traces whose proposer_pubkey matches any of the tracked validators
	for _, traces := range perRelayBidTraces {
		for _, trace := range traces {
			proposerValidatorIndex, ok := proposals[trace.Slot]
			if !ok {
				continue
			}
			proposerPubkey := validatorPubkeyFromIndex[proposerValidatorIndex]
			if trace.ProposerPubkey != fmt.Sprintf("0x%s", proposerPubkey) {
				continue
			}
			if _, ok := bestBids[trace.Slot]; ok {
				if trace.Value > bestBids[trace.Slot].Value {
					bestBids[trace.Slot] = trace
				}
			} else {
				bestBids[trace.Slot] = trace
			}
		}
	}

	return bestBids, err
}
