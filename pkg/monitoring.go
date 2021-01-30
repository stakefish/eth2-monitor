package pkg

import (
	"bufio"
	"context"
	"encoding/hex"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"eth2-monitor/cmd/opts"
	"eth2-monitor/prysmgrpc"
	"eth2-monitor/spec"

	"github.com/pkg/errors"
	bitfield "github.com/prysmaticlabs/go-bitfield"

	ethpb "github.com/prysmaticlabs/ethereumapis/eth/v1alpha1"
	"github.com/rs/zerolog/log"
)

// IndexPubkeys transforms validator public keys into their indexes.
// It returns direct and reversed mapping.
func IndexPubkeys(ctx context.Context, s *prysmgrpc.Service, pubkeys []string) (map[string]spec.ValidatorIndex, map[spec.ValidatorIndex]string, error) {
	cache := LoadCache()

	result := make(map[string]spec.ValidatorIndex)
	reversed := make(map[spec.ValidatorIndex]string)

	for _, pubkey := range pubkeys {
		pubkey := strings.TrimPrefix(pubkey, "0x")
		pubkey = strings.ToLower(pubkey)

		if cachedIndex, ok := cache.Validators[pubkey]; ok {
			if cachedIndex.Index != ^spec.ValidatorIndex(0) {
				result[pubkey] = cachedIndex.Index
				reversed[cachedIndex.Index] = pubkey
				continue
			}
			if cachedIndex.At.Sub(time.Now()) < 8*time.Hour {
				continue
			}
		}

		binPubKey, err := hex.DecodeString(pubkey)
		if err != nil {
			return nil, nil, errors.Wrap(err, "call ValidatorIndexhex.DecodeString failed")
		}
		index, err := s.GetValidatorIndex(binPubKey)
		if err != nil {
			// Cache and skip validators with pending indexes.
			cache.Validators[pubkey] = CachedIndex{
				Index: ^spec.ValidatorIndex(0),
				At:    time.Now(),
			}
			// Ignore pending indexes.
			continue
		}

		result[pubkey] = index
		reversed[index] = pubkey
		cache.Validators[pubkey] = CachedIndex{
			Index: index,
			At:    time.Now(),
		}

		log.Debug().Msgf("Retrieved index %v for pubkey %s", index, pubkey)
	}

	SaveCache(cache)

	return result, reversed, nil
}

// ListProposers returns block proposers scheduled for epoch.
// To improve performance, it has to narrow the set of validators for which it checks duties.
func ListProposers(ctx context.Context, s *prysmgrpc.Service, epoch spec.Epoch, validators map[string]spec.ValidatorIndex, epochCommittees map[spec.Slot]BeaconCommittees) (map[spec.Slot]spec.ValidatorIndex, error) {
	// Filter out non-activated validator indexes and use only active ones.
	var indexes []spec.ValidatorIndex
	activeIndexes := make(map[spec.ValidatorIndex]interface{})
	for _, committees := range epochCommittees {
		for _, indexes := range committees {
			for _, index := range indexes {
				activeIndexes[index] = nil
			}
		}
	}
	for _, index := range validators {
		if _, ok := activeIndexes[index]; ok {
			indexes = append(indexes, index)
		}
	}

	// Make ListValidatorAssignments RPC calls to iterate through assignments and aggregate
	// block proposers into result map.
	chunkSize := 250
	result := make(map[spec.Slot]spec.ValidatorIndex)
	conn := ethpb.NewBeaconChainClient(s.Connection())
	for i := 0; i < len(indexes); i += chunkSize {
		end := i + chunkSize
		if end > len(indexes) {
			end = len(indexes)
		}
		req := &ethpb.ListValidatorAssignmentsRequest{
			QueryFilter: &ethpb.ListValidatorAssignmentsRequest_Epoch{Epoch: uint64(epoch)},
			Indices:     indexes[i:end],
		}

		for {
			opCtx, cancel := context.WithTimeout(ctx, s.Timeout())
			resp, err := conn.ListValidatorAssignments(opCtx, req)
			if err != nil {
				return nil, errors.Wrap(err, "rpc call ListValidatorAssignments failed")
			}
			cancel()

			for _, assignment := range resp.Assignments {
				for _, proposerSlot := range assignment.ProposerSlots {
					result[proposerSlot] = assignment.ValidatorIndex
				}
			}

			req.PageToken = resp.NextPageToken
			if req.PageToken == "" {
				break
			}
		}
	}

	return result, nil
}

type BeaconCommittees map[spec.CommitteeIndex][]spec.ValidatorIndex

// ListBeaconCommittees lists committees for a specific epoch.
func ListBeaconCommittees(ctx context.Context, s *prysmgrpc.Service, epoch spec.Epoch) (map[spec.Slot]BeaconCommittees, error) {
	req := &ethpb.ListCommitteesRequest{
		QueryFilter: &ethpb.ListCommitteesRequest_Epoch{Epoch: uint64(epoch)},
	}

	conn := ethpb.NewBeaconChainClient(s.Connection())

	opCtx, cancel := context.WithTimeout(ctx, s.Timeout())
	resp, err := conn.ListBeaconCommittees(opCtx, req)
	if err != nil {
		return nil, errors.Wrap(err, "rpc call ListBeaconCommittees failed")
	}
	cancel()

	result := make(map[spec.Slot]BeaconCommittees)

	for slot, committees := range resp.Committees {
		if _, ok := result[slot]; !ok {
			result[slot] = make(BeaconCommittees)
		}

		for committeeIndex, items := range committees.Committees {
			result[slot][spec.CommitteeIndex(committeeIndex)] = items.ValidatorIndices
		}
	}

	return result, nil
}

type ChainBlock struct {
	BlockContainer *ethpb.BeaconBlockContainer
	Attestations   []*ChainAttestation
}

type ChainAttestation struct {
	Slot            spec.Slot
	InclusionSlot   spec.Slot
	CommitteeIndex  spec.CommitteeIndex
	AggregationBits []byte
}

// ListBlocks lists blocks and attestations for a specific epoch.
func ListBlocks(ctx context.Context, s *prysmgrpc.Service, epoch spec.Epoch) (map[spec.Slot]*ChainBlock, error) {
	req := &ethpb.ListBlocksRequest{
		QueryFilter: &ethpb.ListBlocksRequest_Epoch{Epoch: epoch},
	}
	conn := ethpb.NewBeaconChainClient(s.Connection())
	opCtx, cancel := context.WithTimeout(ctx, s.Timeout())
	resp, err := conn.ListBlocks(opCtx, req)
	if err != nil {
		return nil, errors.Wrap(err, "rpc call ListBlocks failed")
	}
	cancel()

	result := make(map[spec.Slot]*ChainBlock)

	for {
		for _, blockContainer := range resp.BlockContainers {
			blockContainer := blockContainer
			block := blockContainer.Block.Block
			body := block.Body

			result[block.Slot] = &ChainBlock{
				BlockContainer: blockContainer,
			}

			for _, att := range body.Attestations {
				result[block.Slot].Attestations = append(result[block.Slot].Attestations, &ChainAttestation{
					AggregationBits: att.AggregationBits,
					CommitteeIndex:  att.Data.CommitteeIndex,
					Slot:            att.Data.Slot,
					InclusionSlot:   block.Slot,
				})
			}
		}

		req.PageToken = resp.NextPageToken
		if req.PageToken == "" {
			break
		}
	}

	return result, nil
}

// SubscribeToEpochs subscribes to changings of the beacon chain head.
// Note, if --replay-epoch or --since-epoch options passed, SubscribeToEpochs will not
// listen to real-time changes.
func SubscribeToEpochs(ctx context.Context, s *prysmgrpc.Service, useJustified bool, wg *sync.WaitGroup) {
	defer wg.Done()

	getEpoch := func(chainHead *ethpb.ChainHead) spec.Epoch {
		if useJustified {
			return chainHead.JustifiedEpoch
		}
		return chainHead.HeadEpoch
	}

	lastChainHead, err := s.GetChainHead()
	Must(err)

	if len(opts.Monitor.ReplayEpoch) > 0 {
		for _, epoch := range opts.Monitor.ReplayEpoch {
			epochsChan <- spec.Epoch(epoch)
		}
		close(epochsChan)
		return
	}
	if opts.Monitor.SinceEpoch != ^uint64(0) {
		for epoch := opts.Monitor.SinceEpoch; epoch < getEpoch(lastChainHead); epoch++ {
			epochsChan <- epoch
		}
		close(epochsChan)
		return
	}

	stream, err := s.StreamChainHead()
	if err != nil {
		log.Error().Err(err).Msg("StreamChainHead failed")
		return
	}
	defer stream.CloseSend()

	waitc := make(chan struct{})
	go func() {
		epochsChan <- getEpoch(lastChainHead)

		for {
			chainHead, err := stream.Recv()
			if err == io.EOF {
				waitc <- struct{}{}
				return
			}
			if err != nil {
				close(epochsChan)
				Must(err)
			}

			if getEpoch(chainHead) > getEpoch(lastChainHead) {
				lastChainHead = chainHead

				epochsChan <- getEpoch(lastChainHead)
			}
		}
	}()
	<-waitc
}

type AttestationLoggingStatus struct {
	IsAttested bool
	IsPrinted  bool
	Slot       spec.Slot
}

const (
	// Attestation is assumed to be missed if it was not included within two consequent epochs.
	missedAttestationDistance = 2
)

func LoadKeys(pubkeysFiles []string) ([]string, error) {
	plainKeys := opts.Monitor.Pubkeys[:]
	for _, fname := range pubkeysFiles {
		file, err := os.Open(fname)
		if err != nil {
			return nil, err
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			plainKeys = append(plainKeys, scanner.Text())
		}

		err = scanner.Err()
		if err != nil {
			return nil, err
		}
	}

	return plainKeys, nil
}

// MonitorAttestationsAndProposals listens to the beacon chain head changes and checks new blocks and attestations.
func MonitorAttestationsAndProposals(ctx context.Context, s *prysmgrpc.Service, plainKeys []string, wg *sync.WaitGroup) {
	defer wg.Done()

	directIndexes, reversedIndexes, err := IndexPubkeys(ctx, s, plainKeys)
	Must(err)

	var validatorIndexes []spec.ValidatorIndex
	for index := range reversedIndexes {
		validatorIndexes = append(validatorIndexes, index)
	}

	committees := make(map[spec.Slot]BeaconCommittees)
	blocks := make(map[spec.Slot]*ChainBlock)

	includedAttestations := make(map[spec.Epoch]map[spec.ValidatorIndex]*ChainAttestation)
	attestedEpoches := make(map[spec.Epoch]map[spec.ValidatorIndex]*AttestationLoggingStatus)

	for justifiedEpoch := range epochsChan {
		// On every chain head update we:
		// * Retrieve new committees for the new epoch,
		// * Mark scheduled attestations as attested,
		// * Check attestations if some of them too old.
		log.Info().Msgf("New justified epoch %v", justifiedEpoch)

		var err error
		var epochCommittees map[spec.Slot]BeaconCommittees
		var epochBlocks map[spec.Slot]*ChainBlock
		var proposals map[spec.Slot]spec.ValidatorIndex

		epoch := justifiedEpoch
		Measure(func() {
			epochCommittees, err = ListBeaconCommittees(ctx, s, spec.Epoch(epoch))
			Must(err)
		}, "ListBeaconCommittees(epoch=%v)", epoch)
		Measure(func() {
			epochBlocks, err = ListBlocks(ctx, s, spec.Epoch(epoch))
			Must(err)
		}, "ListBlocks(epoch=%v)", epoch)
		Measure(func() {
			proposals, err = ListProposers(ctx, s, spec.Epoch(epoch), directIndexes, epochCommittees)
			Must(err)
		}, "ListProposers(epoch=%v)", epoch)

		for slot, v := range epochCommittees {
			committees[slot] = v
		}
		for slot, v := range epochBlocks {
			blocks[slot] = v
		}

		attestingValidatorsCount := 0
		for slot, slotCommittees := range epochCommittees {
			var epoch spec.Epoch = slot / spec.SLOTS_PER_EPOCH
			if _, ok := attestedEpoches[epoch]; !ok {
				attestedEpoches[epoch] = make(map[spec.ValidatorIndex]*AttestationLoggingStatus)
			}

			for _, committee := range slotCommittees {
				for _, index := range committee {
					if _, ok := reversedIndexes[index]; ok {
						attestingValidatorsCount++
					}

					if _, ok := attestedEpoches[epoch][index]; !ok {
						attestedEpoches[epoch][index] = &AttestationLoggingStatus{
							IsAttested: false,
							IsPrinted:  false,
							Slot:       slot,
						}
					}
				}
			}
		}

		log.Info().Msgf("Number of attesting validators is %v", attestingValidatorsCount)

		for _, block := range blocks {
			for _, attestation := range block.Attestations {
				// Every included attestation contains aggregation bits, i.e. a list of validators
				// from which attestations were aggregated.
				// We check if a validator was included in this list and, if not, such validator
				// may have missed the attestation.
				// The attestation of such validator might be aggregated and be included in later blocks.
				bits := bitfield.Bitlist(attestation.AggregationBits)

				var epoch spec.Epoch = attestation.Slot / spec.SLOTS_PER_EPOCH
				committee := committees[attestation.Slot][attestation.CommitteeIndex]
				for i, index := range committee {
					if _, ok := includedAttestations[epoch]; !ok {
						includedAttestations[epoch] = make(map[spec.ValidatorIndex]*ChainAttestation)
					}
					if bits.BitAt(uint64(i)) {
						if att := includedAttestations[epoch][index]; att == nil || att.InclusionSlot > attestation.InclusionSlot {
							includedAttestations[epoch][index] = attestation
							attestedEpoches[epoch][index].IsAttested = true
						}
					}
				}
			}
		}

		// Find timed-out attestations and missed blocks. Then, report it.
		var epochsToGarbage []spec.Epoch
		for epoch, validators := range attestedEpoches {
			if epoch <= justifiedEpoch-missedAttestationDistance {
				epochsToGarbage = append(epochsToGarbage, epoch)
			}

			for index, attStatus := range validators {
				if _, ok := reversedIndexes[index]; !ok {
					continue
				}

				if epoch <= justifiedEpoch-missedAttestationDistance && !attStatus.IsAttested && !attStatus.IsPrinted {
					Report("❌ 🧾 Validator %v did not attest epoch %v slot %v", index, epoch, attStatus.Slot)
					attStatus.IsPrinted = true
				} else if att := includedAttestations[epoch][index]; att != nil && !attStatus.IsPrinted {
					var absDistance spec.Slot = att.InclusionSlot - att.Slot
					var optimalDistance spec.Slot = absDistance - 1
					for e := att.Slot + 1; e < att.InclusionSlot; e++ {
						if _, ok := blocks[e]; !ok {
							optimalDistance--
						}
					}
					distanceToCompare := optimalDistance
					if opts.Monitor.UseAbsoluteDistance {
						distanceToCompare = absDistance
					}
					if distanceToCompare > opts.Monitor.DistanceTolerance {
						Report("⚠️ 🧾 Validator %v attested epoch %v slot %v at slot %v, opt distance is %v, abs distance is %v",
							index, epoch, att.Slot, att.InclusionSlot, optimalDistance, absDistance)
					} else if opts.Monitor.PrintSuccessful {
						Report("✅ 🧾 Validator %v attested epoch %v slot %v at slot %v, opt distance is %v, abs distance is %v",
							index, epoch, att.Slot, att.InclusionSlot, optimalDistance, absDistance)
					}
					attStatus.IsPrinted = true
				}
			}
		}

		for slot, index := range proposals {
			if _, ok := blocks[slot]; !ok {
				Report("❌ 🧱 Validator %v missed block at epoch %v and slot %v",
					index, justifiedEpoch, slot)
			}
		}

		// Garbage collect unnessary epochs and blocks.
		for _, epoch := range epochsToGarbage {
			delete(attestedEpoches, epoch)
			delete(includedAttestations, epoch)
			for slot := epoch * spec.SLOTS_PER_EPOCH; slot < (epoch+1)*spec.SLOTS_PER_EPOCH; slot++ {
				delete(blocks, slot)
				delete(committees, slot)
			}
		}
	}
}

// MonitorSlashings listens to the beacon chain head changes and checks for slashings.
func MonitorSlashings(ctx context.Context, s *prysmgrpc.Service, wg *sync.WaitGroup) {
	defer wg.Done()

	for justifiedEpoch := range epochsChan {
		log.Info().Msgf("New justified epoch %v", justifiedEpoch)

		var err error
		var blocks map[spec.Slot]*ChainBlock

		epoch := justifiedEpoch
		Measure(func() {
			blocks, err = ListBlocks(ctx, s, spec.Epoch(epoch))
			Must(err)
		}, "ListBlocks(epoch=%v)", epoch)

		ProcessSlashings(ctx, blocks)
	}
}

// MonitorMaintenanceWindows monitors possible gaps between block proposals for possible maintenance windows.
func MonitorMaintenanceWindows(ctx context.Context, s *prysmgrpc.Service, plainKeys []string, wg *sync.WaitGroup) {
	directIndexes, reversedIndexes, err := IndexPubkeys(ctx, s, plainKeys)
	Must(err)

	validatorIndexes := make(map[spec.ValidatorIndex]interface{})
	for index := range reversedIndexes {
		validatorIndexes[index] = nil
	}

	genesis, err := s.GetGenesis()
	Must(err)
	genesisAt := time.Unix(genesis.GenesisTime.GetSeconds(), int64(genesis.GenesisTime.GetNanos()%1e9))

	log.Info().Msgf("Genesis happened at %v", genesisAt)

	for epoch := range epochsChan {
		log.Info().Msgf("Using epoch %v", epoch)

		var proposals map[spec.Slot]spec.ValidatorIndex
		var committees map[spec.Slot]BeaconCommittees
		Measure(func() {
			committees, err = ListBeaconCommittees(ctx, s, spec.Epoch(epoch))
			Must(err)
		}, "ListBeaconCommittees(epoch=%v)", epoch)
		Measure(func() {
			proposals, err = ListProposers(ctx, s, spec.Epoch(epoch), directIndexes, committees)
			Must(err)
		}, "ListProposers(epoch=%v)", epoch)

		closestSlot := (epoch + 1) * spec.SLOTS_PER_EPOCH
		for slot, index := range proposals {
			if _, ok := validatorIndexes[index]; ok {
				if slot < closestSlot {
					closestSlot = slot
				}

				now := time.Now()
				slotAt := genesisAt.Add(time.Duration(int64(slot*spec.SECONDS_PER_SLOT)) * time.Second)
				if now.After(slotAt) {
					gap := now.Sub(slotAt)
					Report("🚧 🧱 Validator %v proposed a block at epoch %v slot %v %v ago at %v",
						index, epoch, slot, gap, slotAt)
				} else {
					gap := slotAt.Sub(now)
					Report("🚧 🧱 Validator %v proposes a block at epoch %v slot %v in %v at %v",
						index, epoch, slot, gap, slotAt)
				}
			}
		}

		now := time.Now()
		slotAt := genesisAt.Add(time.Duration(int64(closestSlot*spec.SECONDS_PER_SLOT)) * time.Second)
		if now.After(slotAt) {
			now = genesisAt.Add(time.Duration(int64(epoch*spec.SLOTS_PER_EPOCH*spec.SECONDS_PER_SLOT)) * time.Second)
			Report("🚧 🪟 Retrospectively at %v, epoch %v had a maintenance window ending in %v at %v",
				now, epoch, slotAt.Sub(now), slotAt)
		} else {
			Report("🚧 🪟 Epoch %v has a maintenance window ending in %v at %v",
				epoch, slotAt.Sub(now), slotAt)
		}
	}
}
