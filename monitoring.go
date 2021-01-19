package main

import (
	"bufio"
	"context"
	"encoding/hex"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"eth2-monitor/prysmgrpc"
	"eth2-monitor/spec"

	"github.com/pkg/errors"
	bitfield "github.com/prysmaticlabs/go-bitfield"

	ethpb "github.com/prysmaticlabs/ethereumapis/eth/v1alpha1"
	"github.com/rs/zerolog/log"
)

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

func ListProposers(ctx context.Context, s *prysmgrpc.Service, epoch spec.Epoch, validators map[string]spec.ValidatorIndex, epochCommittees map[spec.Slot]BeaconCommittees) (map[spec.Slot]spec.ValidatorIndex, error) {
	activeIndexes := make(map[spec.ValidatorIndex]interface{})
	for _, committees := range epochCommittees {
		for _, indexes := range committees {
			for _, index := range indexes {
				activeIndexes[index] = nil
			}
		}
	}

	var indexes []spec.ValidatorIndex
	for _, index := range validators {
		if _, ok := activeIndexes[index]; ok {
			indexes = append(indexes, index)
		}
	}

	conn := ethpb.NewBeaconChainClient(s.Connection())

	chunkSize := 250
	result := make(map[spec.Slot]spec.ValidatorIndex)
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
				if len(assignment.ProposerSlots) > 0 {
					result[assignment.ProposerSlots[0]] = assignment.ValidatorIndex
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

func SubscribeToEpochs(ctx context.Context, s *prysmgrpc.Service, wg *sync.WaitGroup) {
	defer wg.Done()

	lastChainHead, err := s.GetChainHead()
	Must(err)

	if len(opts.ReplayEpoch) > 0 {
		for _, epoch := range opts.ReplayEpoch {
			epochsChan <- epoch
		}
		close(epochsChan)
		return
	}
	if opts.SinceEpoch != nil {
		for epoch := *opts.SinceEpoch; epoch < lastChainHead.JustifiedEpoch; epoch++ {
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
		epochsChan <- lastChainHead.JustifiedEpoch

		for {
			chainHead, err := stream.Recv()
			if err == io.EOF {
				waitc <- struct{}{}
				return
			}
			if err != nil {
				// TODO: Handle err gracefully.
				panic(err)
				return
			}

			if chainHead.JustifiedEpoch > lastChainHead.JustifiedEpoch {
				lastChainHead = chainHead

				epochsChan <- lastChainHead.JustifiedEpoch
			}
		}
	}()
	<-waitc
}

type BeaconCommittees map[spec.CommitteeIndex][]spec.ValidatorIndex

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

type AttestationLoggingStatus struct {
	IsAttested bool
	IsPrinted  bool
}

func MonitorAttestationsAndProposals(ctx context.Context, s *prysmgrpc.Service, wg *sync.WaitGroup) (*ethpb.ChainHead, error) {
	defer wg.Done()

	plainKeys := opts.Pubkeys
	for _, fname := range opts.Positional.PubkeysFiles {
		file, err := os.Open(fname)
		Must(err)
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			plainKeys = append(plainKeys, scanner.Text())
		}

		err = scanner.Err()
		Must(err)
	}

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

	for {
		select {
		case justifiedEpoch := <-epochsChan:
			log.Info().Msgf("New justified epoch %v", justifiedEpoch)

			// On every chain head update we
			// * Retrieve new committees for the new epoch,
			// * Mark scheduled attestations as attested,
			// * Check attestations if some of them too old.
			epoch := justifiedEpoch

			var err error
			var epochCommittees map[spec.Slot]BeaconCommittees
			var epochBlocks map[spec.Slot]*ChainBlock
			var proposals map[spec.Slot]spec.ValidatorIndex

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

			ProcessSlashings(ctx, epochBlocks)

			for slot, v := range epochCommittees {
				committees[slot] = v
			}
			for slot, v := range epochBlocks {
				blocks[slot] = v
			}

			for slot, epochCommittees := range committees {
				var epoch spec.Epoch = slot / spec.SLOTS_PER_EPOCH
				if _, ok := attestedEpoches[epoch]; !ok {
					attestedEpoches[epoch] = make(map[spec.ValidatorIndex]*AttestationLoggingStatus)
				}

				for _, committee := range epochCommittees {
					for _, index := range committee {
						if _, ok := attestedEpoches[epoch][index]; !ok {
							attestedEpoches[epoch][index] = &AttestationLoggingStatus{
								IsAttested: false,
								IsPrinted:  false,
							}
						}
					}
				}
			}

			for _, block := range blocks {
				for _, attestation := range block.Attestations {
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

			var epochsToGarbage []spec.Epoch
			for epoch, validators := range attestedEpoches {
				if epoch <= justifiedEpoch-2 {
					epochsToGarbage = append(epochsToGarbage, epoch)
				}

				for index, attStatus := range validators {
					if _, ok := reversedIndexes[index]; !ok {
						continue
					}

					if epoch <= justifiedEpoch-2 && !attStatus.IsAttested && !attStatus.IsPrinted {
						log.Warn().Msgf("❌ 🧾 Validator %v did not attest epoch %v", index, epoch)
						attStatus.IsPrinted = true
					} else if att := includedAttestations[epoch][index]; att != nil && !attStatus.IsPrinted {
						var absDistance spec.Slot = att.InclusionSlot - att.Slot - 1
						var optimalDistance spec.Slot = absDistance
						if absDistance > opts.DistanceTolerance {
							for e := att.Slot + 1; e < att.InclusionSlot; e++ {
								if _, ok := blocks[e]; !ok {
									optimalDistance--
								}
							}
						}
						if optimalDistance > opts.DistanceTolerance {
							log.Warn().Msgf("⚠️ 🧾 Validator %v attested epoch %v slot %v at slot %v, opt distance is %v, abs distance is %v",
								index, epoch, att.Slot, att.InclusionSlot, optimalDistance, absDistance)
						} else if opts.PrintSuccessful {
							log.Info().Msgf("✅ 🧾 Validator %v attested epoch %v slot %v at slot %v, opt distance is %v, abs distance is %v",
								index, epoch, att.Slot, att.InclusionSlot, optimalDistance, absDistance)
						}
						attStatus.IsPrinted = true
					}
				}
			}

			for slot, index := range proposals {
				if _, ok := blocks[slot]; !ok {
					log.Warn().Msgf("❌ 🧱 Validator %v missed block at epoch %v and slot %v",
						index, justifiedEpoch, slot)
				}
			}

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
}
