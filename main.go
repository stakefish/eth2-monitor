package main

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"
	"sync"
	"time"

	"eth2-monitor/prysmgrpc"
	"eth2-monitor/spec"

	"github.com/gogo/protobuf/types"
	"github.com/pkg/errors"
	ethpb "github.com/prysmaticlabs/ethereumapis/eth/v1alpha1"
	bitfield "github.com/prysmaticlabs/go-bitfield"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/rs/zerolog/pkgerrors"
)

// var log zerolog.Logger

var ValidatorKeys = map[spec.ValidatorIndex]string{
	// Proposed epoch=0 slot=1
	// Missed attestation epoch=0 slot=4
	// Missed attestation epoch=1 slot=48
	// Missed attestation epoch=2 slot=65
	// Orphaned attestation epoch=3 slot=110
	61090: "aed825e4d2b730bf483c235f734a91ffe82f0cef4e3d492d1f3ac2d9bd9b379d04e5f04e334c2532d6a73a91292a9095",
	// Orphaned epoch=0 slot=2
	// Orphaned attestation epoch=4 slot=154
	97715: "8fc9924187b17bc48d75fa225c0c9beee585f73deaed406a6817ab54f9e641a568472d0bcabb30e586da8bb8158d028d",
	// Missed   epoch=3 slot=96
	62723: "a8c80e7388d4c714707ec1ddfb648466d1f5d1de6a95564572384ac0d803bf01bef652d949a2c28c0ab8bbc163320154",
}

func Measure(handler func(), title string, args ...interface{}) {
	start := time.Now()
	handler()
	elapsed := time.Now().Sub(start)
	log.Debug().Msgf("⌛ %s took %v", fmt.Sprintf(title, args...), elapsed)
}

type CachedIndex struct {
	Index spec.ValidatorIndex
	At    time.Time
}
type LocalCache struct {
	Validators map[string]CachedIndex
}

func LoadCache() *LocalCache {
	cache := &LocalCache{
		Validators: make(map[string]CachedIndex),
	}

	fd, err := os.Open("/tmp/stakefish-eth2-monitor-cache.json")
	if err != nil {
		log.Debug().Err(err).Msg("LoadCache: os.Open failed; skip")
		return cache
	}
	defer fd.Close()

	rawCache, err := ioutil.ReadAll(fd)
	if err != nil {
		log.Debug().Err(err).Msg("LoadCache: ioutil.ReadAll failed; skip")
		return cache
	}
	json.Unmarshal(rawCache, cache)

	return cache
}

func SaveCache(cache *LocalCache) {
	rawCache, err := json.MarshalIndent(cache, "", "  ")
	if err != nil {
		log.Debug().Err(err).Msg("SaveCache: json.MarshalIndent failed; skip")
		return
	}

	// TODO: Create a temporary file.
	fd, err := os.OpenFile("/tmp/stakefish-eth2-monitor-cache.json.tmp", os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		log.Debug().Err(err).Msg("SaveCache: os.Open failed; skip")
		return
	}
	defer fd.Close()

	for bytesWritten := 0; bytesWritten < len(rawCache); {
		nWritten, err := fd.Write(rawCache[bytesWritten:])
		if err != nil && err != io.ErrShortWrite {
			log.Debug().Err(err).Msg("SaveCache: fd.Write failed; skip")
			break
		}
		bytesWritten += nWritten
	}
	os.Rename("/tmp/stakefish-eth2-monitor-cache.json.tmp", "/tmp/stakefish-eth2-monitor-cache.json")
}

func IndexPubkeys(ctx context.Context, s *prysmgrpc.Service, pubkeys []string) (map[string]spec.ValidatorIndex, map[spec.ValidatorIndex]string, error) {
	cache := LoadCache()

	conn := ethpb.NewBeaconNodeValidatorClient(s.Connection())

	result := make(map[string]spec.ValidatorIndex)
	reversed := make(map[spec.ValidatorIndex]string)

	for _, pubkey := range pubkeys {
		pubkey := strings.TrimPrefix(pubkey, "0x")
		pubkey = strings.ToLower(pubkey)

		if cachedIndex, ok := cache.Validators[pubkey]; ok && cachedIndex.At.Sub(time.Now()) < 3600*time.Second {
			if cachedIndex.Index != ^spec.ValidatorIndex(0) {
				result[pubkey] = cachedIndex.Index
				reversed[cachedIndex.Index] = pubkey
			}
			continue
		}

		pk, err := hex.DecodeString(pubkey)
		if err != nil {
			return nil, nil, errors.Wrap(err, "call ValidatorIndexhex.DecodeString failed")
		}
		req := &ethpb.ValidatorIndexRequest{
			PublicKey: pk,
		}
		opCtx, cancel := context.WithTimeout(ctx, s.Timeout())
		resp, err := conn.ValidatorIndex(opCtx, req)
		cancel()
		if err != nil {
			// Cache and skip validators with pending indexes.
			cache.Validators[pubkey] = CachedIndex{
				Index: ^spec.ValidatorIndex(0),
				At:    time.Now(),
			}
			continue
			// return nil, nil, errors.Wrap(err, "rpc call ValidatorIndex failed")
		}

		result[pubkey] = resp.Index
		reversed[resp.Index] = pubkey
		cache.Validators[pubkey] = CachedIndex{
			Index: resp.Index,
			At:    time.Now(),
		}

		log.Debug().Msgf("Retrieved index %v for pubkey %s", resp.Index, pubkey)
	}

	SaveCache(cache)

	return result, reversed, nil
}

func SubscribeToDuties(ctx context.Context, s *prysmgrpc.Service, wg *sync.WaitGroup, req *ethpb.DutiesRequest) {
	defer wg.Done()

	conn := ethpb.NewBeaconNodeValidatorClient(s.Connection())

	stream, err := conn.StreamDuties(ctx, req)
	if err != nil {
		panic(err)
	}
	defer stream.CloseSend()

	waitc := make(chan struct{})
	go func() {
		for {
			resp, err := stream.Recv()
			if err == io.EOF {
				waitc <- struct{}{}
				return
			}
			if err != nil {
				panic(err)
				return
			}

			for _, duty := range resp.NextEpochDuties {
				fmt.Printf("Public Key: %v\n", hex.EncodeToString(duty.PublicKey))
				fmt.Printf("Validator Status: %v\n", duty.Status)
				fmt.Printf("Validator Index: %v\n", duty.ValidatorIndex)
				fmt.Printf("Committee Index: %v\n", duty.CommitteeIndex)
				fmt.Printf("Attester Slot: %v\n", duty.AttesterSlot)
				fmt.Printf("Proposer Slots: %v\n", duty.ProposerSlots)
				fmt.Printf("\n")

				s.DutiesChan <- duty
			}
		}
	}()
	<-waitc
}

func SubscribeToChainHead(ctx context.Context, s *prysmgrpc.Service, wg *sync.WaitGroup) {
	defer wg.Done()

	lastChainHead, err := GetChainHead(ctx, s)
	if err != nil {
		panic(err)
	}
	epoch := lastChainHead.JustifiedEpoch
	lastChainHead.JustifiedEpoch -= 8

	for ; lastChainHead.JustifiedEpoch < epoch; lastChainHead.JustifiedEpoch++ {
		s.ChainHeadChan <- &ethpb.ChainHead{JustifiedEpoch: lastChainHead.JustifiedEpoch}
	}

	conn := ethpb.NewBeaconChainClient(s.Connection())

	stream, err := conn.StreamChainHead(ctx, &types.Empty{})
	if err != nil {
		panic(err)
	}
	defer stream.CloseSend()

	waitc := make(chan struct{})
	go func() {
		s.ChainHeadChan <- lastChainHead

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

				s.ChainHeadChan <- lastChainHead
			}
		}
	}()
	<-waitc
}

func GetChainHead(ctx context.Context, s *prysmgrpc.Service) (*ethpb.ChainHead, error) {
	conn := ethpb.NewBeaconChainClient(s.Connection())

	opCtx, cancel := context.WithTimeout(ctx, s.Timeout())
	resp, err := conn.GetChainHead(opCtx, &types.Empty{})
	cancel()
	if err != nil {
		return nil, errors.Wrap(err, "rpc call GetChainHead failed")
	}
	return resp, nil
}

func ListValidatorAssignments(ctx context.Context, s *prysmgrpc.Service, epoch spec.Epoch) error {
	req := &ethpb.ListValidatorAssignmentsRequest{}
	if epoch == 0 {
		req.QueryFilter = &ethpb.ListValidatorAssignmentsRequest_Genesis{Genesis: true}
	} else {
		req.QueryFilter = &ethpb.ListValidatorAssignmentsRequest_Epoch{Epoch: uint64(epoch)}
	}

	fmt.Printf("\n\n## Assignments for epoch %v ##\n\n", epoch)
	conn := ethpb.NewBeaconChainClient(s.Connection())
	for {
		opCtx, cancel := context.WithTimeout(ctx, s.Timeout())
		resp, err := conn.ListValidatorAssignments(opCtx, req)
		if err != nil {
			// TODO: Handle properly.
			panic(err)
		}
		cancel()

		fmt.Printf("Assignments for epoch=%v:\n", resp.Epoch)
		for _, assignment := range resp.Assignments {
			fmt.Printf("validator_index=\t%+v\n", assignment.ValidatorIndex)
			fmt.Printf("committee_index=\t%+v\n", assignment.CommitteeIndex)
			fmt.Printf("attester_slot=\t%+v\n", assignment.AttesterSlot)
			fmt.Printf("proposer_slots=\t%+v\n", assignment.ProposerSlots)
		}

		req.PageToken = resp.NextPageToken
		if req.PageToken == "" {
			break
		}
	}
	return nil
}

func GetIndividualVotes(ctx context.Context, s *prysmgrpc.Service, epoch spec.Epoch, indexes []spec.ValidatorIndex) error {
	req := &ethpb.IndividualVotesRequest{}
	req.Epoch = uint64(epoch)
	req.Indices = []uint64(indexes)

	conn := ethpb.NewBeaconChainClient(s.Connection())
	opCtx, cancel := context.WithTimeout(ctx, s.Timeout())
	resp, err := conn.GetIndividualVotes(opCtx, req)
	if err != nil {
		// TODO: Handle properly.
		panic(err)
	}
	cancel()

	fmt.Printf("\n\n## Individual votes for epoch %v ##\n\n", epoch)
	for _, vote := range resp.IndividualVotes {
		fmt.Printf("validator_index=\t%+v\n", vote.ValidatorIndex)
		fmt.Printf("epoch=\t%+v\n", vote.Epoch)
		fmt.Printf("inclusion_slot=\t%+v\n", vote.InclusionSlot)
		fmt.Printf("inclusion_distance=\t%+v\n", vote.InclusionDistance)
	}

	return nil
}

type BeaconCommittees map[spec.CommitteeIndex][]spec.ValidatorIndex

func ListBeaconCommittees(ctx context.Context, s *prysmgrpc.Service, epoch spec.Epoch) (map[spec.Slot]BeaconCommittees, error) {
	req := &ethpb.ListCommitteesRequest{}
	// if epoch == 0 {
	// 	req.QueryFilter = &ethpb.ListCommitteesRequest_Genesis{Genesis: true}
	// } else {
	req.QueryFilter = &ethpb.ListCommitteesRequest_Epoch{Epoch: uint64(epoch)}
	// }

	conn := ethpb.NewBeaconChainClient(s.Connection())

	opCtx, cancel := context.WithTimeout(ctx, s.Timeout())
	resp, err := conn.ListBeaconCommittees(opCtx, req)
	if err != nil {
		return nil, err
	}
	cancel()

	result := make(map[spec.Slot]BeaconCommittees)

	// fmt.Printf("\n\n## Beacon committees for epoch %v ##\n\n", resp.Epoch)
	for slot, committees := range resp.Committees {
		// fmt.Printf("Slot:\t%+v\n", slot)
		// fmt.Printf("Committees:\n")
		if _, ok := result[slot]; !ok {
			result[slot] = make(BeaconCommittees)
		}

		for committeeIndex, items := range committees.Committees {
			// fmt.Printf("\tcommitteeIndex=%v\n", committeeIndex)
			// fmt.Printf("\tvalidators=%+v\n", items.ValidatorIndices)
			result[slot][spec.CommitteeIndex(committeeIndex)] = items.ValidatorIndices
		}
	}
	// fmt.Printf("Active validator count:\t%+v\n", resp.ActiveValidatorCount)

	return result, nil
}

type Block struct {
	Proposer     spec.ValidatorIndex
	Attestations []*BlockAttestation
}

type BlockAttestation struct {
	Slot            spec.Slot
	InclusionSlot   spec.Slot
	CommitteeIndex  spec.CommitteeIndex
	AggregationBits []byte
}

func ListBlocks(ctx context.Context, s *prysmgrpc.Service, epoch spec.Epoch) (map[spec.Slot]*Block, error) {
	req := &ethpb.ListBlocksRequest{
		QueryFilter: &ethpb.ListBlocksRequest_Epoch{Epoch: epoch},
	}
	conn := ethpb.NewBeaconChainClient(s.Connection())
	opCtx, cancel := context.WithTimeout(ctx, s.Timeout())
	resp, err := conn.ListBlocks(opCtx, req)
	if err != nil {
		return nil, err
	}
	cancel()

	result := make(map[spec.Slot]*Block)

	// fmt.Printf("\n\n## Blocks for epoch %v ##\n\n", epoch)
	for {
		for _, blockContainer := range resp.BlockContainers {
			block := blockContainer.Block.Block
			// fmt.Printf("Block Slot: %v\n", block.Slot)
			// fmt.Printf("Block Proposer: %v\n", block.ProposerIndex)

			result[block.Slot] = &Block{
				Proposer: block.ProposerIndex,
			}

			body := block.Body
			// fmt.Printf("Attestations: %v\n", len(body.Attestations))
			for _, att := range body.Attestations {
				// fmt.Printf("\tSlot: %v\n", att.Data.Slot)
				// fmt.Printf("\tCommittee Index: %v\n", att.Data.CommitteeIndex)
				// fmt.Printf("Aggregation Bits: %v\n", bitfield.Bitlist(att.AggregationBits).BitIndices())

				result[block.Slot].Attestations = append(result[block.Slot].Attestations, &BlockAttestation{
					AggregationBits: att.AggregationBits,
					CommitteeIndex:  att.Data.CommitteeIndex,
					Slot:            att.Data.Slot,
					InclusionSlot:   block.Slot,
				})
			}
		}

		if req.PageToken == "" {
			break
		}
	}

	return result, nil
}

func ListIndexedAttestations(ctx context.Context, s *prysmgrpc.Service, epoch spec.Epoch) error {
	req := &ethpb.ListIndexedAttestationsRequest{
		QueryFilter: &ethpb.ListIndexedAttestationsRequest_Epoch{Epoch: epoch},
	}

	conn := ethpb.NewBeaconChainClient(s.Connection())
	fmt.Printf("\n\n## Indexed Attestations for epoch %v ##\n\n", epoch)
	for {
		opCtx, cancel := context.WithTimeout(ctx, s.Timeout())
		resp, err := conn.ListIndexedAttestations(opCtx, req)
		if err != nil {
			// TODO: Handle properly.
			panic(err)
		}
		cancel()

		for _, att := range resp.IndexedAttestations {
			fmt.Printf("Attesting indexes: %+v\n", att.AttestingIndices)
			fmt.Printf("Slot: %v\n", att.Data.Slot)
			fmt.Printf("Committee Index: %v\n", att.Data.CommitteeIndex)
		}

		req.PageToken = resp.NextPageToken
		if req.PageToken == "" {
			break
		}
	}

	return nil
}

type BlockAttestationStatus struct {
	IsAttested bool
	IsPrinted  bool
}

func MonitorAttestationsAndProposals(ctx context.Context, s *prysmgrpc.Service) (*ethpb.ChainHead, error) {
	var plainKeys []string
	file, err := os.Open("pubkeys.txt")
	Must(err)
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		plainKeys = append(plainKeys, scanner.Text())
	}

	err = scanner.Err()
	Must(err)

	_, reversedIndexes, err := IndexPubkeys(ctx, s, plainKeys)
	Must(err)

	var validatorIndexes []spec.ValidatorIndex
	for index := range reversedIndexes {
		validatorIndexes = append(validatorIndexes, index)
	}

	// duties := make(map[spec.ValidatorIndex][]*ethpb.DutiesResponse_Duty)

	committees := make(map[spec.Slot]BeaconCommittees)
	blocks := make(map[spec.Slot]*Block)

	includedAttestations := make(map[spec.Epoch]map[spec.ValidatorIndex]*BlockAttestation)
	attestedEpoches := make(map[spec.Epoch]map[spec.ValidatorIndex]*BlockAttestationStatus)

	for {
		select {
		case chainHead := <-s.ChainHeadChan:
			log.Debug().Msgf("New justified epoch %v and slot %v",
				chainHead.JustifiedEpoch, chainHead.JustifiedSlot)

			// On every chain head update we
			// * Retrieve new committees for the new epoch,
			// * Mark scheduled attestations as attested,
			// * Check attestations if some of them too old.
			epoch := chainHead.JustifiedEpoch

			var err error
			var epochCommittees map[spec.Slot]BeaconCommittees
			var epochBlocks map[spec.Slot]*Block

			Measure(func() {
				epochCommittees, err = ListBeaconCommittees(ctx, s, spec.Epoch(epoch))
				Must(err)
			}, "ListBeaconCommittees(epoch=%v)", epoch)
			Measure(func() {
				epochBlocks, err = ListBlocks(ctx, s, spec.Epoch(epoch))
				Must(err)
			}, "ListBlocks(epoch=%v)", epoch)

			for slot, v := range epochCommittees {
				committees[slot] = v
			}
			for slot, v := range epochBlocks {
				blocks[slot] = v
			}

			for slot, epochCommittees := range committees {
				var epoch spec.Epoch = slot / spec.SLOTS_PER_EPOCH
				if _, ok := attestedEpoches[epoch]; !ok {
					attestedEpoches[epoch] = make(map[spec.ValidatorIndex]*BlockAttestationStatus)
				}

				for _, committee := range epochCommittees {
					for _, index := range committee {
						if _, ok := attestedEpoches[epoch][index]; !ok {
							attestedEpoches[epoch][index] = &BlockAttestationStatus{IsAttested: false, IsPrinted: false}
						}
					}
				}
			}

			for blockSlot, block := range blocks {
				_ = blockSlot
				// fmt.Printf("Checking block at slot %v\n", blockSlot)
				for _, attestation := range block.Attestations {
					bits := bitfield.Bitlist(attestation.AggregationBits)

					var epoch spec.Epoch = attestation.Slot / spec.SLOTS_PER_EPOCH
					committee := committees[attestation.Slot][attestation.CommitteeIndex]
					// fmt.Printf("Checking committee %v: %+v\n", attestation.CommitteeIndex, committee)
					for i, index := range committee {
						if _, ok := includedAttestations[epoch]; !ok {
							includedAttestations[epoch] = make(map[spec.ValidatorIndex]*BlockAttestation)
						}
						if bits.BitAt(uint64(i)) {
							// fmt.Printf("Validator %v attested (blockSlot=%v, slot=%v, committee=%v)\n", index, blockSlot, attestation.Slot, attestation.CommitteeIndex)
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
				if epoch <= chainHead.JustifiedEpoch-2 {
					epochsToGarbage = append(epochsToGarbage, epoch)
				}

				for index, attStatus := range validators {
					if _, ok := reversedIndexes[index]; !ok {
						continue
					}

					if epoch <= chainHead.JustifiedEpoch-2 && !attStatus.IsAttested && !attStatus.IsPrinted {
						log.Warn().Msgf("❌ Validator %v did not attest epoch %v", index, epoch)
						attStatus.IsPrinted = true
					} else if att := includedAttestations[epoch][index]; att != nil && !attStatus.IsPrinted {
						distance := att.InclusionSlot - att.Slot - 1
						var emoji string
						if distance > 1 {
							emoji = "⚠️"
							log.Warn().Msgf("%s Validator %v attested epoch %v slot %v at slot %v, distance is %v",
								emoji, index, epoch, att.Slot, att.InclusionSlot, distance)
						} else {
							emoji = "✅"
							log.Info().Msgf("%s Validator %v attested epoch %v slot %v at slot %v, distance is %v",
								emoji, index, epoch, att.Slot, att.InclusionSlot, distance)
						}
						attStatus.IsPrinted = true
					}
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

			///
			/*
				epoch := chainHead.HeadEpoch - 1

				req := &ethpb.ListIndexedAttestationsRequest{}
				if epoch == 0 {
					req.QueryFilter = &ethpb.ListIndexedAttestationsRequest_GenesisEpoch{GenesisEpoch: true}
				} else {
					req.QueryFilter = &ethpb.ListIndexedAttestationsRequest_Epoch{Epoch: epoch}
				}
				conn := ethpb.NewBeaconChainClient(s.Connection())
				for {
					opCtx, cancel := context.WithTimeout(ctx, s.Timeout())
					resp, err := conn.ListIndexedAttestations(opCtx, req)
					if err != nil {
						// TODO: Handle properly.
						panic(err)
					}
					cancel()

					// fmt.Printf("Current duties: %+v\n\n", duties)

					for i := range resp.IndexedAttestations {
						att := resp.IndexedAttestations[i]
						go func() { s.IndexedAttestationsChan <- att }()
					}

					req.PageToken = resp.NextPageToken
					if req.PageToken == "" {
						break
					}
				}
			*/
			/*
				case att := <-s.IndexedAttestationsChan:
					// fmt.Printf("Received attestation: slot=%v commitee=%v indices=%v\n\n", att.Data.Slot, att.Data.CommitteeIndex, att.AttestingIndices)

					indicies := make(map[spec.ValidatorIndex]int)
					for i, index := range att.AttestingIndices {
						indicies[spec.ValidatorIndex(index)] = i
					}

				Done:
					for index, validatorDuties := range duties {
						if _, ok := indicies[index]; ok {
							for i, duty := range validatorDuties {
								if duty.CommitteeIndex == att.Data.CommitteeIndex &&
									duty.AttesterSlot <= att.Data.Slot {
									fmt.Printf("Attestation is included: distance=%v\n", att.Data.Slot-duty.AttesterSlot)
									fmt.Printf("Attestation: %+v\n", att)
									fmt.Printf("Duty: %+v\n", duty)
									fmt.Printf("\n")
									copy(duties[index][i:], duties[index][i+1:])
									duties[index] = duties[index][:len(duties[index])-1]
									break Done
								}
							}
						}
					}

				case block := <-s.SignedBlocksChan:
					fmt.Printf("Received block: %+v\n\n", block)
					// for _, attestation := range block.Block.Body.Attestations {

					// }
				case duty := <-s.DutiesChan:
					// var pk [48]byte
					// copy(pk[:], duty.PublicKey[:])
					index := spec.ValidatorIndex(duty.ValidatorIndex)
					duties[index] = append(duties[index], duty)
			*/
		}
	}
}

func Must(err error) {
	if err != nil {
		log.Fatal().Err(err).Stack().Msg("Fatal error occurred")
		panic(err)
	}
}

func init() {
	zerolog.ErrorStackMarshaler = pkgerrors.MarshalStack
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
}

func main() {
	var plainKeys []string
	file, err := os.Open("pubkeys.txt")
	Must(err)
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		plainKeys = append(plainKeys, scanner.Text())
	}

	err = scanner.Err()
	Must(err)

	////

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s, err := prysmgrpc.New(ctx,
		prysmgrpc.WithAddress("localhost:4000"),
		prysmgrpc.WithLogLevel(zerolog.WarnLevel))
	Must(err)

	/*
		lastChainHead, err := GetChainHead(ctx, s)
		if err != nil {
			panic(err)
		}
	*/

	// conn := ethpb.NewBeaconNodeValidatorClient(s.Connection())

	// pubkey, err := hex.DecodeString("afac0d79ea9b3d9063920e3f2eca02444488e558b41e51c22f49c172bd4f19d91a8af0ff6f5f2a942a080d5af6ea2da4")
	// if err != nil {
	// 	panic(err)
	// }

	// pubKeys := [][]byte{
	// 	pubkey,
	// }

	// req := &ethpb.DutiesRequest{
	// 	// Epoch:      uint64(epoch),
	// 	PublicKeys: pubKeys,
	// }

	// {
	// 	opCtx, cancel := context.WithTimeout(ctx, s.Timeout())
	// 	resp, err := conn.GetDuties(opCtx, req)
	// 	defer cancel()
	// 	if err != nil {
	// 		panic(err)
	// 	}
	// 	fmt.Printf("resp=%+v\n", resp)
	// }
	// // if err != nil {
	// // 	return nil, errors.Wrap(err, "call to GetDuties() failed")
	// // }

	/*
		_, reversedIndexes, err := IndexPubkeys(ctx, s, plainKeys)
		Must(err)

		var validatorIndexes []spec.ValidatorIndex
		for index := range reversedIndexes {
			validatorIndexes = append(validatorIndexes, index)
		}

		committees := make(map[spec.Slot]BeaconCommittees)
		blocks := make(map[spec.Slot]*Block)
		for epoch := lastChainHead.JustifiedEpoch; epoch >= lastChainHead.JustifiedEpoch-4; epoch-- {
			var err error
			var epochCommittees map[spec.Slot]BeaconCommittees
			var epochBlocks map[spec.Slot]*Block

			if epoch != lastChainHead.JustifiedEpoch {
				Measure(func() {
					epochCommittees, err = ListBeaconCommittees(ctx, s, spec.Epoch(epoch))
					Must(err)
				}, "ListBeaconCommittees(epoch=%v)", epoch)

				for k, v := range epochCommittees {
					committees[k] = v
				}
			}

			Measure(func() {
				epochBlocks, err = ListBlocks(ctx, s, spec.Epoch(epoch))
				Must(err)
			}, "ListBlocks(epoch=%v)", epoch)

			for k, v := range epochBlocks {
				blocks[k] = v
			}
		}

		includedAttestations := make(map[spec.ValidatorIndex]map[spec.Epoch]*BlockAttestation)
		attestedEpoches := make(map[spec.Epoch]map[spec.ValidatorIndex]bool)

		for slot, epochCommittees := range committees {
			var epoch spec.Epoch = slot / spec.SLOTS_PER_EPOCH
			if _, ok := attestedEpoches[epoch]; !ok {
				attestedEpoches[epoch] = make(map[spec.ValidatorIndex]bool)
			}

			for _, committee := range epochCommittees {
				for _, index := range committee {
					attestedEpoches[epoch][index] = false
				}
			}
		}

		for blockSlot, block := range blocks {
			_ = blockSlot
			// fmt.Printf("Checking block at slot %v\n", blockSlot)
			for _, attestation := range block.Attestations {
				bits := bitfield.Bitlist(attestation.AggregationBits)

				var epoch spec.Epoch = attestation.Slot / spec.SLOTS_PER_EPOCH
				committee := committees[attestation.Slot][attestation.CommitteeIndex]
				// fmt.Printf("Checking committee %v: %+v\n", attestation.CommitteeIndex, committee)
				for i, index := range committee {
					if _, ok := includedAttestations[index]; !ok {
						includedAttestations[index] = make(map[spec.Epoch]*BlockAttestation)
					}
					if bits.BitAt(uint64(i)) {
						// fmt.Printf("Validator %v attested (blockSlot=%v, slot=%v, committee=%v)\n", index, blockSlot, attestation.Slot, attestation.CommitteeIndex)
						if att := includedAttestations[index][epoch]; att == nil || att.InclusionSlot > attestation.InclusionSlot {
							includedAttestations[index][epoch] = attestation
							attestedEpoches[epoch][index] = true
						}
					}
				}
			}
		}

		for epoch, validators := range attestedEpoches {
			for index, attStatus := range validators {
				if _, ok := reversedIndexes[index]; !ok {
					continue
				}

				if !attStatus.IsAttested && !attStatus.IsPrinted {
					log.Info().Msgf("❌ Validator %v did not attest epoch %v", index, epoch)
					attStatus.IsPrinted = true
				} else if att := includedAttestations[index][epoch]; att != nil && !attStatus.IsPrinted {
					log.Info().Msgf("✅ Validator %v attested epoch %v slot %v at slot %v, distance is %v", index, epoch, att.Slot, att.InclusionSlot, att.InclusionSlot-att.Slot-1)
					attStatus.IsPrinted = true
				}
			}
		}
	*/

	// for i := 0; i <= 5; i++ {
	// 	Measure("ListBeaconCommittees", func() {
	// 		ListBeaconCommittees(ctx, s, spec.Epoch(i))
	// 	})
	// }
	// for i := 0; i <= 5; i++ {
	// 	Measure("ListBlocks", func() {
	// 		ListBlocks(ctx, s, spec.Epoch(i))
	// 	})
	// }
	// for i := 0; i <= 5; i++ {
	// 	Measure("ListIndexedAttestations", func() {
	// 		ListIndexedAttestations(ctx, s, spec.Epoch(i))
	// 	})
	// }
	// for i := 0; i <= 20; i++ {
	// 	Measure("GetIndividualVotes", func() {
	// 		GetIndividualVotes(ctx, s, spec.Epoch(i), validatorIndexes)
	// 	})
	// }
	// for i := 138; i <= 143; i++ {
	// 	Measure("GetIndividualVotes", func() {
	// 		GetIndividualVotes(ctx, s, spec.Epoch(i), validatorIndexes)
	// 	})
	// }

	// Measure("ListBeaconCommittees", func() {
	// 	ListBeaconCommittees(ctx, s, spec.Epoch(lastChainHead.HeadEpoch-10))
	// })
	// Measure("GetIndividualVotes", func() {
	// 	GetIndividualVotes(ctx, s, spec.Epoch(lastChainHead.HeadEpoch-10), []spec.ValidatorIndex{109733})
	// })

	var wg sync.WaitGroup

	wg.Add(1)
	// go SubscribeToDuties(ctx, s, &wg, req)
	go SubscribeToChainHead(ctx, s, &wg)

	go MonitorAttestationsAndProposals(ctx, s)

	wg.Wait()
}
