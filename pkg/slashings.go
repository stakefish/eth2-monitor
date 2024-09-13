package pkg

import (
	"context"
	"eth2-monitor/beaconchain"
	"eth2-monitor/spec"
	"fmt"

	"eth2-monitor/cmd/opts"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/rs/zerolog/log"
)

func ethFromGwei(gwei int64) float32 {
	return float32(gwei) * float32(1e-9)
}

func ReportSlashing(ctx context.Context, beacon *beaconchain.BeaconChain, prefix string, reason string, slot spec.Slot, slasher spec.ValidatorIndex, slashee spec.ValidatorIndex) {
	var epoch = slot / spec.SLOTS_PER_EPOCH
	var balanceDiff *int64
	var err error

	rewardStr := ""

	if opts.Slashings.ShowSlashingReward {
		rewardStr = "; reward is unknown"

		Measure(func() {
			nextEpochSlot := (epoch + 1) * spec.SLOTS_PER_EPOCH
			balanceDiff, err = beacon.GetValidatorBalanceDiff(ctx, phase0.ValidatorIndex(slasher), phase0.Slot(slot), phase0.Slot(nextEpochSlot))
		}, "ListValidatorBalance(epoch=%v, slasher=%v)", epoch, slasher)
		if err != nil {
			log.Error().Err(err).Msg("ListValidatorBalance failed while determining slasher's reward")
		} else {
			rewardStr = fmt.Sprintf("; next epoch reward is %.03f ETH", ethFromGwei(*balanceDiff))
		}
	}

	Report("%s Slashing occurred! Validator %v %s and slashed by %v at slot %v%s",
		prefix, slashee, reason, slasher, slot, rewardStr)
	TweetSlashing(reason, slot, slasher, slashee)
}

func ProcessSlashings(ctx context.Context, beacon *beaconchain.BeaconChain, blocks map[spec.Slot][]*ChainBlock) {
	for slot, chainBlocks := range blocks {
		for _, chainBlock := range chainBlocks {
			slasher := chainBlock.ProposerIndex
			proposerSlashings := chainBlock.ProposerSlashings
			attesterSlashings := chainBlock.AttesterSlashings

			for _, proposerSlashing := range proposerSlashings {
				slashee := spec.ValidatorIndex(proposerSlashing.SignedHeader1.Message.ProposerIndex)

				ReportSlashing(ctx, beacon, "🚫 🧱", "proposed two conflicting blocks", slot, slasher, slashee)
			}

			for _, attesterSlashing := range attesterSlashings {
				var slashee spec.ValidatorIndex
				attestation1Validators := make(map[spec.ValidatorIndex]interface{})
				for _, index := range attesterSlashing.Attestation1.AttestingIndices {
					attestation1Validators[index] = nil
				}

				for _, index := range attesterSlashing.Attestation2.AttestingIndices {
					if _, ok := attestation1Validators[index]; ok {
						slashee = index
						break
					}
				}

				ReportSlashing(ctx, beacon, "🚫 🧾", "attested two conflicting blocks", slot, slasher, slashee)
			}
		}
	}
}
