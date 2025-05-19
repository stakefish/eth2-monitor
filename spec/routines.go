package spec

import "github.com/attestantio/go-eth2-client/spec/phase0"

func EpochLowestSlot(epoch phase0.Epoch) phase0.Slot {
	return phase0.Slot(epoch * SLOTS_PER_EPOCH)
}

func EpochHighestSlot(epoch phase0.Epoch) phase0.Slot {
	return phase0.Slot(((epoch + 1) * SLOTS_PER_EPOCH) - 1)
}

func EpochFromSlot(slot phase0.Slot) phase0.Epoch {
	return phase0.Epoch(slot / SLOTS_PER_EPOCH)
}
