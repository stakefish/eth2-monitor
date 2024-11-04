package spec

func EpochLowestSlot(epoch Epoch) Slot {
	return epoch * SLOTS_PER_EPOCH
}

func EpochHighestSlot(epoch Epoch) Slot {
	return ((epoch + 1) * SLOTS_PER_EPOCH) - 1
}
