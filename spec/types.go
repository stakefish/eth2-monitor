package spec

// Slot is a slot number.
type Slot = uint64

// Epoch is an epoch number.
type Epoch = uint64

// CommitteeIndex is a committee index at a slot.
type CommitteeIndex = uint64

// ValidatorIndex is a validator registry index.
type ValidatorIndex = uint64

// Gwei is an amount in Gwei.
type Gwei = uint64

// Root is a merkle root.
type Root = [32]byte

// Version is a fork version.
type Version = [4]byte

// DomainType is a domain type.
type DomainType = [4]byte

// ForkDigest is a digest of fork data.
type ForkDigest = [4]byte

// Domain is a signature domain.
type Domain = [32]byte

// BLSPubKey is a BLS12-381 public key.
type BLSPubKey = [48]byte
