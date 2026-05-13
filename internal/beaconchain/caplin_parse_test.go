package beaconchain

// Direct-parse unit test for the captured block_canonical.json fixture.
// Pulls the .data field out of the beacon API envelope and unmarshals it
// into electra.SignedBeaconBlock — the same Go type Fulu uses (Fulu
// reuses the Electra block structure in go-eth2-client).
//
// Catches schema drift the moment fixtures are refreshed: if a future
// fork or a different beacon client (Caplin, Lighthouse, Prysm) emits a
// shape go-eth2-client can't decode, this test fails before any
// integration test does. It also acts as a regression guard for the
// stakefish go-eth2-client fork — its Caplin-tolerant UnmarshalJSON
// methods on phase0.Slot/Epoch/Gwei/ValidatorIndex and electra
// DepositRequest are exactly what makes this raw-bytes parse succeed.
// If the replace directive is ever dropped, this test fails first.

import (
	"encoding/json"
	"testing"

	"github.com/attestantio/go-eth2-client/spec/electra"
)

func TestParseCapturedBlock_ShapeMatchesElectra(t *testing.T) {
	meta := loadMeta(t, "happy_path")
	body := loadFixture(t, "happy_path", "block_canonical.json")

	// Beacon API envelope: {"version":"fulu","data":{...},"execution_optimistic":bool,"finalized":bool}
	var envelope struct {
		Version string                        `json:"version"`
		Data    *electra.SignedBeaconBlock    `json:"data"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		t.Fatalf("unmarshal block_canonical.json into electra.SignedBeaconBlock: %v\n"+
			"This means the captured response shape no longer matches what "+
			"go-eth2-client expects. Either the upstream beacon changed, the "+
			"fork changed (Fulu->Glamsterdam?), or the stakefish go-eth2-client "+
			"fork's Caplin tolerance no longer covers a new unquoted-uint64 "+
			"field. Inspect the fixture and align.", err)
	}
	if envelope.Data == nil {
		t.Fatal("envelope.data was nil after unmarshal — fixture is missing the .data field")
	}
	if envelope.Version == "" {
		t.Error("envelope.version was empty — beacon API used to set this; check upstream")
	}

	// Sanity-check a handful of fields against meta.json. Anchoring the
	// assertion to meta (not a hard-coded slot) means the test stays
	// green across `make refresh-fixtures` runs.
	got := uint64(envelope.Data.Message.Slot)
	if got != meta.CanonicalSlot {
		t.Errorf("parsed slot = %d, meta.CanonicalSlot = %d — fixture/meta mismatch", got, meta.CanonicalSlot)
	}
	if envelope.Data.Message.Body == nil {
		t.Fatal("Body is nil — go-eth2-client failed to decode the inner BeaconBlockBody")
	}
	if envelope.Data.Message.Body.ExecutionPayload == nil {
		t.Error("ExecutionPayload is nil — Fulu/Electra blocks always carry an execution payload, even empty ones")
	}
}
