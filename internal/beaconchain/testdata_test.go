package beaconchain

// Helpers for the offline fixture-backed tests in this package. Fixtures
// are organized into scenario subdirectories under testdata/beacon/:
//
//   _shared/             - go-eth2-client startup probes + SSE excerpt,
//                          invariant across scenarios on a given chain.
//   happy_path/          - canonical block + duties + committees at a
//                          stable test epoch (no missed slots).
//   missed_proposal/     - same as happy_path PLUS a 404 envelope for
//                          a real missed slot inside the test epoch.
//   empty_block/         - block_canonical is structurally empty (no EL
//                          txns, no blobs, no post-Pectra exec requests).
//   delayed_attestation/ - block_canonical carries attestations with
//                          raw distance > 3.
//   cross_epoch_attestation/ - block_canonical (epoch E+1) carries
//                          attestations from epoch E; block_prev.json is
//                          a canonical block from epoch E.
//
// Each scenario directory has its own meta.json with scenario-specific
// anchor fields. Fixtures are refreshed via `make refresh-fixtures`
// (tools/fixturegen/main.go --scenario=<name>).
//
// The fixtures are embedded into the test binary so tests run from any
// working directory and so `go test ./...` picks them up without an
// implicit `cd` requirement.

import (
	"embed"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// all: prefix is required so the embed includes _shared/ (Go normally
// excludes path components beginning with '_' or '.').
//
//go:embed all:testdata/beacon
var fixtures embed.FS

// defaultChain is the chain the fixtures committed under
// testdata/beacon/<defaultChain>/ were captured from. Hoodi staging is
// the only chain captured today; future chains land at sibling
// subdirectories (testdata/beacon/sepolia/, testdata/beacon/mainnet/,
// etc.) and a future change would promote this to a parameter.
const defaultChain = "hoodi"

// fixtureMeta is the union of fields any scenario may write. Each
// scenario only fills what it needs; omitempty keeps reader code from
// asserting on absent values. Mirrors tools/fixturegen/main.go's meta.
type fixtureMeta struct {
	Scenario          string `json:"scenario"`
	Chain             string `json:"chain,omitempty"`
	FinalizedEpoch    uint64 `json:"finalized_epoch,omitempty"`
	TestEpoch         uint64 `json:"test_epoch,omitempty"`
	CanonicalSlot     uint64 `json:"canonical_slot,omitempty"`
	MissedSlot        uint64 `json:"missed_slot,omitempty"`
	HasMissed         bool   `json:"has_missed,omitempty"`
	EmptyBlockSlot    uint64 `json:"empty_block_slot,omitempty"`
	DelayedBlockSlot  uint64 `json:"delayed_block_slot,omitempty"`
	MaxDistance       uint64 `json:"max_distance,omitempty"`
	PrevEpoch         uint64   `json:"prev_epoch,omitempty"`
	PrevCanonicalSlot uint64   `json:"prev_canonical_slot,omitempty"`
	CapturedSlots     []uint64 `json:"captured_slots,omitempty"`
	CapturedAt        string   `json:"captured_at"`
	GeneratorVersion  string   `json:"generator_version"`
}

// loadMeta reads testdata/beacon/<chain>/<scenario>/meta.json. Tests
// use this to discover which slot/epoch the scenario's fixtures are
// anchored to so assertions match the captured values without
// re-encoding them.
func loadMeta(t *testing.T, scenario string) fixtureMeta {
	t.Helper()
	path := "testdata/beacon/" + defaultChain + "/" + scenario + "/meta.json"
	b, err := fixtures.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v (run `make refresh-scenario SCENARIO=%s`)", path, err, scenario)
	}
	var m fixtureMeta
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal %s: %v", path, err)
	}
	return m
}

// loadFixture reads testdata/beacon/<chain>/<scenario>/<name> and
// fails the test if the file is missing.
func loadFixture(t *testing.T, scenario, name string) []byte {
	t.Helper()
	path := "testdata/beacon/" + defaultChain + "/" + scenario + "/" + name
	b, err := fixtures.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v (run `make refresh-scenario SCENARIO=%s`)", path, err, scenario)
	}
	return b
}

// loadSharedFixture reads testdata/beacon/<chain>/_shared/<name>.
// Convenience for tests that compose their own server mux around the
// startup probes that go-eth2-client's http.New() expects.
func loadSharedFixture(t *testing.T, name string) []byte {
	t.Helper()
	return loadFixture(t, "_shared", name)
}

// fixtureRoute pins a captured response file to the request path it
// represents, plus the status code the upstream returned at capture
// time. Tests pass a slice of these to fixtureServer. Set Handler to
// override the static replay for flaky-behaviour scenarios.
type fixtureRoute struct {
	Path    string
	Status  int
	File    string
	Handler http.HandlerFunc
}

// goEth2ClientStartupProbes is the set of endpoints go-eth2-client's
// http.New() probes on initialisation. Files live under _shared/ since
// they're invariant across scenarios on a given chain.
var goEth2ClientStartupProbes = map[string]string{
	"/eth/v1/node/syncing":            "node_syncing.json",
	"/eth/v1/node/version":            "node_version.json",
	"/eth/v1/config/spec":             "config_spec.json",
	"/eth/v1/config/deposit_contract": "config_deposit_contract.json",
	"/eth/v1/config/fork_schedule":    "config_fork_schedule.json",
	"/eth/v1/beacon/genesis":          "beacon_genesis.json",
}

// fixtureServer stands up an httptest.Server that replays captured
// responses for the given scenario's routes plus the standard
// go-eth2-client startup probes (always from _shared/). Pattern
// matching is exact (no wildcards). Routes passed in by the caller
// override probe defaults if their paths collide. All other paths
// return 404 so tests fail loudly if a code path issues an unexpected
// request.
//
// Cleanup is registered with t.Cleanup so callers don't have to defer
// the .Close().
func fixtureServer(t *testing.T, scenario string, routes []fixtureRoute) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	registerShared := func(path string, status int, file string) {
		mux.HandleFunc(path, func(w http.ResponseWriter, req *http.Request) {
			body := loadSharedFixture(t, file)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_, _ = w.Write(body)
		})
	}
	registerScenario := func(path string, status int, file string) {
		mux.HandleFunc(path, func(w http.ResponseWriter, req *http.Request) {
			body := loadFixture(t, scenario, file)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_, _ = w.Write(body)
		})
	}
	overridden := make(map[string]bool, len(routes))
	for _, r := range routes {
		overridden[r.Path] = true
	}
	for path, file := range goEth2ClientStartupProbes {
		if overridden[path] {
			continue
		}
		registerShared(path, http.StatusOK, file)
	}
	for _, r := range routes {
		if r.Handler != nil {
			mux.HandleFunc(r.Path, r.Handler)
			continue
		}
		registerScenario(r.Path, r.Status, r.File)
	}
	s := httptest.NewServer(mux)
	t.Cleanup(s.Close)
	return s
}
