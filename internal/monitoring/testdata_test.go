package monitoring

// Helpers for fixture-backed integration tests in this package. There
// are two fixture sources:
//
//   - In-package: testdata/mev/*_bidtraces.json — captured from public
//     MEV relays, embedded via embed.FS.
//   - Cross-package: ../beaconchain/testdata/beacon/<scenario>/*.json
//     and .../beacon/_shared/*.json — captured beacon API responses,
//     organized into scenario subdirectories. Used by monitoring
//     integration tests that stand up a real BeaconChain against an
//     httptest fake server. Loaded via os.ReadFile with a relative
//     path; `go test` runs each test binary with cwd set to the
//     package directory, so the path resolves deterministically.
//
// `make refresh-fixtures` regenerates both sets via tools/fixturegen.

import (
	"embed"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

//go:embed testdata/mev/*.json
var monitoringFixtures embed.FS

// loadMEVFixture reads testdata/mev/<name>_bidtraces.json (raw HTTP
// response from a relay's proposer_payload_delivered endpoint).
func loadMEVFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := monitoringFixtures.ReadFile("testdata/mev/" + name + "_bidtraces.json")
	if err != nil {
		t.Fatalf("read MEV fixture %s: %v (run `make refresh-scenario SCENARIO=mev`)", name, err)
	}
	return b
}

// defaultBeaconChain is the chain the cross-package beacon fixtures
// were captured against. Mirrors `defaultChain` in
// internal/beaconchain/testdata_test.go; the two must agree for the
// monitoring tests' file lookups to match what the beaconchain tests
// see via embed.FS.
const defaultBeaconChain = "hoodi"

// beaconFixtureMeta mirrors the fixtureMeta struct in
// internal/beaconchain/testdata_test.go. Duplicated rather than
// imported because Go test files cannot be cross-package dependencies.
type beaconFixtureMeta struct {
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

const beaconTestdataRel = "../beaconchain/testdata"

// loadBeaconMeta reads ../beaconchain/testdata/beacon/<chain>/<scenario>/meta.json.
func loadBeaconMeta(t *testing.T, scenario string) beaconFixtureMeta {
	t.Helper()
	path := filepath.Join(beaconTestdataRel, "beacon", defaultBeaconChain, scenario, "meta.json")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v (run `make refresh-scenario SCENARIO=%s`)", path, err, scenario)
	}
	var m beaconFixtureMeta
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal %s: %v", path, err)
	}
	return m
}

// loadBeaconFixture reads ../beaconchain/testdata/beacon/<chain>/<scenario>/<name>.
func loadBeaconFixture(t *testing.T, scenario, name string) []byte {
	t.Helper()
	path := filepath.Join(beaconTestdataRel, "beacon", defaultBeaconChain, scenario, name)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v (run `make refresh-scenario SCENARIO=%s`)", path, err, scenario)
	}
	return b
}

// loadSharedBeaconFixture reads ../beaconchain/testdata/beacon/<chain>/_shared/<name>.
// Convenience for tests that compose their own server mux around the
// go-eth2-client startup probes.
func loadSharedBeaconFixture(t *testing.T, name string) []byte {
	t.Helper()
	return loadBeaconFixture(t, "_shared", name)
}

// beaconStartupProbes lists the standard go-eth2-client startup probe
// endpoints captured under _shared/. fixtureServer registers these
// automatically so tests don't have to enumerate them.
// Mirrors goEth2ClientStartupProbes in beaconchain/testdata_test.go.
var beaconStartupProbes = map[string]string{
	"/eth/v1/node/syncing":            "node_syncing.json",
	"/eth/v1/node/version":            "node_version.json",
	"/eth/v1/config/spec":             "config_spec.json",
	"/eth/v1/config/deposit_contract": "config_deposit_contract.json",
	"/eth/v1/config/fork_schedule":    "config_fork_schedule.json",
	"/eth/v1/beacon/genesis":          "beacon_genesis.json",
}

// fixtureRoute pins a captured response file to a request path.
type fixtureRoute struct {
	Path    string
	Status  int
	File    string
	Handler http.HandlerFunc // optional override; if set, File/Status are ignored
}

// fixtureServer stands up an httptest.Server replaying captured
// responses for the supplied scenario's routes plus the standard
// go-eth2-client startup probes (always from _shared/). Caller-supplied
// routes win on path collision.
//
// Pass a route with Handler (and empty File/Status) to script flaky
// behaviour (transient 5xx, slow-then-OK, ctx-cancel test) — the route's
// path resolves to that handler instead of a static fixture.
func fixtureServer(t *testing.T, scenario string, routes []fixtureRoute) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	registerShared := func(path string, status int, file string) {
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			body := loadSharedBeaconFixture(t, file)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_, _ = w.Write(body)
		})
	}
	registerScenario := func(path string, status int, file string) {
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			body := loadBeaconFixture(t, scenario, file)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_, _ = w.Write(body)
		})
	}
	overridden := make(map[string]bool, len(routes))
	for _, r := range routes {
		overridden[r.Path] = true
	}
	for path, file := range beaconStartupProbes {
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
