package monitoring

// Helpers for fixture-backed integration tests in this package. There
// are two fixture sources:
//
//   - In-package: testdata/mev/*_bidtraces.json — captured from public
//     MEV relays, embedded via embed.FS.
//   - Cross-package: ../beaconchain/testdata/beacon/*.json — captured
//     beacon API responses, used by monitoring integration tests that
//     stand up a real BeaconChain against an httptest fake server.
//     Loaded via os.ReadFile with a relative path; `go test` runs
//     each test binary with cwd set to the package directory, so the
//     path resolves deterministically.
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
		t.Fatalf("read MEV fixture %s: %v (run `make refresh-fixtures`)", name, err)
	}
	return b
}

// beaconFixtureMeta mirrors the fixtureMeta struct in
// internal/beaconchain/testdata_test.go. Duplicated rather than
// imported because Go test files cannot be cross-package dependencies.
type beaconFixtureMeta struct {
	FinalizedEpoch   uint64 `json:"finalized_epoch"`
	TestEpoch        uint64 `json:"test_epoch"`
	CanonicalSlot    uint64 `json:"canonical_slot"`
	MissedSlot       uint64 `json:"missed_slot,omitempty"`
	HasMissed        bool   `json:"has_missed"`
	CapturedAt       string `json:"captured_at"`
	GeneratorVersion string `json:"generator_version"`
}

const beaconTestdataRel = "../beaconchain/testdata"

func loadBeaconMeta(t *testing.T) beaconFixtureMeta {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(beaconTestdataRel, "meta.json"))
	if err != nil {
		t.Fatalf("read beacon meta.json: %v (run `make refresh-fixtures`)", err)
	}
	var m beaconFixtureMeta
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal beacon meta.json: %v", err)
	}
	return m
}

func loadBeaconFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(beaconTestdataRel, "beacon", name))
	if err != nil {
		t.Fatalf("read beacon fixture %s: %v (run `make refresh-fixtures`)", name, err)
	}
	return b
}

// beaconStartupProbes lists the standard go-eth2-client startup probe
// endpoints captured in beaconchain/testdata. fixtureServer registers
// these automatically so monitoring tests don't have to enumerate them.
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
	Handler http.HandlerFunc // optional override; if set, File/Status are ignored for this route
}

// fixtureServer stands up an httptest.Server replaying captured
// responses for the supplied routes plus all standard go-eth2-client
// startup probes. Caller-supplied routes win on path collision.
//
// Pass a route with Handler (and empty File/Status) to script flaky
// behaviour (transient 5xx, slow-then-OK, ctx-cancel test) — the route's
// path resolves to that handler instead of a static fixture.
func fixtureServer(t *testing.T, routes []fixtureRoute) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	register := func(path string, status int, file string) {
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			body := loadBeaconFixture(t, file)
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
		register(path, http.StatusOK, file)
	}
	for _, r := range routes {
		if r.Handler != nil {
			mux.HandleFunc(r.Path, r.Handler)
			continue
		}
		register(r.Path, r.Status, r.File)
	}
	s := httptest.NewServer(mux)
	t.Cleanup(s.Close)
	return s
}
