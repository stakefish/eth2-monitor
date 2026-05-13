package beaconchain

// Helpers for the offline fixture-backed tests in this package. Fixtures
// live under testdata/ and are refreshed via `make refresh-fixtures`
// (tools/fixturegen/main.go captures them from a real beacon node).
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

//go:embed testdata/beacon/*.json testdata/beacon/*.sse testdata/meta.json
var fixtures embed.FS

// fixtureMeta mirrors tools/fixturegen/main.go's meta struct.
// Intentionally omits any endpoint identifier — see the meta struct
// doc in fixturegen for rationale.
type fixtureMeta struct {
	FinalizedEpoch   uint64 `json:"finalized_epoch"`
	TestEpoch        uint64 `json:"test_epoch"`
	CanonicalSlot    uint64 `json:"canonical_slot"`
	MissedSlot       uint64 `json:"missed_slot,omitempty"`
	HasMissed        bool   `json:"has_missed"`
	CapturedAt       string `json:"captured_at"`
	GeneratorVersion string `json:"generator_version"`
}

// loadMeta reads testdata/meta.json. Tests use this to discover which
// slot/epoch the captured fixtures are anchored to so assertions match
// the real captured values without re-encoding them in test source.
func loadMeta(t *testing.T) fixtureMeta {
	t.Helper()
	b, err := fixtures.ReadFile("testdata/meta.json")
	if err != nil {
		t.Fatalf("read meta.json: %v", err)
	}
	var m fixtureMeta
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal meta.json: %v", err)
	}
	return m
}

// loadFixture reads testdata/beacon/<name> and fails the test if the
// file is missing — `make refresh-fixtures` is the recovery path.
func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := fixtures.ReadFile("testdata/beacon/" + name)
	if err != nil {
		t.Fatalf("read fixture %s: %v (run `make refresh-fixtures`)", name, err)
	}
	return b
}

// fixtureRoute pins a captured response file to the request path it
// represents, plus the status code the upstream returned at capture
// time. Tests pass a slice of these to fixtureServer.
type fixtureRoute struct {
	Path   string
	Status int
	File   string
}

// goEth2ClientStartupProbes is the set of endpoints go-eth2-client's
// http.New() probes on initialisation to verify the upstream is alive
// and to populate its chain-config cache. Each fixtureServer registers
// these automatically so tests don't have to enumerate them per call.
// Captured by tools/fixturegen/main.go.
var goEth2ClientStartupProbes = map[string]string{
	"/eth/v1/node/syncing":            "node_syncing.json",
	"/eth/v1/node/version":            "node_version.json",
	"/eth/v1/config/spec":             "config_spec.json",
	"/eth/v1/config/deposit_contract": "config_deposit_contract.json",
	"/eth/v1/config/fork_schedule":    "config_fork_schedule.json",
	"/eth/v1/beacon/genesis":          "beacon_genesis.json",
}

// fixtureServer stands up an httptest.Server that replays captured
// responses for the given routes plus the standard go-eth2-client
// startup probes (see goEth2ClientStartupProbes). Pattern matching is
// exact (no wildcards). Routes passed in by the caller override probe
// defaults if their paths collide. All other paths return 404 so tests
// fail loudly if a code path issues an unexpected request.
//
// Cleanup is registered with t.Cleanup so callers don't have to defer
// the .Close().
func fixtureServer(t *testing.T, routes []fixtureRoute) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	register := func(path string, status int, file string) {
		mux.HandleFunc(path, func(w http.ResponseWriter, req *http.Request) {
			body := loadFixture(t, file)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_, _ = w.Write(body)
		})
	}
	// Caller routes win — register them last so a colliding probe path
	// (rare but possible) gets the test-specific response.
	overridden := make(map[string]bool, len(routes))
	for _, r := range routes {
		overridden[r.Path] = true
	}
	for path, file := range goEth2ClientStartupProbes {
		if overridden[path] {
			continue
		}
		register(path, http.StatusOK, file)
	}
	for _, r := range routes {
		register(r.Path, r.Status, r.File)
	}
	s := httptest.NewServer(mux)
	t.Cleanup(s.Close)
	return s
}
