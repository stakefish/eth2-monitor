package pkg

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/attestantio/go-eth2-client/spec/phase0"
)

// withTempCachePath redirects cacheFilePath to a fresh temp file for the
// duration of the test. Critical for tests that call SaveCache/LoadCache so
// they don't clobber the developer's real cache at $TMPDIR.
func withTempCachePath(t *testing.T) {
	t.Helper()
	prev := cacheFilePath
	cacheFilePath = filepath.Join(t.TempDir(), "cache.json")
	t.Cleanup(func() { cacheFilePath = prev })
}

// TestCache_RoundTrip — write a populated cache, read it back, contents match.
// Asserts: Validators map round-trips, LastEpoch round-trips, At timestamps
// survive (compared via UnixNano to avoid monotonic-clock differences).
func TestCache_RoundTrip(t *testing.T) {
	withTempCachePath(t)

	now := time.Now().UTC().Truncate(time.Second)
	original := &LocalCache{
		Validators: map[string]CachedIndex{
			"pk1": {Index: 100, At: now},
			"pk2": {Index: 200, At: now.Add(-time.Hour)},
		},
		LastEpoch: 42,
	}

	SaveCache(original)
	loaded := LoadCache()

	if loaded.LastEpoch != 42 {
		t.Errorf("LastEpoch round-trip: got %v, want 42", loaded.LastEpoch)
	}
	if len(loaded.Validators) != 2 {
		t.Fatalf("Validators round-trip: got %d entries, want 2", len(loaded.Validators))
	}
	for pk, want := range original.Validators {
		got, ok := loaded.Validators[pk]
		if !ok {
			t.Errorf("Validators[%q] missing after round-trip", pk)
			continue
		}
		if got.Index != want.Index {
			t.Errorf("Validators[%q].Index = %v, want %v", pk, got.Index, want.Index)
		}
		if !got.At.Equal(want.At) {
			t.Errorf("Validators[%q].At = %v, want %v", pk, got.At, want.At)
		}
	}
}

// TestCache_MergeAcrossCalls — successive SaveCache calls accumulate state.
// The second call should not erase entries from the first.
func TestCache_MergeAcrossCalls(t *testing.T) {
	withTempCachePath(t)

	now := time.Now().UTC().Truncate(time.Second)
	SaveCache(&LocalCache{
		Validators: map[string]CachedIndex{"pk1": {Index: 1, At: now}},
		LastEpoch:  10,
	})
	SaveCache(&LocalCache{
		Validators: map[string]CachedIndex{"pk2": {Index: 2, At: now}},
		LastEpoch:  20,
	})

	loaded := LoadCache()
	if loaded.LastEpoch != 20 {
		t.Errorf("LastEpoch = %v, want 20 (monotonic forward merge)", loaded.LastEpoch)
	}
	if _, ok := loaded.Validators["pk1"]; !ok {
		t.Errorf("pk1 lost across merge")
	}
	if _, ok := loaded.Validators["pk2"]; !ok {
		t.Errorf("pk2 missing after second SaveCache")
	}
}

// TestCache_LastEpochNeverRegresses — a SaveCache with a stale LastEpoch must
// not roll back the persisted value. Documents the existing forward-only
// invariant in SaveCache.
func TestCache_LastEpochNeverRegresses(t *testing.T) {
	withTempCachePath(t)

	SaveCache(&LocalCache{LastEpoch: 100})
	SaveCache(&LocalCache{LastEpoch: 50}) // stale; should be ignored

	if got := LoadCache().LastEpoch; got != 100 {
		t.Errorf("LastEpoch = %v, want 100 (stale write must not regress)", got)
	}
}

// TestCache_TornFileGracefulFallback — a malformed cache file (simulating a
// torn write from a previous crash) must not crash LoadCache; it must return
// an empty-but-valid cache so the monitor can re-resolve validators.
func TestCache_TornFileGracefulFallback(t *testing.T) {
	withTempCachePath(t)

	if err := os.WriteFile(cacheFilePath, []byte("{\"Validators\": {\"pk1\""), 0o600); err != nil {
		t.Fatalf("seed corrupt cache: %v", err)
	}

	loaded := LoadCache()
	if loaded == nil {
		t.Fatal("LoadCache returned nil on corrupt file; expected empty-but-valid cache")
	}
	if loaded.Validators == nil {
		t.Error("Validators map is nil; LoadCache must initialise it even on parse failure")
	}
}

// TestCache_NullValidatorsDoesNotPanicSaveCache regresses the nil-map
// panic. An on-disk cache containing `"Validators": null` (manual edit
// or a previous format) used to make json.Unmarshal set
// cache.Validators to nil; SaveCache's merge loop then panicked with
// "assignment to entry in nil map" on the first write.
//
// Note: phase0.Epoch's UnmarshalJSON requires a quoted decimal string,
// so the seed JSON uses "5" rather than 5 — without this the parse
// would fail and LoadCache's error-path reset would mask the bug.
func TestCache_NullValidatorsDoesNotPanicSaveCache(t *testing.T) {
	withTempCachePath(t)

	if err := os.WriteFile(cacheFilePath, []byte(`{"Validators": null, "LastEpoch": "5"}`), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}

	loaded := LoadCache()
	if loaded.Validators == nil {
		t.Fatal("LoadCache returned nil Validators despite the post-Unmarshal re-init")
	}
	if loaded.LastEpoch != 5 {
		t.Errorf("LastEpoch round-trip via null-Validators path = %v, want 5", loaded.LastEpoch)
	}

	// SaveCache must not panic when merging a non-empty new cache on top
	// of the just-loaded state.
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("SaveCache panicked after LoadCache returned null Validators: %v", r)
		}
	}()
	SaveCache(&LocalCache{
		Validators: map[string]CachedIndex{"pk1": {Index: 1}},
		LastEpoch:  6,
	})

	// Round-trip: the merged entry must be visible on next load.
	if _, ok := LoadCache().Validators["pk1"]; !ok {
		t.Error("entry written after null-Validators load was not persisted")
	}
}

// TestCache_PartialUnmarshalDoesNotLeak — regression for the "returns
// partial cache while logging 'empty cache'" mismatch. Seed a JSON file
// that decodes far enough to populate one Validators entry, then fails.
// LoadCache must NOT propagate that partial entry — otherwise SaveCache
// would later persist it and lock the corruption in.
//
// The malformed JSON below has a syntactically valid Validators map with
// one entry, followed by a malformed LastEpoch field (string where uint
// is expected). Go's json.Unmarshal populates the valid map first, then
// errors on the malformed field — exactly the partial-population case.
func TestCache_PartialUnmarshalDoesNotLeak(t *testing.T) {
	withTempCachePath(t)

	bad := `{
		"Validators": {"pk-leaked": {"Index": 7, "At": "2024-01-01T00:00:00Z"}},
		"LastEpoch": "not-a-number"
	}`
	if err := os.WriteFile(cacheFilePath, []byte(bad), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}

	loaded := LoadCache()
	if loaded == nil {
		t.Fatal("LoadCache returned nil")
	}
	if _, leaked := loaded.Validators["pk-leaked"]; leaked {
		t.Error("partial Unmarshal leaked an entry into the returned cache; should be reset to empty")
	}
	if loaded.LastEpoch != 0 {
		t.Errorf("LastEpoch = %v, want 0 on corrupt cache", loaded.LastEpoch)
	}
}

// TestCache_MissingFileEmpty — first-run case: no cache file exists yet.
// LoadCache must return an empty-but-valid cache.
func TestCache_MissingFileEmpty(t *testing.T) {
	withTempCachePath(t)

	loaded := LoadCache()
	if loaded == nil || loaded.Validators == nil {
		t.Fatal("LoadCache on missing file returned nil or nil Validators")
	}
	if loaded.LastEpoch != 0 {
		t.Errorf("LastEpoch = %v, want 0 for fresh cache", loaded.LastEpoch)
	}
}

// TestCache_TmpfileCleanupOnSuccess — after a successful SaveCache the
// transient tmpfile should not be lying around next to the cache file.
// (SaveCache now creates the tmpfile in path.Dir(cacheFilePath) so the
// rename is guaranteed to be on one filesystem.)
func TestCache_TmpfileCleanupOnSuccess(t *testing.T) {
	withTempCachePath(t)

	SaveCache(&LocalCache{LastEpoch: 1})

	matches, err := filepath.Glob(filepath.Join(filepath.Dir(cacheFilePath), "stakefish-eth2-monitor-cache.*.json"))
	if err != nil {
		t.Fatalf("Glob: %v", err)
	}
	if len(matches) > 0 {
		t.Errorf("leaked tmpfile(s) after SaveCache: %v", matches)
	}
}

// TestSaveCache_NilArgumentIsNoOp — SaveCache is a public API; a nil
// LocalCache argument would otherwise nil-deref on the merge loop.
// The guard must short-circuit silently without touching the on-disk
// cache file.
func TestSaveCache_NilArgumentIsNoOp(t *testing.T) {
	withTempCachePath(t)

	// Seed an existing cache so we can detect any mutation.
	SaveCache(&LocalCache{LastEpoch: 42})
	before := LoadCache().LastEpoch

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("SaveCache(nil) panicked: %v", r)
		}
	}()
	SaveCache(nil)

	after := LoadCache().LastEpoch
	if after != before {
		t.Errorf("SaveCache(nil) mutated cache: LastEpoch %v → %v", before, after)
	}
}

// TestCache_VALIDATOR_INDEX_INVALID_RoundTrip — the sentinel constant for
// "beacon API reports no index" must survive a round trip so ResolveValidator-
// Keys keeps skipping these pubkeys until the TTL expires.
func TestCache_VALIDATOR_INDEX_INVALID_RoundTrip(t *testing.T) {
	withTempCachePath(t)

	now := time.Now().UTC().Truncate(time.Second)
	SaveCache(&LocalCache{
		Validators: map[string]CachedIndex{
			"missing": {Index: VALIDATOR_INDEX_INVALID, At: now},
		},
	})

	got, ok := LoadCache().Validators["missing"]
	if !ok {
		t.Fatal("missing pubkey entry not preserved across round-trip")
	}
	if got.Index != phase0.ValidatorIndex(VALIDATOR_INDEX_INVALID) {
		t.Errorf("Index = %v, want VALIDATOR_INDEX_INVALID", got.Index)
	}
}
