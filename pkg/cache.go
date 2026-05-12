package pkg

import (
	"encoding/json"
	"io"
	"os"
	"path"
	"time"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/rs/zerolog/log"
)

type CachedIndex struct {
	Index phase0.ValidatorIndex
	At    time.Time
}

type LocalCache struct {
	Validators map[string]CachedIndex
	// LastEpoch is the highest epoch the monitor has finished processing.
	// On restart it's loaded and used to skip already-processed epochs so
	// cumulative metric counters don't spike from re-processing.
	LastEpoch phase0.Epoch
}

var (
	cacheFilePath = path.Join(os.TempDir(), "stakefish-eth2-monitor-cache.json")
)

func LoadCache() *LocalCache {
	cache := &LocalCache{
		Validators: make(map[string]CachedIndex),
	}

	log.Trace().Msgf("Validator Index Cache Path %v", cacheFilePath)

	fd, err := os.Open(cacheFilePath)
	if err != nil {
		log.Debug().Err(err).Msg("LoadCache: os.Open failed; skip")
		return cache
	}
	defer func() { _ = fd.Close() }()

	rawCache, err := io.ReadAll(fd)
	if err != nil {
		log.Debug().Err(err).Msg("LoadCache: io.ReadAll failed; skip")
		return cache
	}
	err = json.Unmarshal(rawCache, cache)
	if err != nil {
		// json.Unmarshal may have partially populated cache before failing
		// (e.g. valid entries up to a torn-write boundary, then garbage).
		// Returning that partial state would let a subsequent SaveCache
		// persist the half-decoded data, locking in the corruption. Reset
		// to a clean LocalCache so the caller (and the log) agree.
		log.Error().Err(err).Msg("LoadCache: json.Unmarshal failed; returning empty cache")
		return &LocalCache{
			Validators: make(map[string]CachedIndex),
		}
	}

	return cache
}

func SaveCache(newCache *LocalCache) {
	// Merge with the current cache.
	cache := LoadCache()
	for pubkey, validator := range newCache.Validators {
		cache.Validators[pubkey] = validator
	}
	// LastEpoch advances forward only — concurrent writers can't roll it back.
	if newCache.LastEpoch > cache.LastEpoch {
		cache.LastEpoch = newCache.LastEpoch
	}

	rawCache, err := json.MarshalIndent(cache, "", "  ")
	if err != nil {
		log.Debug().Err(err).Msg("SaveCache: json.MarshalIndent failed; skip")
		return
	}

	tmpfile, err := os.CreateTemp("", "stakefish-eth2-monitor-cache.*.json")
	if err != nil {
		log.Warn().Err(err).Msg("SaveCache: os.CreateTemp failed; skip")
		return
	}
	tmpPath := tmpfile.Name()
	// Remove the tmpfile on any error path; once Rename succeeds this Remove
	// targets a path that no longer exists and is a harmless no-op.
	defer func() { _ = os.Remove(tmpPath) }()

	if _, err := tmpfile.Write(rawCache); err != nil {
		_ = tmpfile.Close()
		log.Warn().Err(err).Msg("SaveCache: tmpfile.Write failed; skip")
		return
	}
	// Sync + Close before Rename so the rename swaps in a file whose
	// contents are guaranteed on disk. Without Sync a crash between
	// Write and Rename can leave torn JSON, which LoadCache logs as a
	// json.Unmarshal error and silently returns an empty cache — forcing
	// every validator index to be re-resolved on the next restart.
	if err := tmpfile.Sync(); err != nil {
		_ = tmpfile.Close()
		log.Warn().Err(err).Msg("SaveCache: tmpfile.Sync failed; skip")
		return
	}
	if err := tmpfile.Close(); err != nil {
		log.Warn().Err(err).Msg("SaveCache: tmpfile.Close failed; skip")
		return
	}
	if err := os.Rename(tmpPath, cacheFilePath); err != nil {
		log.Error().Err(err).Msg("SaveCache: os.Rename failed; skip")
	}
}
