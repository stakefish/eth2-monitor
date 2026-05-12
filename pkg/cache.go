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

	// Cap the read so a corrupted cache file or hostile filesystem
	// (someone symlinking cacheFilePath to /dev/zero) can't exhaust the
	// allocator. 64 MiB covers ~640k validators at ~100 bytes/entry —
	// orders of magnitude past realistic deployments.
	const maxCacheBytes = 64 << 20
	rawCache, err := io.ReadAll(io.LimitReader(fd, maxCacheBytes))
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

	// JSON `null` overrides the pre-initialised empty map with nil. Re-init
	// so SaveCache's merge loop doesn't panic on the first write. Trigger
	// path: an external edit or older-format cache file containing
	// `"Validators": null`.
	if cache.Validators == nil {
		cache.Validators = make(map[string]CachedIndex)
	}

	return cache
}

func SaveCache(newCache *LocalCache) {
	if newCache == nil {
		// Public API — a future caller passing nil would otherwise
		// nil-deref on the merge loop below. Silently no-op; nothing
		// to merge.
		return
	}
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

	// Create the tmpfile in the SAME directory as cacheFilePath so the
	// subsequent os.Rename is guaranteed to be on one filesystem (Rename
	// returns EXDEV otherwise). Today both default to $TMPDIR, but a
	// future caller overriding cacheFilePath (or a setup where /tmp is a
	// tmpfs but the cache lives elsewhere) would otherwise silently fail
	// every save.
	tmpfile, err := os.CreateTemp(path.Dir(cacheFilePath), "stakefish-eth2-monitor-cache.*.json")
	if err != nil {
		log.Warn().Err(err).Msg("SaveCache: os.CreateTemp failed; skip")
		return
	}
	tmpPath := tmpfile.Name()
	renamed := false
	// Only clean up the tmpfile if Rename never succeeded. After a successful
	// Rename, tmpPath is a stale name that another process could have reused
	// (tmpfile suffixes are random so the window is tiny, but the TOCTOU is
	// avoidable). The flag makes the cleanup precise.
	defer func() {
		if !renamed {
			_ = os.Remove(tmpPath)
		}
	}()

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
		return
	}
	renamed = true

	// fsync the parent directory so the new directory entry survives a
	// crash. Without this, ext4/xfs journals may delay metadata commit
	// beyond Rename's syscall return; a crash in that window can leave
	// cacheFilePath pointing at the old inode (or no entry) despite the
	// file content being durable. Best-effort: ENOTDIR / EPERM on exotic
	// filesystems is logged but doesn't block forward progress.
	if dir, err := os.Open(path.Dir(cacheFilePath)); err == nil {
		_ = dir.Sync()
		_ = dir.Close()
	} else {
		log.Debug().Err(err).Msg("SaveCache: open(parent) for dir-fsync failed; rename may not be crash-durable")
	}
}
