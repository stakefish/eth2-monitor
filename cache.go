package main

import (
	"encoding/json"
	"io"
	"io/ioutil"
	"os"
	"path"
	"time"

	"eth2-monitor/spec"

	"github.com/rs/zerolog/log"
)

type CachedIndex struct {
	Index spec.ValidatorIndex
	At    time.Time
}

type LocalCache struct {
	Validators map[string]CachedIndex
}

var (
	cacheFilePath = path.Join(os.TempDir(), "stakefish-eth2-monitor-cache.json")
)

func LoadCache() *LocalCache {
	cache := &LocalCache{
		Validators: make(map[string]CachedIndex),
	}

	fd, err := os.Open(cacheFilePath)
	if err != nil {
		log.Debug().Err(err).Msg("LoadCache: os.Open failed; skip")
		return cache
	}
	defer fd.Close()

	rawCache, err := ioutil.ReadAll(fd)
	if err != nil {
		log.Debug().Err(err).Msg("LoadCache: ioutil.ReadAll failed; skip")
		return cache
	}
	json.Unmarshal(rawCache, cache)

	return cache
}

func SaveCache(newCache *LocalCache) {
	// Merge with the current cache.
	cache := LoadCache()
	for pubkey, validator := range newCache.Validators {
		validator := validator
		cache.Validators[pubkey] = validator
	}

	rawCache, err := json.MarshalIndent(cache, "", "  ")
	if err != nil {
		log.Debug().Err(err).Msg("SaveCache: json.MarshalIndent failed; skip")
		return
	}

	tmpfile, err := ioutil.TempFile("", "stakefish-eth2-monitor-cache.*.json")
	if err != nil {
		log.Debug().Err(err).Msg("SaveCache: os.Open failed; skip")
		return
	}
	defer os.Remove(tmpfile.Name())

	for bytesWritten := 0; bytesWritten < len(rawCache); {
		nWritten, err := tmpfile.Write(rawCache[bytesWritten:])
		if err != nil && err != io.ErrShortWrite {
			log.Debug().Err(err).Msg("SaveCache: tmpfile.Write failed; skip")
			break
		}
		bytesWritten += nWritten
	}
	os.Rename(tmpfile.Name(), cacheFilePath)
}
