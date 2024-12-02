package pkg

import (
	"cmp"
	"maps"
	"slices"
	"sort"

	"github.com/rs/zerolog/log"
)

func Must(err error) {
	if err != nil {
		log.Error().Stack().Err(err).Msg("Fatal error occurred")
		panic(err)
	}
}

func sortedKeys[K cmp.Ordered, V any](m map[K]V) []K {
	keys := slices.Collect(maps.Keys(m))
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	return keys
}
