package main

import (
	"github.com/rs/zerolog/log"
)

func Must(err error) {
	if err != nil {
		log.Error().Stack().Err(err).Msg("Fatal error occurred")
		panic(err)
	}
}
