package pkg

import (
	"fmt"
	"time"

	"github.com/rs/zerolog/log"
)

func Measure(handler func(), title string, args ...interface{}) {
	start := time.Now()
	handler()
	elapsed := time.Since(start)
	log.Debug().Msgf("⏱️ %s took %v", fmt.Sprintf(title, args...), elapsed)
}
