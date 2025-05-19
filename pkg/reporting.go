package pkg

import (
	"bytes"
	"encoding/json"
	"eth2-monitor/cmd/opts"
	"fmt"
	"net/http"

	"github.com/rs/zerolog/log"
)

func Report(format string, args ...interface{}) {
	message := fmt.Sprintf(format, args...)

	log.Warn().Msg(message)

	reportToSlack(message)
}

func Info(format string, args ...interface{}) {
	message := fmt.Sprintf(format, args...)

	log.Info().Msg(message)

	reportToSlack(message)
}

func reportToSlack(message string) {
	if opts.SlackURL == "" {
		return
	}

	var body struct {
		Text     string  `json:"text"`
		Username *string `json:"username"`
	}
	body.Text = message
	if opts.SlackUsername != "" {
		body.Username = &opts.SlackUsername
	}

	buf, err := json.Marshal(body)
	if err != nil {
		log.Warn().Err(err).Msgf("json.Marshal failed while reporting %q; skip", message)
	}

	resp, err := http.Post(opts.SlackURL, "application/json", bytes.NewBuffer([]byte(buf)))
	if err != nil {
		log.Warn().Err(err).Msgf("http.Post failed while reporting %q; skip", message)
	}
	defer resp.Body.Close()
}
