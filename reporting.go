package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/rs/zerolog/log"
)

func Report(format string, args ...interface{}) {
	message := fmt.Sprintf(format, args...)

	log.Warn().Msgf(message)

	reportToSlack(message)
	reportToTwitter(message)
}

func reportToSlack(message string) {
	if opts.SlackURL == "" {
		return
	}

	var body struct {
		Text string `json:"text"`
	}
	body.Text = message

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

func reportToTwitter(message string) {
}
