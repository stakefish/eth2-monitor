package pkg

import (
	"bytes"
	"encoding/json"
	"eth2-monitor/cmd/opts"
	"fmt"
	"net/http"
	"time"

	"github.com/rs/zerolog/log"
)

// slackClient is the http.Client used for Slack webhook POSTs. It has an
// explicit Timeout so a hung Slack endpoint can never stall the per-epoch
// reporting path (Report/Info are called inline from the orchestrator).
//
// Exposed at package scope so tests can override it for fake servers.
var slackClient = &http.Client{Timeout: 5 * time.Second}

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
		return
	}

	resp, err := slackClient.Post(opts.SlackURL, "application/json", bytes.NewBuffer(buf))
	if err != nil {
		// http.Post returns (nil, err) on transport-level failures, so we
		// can't defer Close on the response. Bail before that.
		log.Warn().Err(err).Msgf("http.Post failed while reporting %q; skip", message)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	// Slack returns 2xx with "ok" on success, 4xx on bad payload / expired
	// webhook, 429 on rate-limit. The transport-level POST succeeded but
	// Slack may still have rejected it — surface that so operators can
	// tell "Report wasn't called" from "Report was called but Slack said no".
	if resp.StatusCode/100 != 2 {
		log.Warn().Int("status", resp.StatusCode).Msgf("Slack rejected report %q", message)
	}
}
