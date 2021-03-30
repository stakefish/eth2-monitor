package pkg

import (
	"bytes"
	"encoding/json"
	"eth2-monitor/cmd/opts"
	"eth2-monitor/spec"
	"fmt"
	"net/http"
	"strings"

	"github.com/dghubble/go-twitter/twitter"
	"github.com/dghubble/oauth1"
	"github.com/rs/zerolog/log"
)

func Report(format string, args ...interface{}) {
	message := fmt.Sprintf(format, args...)

	log.Warn().Msgf(message)

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

func TweetSlashing(reason string, slot spec.Slot, slasher spec.ValidatorIndex, slashee spec.ValidatorIndex) {
	message := fmt.Sprintf(`📢🔪 Slashing Alert 🔪📢
👁️ Validator %v
🧐 %s
🔪 Slashed by Validator %v
📊 Occurred at Slot %v`, slashee, strings.Title(reason), slasher, slot)
	reportToTwitter(message)
}

func reportToTwitter(message string) {
	if !(opts.Slashings.TwitterConsumerKey != "" && opts.Slashings.TwitterConsumerSecret != "" &&
		opts.Slashings.TwitterAccessToken != "" && opts.Slashings.TwitterAccessSecret != "") {
		return
	}

	config := oauth1.NewConfig(opts.Slashings.TwitterConsumerKey, opts.Slashings.TwitterConsumerSecret)
	token := oauth1.NewToken(opts.Slashings.TwitterAccessToken, opts.Slashings.TwitterAccessSecret)

	// OAuth1 http.Client will automatically authorize Requests
	httpClient := config.Client(oauth1.NoContext, token)

	// Twitter client
	client := twitter.NewClient(httpClient)

	// Send a Tweet
	_, _, err := client.Statuses.Update(message, nil)
	if err != nil {
		log.Warn().Err(err).Msgf("client.Statuses.Update failed while posting a tweet %q; skip", message)
	}
}
