package beaconchain

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// Caplin (Erigon's CL) emits uint64 fields in execution_requests (Gwei amounts
// and indices) as bare JSON numbers instead of the spec-required quoted
// strings, which trips go-eth2-client's strict unmarshal. We rewrite responses
// from the beacon block endpoint to quote any unquoted "amount":N and
// "index":N so the parser accepts them. Both fields are uint64-typed and
// spec'd as quoted decimal strings everywhere they appear in beacon API JSON,
// so this rewrite is safe across the response.
// Drop this file once Caplin (or attestantio/go-eth2-client) is fixed.

const blockEndpointPath = "/eth/v2/beacon/blocks/"

var unquotedNumericField = regexp.MustCompile(`"(amount|index)"\s*:\s*(\d+)`)

func fixCaplinAmounts(body []byte) []byte {
	return unquotedNumericField.ReplaceAll(body, []byte(`"$1":"$2"`))
}

type caplinAmountFixer struct {
	base http.RoundTripper
}

func (c *caplinAmountFixer) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := c.base.RoundTrip(req)
	if err != nil {
		return resp, err
	}
	// The beacon API base URL may include a path prefix (e.g. a credential
	// token segment), so match the endpoint as a substring rather than a
	// prefix. SSZ (application/octet-stream) responses are binary and must
	// not be touched.
	if resp.StatusCode != http.StatusOK ||
		!strings.Contains(req.URL.Path, blockEndpointPath) ||
		!strings.Contains(resp.Header.Get("Content-Type"), "application/json") {
		return resp, nil
	}

	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		return nil, err
	}
	fixed := fixCaplinAmounts(body)
	resp.Body = io.NopCloser(bytes.NewReader(fixed))
	resp.ContentLength = int64(len(fixed))
	resp.Header.Del("Content-Length")
	return resp, nil
}

func newCaplinCompatClient(timeout time.Duration) *http.Client {
	base := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   timeout,
			KeepAlive: 30 * time.Second,
			DualStack: true,
		}).DialContext,
		MaxIdleConns:        64,
		MaxConnsPerHost:     64,
		MaxIdleConnsPerHost: 64,
		IdleConnTimeout:     600 * time.Second,
	}
	return &http.Client{Transport: &caplinAmountFixer{base: base}}
}
