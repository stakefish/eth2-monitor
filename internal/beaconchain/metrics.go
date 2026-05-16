package beaconchain

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// RequestMetrics is the metrics surface the beacon HTTP transport reports
// against. It is owned and registered by internal/monitoring/metrics.go;
// beaconchain only consumes it. A nil value disables instrumentation, so
// callers that wire the HTTP client outside of the orchestrator (e.g. ad-hoc
// scripts, future tests that drive the transport directly) can pass nil
// instead of setting up an isolated Prometheus registry.
type RequestMetrics struct {
	Requests *prometheus.CounterVec
	Duration *prometheus.HistogramVec
}

// endpointTemplate maps a beacon API URL path to a templated label value:
// the path from /eth/v* onward, with dynamic segments replaced by their
// spec-standard placeholders ({state_id}, {block_id}, {epoch}, {validator_id}).
//
// The base URL can carry a credential segment ahead of /eth/... (some
// hosted beacon endpoints inject a token path prefix), so the prefix is
// stripped before templating. Any path that does not contain /eth/v is
// reported as "other".
func endpointTemplate(path string) string {
	i := strings.Index(path, "/eth/v")
	if i < 0 {
		return "other"
	}
	path = path[i:]
	if q := strings.IndexByte(path, '?'); q >= 0 {
		path = path[:q]
	}
	segs := strings.Split(path, "/") // leading "" then "eth", "v1", ...
	for j := 2; j < len(segs); j++ {
		switch segs[j-1] {
		case "states":
			segs[j] = "{state_id}"
		case "blocks", "headers":
			segs[j] = "{block_id}"
		case "validators":
			// /beacon/states/{state_id}/validators is itself a valid endpoint
			// with no trailing id; only replace when there is a real child segment.
			segs[j] = "{validator_id}"
		case "proposer", "attester", "sync":
			if j >= 3 && segs[j-2] == "duties" {
				segs[j] = "{epoch}"
			}
		}
	}
	return strings.Join(segs, "/")
}

func statusClass(resp *http.Response, err error) string {
	if err != nil || resp == nil {
		return "error"
	}
	return fmt.Sprintf("%dxx", resp.StatusCode/100)
}

type instrumentingTransport struct {
	base http.RoundTripper
	m    *RequestMetrics
}

func (t *instrumentingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	start := time.Now()
	resp, err := t.base.RoundTrip(req)
	elapsed := time.Since(start).Seconds()

	endpoint := endpointTemplate(req.URL.Path)
	method := req.Method
	t.m.Requests.WithLabelValues(endpoint, method, statusClass(resp, err)).Inc()
	t.m.Duration.WithLabelValues(endpoint, method).Observe(elapsed)

	return resp, err
}
