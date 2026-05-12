package beaconchain

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// RequestMetrics is the metrics surface the beacon HTTP transport reports
// against. It is owned and registered by pkg/metrics.go; beaconchain only
// consumes it. A nil value disables instrumentation, which keeps
// caplin_compat_test.go's transport-only test path free of Prometheus setup.
type RequestMetrics struct {
	Requests *prometheus.CounterVec
	Duration *prometheus.HistogramVec
}

// classifyEndpoint maps a beacon API URL path to a stable, low-cardinality
// label value. strings.Contains is used (rather than prefix matching) because
// the beacon base URL can carry a credential segment ahead of /eth/... — see
// caplin_compat.go's note on the same issue.
func classifyEndpoint(path string) string {
	switch {
	case strings.Contains(path, "/beacon/states/") && strings.HasSuffix(path, "/validators"):
		return "validators"
	case strings.Contains(path, "/beacon/blocks/"):
		return "block"
	case strings.Contains(path, "/validator/duties/proposer/"):
		return "proposer_duties"
	case strings.Contains(path, "/validator/duties/attester/"):
		return "attester_duties"
	case strings.Contains(path, "/finality_checkpoints"):
		return "finality"
	case strings.Contains(path, "/committees"):
		return "committees"
	case strings.Contains(path, "/eth/v1/events"):
		return "events"
	default:
		return "other"
	}
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

	endpoint := classifyEndpoint(req.URL.Path)
	method := req.Method
	t.m.Requests.WithLabelValues(endpoint, method, statusClass(resp, err)).Inc()
	t.m.Duration.WithLabelValues(endpoint, method).Observe(elapsed)

	return resp, err
}
