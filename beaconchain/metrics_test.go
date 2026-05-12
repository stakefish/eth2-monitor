package beaconchain

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

func TestClassifyEndpoint(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"/eth/v1/beacon/states/head/validators", "validators"},
		{"/temporary-abc123/eth/v1/beacon/states/12345/validators", "validators"},
		{"/eth/v2/beacon/blocks/123", "block"},
		{"/eth/v2/beacon/blocks/head", "block"},
		{"/eth/v1/validator/duties/proposer/42", "proposer_duties"},
		{"/eth/v1/validator/duties/attester/42", "attester_duties"},
		{"/eth/v1/beacon/states/head/finality_checkpoints", "finality"},
		{"/eth/v1/beacon/states/head/committees", "committees"},
		{"/eth/v1/events", "events"},
		{"/eth/v1/events?topics=head", "events"},
		{"/eth/v1/node/version", "other"},
		{"/", "other"},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			if got := classifyEndpoint(tt.path); got != tt.want {
				t.Errorf("classifyEndpoint(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

func counterValue(t *testing.T, c prometheus.Counter) float64 {
	t.Helper()
	var m dto.Metric
	if err := c.Write(&m); err != nil {
		t.Fatalf("counter Write: %v", err)
	}
	return m.GetCounter().GetValue()
}

func histogramCount(t *testing.T, h prometheus.Observer) uint64 {
	t.Helper()
	collector, ok := h.(prometheus.Histogram)
	if !ok {
		t.Fatalf("observer is not a histogram: %T", h)
	}
	var m dto.Metric
	if err := collector.Write(&m); err != nil {
		t.Fatalf("histogram Write: %v", err)
	}
	return m.GetHistogram().GetSampleCount()
}

func newTestRequestMetrics() *RequestMetrics {
	reg := prometheus.NewRegistry()
	requests := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "beacon_api_requests_total",
	}, []string{"endpoint", "method", "status_class"})
	duration := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "beacon_api_request_duration_seconds",
		Buckets: prometheus.DefBuckets,
	}, []string{"endpoint", "method"})
	reg.MustRegister(requests, duration)
	return &RequestMetrics{Requests: requests, Duration: duration}
}

func TestInstrumentingTransportRecordsSuccess(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{}`)
	}))
	defer upstream.Close()

	m := newTestRequestMetrics()
	client := &http.Client{Transport: &instrumentingTransport{base: http.DefaultTransport, m: m}}

	resp, err := client.Get(upstream.URL + "/eth/v2/beacon/blocks/123")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	_ = resp.Body.Close()

	if got := counterValue(t, m.Requests.WithLabelValues("block", "GET", "2xx")); got != 1 {
		t.Errorf("requests counter = %v, want 1", got)
	}
	if got := histogramCount(t, m.Duration.WithLabelValues("block", "GET")); got != 1 {
		t.Errorf("duration sample count = %v, want 1", got)
	}
}

type errTransport struct{}

func (errTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("boom")
}

func TestInstrumentingTransportRecordsTransportError(t *testing.T) {
	m := newTestRequestMetrics()
	client := &http.Client{Transport: &instrumentingTransport{base: errTransport{}, m: m}}

	req, _ := http.NewRequest(http.MethodPost, "http://example.invalid/eth/v1/beacon/states/head/validators", strings.NewReader(""))
	_, err := client.Do(req)
	if err == nil {
		t.Fatal("expected error from transport")
	}

	if got := counterValue(t, m.Requests.WithLabelValues("validators", "POST", "error")); got != 1 {
		t.Errorf("requests counter (error) = %v, want 1", got)
	}
	if got := histogramCount(t, m.Duration.WithLabelValues("validators", "POST")); got != 1 {
		t.Errorf("duration sample count = %v, want 1", got)
	}
}

func TestInstrumentingTransportRecordsHTTPError(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer upstream.Close()

	m := newTestRequestMetrics()
	client := &http.Client{Transport: &instrumentingTransport{base: http.DefaultTransport, m: m}}

	resp, err := client.Get(upstream.URL + "/eth/v1/events?topics=head")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	_ = resp.Body.Close()

	if got := counterValue(t, m.Requests.WithLabelValues("events", "GET", "5xx")); got != 1 {
		t.Errorf("requests counter (5xx) = %v, want 1", got)
	}
}
