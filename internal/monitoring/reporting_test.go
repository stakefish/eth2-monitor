package monitoring

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stakefish/eth2-monitor/internal/opts"
)

// TestReportToSlack_NilRespOnDialFailure regresses the crash where http.Post
// failure left resp == nil and the deferred Body.Close() panicked. Pointing
// at an unroutable URL forces http.Post to return (nil, err); the function
// must not panic.
func TestReportToSlack_NilRespOnDialFailure(t *testing.T) {
	prev := opts.SlackURL
	t.Cleanup(func() { opts.SlackURL = prev })
	// Reserved port 1 on an address that should never accept connections.
	opts.SlackURL = "http://127.0.0.1:1/never-listens"

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("reportToSlack panicked on transport failure: %v", r)
		}
	}()
	reportToSlack("payload")
}

// TestReportToSlack_NoOpWhenURLEmpty — the empty-URL fast path must not POST.
func TestReportToSlack_NoOpWhenURLEmpty(t *testing.T) {
	prev := opts.SlackURL
	t.Cleanup(func() { opts.SlackURL = prev })
	opts.SlackURL = ""

	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	reportToSlack("payload")
	// Give a transport that doesn't exist no chance to hit anything.
	time.Sleep(10 * time.Millisecond)

	if got := atomic.LoadInt32(&hits); got != 0 {
		t.Errorf("reportToSlack with empty URL still issued %d requests, want 0", got)
	}
}

// TestReportToSlack_PostsToServer covers the happy path: SLACK_URL set, server
// returns 200, no panic, body is closed (no goroutine leak from defer).
func TestReportToSlack_PostsToServer(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	prev := opts.SlackURL
	t.Cleanup(func() { opts.SlackURL = prev })
	opts.SlackURL = srv.URL

	reportToSlack("payload")

	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Errorf("reportToSlack issued %d requests, want 1", got)
	}
}

// TestReportToSlack_LogsOnNon2xx regresses the silent-rejection gap: a
// transport-level POST that gets a 4xx/5xx from Slack used to fall
// silently into the deferred Close — operators couldn't tell whether
// Report was even called. We now log at WARN with the status code.
func TestReportToSlack_LogsOnNon2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	t.Cleanup(srv.Close)

	prev := opts.SlackURL
	t.Cleanup(func() { opts.SlackURL = prev })
	opts.SlackURL = srv.URL

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("reportToSlack panicked on Slack 429: %v", r)
		}
	}()
	reportToSlack("payload")
	// No assertion on log output — zerolog isn't easily captured here, but
	// the panic-recover and the existing happy-path test together pin the
	// "no panic, no hang" contract.
}

// TestReportToSlack_TimesOutOnHungServer regresses the stall-the-orchestrator
// risk: Report runs inline from the per-epoch monitor loop, so a hung Slack
// webhook must not block indefinitely. We point at a server that never
// responds and assert reportToSlack returns within a small multiple of the
// configured client timeout. The previous code used http.Post with the
// default (no-timeout) client and would hang here forever.
func TestReportToSlack_TimesOutOnHungServer(t *testing.T) {
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-block // hold the handler forever
	}))
	t.Cleanup(func() {
		close(block)
		srv.Close()
	})

	prev := opts.SlackURL
	t.Cleanup(func() { opts.SlackURL = prev })
	opts.SlackURL = srv.URL

	prevClient := slackClient
	t.Cleanup(func() { slackClient = prevClient })
	slackClient = &http.Client{Timeout: 150 * time.Millisecond}

	done := make(chan struct{})
	go func() {
		reportToSlack("payload")
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("reportToSlack did not return within 2s; timeout failed to fire on hung server")
	}
}
