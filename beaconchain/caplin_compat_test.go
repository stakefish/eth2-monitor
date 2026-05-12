package beaconchain

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFixCaplinAmounts(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "bare number gets quoted",
			in:   `{"amount":32000000000}`,
			want: `{"amount":"32000000000"}`,
		},
		{
			name: "already quoted unchanged",
			in:   `{"amount":"32000000000"}`,
			want: `{"amount":"32000000000"}`,
		},
		{
			name: "multiple unquoted get quoted",
			in:   `[{"amount":1},{"amount":2},{"amount":3}]`,
			want: `[{"amount":"1"},{"amount":"2"},{"amount":"3"}]`,
		},
		{
			name: "mixed quoted and unquoted",
			in:   `[{"amount":"1"},{"amount":2}]`,
			want: `[{"amount":"1"},{"amount":"2"}]`,
		},
		{
			name: "whitespace around colon",
			in:   `{"amount" : 42, "amount":   99}`,
			want: `{"amount":"42", "amount":"99"}`,
		},
		{
			name: "no amount field unchanged",
			in:   `{"slot":"123","proposer_index":"7"}`,
			want: `{"slot":"123","proposer_index":"7"}`,
		},
		{
			name: "deposit request shape (amount only unquoted)",
			in:   `{"deposits":[{"pubkey":"0xab","withdrawal_credentials":"0xcd","amount":32000000000,"signature":"0xef","index":"5"}]}`,
			want: `{"deposits":[{"pubkey":"0xab","withdrawal_credentials":"0xcd","amount":"32000000000","signature":"0xef","index":"5"}]}`,
		},
		{
			name: "deposit request shape (amount and index unquoted)",
			in:   `{"deposits":[{"pubkey":"0xab","withdrawal_credentials":"0xcd","amount":32000000000,"signature":"0xef","index":5}]}`,
			want: `{"deposits":[{"pubkey":"0xab","withdrawal_credentials":"0xcd","amount":"32000000000","signature":"0xef","index":"5"}]}`,
		},
		{
			name: "index alone unquoted",
			in:   `{"index":42}`,
			want: `{"index":"42"}`,
		},
		{
			name: "index already quoted unchanged",
			in:   `{"index":"42"}`,
			want: `{"index":"42"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := string(fixCaplinAmounts([]byte(tt.in)))
			if got != tt.want {
				t.Errorf("fixCaplinAmounts() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCaplinAmountFixerRewritesBlockEndpoint(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := `{"data":{"message":{"body":{"execution_requests":{"deposits":[{"amount":32000000000}]}}}}}`
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, body)
	}))
	defer upstream.Close()

	client := &http.Client{Transport: &caplinAmountFixer{base: http.DefaultTransport}}

	resp, err := client.Get(upstream.URL + "/eth/v2/beacon/blocks/123")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !strings.Contains(string(body), `"amount":"32000000000"`) {
		t.Fatalf("expected amount to be quoted, got: %s", body)
	}
	if strings.Contains(string(body), `"amount":32000000000`) {
		t.Fatalf("unquoted amount still present: %s", body)
	}
	if resp.ContentLength != int64(len(body)) {
		t.Errorf("ContentLength = %d, want %d", resp.ContentLength, len(body))
	}
}

func TestCaplinAmountFixerLeavesOtherEndpointsUntouched(t *testing.T) {
	original := `{"data":[{"amount":12345,"index":"7"}]}`
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, original)
	}))
	defer upstream.Close()

	client := &http.Client{Transport: &caplinAmountFixer{base: http.DefaultTransport}}

	resp, err := client.Get(upstream.URL + "/eth/v1/beacon/states/head/validators")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(body) != original {
		t.Fatalf("non-block endpoint body modified: got %s, want %s", body, original)
	}
}

func TestCaplinAmountFixerRewritesWithBaseURLPathPrefix(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := `{"deposits":[{"amount":32000000000}],"withdrawals":[{"amount":1000000}]}`
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, body)
	}))
	defer upstream.Close()

	client := &http.Client{Transport: &caplinAmountFixer{base: http.DefaultTransport}}

	resp, err := client.Get(upstream.URL + "/temporary-abc123/eth/v2/beacon/blocks/123")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	want := `{"deposits":[{"amount":"32000000000"}],"withdrawals":[{"amount":"1000000"}]}`
	if string(body) != want {
		t.Fatalf("rewrite with prefix: got %s, want %s", body, want)
	}
}

func TestCaplinAmountFixerLeavesSSZBodyUntouched(t *testing.T) {
	original := []byte{0xde, 0xad, 0xbe, 0xef, '"', 'a', 'm', 'o', 'u', 'n', 't', '"', ':', '1', '2', '3'}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(original)
	}))
	defer upstream.Close()

	client := &http.Client{Transport: &caplinAmountFixer{base: http.DefaultTransport}}

	resp, err := client.Get(upstream.URL + "/eth/v2/beacon/blocks/123")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(body, original) {
		t.Fatalf("SSZ body modified: got %v, want %v", body, original)
	}
}

func TestCaplinAmountFixerPassesThroughNon200(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, `{"amount":1}`)
	}))
	defer upstream.Close()

	client := &http.Client{Transport: &caplinAmountFixer{base: http.DefaultTransport}}

	resp, err := client.Get(upstream.URL + "/eth/v2/beacon/blocks/999")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(body) != `{"amount":1}` {
		t.Fatalf("non-200 body should pass through unchanged, got: %s", body)
	}
}
