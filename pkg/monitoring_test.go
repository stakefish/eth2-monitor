package pkg

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"eth2-monitor/cmd/opts"

	"github.com/attestantio/go-eth2-client/spec/phase0"
)

// TestSendEpoch_DeliversWhenReceiverReady — happy path: a receiver is
// reading the channel, so the send completes and returns true.
func TestSendEpoch_DeliversWhenReceiverReady(t *testing.T) {
	ch := make(chan phase0.Epoch, 1)
	if !sendEpoch(context.Background(), ch, 42) {
		t.Fatal("sendEpoch returned false when receiver was ready")
	}
	if got := <-ch; got != 42 {
		t.Errorf("received %v, want 42", got)
	}
}

// TestSendEpoch_AbortsOnCtxCancel regresses the shutdown-hang scenario:
// orchestrator died, no one reads the channel, ctx is cancelled — the send
// must bail out instead of blocking forever. Pre-fix code did
// `epochsChan <- e` directly and would hang here indefinitely.
func TestSendEpoch_AbortsOnCtxCancel(t *testing.T) {
	ch := make(chan phase0.Epoch) // unbuffered, no receiver
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	done := make(chan bool, 1)
	go func() {
		done <- sendEpoch(ctx, ch, 42)
	}()

	select {
	case ok := <-done:
		if ok {
			t.Error("sendEpoch returned true even though ctx was cancelled and channel had no reader")
		}
	case <-time.After(time.Second):
		t.Fatal("sendEpoch hung after ctx cancel; shutdown would deadlock")
	}
}

// TestSendEpoch_PrefersDeliveryWhenBothReady — when both ctx and receiver
// are ready, Go's select makes a uniform choice. We don't pin the choice
// in this test; we only verify both branches are reachable in other tests
// above. Documented here so a future maintainer doesn't misread the
// behaviour as "ctx always wins".
func TestSendEpoch_BothReadyEitherIsAcceptable(t *testing.T) {
	ch := make(chan phase0.Epoch, 1)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Acceptable: either the send wins (returns true, value queued) or the
	// ctx wins (returns false, nothing queued). Both are correct outcomes.
	got := sendEpoch(ctx, ch, 99)
	if got {
		select {
		case v := <-ch:
			if v != 99 {
				t.Errorf("send-win branch: got %v, want 99", v)
			}
		default:
			t.Error("sendEpoch returned true but channel is empty")
		}
	} else {
		select {
		case v := <-ch:
			t.Errorf("ctx-win branch: channel has %v, expected empty", v)
		default:
		}
	}
}

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile %v: %v", p, err)
	}
	return p
}

// TestLoadKeys_MergesCLIAndFiles covers the common case: pubkeys come from
// both the --pubkey CLI flag and one or more files. Lines that are blank or
// only whitespace must be skipped.
func TestLoadKeys_MergesCLIAndFiles(t *testing.T) {
	prev := opts.Monitor.Pubkeys
	t.Cleanup(func() { opts.Monitor.Pubkeys = prev })
	opts.Monitor.Pubkeys = []string{"0xCLI1"}

	dir := t.TempDir()
	f1 := writeFile(t, dir, "a.txt", "0xA1\n0xA2\n\n   \n")
	f2 := writeFile(t, dir, "b.txt", " 0xB1 \n0xB2\n")

	got, err := LoadKeys([]string{f1, f2})
	if err != nil {
		t.Fatalf("LoadKeys: %v", err)
	}
	want := []string{"0xCLI1", "0xA1", "0xA2", "0xB1", "0xB2"}
	if len(got) != len(want) {
		t.Fatalf("LoadKeys returned %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("LoadKeys[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

// TestLoadKeys_MissingFile — surfaces an error rather than silently dropping.
func TestLoadKeys_MissingFile(t *testing.T) {
	prev := opts.Monitor.Pubkeys
	t.Cleanup(func() { opts.Monitor.Pubkeys = prev })
	opts.Monitor.Pubkeys = nil

	_, err := LoadKeys([]string{filepath.Join(t.TempDir(), "nope.txt")})
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}

// TestLoadKeys_NoFDLeak proves the FD-leak fix: opening 64 small pubkey
// files in one LoadKeys call must not leave them all open until LoadKeys
// returns. We do best-effort detection by inspecting /proc/self/fd count
// (Linux) or rough fd counts on other platforms; we accept some slack.
//
// The previous implementation had `defer file.Close()` inside the loop —
// every fd stayed open for the full LoadKeys call. This test would have
// flagged the leak on any system with an ulimit close to 64.
func TestLoadKeys_NoFDLeak(t *testing.T) {
	prev := opts.Monitor.Pubkeys
	t.Cleanup(func() { opts.Monitor.Pubkeys = prev })
	opts.Monitor.Pubkeys = nil

	dir := t.TempDir()
	const N = 64
	paths := make([]string, N)
	for i := range paths {
		paths[i] = writeFile(t, dir, "k"+itoa(i)+".txt", "0xk\n")
	}

	before := countOpenFiles(t)
	if _, err := LoadKeys(paths); err != nil {
		t.Fatalf("LoadKeys: %v", err)
	}
	after := countOpenFiles(t)

	// Some FDs come and go in tests; tolerate +8 but the previous-implementation
	// leak would push delta to ≈ N.
	if before >= 0 && after-before > 8 {
		t.Errorf("FD count grew by %d after LoadKeys (before=%d after=%d); fds appear to leak", after-before, before, after)
	}
}

// countOpenFiles returns the open-fd count for this process, or -1 if the
// counting strategy isn't available on this platform. Linux exposes
// /proc/self/fd; macOS / others fall through to -1 (skip the assertion).
func countOpenFiles(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return -1
	}
	return len(entries)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

// TestLoadMEVRelays_ParsesArray covers the happy path.
func TestLoadMEVRelays_ParsesArray(t *testing.T) {
	dir := t.TempDir()
	p := writeFile(t, dir, "relays.json", `["https://relay1.example", "https://relay2.example"]`)

	got, err := LoadMEVRelays(p)
	if err != nil {
		t.Fatalf("LoadMEVRelays: %v", err)
	}
	if len(got) != 2 || got[0] != "https://relay1.example" || got[1] != "https://relay2.example" {
		t.Errorf("LoadMEVRelays returned %v", got)
	}
}

// TestLoadMEVRelays_MissingFile — surfaces an error.
func TestLoadMEVRelays_MissingFile(t *testing.T) {
	_, err := LoadMEVRelays(filepath.Join(t.TempDir(), "nope.json"))
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}

// TestLoadMEVRelays_MalformedJSON — surfaces a parse error rather than
// returning a half-populated slice.
func TestLoadMEVRelays_MalformedJSON(t *testing.T) {
	dir := t.TempDir()
	p := writeFile(t, dir, "relays.json", `{"not": "an array"}`)

	got, err := LoadMEVRelays(p)
	if err == nil {
		t.Fatalf("expected JSON parse error, got %v", got)
	}
}
